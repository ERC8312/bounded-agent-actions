# Aggregate Budget Profile (`IAggregateBudget`)

An **optional companion profile** of the Bounded Agent Actions ERC. The base
profile (`IBoundedAgentAction` / `IBudgetSubstrate`) meters one envelope's
cumulative spend. This profile meters the **aggregate spend of a whole delegation
tree** against a single conserved root cap: an agent spawns sub-agents, which
re-delegate further, each acting under its own key, and the sum of spend across
every node in a period is bounded by one root budget.

A tree is not an envelope, so `IAggregateBudget` does **not** extend
`IBoundedAgentAction`. An implementation MAY support both interface ids. **The base
interfaces are unchanged.**

- ERC-165 interface id: **`0xc7cabe86`**
- Reference implementation: [`src/AggregateBudgetCursor.sol`](src/AggregateBudgetCursor.sol)
- Conformance suite: [`test/AggregateBudgetConformance.t.sol`](test/AggregateBudgetConformance.t.sol)

## Motivation

The scaling pattern for autonomous agents is a **tree**, not a single agent. A
principal who funds a fleet wants one guarantee over the whole tree: the sum of
spend across every sub-agent in a period stays within a single cap `B`, no matter
how the tree fans out or re-delegates — and with **no pooled custody** (each agent
holds its own key) and **no trusted coordinator**.

No existing on-chain primitive provides this:

| Option | Why it fails the fleet case |
|--------|-----------------------------|
| Shared account / ERC-20 balance | "Conserves" only by sharing **custody**; every draw serializes through one key |
| Allowance / delegation graph (ERC-7710, `approveDelegation`) | Grants are **independently minted** — *k* agents at `B` each already sum to `kB` |
| Escrow | **Atomic only** — no standing budget across many agents over a period |
| Hierarchical cards (Ramp/Brex) | **Centralized and trusted** — not on-chain, not stranger-verifiable |

## Normative conservation property

For every root and every period,

> **Σ over all admitted `draw()` of `amount` ≤ root `cap`.**

This holds regardless of fan-out, depth, or re-delegation. Two facts make it
non-trivial (both proved in the companion paper (in submission), §"Fleet Conservation"):

**Fleet Amplification (Proposition).** *Path-local* accounting — a fresh spend
counter per delegation edge, the shape of per-grant allowances, caveat chains,
session keys, ERC-7710 redelegation — admits an **unbounded** aggregate. A root
holding `sk_root` opens *k* sibling paths each capped at `B` and realizes `kB`; any
shared counter that lives in `sk_root`'s write-domain is reset by `sk_root` between
paths (Key Sovereignty). Such an implementation is therefore **NON-CONFORMANT**
even though every per-edge check passes. The paired
[`PerEdgeBudgetMock`](test/AggregateBudgetCursor.t.sol) exhibits the `2B` case
concretely.

**Fleet-Conservation Dichotomy (Theorem).** A finite aggregate bound `B` is
achievable **iff** the running accumulator is a single register keyed on the
**root** (not the edge) and held **outside the write-domain of every key reachable
in the tree** — i.e. immutable, non-principal-controlled register code (deployment
shape **D1**). Path-local accounting admits no finite bound; the shared root
register admits exactly `B`.

## Conformance requirements

A conformant implementation:

1. **MUST** key its running meter on the **root**, not on the delegation edge, so
   that `spentRoot(rootId, period)` is the sum over the whole tree.
2. **MUST** revert a `draw()` that would take `spentRoot(rootId, period) + amount`
   above the root `cap`.
3. **MUST NOT** expose an owner/upgrade/admin authority that can reset or decrement
   the meter (the **D1** requirement). An upgradeable or admin-controlled meter
   returns the accumulator to a key's write-domain and is non-conformant.
4. **MUST NOT** decrement the meter on `revoke()` — realized spend stays realized;
   revocation only shrinks future headroom.
5. **MUST** gate `draw()` on the node's agent and an unrevoked path to the root;
   **MUST** gate `delegate()` on the parent node's agent.
6. **MUST** treat a capped node (`nodeCap != 0`) as a **leaf**: it MUST NOT be able
   to delegate. Without this, a node capped at `X` mints itself an uncapped child
   and draws the full root headroom, defeating its own cap. With it, capped leaves
   under uncapped backbone nodes make `nodeCap` a **hard per-counterparty bound**,
   and choosing per-leaf caps with `Σ nodeCap ≤ cap` gives every leaf a guaranteed
   allocation (no leaf can be starved by its siblings) — the flat-tree reservation
   discipline. `Σ nodeCap > cap` (overbooking) is permitted and reintroduces
   contention by explicit choice.
7. **MUST** advertise `0xc7cabe86` and `0x01ffc9a7` (ERC-165) via
   `supportsInterface`.

## Scope and non-goals (normative)

- **Safety, single chain.** The bound is enforced by the serialized
  check-then-increment of one register under transaction serialization.
  Cross-chain aggregation is **out of scope** (it requires cross-chain atomic
  decrement).
- **No per-subtree meter.** The only conserved quantity is the global root. An
  optional per-node attenuation cap (`nodeCap`) MAY additionally bound a single
  node's own draws, but it does **not** ring-fence a sub-budget for that node's
  subtree; a single unattenuated leaf may draw the whole root cap. Implementations
  **MUST NOT** present a node cap as a subtree cap.
- **Non-bypassability is a substrate obligation.** Like the base profile, a
  conformant meter must sit on the sole path to asset movement; this interface
  meters and does not itself move assets or gate execution.
- **No reserve/refund.** Draws are final within a period. A liveness extension
  (reserving headroom so an in-flight action does not strand budget) is out of
  scope for this minimal safety profile.

## Relation to prior aggregate-authority mechanisms

Metering aggregate authority across a delegated subtree is the object-capability
**membrane/meter** pattern (Miller, *Robust Composition*, 2006); hierarchical rate
limits and IAM permission boundaries enforce the same shape operationally. Each
assumes a **trusted enforcer** — a vat, a kernel scheduler, a policy evaluator at a
choke point the delegator does not own. This profile removes that assumption: the
enforcer is the delegator, and the only trust anchor is consensus-fixed register
state. It is the ledger form of results showing a property unenforceable against an
environment-owning adversary without an external anchor (attested execution,
Pass–Shi–Tramèr 2017; robust declassification, Zdancewic–Myers 2001), and the
double-spend impossibility lifted from a single bearer note to a whole delegation
tree.
