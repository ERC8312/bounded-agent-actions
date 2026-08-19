# Reservation and Reversal Profile (`IReservingBudget`)

A companion profile of the Bounded Agent Actions ERC, extending the
[Aggregate Budget Profile](AGGREGATE-BUDGET-PROFILE.md). The aggregate profile
meters realized spend and states two non-goals this profile lifts:

> **No reserve/refund.** Draws are final within a period. A liveness extension
> (reserving headroom so an in-flight action does not strand budget) is out of
> scope for this minimal safety profile.

- Reference implementation: [`src/ReservingBudgetCursor.sol`](src/ReservingBudgetCursor.sol)
- The reference passes the base profile's conformance suite unmodified. An
  extension that broke the base semantics would fail those vectors; this is the
  evidence that holds are **additive**, not a fork.

## Motivation

Authorize-now-settle-later is the dominant shape in payments. A card
authorization is a promise to collect later; a unified-balance attestation is a
promise to burn later. In both, the amount finally taken is frequently **less**
than the amount authorized, and the gap between the two is measured in days.

A pure spend meter cannot express this. It offers two options and both are
wrong:

- **Draw at authorization.** The meter now reflects an amount that was never
  taken. Every partial capture permanently over-meters, and headroom the
  principal is entitled to is destroyed.
- **Draw at settlement.** The authorization is backed by nothing. Between the
  promise and the draw, any other party sharing the cap may consume the
  authority the promise depended on, and settlement fails for a reason no
  participant could have seen coming.

The second failure is not hypothetical and is not exotic; it is the ordinary
case the moment more than one rail draws on one bound.

## The conservation property, extended

For every root and every period,

> **Σ over all realized draws + Σ over all outstanding holds ≤ root `cap`,
> at every point in time.**

The base profile's property is the special case where no holds exist. The
extension's value is entirely in the second term: a hold consumes headroom the
instant it is taken, so a claim that has been admitted cannot later be refused
**for want of authority**.

### Hold Amplification (Proposition)

*Path-local* accounting of holds — a reservation counter kept in a router, a
desk, a per-issuer ledger, or any register other than the one keyed on the root
— admits an **unbounded committed aggregate**, by exactly the argument of the
base profile's Fleet Amplification result applied one layer up.

Concretely: with holds kept per-holder, *k* holders may each hold *B* against a
root cap of *B*, because no holder can see another's book. Each holder's local
check passes. The first settlement succeeds and the remaining *k−1* fail — a
failure produced by an accounting error, not by any participant's misbehaviour.

A second and more damaging case follows if commit does not re-check the cap
(which a correct implementation must not, see requirement 3): a sibling draw
that consumes held headroom lets a later commit push realized spend **past the
cap**, breaking the base profile's own property. The two requirements are
coupled — an implementation that adopts commit-without-recheck while leaving
`draw()` blind to holds is strictly worse than one that has neither.

Both cases are exhibited as executable counterexamples in the reference test
suite.

### Dichotomy

A finite bound on *committed* authority is achievable **iff** holds live in the
same root-keyed register as realized spend, and every path that consumes
authority — draws and reservations alike — checks against their sum.

## Conformance requirements

A conformant implementation:

1. **MUST** hold reservations in the same register, keyed on the same root and
   period, as realized spend. A reservation counter outside that register is
   non-conformant even if every local check passes.
2. **MUST** admit a `draw()` only if `spent + reserved + amount ≤ cap`. A draw
   may not consume authority another party is holding.
3. **MUST NOT** re-check the cap on `commit()`. The headroom was consumed at
   reservation and the committed amount does not exceed it; re-checking
   reintroduces exactly the failure this profile exists to remove.
4. **MUST** reject a commit exceeding its hold, and **MUST** return the
   unconsumed remainder to available authority on a partial commit. Card rails
   routinely settle **above** the authorized amount (gratuities, fuel); the
   conformant representation is **incremental authorization** — an additional
   `reserve()` for the excess, subject to headroom, committed alongside the
   original. If the incremental hold is refused, the excess is the operator's
   exposure, exactly as a declined incremental authorization is on card rails
   today. A commit above its hold is never the mechanism.
5. **MUST** permit any caller to release a hold after its expiry, so an
   abandoned hold cannot strand authority indefinitely, and **MUST** bound hold
   duration.
6. **MUST NOT** invalidate an outstanding hold on revocation. This is a
   deliberate divergence from key-level revocation and implementations **MUST**
   document it: revocation stops *new* authority — further reserves and further
   draws — while a hold has already consumed headroom, and honouring it is the
   reading consistent with the base profile's rule that revocation never
   refunds the meter. An implementation that instead voids outstanding holds
   **MUST NOT** claim that an admitted claim cannot fail.
7. **MAY** permit a hold to outlive the period in which it was taken, and if so
   **MUST** settle it against the period it was **taken** in, not the period it
   lands in. Card capture windows routinely exceed a daily cap period; an
   implementation that forbids straddling is conformant but is unusable with
   any resetting cap, and **MUST** say so.

### The grief bound

The hold guarantee and the grief surface are the same coin: whatever cannot be
clawed back from an honest holder also cannot be clawed back from a compromised
one. Under requirements 5 and 6, an **unattenuated** node may reserve the entire
root cap for the maximum hold duration, and revocation — correctly — frees
nothing: every other rail is refused until expiry. Thirty days of refusal on
every rail is a loss by another name, and the reference test suite exhibits the
attack.

Accordingly, a conformant implementation:

11. **MUST** bound the maximum hold duration, and **SHOULD** make the bound a
    per-root parameter chosen by the issuer at creation, with the profile
    ceiling as its maximum.
12. **SHOULD** require reserving nodes to carry an attenuation cap, and
    deployments **SHOULD** attenuate every reserving node, so the worst-case
    freeze is a sublimit for a bounded window rather than the root for the
    ceiling. The residual — a compromised leaf holding its own sublimit for its
    ttl — is the priced cost of the settlement guarantee, and implementations
    **MUST** state it rather than claim the grief away.

### Sublimit administration

Attenuation caps are risk parameters, not conserved quantities; resizing them
does not touch the meter. An implementation **MAY** allow the issuer to adjust a
node's cap between periods (corridor and program limits are resized routinely),
and this does not violate the D1 no-admin rule, which protects the
**accumulator** — spend and holds — never the policy bounds around it. Two
allocation modes deserve names: **overbooked** (Σ node caps > root cap), where
sublimits are marketing and only the root refuses; and **guaranteed** (Σ node
caps ≤ root cap), where every node holds an allocation no sibling can starve —
the base profile's flat-tree reservation discipline. A deployment carrying
statutory obligations (consumer remedies, refund rights) **SHOULD** place them
in a guaranteed-mode node, so a required remedy is never refused at the group
cap by ordinary traffic.

### Reversals

Money on real rails moves backward: refunds, reversals, chargebacks, some of
them months after settlement. An implementation supporting them:

8. **MUST** bound a credit by the realized spend of the node being credited, so
   no node can mint headroom it never consumed.
9. **MUST** expose gross drawn alongside net spend. Once value can return, **the
   cap binds NET exposure, not gross turnover** — this is the honest statement
   and implementations **MUST NOT** describe a reversible meter as bounding
   total throughput.
10. **MUST** treat non-forgeability of a reversal as a **substrate obligation**,
    on the same footing as non-bypassability of a draw. A conformant substrate
    credits authority only after observing that the funds have actually
    returned. Crediting on an assertion that a refund occurred is a headroom
    mint with extra steps. Stated honestly for card rails: money returns as a
    clearing file, not as an on-chain event, so "observed" there means the
    substrate operator's attestation of the file — the credit leg inherits the
    attestation trust model, and implementations **MUST** say so rather than
    imply on-chain observability they do not have. A dispute is also a state
    machine, not a single credit: provisional credit, representment (a re-draw,
    months later, against the original period's slot), and pre-arbitration
    reversals of reversals are representable as draw/credit pairs on that slot,
    but the sequencing policy is the substrate's, not this profile's.

### Authorization-path placement

Where does `reserve()` execute inside a network authorization window? This
profile does not answer it, and implementations **MUST NOT** imply that a chain
write fits synchronously inside a terminal's latency budget on chains where it
does not. The honest deployment shapes are: (a) chains whose finality fits the
budget, named and measured; (b) **pre-reservation** — a session-sized hold taken
before traffic, with captures landing under it asynchronously; (c) an operator
sequencer with deferred anchoring, which reintroduces a trusted operator for
the interval and **MUST** be disclosed as such. An issuer consuming holds
**MUST** decide the confirmation depth at which it treats a hold as real; a
reorg-reverted hold is not a hold.

### Session holds

An implementation **MAY** support multi-capture holds: one reservation,
several commits drawing it down until exhaustion or expiry, the remainder
returning at close. This is the natural shape for (b) above — one chain write
per session rather than per authorization — and for high-frequency agent
traffic generally. Conservation is unchanged: the session hold consumes
headroom once, and Σ commits ≤ the hold.

### Refusal semantics

A refusal from the register is a decline some rail's customer experiences, on
a rail whose decline codes know nothing of group caps. Implementations
**SHOULD** expose (a) a free, read-only headroom query suitable for
consultation *before* authorization or routing — so a cap refusal becomes a
routing decision rather than a decline — and (b) typed, machine-readable
refusal reasons (root cap, node cap, revoked path, expired hold, stale
attestation) rather than a bare revert. The decline belongs to the rail that
surfaces it; giving that rail the reason is what makes the decline ownable.

## Scope and non-goals (normative)

- **Authority, not funds.** This profile bounds authority. It does **not**
  establish that funds exist to settle a held claim. Where a pool's balance is
  maintained off-chain or spans chains, it cannot be read from one chain, and
  an implementation **MUST NOT** present a conserved authority bound as a
  liquidity guarantee. The precise claim a conformant implementation may make
  is: *an admitted claim cannot fail for want of authority.*
- **Amount, and nothing else.** The meter binds quantity. It does not bind
  counterparty, jurisdiction, merchant category, or provenance, and an
  in-envelope payment to a prohibited counterparty satisfies it. This profile is
  a deterministic input to compliance controls and replaces none of them.
- **Enrolled-subset semantics.** The register proves conservation over the
  rails that consult it and cannot distinguish full coverage from partial from
  inside the record. Consumers of the bound — underwriters especially —
  **MUST** treat it as a *signal* about enrolled exposure (which it makes
  provable where it was previously unverifiable) and **MUST NOT** price it as
  a guarantee over a principal's total activity unless custody establishes
  that every path is enrolled.
- **Non-bypassability remains a substrate obligation**, inherited unchanged from
  the base profile. A register sees across rails and binds nothing on its own; a
  policy engine binds every path for the keys it holds and is blind past them.
  The guarantee is a composition of the two, and neither alone is sufficient.
- **Single chain**, inherited unchanged. See the base ERC's partition
  construction for the cross-chain case a global bound can be given today.
