# Bounded Agent Actions — Reference Implementation

Minimal, CC0, dependency-free reference for the **Bounded Agent Actions** ERC
(an on-chain interface that meters an agent's aggregate authority across calls
via a cursor). Canonical spec at
[ethereum/ERCs PR #1833](https://github.com/ethereum/ERCs/pull/1833) (ERC-8312).
Discussion: [Ethereum Magicians thread 28851](https://ethereum-magicians.org/t/erc-bounded-agent-actions-a-metering-layer-for-agent-authority/28851).

This repository is the reference implementation only. The normative specification
lives in ethereum/ERCs; this code exists to show the interface is implementable and
the profiles interoperable.

## Contents

| File | Role |
|------|------|
| `src/IBoundedAgentAction.sol` | Base interface (register / read / advance / status) |
| `src/IBudgetSubstrate.sol` | Typed extension for the Budget Substrate Profile |
| `src/IContestableEnvelope.sol` | Optional contestation extension |
| `src/IAggregateBudget.sol` | Optional aggregate-budget profile (one conserved cap across a delegation tree) — see [AGGREGATE-BUDGET-PROFILE.md](AGGREGATE-BUDGET-PROFILE.md) |
| `src/ReservingBudgetCursor.sol` | Reservation and reversal profile — authorize-now-settle-later, and authority credited back when value returns. See [RESERVATION-PROFILE.md](RESERVATION-PROFILE.md) |
| `src/EnvelopeRegistry.sol` | Reference registry implementing the Budget Substrate Profile |
| `src/AggregateBudgetCursor.sol` | Reference implementation of the aggregate-budget profile |
| `test/EnvelopeRegistry.t.sol` | Conformance suite (22 tests) |
| `test/AggregateBudgetConformance.t.sol` | Aggregate-profile conformance suite (9 tests) |
| `test/AggregateBudgetCursor.t.sol` | Aggregate reference unit tests, incl. the `2B` amplification counterexample (19 tests) |
| `test/AggregateBudgetCursor.invariant.t.sol` | Stateful conservation invariant over randomised trees |
| `src/IERC165.sol` | Vendored ERC-165 interface (keeps this dependency-free) |

## Companion documents

- [AGGREGATE-BUDGET-PROFILE.md](AGGREGATE-BUDGET-PROFILE.md) — one conserved cap across a delegation tree.
- [RESERVATION-PROFILE.md](RESERVATION-PROFILE.md) — holds, partial capture, expiry, and reversals. Lifts the base profile's `no reserve/refund` non-goal.
- [CONFIDENTIALITY-CONSIDERATIONS.md](CONFIDENTIALITY-CONSIDERATIONS.md) — the recomputability-versus-confidentiality tension, and the meter/payment separation that makes it tractable.

## Scope and limitations

This is a **toy budget substrate**: the cursor is a running spend counter and the
witness is an ECDSA authorization bound to `(id, prevCursor)`. It demonstrates the
interface, the profile semantics, and the conformance vectors.

It deliberately **does not bind assets or gate an execution path**, so it is *not*
non-bypassable by the principal's own key. Per the ERC, non-bypassability is a
substrate obligation and is out of scope for this minimal example. It contains
none of the production substrate (no ZK prover, no kernel, no credit logic).

## ERC-165 interface ids (computed from this implementation)

- `IBoundedAgentAction` — `0x3985961d`
- `IBudgetSubstrate` — `0x021ca455`
- `IContestableEnvelope` — `0xe664d441`
- `IAggregateBudget` — `0xc7cabe86`

## Testing

`forge-std` is vendored under `lib/` (gitignored) for local testing:

```
forge test -vv
```

For a published copy, replace the vendored lib with `forge install foundry-rs/forge-std`.

## License

CC0-1.0 (interfaces, implementation, and tests).
