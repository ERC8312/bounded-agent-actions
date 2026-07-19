# Bounded Agent Actions — Reference Implementation

CC0 reference implementation of the Bounded Agent Actions ERC; canonical spec at
[ethereum/ERCs PR #1833](https://github.com/ethereum/ERCs/pull/1833) (ERC-8312).
Discussion: [Ethereum Magicians thread 28851](https://ethereum-magicians.org/t/erc-bounded-agent-actions-a-metering-layer-for-agent-authority/28851).

This repository is the reference implementation only. The normative specification
lives in ethereum/ERCs; this code exists to show the interface is implementable and
the Budget Substrate Profile interoperable.

## Contents

| Path | Role |
|:-----|:-----|
| `src/IBoundedAgentAction.sol` | Base interface: register, read, advance, status |
| `src/IBudgetSubstrate.sol` | Typed extension for the Budget Substrate Profile |
| `src/IContestableEnvelope.sol` | Optional contestation extension |
| `src/EnvelopeRegistry.sol` | Reference registry implementing the Budget Substrate Profile |
| `src/IERC165.sol` | Vendored ERC-165 interface (keeps this dependency-free) |
| `src/IAggregateBudget.sol` | Optional aggregate-budget companion profile: one conserved cap across a delegation tree ([profile notes](AGGREGATE-BUDGET-PROFILE.md)) |
| `src/AggregateBudgetCursor.sol` | Reference implementation of the aggregate-budget profile |
| `test/EnvelopeRegistry.t.sol` | Conformance suite |
| `test/AggregateBudgetConformance.t.sol` | Aggregate-profile conformance suite (interface-typed; portable to other implementations) |
| `test/AggregateBudgetCursor.t.sol` | Aggregate reference unit tests, including the per-edge amplification counterexample |
| `test/AggregateBudgetCursor.invariant.t.sol` | Stateful conservation invariant over randomised delegation trees |

## Scope

This is a deliberately minimal budget substrate. The cursor is a running spend
counter and the witness is an ECDSA authorization bound to `(id, prevCursor)`.

It **meters but does not enforce**: it binds no assets and gates no execution path,
so it is not non-bypassable by the principal's own key. Per the ERC, non-bypassability
is a substrate obligation and is out of scope for this minimal example. It contains
no production substrate: no proof system, no execution kernel, no credit logic.

## Frozen ERC-165 interface ids

| Interface | id |
|:----------|:-----|
| `IBoundedAgentAction` | `0x3985961d` |
| `IBudgetSubstrate` | `0x021ca455` |
| `IContestableEnvelope` | `0xe664d441` |
| `IAggregateBudget` | `0xc7cabe86` |

## Build and test

```
forge install foundry-rs/forge-std
forge test
```

## License

CC0-1.0. See [LICENSE](LICENSE).
