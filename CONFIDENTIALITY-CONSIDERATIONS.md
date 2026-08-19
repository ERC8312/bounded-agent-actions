# Confidentiality Considerations

Non-normative guidance for the Bounded Agent Actions family. The base ERC states
that it does not define a privacy protocol and does not guarantee unlinkability.
That remains true. This note exists because the omission is read, correctly, as
an unanswered objection rather than a neutral scoping choice — and because the
objection has a structural answer worth writing down.

## The objection, stated at full strength

A conserved bound is only useful if participants who do not trust each other can
each recompute it. Recomputability requires a shared record. A shared record of
every draw against a principal's bound discloses that principal's spending
**across rails, to its own counterparties, in real time**.

For a consumer this is a privacy problem. For a corporate principal it is a
commercial-confidentiality problem, which is the more immediately fatal of the
two: a competitor deriving a rival's cross-rail spend velocity does not need to
identify a single payee to extract value from the record. Reviewers reach this
objection before privacy counsel is consulted, and any deployment plan that does
not address it should expect to be stopped there.

**This tension is real and is not resolved by better engineering alone.**
Stranger-recomputability and confidentiality pull in opposite directions.

## What makes the tension tractable

**The meter and the payment are different objects.**

The quantity a bound conserves is an *amount*. The quantity that leaks a
commercial position is a *counterparty*, a *timing*, and a *pattern*. The
authorization witness must **bind** a payee — an authorized amount any holder
could redirect is not an authorization — but binding does not require revealing.
The v1 preimage ([`SpendPreimage.sol`](src/SpendPreimage.sol)) binds the payee
in cleartext, which puts it in public calldata when the witness is submitted
on-chain. The v2 preimage ([`SpendPreimageV2.sol`](src/SpendPreimageV2.sol))
binds it behind a blinded commitment: the signature still covers exactly one
payment destination — enforced at settlement by whoever verifies the opening
against the actual transfer target, an integration obligation the reference
meters do not perform — and the public record never learns which. The meter
itself carries a payee in neither version: no payee reaches any event, raw or
hashed, across both budget cursors' full lifecycles
([`test/PayeeOffMeter.t.sol`](test/PayeeOffMeter.t.sol), scanner proven live
against a decoy), the spend-witness cursor's state and events carry none by
construction, and the v1-reveals/v2-conceals split is pinned by
[`test/SpendPreimageV2.t.sol`](test/SpendPreimageV2.t.sol).

That separation admits a composition the naive reading forecloses:

| Object | Visibility | Who needs it |
|---|---|---|
| Root cap | public | anyone verifying the bound |
| Aggregate consumed against it | public | anyone verifying the bound |
| Which node consumed it | public in the references; a substrate MAY blind it (leak 3) | the principal, the substrate |
| Payee, memo, purpose | **never on the meter** | the counterparties, and their supervisors |

Under the committed (v2) preimage, a bound is public and recomputable while the
payments behind it remain confidential: the verifier answers *was the bound
respected* and sees a commitment where the counterparty would be. Under v1 the
bound is equally sound but the payment is not confidential — the composition is
available, not automatic, and a deployment gets it only by choosing the
committed witness.

## Residual leakage, and what closes it

Separating payee from amount is necessary and not sufficient. Three leaks
survive it, and implementations should address each explicitly rather than
claiming confidentiality wholesale.

1. **Per-transaction timing.** A meter that decrements once per authorization
   publishes a timeline even with no payee attached, and a timeline against a
   published price list is frequently enough to fingerprint the underlying
   activity. **Mitigation:** decrement once per settlement batch rather than
   once per transaction. Per-claim holds do **not** achieve this: a hold
   consumes headroom the instant it is taken — that is the hold-amplification
   defense — so per-claim reservations republish the timeline one ledger over.
   The shape that works is a **standing buffer** — the reservation profile's
   own hold and commit, taken once per period instead of once per claim: one
   hold per node per period sized to the batch envelope, per-claim vouchers
   admitted against it off-record, one net settlement at period end.
   Conservation holds — settled plus buffer never exceeds the cap, the stateful
   invariant in
   [`test/ReservingBudgetCursor.invariant.t.sol`](test/ReservingBudgetCursor.invariant.t.sol)
   — and the public timeline coarsens to the period: twenty-five payments leave
   three meter events, selector and payload pinned, in
   [`test/ReservingBufferPattern.t.sol`](test/ReservingBufferPattern.t.sol).
   The stated cost: within the buffer, per-claim conformance is verified against
   the holder's book rather than recomputable by strangers — the
   proof-for-record substitution below, one level down. The same test file
   demonstrates the cost, not just the benefit: a book that over-admits past the
   buffer still settles a conformant net, and the chain cannot see it.
2. **Amount fingerprinting.** Distinctive amounts identify counterparties
   without naming them. **Mitigation:** batch settlement, as above; where that
   is insufficient, the amount itself must move behind a commitment, which is a
   substrate change rather than an interface one.
3. **Node-level attribution.** Per-node sublimits are useful precisely because
   they are legible, and legibility is disclosure. **Mitigation:** node identity
   is a substrate choice; a substrate MAY key nodes to commitments rather than
   to addresses, at the cost of making sublimit conformance harder to check
   externally.

## Where a shielded construction sits

A substrate MAY validate a draw against a commitment rather than against public
state — the base ERC contemplates exactly this in leaving `cursorRoot`,
`capabilityRoot`, and the witness opaque. The honest description of that design
point is a **substitution, not a feature flag**: once aggregate state is
shielded, verification moves in-circuit, and "recomputable by any party from the
public record" is replaced by "verifiable by any party against a proof."

Both are sound. They are not the same guarantee, they suit different
counterparties, and an implementation **should not** claim both simultaneously.

## Guidance

- State which construction is in use, and do not describe a transparent meter as
  confidential.
- Prefer per-batch meter movement to per-transaction, by default — via a
  standing buffer (a period-sized reservation-profile hold), not per-claim
  holds.
- Never place a payee on the meter, even where it would be convenient.
- Bind the payee in the witness behind a blinded commitment rather than in
  cleartext; the blinding is load-bearing, since an unblinded or predictable
  hash over a small payee set is dictionary-searchable, and it must be fresh
  per draw or shared blindings link the payments that share them. Verify the
  opening off-chain — a real payee passed through transaction calldata defeats
  the construction.
- Where a supervisor or lender needs more than the bound, give them a scoped
  viewing capability rather than making the record public to everyone.
- Treat the confidentiality claim as falsifiable: if a party can derive a
  principal's counterparties or spend pattern from the public record, the claim
  fails regardless of what the interface says.
