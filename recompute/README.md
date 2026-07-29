# Recompute recipes

Scripts that check a published invariant against live chain state, from public
data only, without trusting a view function or an RPC's reported value.

The discipline is the one this repository's own profiles are written for: an
invariant is only as strong as a stranger's ability to re-derive it. A cursor
that reports `remaining` through a getter proves nothing a stranger can check;
the same cursor proven from its storage slot under a block's state root does.
These scripts apply that to deployed contracts, including implementations of
other specifications.

| Path | Checks |
|:-----|:-------|
| `erc8350_sepolia.py` | ERC-8350 Agent Memory State Registry: sequenced-transition rule on its public Sepolia deployment |

## `erc8350_sepolia.py`

ERC-8350 requires that each memory-state transition be the unique successor of
the current state, via `sequence == currentSequence + 1` and
`prevStateRoot == currentStateRoot`. Its published test vectors fix the hashing;
they say nothing about whether the deployed registry agrees with them.

This script closes that gap. For every Memory Space it:

1. recomputes each `transitionId` from the EIP-712 type string;
2. recomputes each `nextStateRoot` as
   `keccak(MEMORY_STATE_TYPEHASH, prevStateRoot, transitionId)`;
3. checks the chain is gapless, from sequence 1 with `prevStateRoot == 0`;
4. proves the head from contract storage and compares it with the head obtained
   by replaying the event path.

Step 4 is the one worth having. Steps 1 to 3 check the itemized path; step 4
checks that the single slot a consumer would read as "current state" is exactly
the sum of that path. A registry whose stored head disagreed with its own
emitted history would pass a golden-vector test and fail here.

Storage is read by walking the Merkle-Patricia trie: the account proof from the
block's state root to obtain the storage root, then each requested slot from
that storage root. The `value` and `storageHash` fields `eth_getProof` reports
are asserted against the independently walked results and are otherwise unused.
Given the block's state root, that removes trust in the registry's view
functions and in the proof-serving endpoint.

The state root itself is not taken on faith either: the script reconstructs the
block header, checks `keccak(rlp(header))` against the block hash, and prints
that hash for checking against any explorer (`--cross-check-rpc` automates a
second opinion). What one endpoint can still do is omit — hide a Memory Space
by filtering logs — which no single-source check can exclude.

```
pip install pycryptodome
python3 erc8350_sepolia.py
python3 erc8350_sepolia.py --rpc-url URL --registry 0x... --block N
```

Exit code is 0 only if every Space verifies.

Result as of 2026-07-29, registry
`0xDdf21937ba80b5fF973610877A0955b320C91241`: five transitions across two Memory
Spaces, all verified. Every id and root recomputes, both chains are gapless, and
both stored heads — all three fields of `head()`: transitionId, stateRoot,
sequence — equal their replayed paths.

## Scope

These scripts check state machines, not meaning. Verifying that a commitment
chain is well formed says nothing about whether the committed data is available,
truthful, or useful, which the specifications concerned are explicit about
placing out of scope.

The trie walker is minimal. It handles branch, extension and leaf nodes with
hash references and raises on an inlined node rather than guessing, so an
unsupported proof shape is an error and never a silent pass. Storage layouts are
taken from each target's reference implementation; a registry deployed from
different source needs its layout supplied.

Most endpoints serve `eth_getProof` only within a recent window, so an old
`--block` will be refused. The observation block is an observation point, not
part of the claim: while no new transitions land, every later block yields the
same head.
