# ptdiff: differential PT backend comparison

Phase 1 success criterion for the perf-based Intel PT backend. Replays one corpus
under two PT backends and checks that they produce the same coverage.

## Why a differential test at all

An earlier feasibility experiment hit a case where libxdc returned
`decoder_success` while silently discarding an entire trace, producing constant
coverage that looked like a working pipeline. Nothing short of comparing against
a known-good decoder catches that class of bug, which is why the pass condition is
"agrees with vmx_pt" rather than "finds crashes".

## Usage

Backend selection rides on `-global nyx.pt_backend=<kind>`, which sets the qdev
property without touching the device string `worker/qemu.py` builds by
concatenation, so no fuzzer patch is needed.

```
export KAFL_QEMU_PATH=/path/to/qemu-nyx-perf/x86_64-softmmu/qemu-system-x86_64
export KAFL_PAYLOAD_SIZE=294912

python3 ptdiff.py \
    --corpus ./seeds --backends vmx,perf --repeat 5 \
    --workdir /dev/shm/ptdiff \
    --kernel /boot/vmlinuz-$(uname -r) --initrd ./fs_fuzzer.cpio.gz \
    --memory 512 --sharedir $PWD/sharedir -t 4 \
    --append "nokaslr oops=panic nopti mitigations=off console=ttyS0 hprintf=7"
```

Every other argument is passed to kAFL's own `debug` parser untouched, so a target
is described exactly as it would be for `kafl debug`.

`--backends stock` adds no `-global` at all, for comparing against an unmodified
QEMU build.

The arms run strictly sequentially and each is torn down before the next starts.
This is a hard requirement: vmx_pt puts `RTIT_CTL` on the VMX MSR autoload list
with `TraceEn` cleared, so once any vCPU has issued `KVM_VMX_PT_ENABLE`, every VM
exit silently kills a live host perf session. vmx_pt never calls
`x86_add_exclusive`, so perf sees no `EBUSY` and no warning; the trace just stops.
A concurrent run would not fail, it would quietly produce wrong data.

## The criterion, and why it is not exact bitmap equality

The spec originally called for per-input bitmap hash equality. That is not usable
on a real target, and the measurements below are why. All were taken on
`6.8.0-nyx-nyx-cr3`, i9-13900K, with the `fs_fuzzer` example.

**Bitmap hashes are not reproducible, on stock QEMU too.** Replaying three seeds
several times each, 3 of 3 inputs produced varying hashes. Critically the *stock
deployed* QEMU, containing none of this work, was equally unstable. The variance
is the target, not the decoder. Any criterion built on hash equality fails on an
unmodified binary.

**Raw per-execution edge sets are also unstable**, but only barely: a fringe of
roughly 30 to 46 edges out of ~5400 flickers, so ~99.5% of coverage is stable.

**The per-input core (edges hit on *every* repeat) is stable within a session** at
`--repeat 6`, but not across sessions. Four sessions of the identical command gave
core sizes differing by up to 11 edges. This matters because the two arms cannot
share a session, per the serialisation requirement above, so comparing arms always
means comparing sessions.

**Baseline normalisation was tried and rejected.** The idea was to subtract the
session baseline (the intersection of every input's core, i.e. the shared boot and
handshake path) and compare the remainder. It failed twice:

1. Not portable. It appeared to work across one pair of sessions, then four
   sessions showed signature sizes of 13, 15, 14, 14 for the same input. Two
   agreeing measurements on a known-noisy metric is not evidence.
2. Fragile by construction. The baseline is an intersection over all inputs, so a
   single zero-coverage input collapses it to the empty set. This is not
   hypothetical: a 1-byte seed yields a 0-edge core, and on a varied corpus the
   baseline became 0 and "signatures" silently degenerated into raw cores. A
   criterion that quietly becomes a different criterion is worse than one that
   fails loudly.

`session_baseline()` and `signatures()` are kept as diagnostics for seeing how
much of an input's coverage is the shared path. They are not the criterion.

**What is used: per-input core agreement within a tolerance.** Cross-session core
noise is under 1% (measured: ext2 spread 15 of 1928, ext4_small 10 of 5388,
garbage 2 of 1727). The faults this exists to catch remove whole regions of a
trace. Those are orders of magnitude apart, so a 3% tolerance separates them with
room to spare.

Note the criterion deliberately does not try to distinguish inputs from each
other. That was the error behind the baseline idea. Two arms are compared on the
*same* input, so input-to-input similarity is irrelevant; only within-input
cross-session stability matters.

## Corpus requirements

The corpus must be varied, and this is not a detail. Three near-identical ext4
images (256, 260, 280 blocks) exercise almost the same code: input-specific
coverage was 0 to 15 edges, below the ~11 edge noise floor, so no criterion could
work. Replacing them with ext2, ext3, two ext4 sizes, vfat, random bytes and a
1-byte file raised input-specific coverage to 1727 to 1951 edges, putting the
noise at 0.6% of the signal.

An input that produces zero coverage is reported and excluded rather than counted
as a pass, since a 0 versus 0 comparison proves nothing.

## Validation

`validate_criterion.py` checks the criterion against known-answer cases using
saved core dumps, because a criterion nobody has tried to break is just an
assertion. Results as of the last run:

| case | expected | result |
|---|---|---|
| same backend, 3 session pairs | pass | pass, worst divergence 0.98% |
| total loss, all inputs | detect | detected, 100% |
| total loss, one input | detect | detected, 100% |
| region loss, 20% contiguous span | detect | detected, 20.2% |
| 5% scattered loss | detect | detected, 5.5% |
| single edge removed | (floor) | not detected |

Measured sensitivity floor on a 1928-edge core, against a different session so
the number includes cross-session noise: 2% loss is not detected, 3% is. The
harness does not claim better sensitivity than that.

## Helper scripts

- `validate_criterion.py`: known-answer validation, as above.
- `measure_portability.py`: compares saved cores across N sessions and reports
  which candidate criteria hold. Use this before trusting a criterion on a new
  target.
- `diff_cores.py`: classifies a cross-session core difference as nested,
  overlapping, or confined to the known fringe.

All three take core dumps written by `--save-cores`.
