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


## New option: --dump-edges (diagnostic only)

**NOTE:** This supersedes the older criterion described above. See the `--calibrate` section below for the current gate mode.

`--dump-edges <dir>` captures guest virtual addresses of edges instead of hashed bitmap indices. It enables kAFL's `trace_cb`, which makes QEMU write `from,to,count` lines to `<workdir>/redqueen_workdir_<qid>/pt_trace_results.txt`.

**CRITICAL WARNING:** `trace_cb` installs `alt_bitmap_add()` as libxdc's edge callback, and that writes into the SAME shared bitmap libxdc fills, using a different hash (`mix_bits`). So the bitmap produced under `--dump-edges` is a blend of two hash schemes and is NOT comparable with a run without it.

Observed symptom: ext4_small reported a 9448-edge core with `--dump-edges` vs 5388 without. Use it to find WHICH addresses differ, then re-run without it to judge pass/fail.

## New option: --calibrate (the current primary criterion)

Runs each backend TWICE (4 sessions for 2 backends) and passes if the cross-arm difference is at most `CALIB_SLACK` (1.5) times the larger within-backend session difference.

**Rationale:** A fixed percentage tolerance cannot work on this target. Measured with symbolised guest addresses:
- Two same-backend sessions differ by 50-54 edges (vmx-vs-vmx 54, perf-vs-perf 50)
- The two arms differ by 63 edges
- Repeats of ONE input inside a single session span 126 edges (11722, 11846, 11848)

The quantity under test is smaller than the noise.

A percentage makes it worse by dividing a roughly-constant absolute difference by a varying denominator: the same ~52-edge gap scored 2.94% on ext2 (pass) and 3.36% on garbage (fail) in the same run, and ext4_big flipped pass to fail between two runs of identical code.

Sessions are INTERLEAVED (vmx, perf, vmx, perf) not grouped, so slow drift in machine state does not land entirely on one arm.

**Honest limitation:** This trades absolute sensitivity for honesty about the noise floor. It can be fooled by a defect that is stable WITHIN a backend (such a defect inflates both numbers together). Address-level inspection via `--dump-edges` covers that case. The two are complementary.

## Userspace ASLR is a structural confound

`nokaslr` on the guest cmdline disables KERNEL ASLR only; the userspace mmap base is re-randomised every boot.

Measured: after subtracting each side's own lowest page, 7 of 7 userspace pages match and all 8 of 8 distinct page offsets are shared. Bases differed by 0x97d47b1a pages.

Because the arms can never share a session (vmx_pt clobbers a live perf session on every VM exit), they can never share an ASLR base, so EVERY userspace edge is guaranteed to hash to a different bitmap index in the two arms.

On fs_fuzzer only 15-16 edges are userspace so it is small, but on a userspace-heavy target it would swamp the signal and be indistinguishable from a decoder bug. Future targets need `norandmaps` or a kernel-only comparison.

## The ~50-edge gap that failed the old gate is NOT a backend defect

It is target nondeterminism plus a real difference in what the two tracing modes observe.

Evidence: symbolising against `/boot/System.map-6.8.0-nyx-nyx-cr3` showed ZERO KVM host-only functions (`vmx_vcpu_run`, `vmx_handle_exit`, `kvm_arch_vcpu_ioctl_run`, `vcpu_enter_guest`, ...) on either arm and zero addresses in the module region, so the libxdc NR filter is working.

The perf-only edges are asynchronous work:

| Function | Edges |
|---|---|
| `__do_softirq` | 25 |
| `timerqueue_add` | 16 |
| `rcu_gp_init` | 14 |
| `rcu_gp_cleanup` | 14 |
| `sysvec_apic_timer_interrupt` | 12 |

perf's kernel core is consistently LARGER than vmx's (11706/11658 vs 11586/11540) because a host-wide event observes that async work while vmx_pt's hardware filtering sees less of it.

**Important caveat:** Host and guest run the SAME kernel build with nokaslr, so a leaked host address would be byte-identical to the equivalent guest address. No address-range test can separate them; only asking WHICH FUNCTIONS appear works.

## Analysis helper scripts

The following scripts now exist at `/tmp/`:
- `addrgap.py`: raw address-level gap analysis
- `aslr.py`: ASLR base detection and page offset alignment
- `symgap.py`: takes a dumpdir and a System.map, shows symbolised gap
- `control.py`: takes two dumpdirs, a System.map and a backend name

**NOT yet committed.** These should be moved into `tools/ptdiff/` if kept.

`symgap.py` takes a dumpdir and a System.map; `control.py` takes two dumpdirs, a System.map and a backend name.
