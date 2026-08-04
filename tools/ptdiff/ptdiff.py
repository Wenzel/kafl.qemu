#!/usr/bin/env python3
"""Differential replay: same corpus, both PT backends, compare bitmap hashes.

This is Phase 1 success criterion 1. For a fixed target and a fixed corpus,
replaying every input under the vmx and perf backends must yield identical
coverage bitmap hashes, input for input. Any mismatch is a decode bug, not a
tuning issue.

Why this specific test rather than "it finds crashes too": the feasibility
work hit a case where libxdc returned decoder_success while silently
discarding an entire trace, producing constant coverage that looked like a
working pipeline. Differential bitmap comparison is the only thing that
catches that class of bug. It is also why the constant-coverage check below
is not redundant with the mismatch count: two arms that both discard
everything would agree perfectly and still be broken.

The arms run strictly sequentially and each is fully torn down before the
next starts. That is a hard requirement, not tidiness. vmx_pt puts RTIT_CTL
on the VMX MSR autoload list with TraceEn cleared, so once any vCPU has
issued KVM_VMX_PT_ENABLE, every VM exit silently kills a live host perf
session. vmx_pt never calls x86_add_exclusive, so perf sees no EBUSY and no
warning; the trace just stops. A concurrent run would not fail, it would
quietly produce wrong data.

Backend selection rides on qemu_extra as "-global nyx.pt_backend=<kind>".
worker/qemu.py assembles the nyx device property string by concatenation and
offers no extension point, but -global sets a qdev property without touching
that string, so no fuzzer change is needed.

Invoked like a kafl subcommand, since it reuses kafl's own argument parser:

    python3 ptdiff.py --corpus <dir> --workdir <dir> \
        [every other kafl debug argument for the target]
"""
import argparse
import json
import logging
import os
import shutil
import sys

from kafl_fuzzer.common.config import (ConfigParserBuilder, settings,
                                       update_from_namespace, validate)
from kafl_fuzzer.common.logger import setup_basic_logging
from kafl_fuzzer.common.util import prepare_working_dir, read_binary_file
from kafl_fuzzer.worker.qemu import qemu

logger = logging.getLogger(__name__)

# Set once by main() from --baseline-tolerance. A one-element list rather than a
# bare global so compare() can read it without a global statement.
own_tolerance = [0.03]

# How much worse the cross-arm difference may be than the within-backend one
# before it counts as a real difference. 1.5 rather than 1.0 because the
# within-backend number is itself a single sample of a random quantity, and a
# threshold set at exactly one sample of the noise fails roughly half the time
# by construction.
CALIB_SLACK = 1.5

# Arguments this script consumes itself. Everything else is handed to kafl's
# own parser untouched, so a target is described exactly as it would be for
# kafl debug and no option list has to be mirrored here.
OWN_ARGS = ("--corpus", "--backends", "--limit", "--report", "--repeat",
            "--save-cores", "--baseline-tolerance", "--dump-edges",
            "--calibrate", "--keep-workdirs")


# Own arguments that take no value. Splitting has to know about these, because
# consuming the following token for a bare flag steals the next real argument:
# "--calibrate --workdir /x" became own=["--calibrate", "--workdir"] and left
# argparse to reject "--workdir" as unrecognised, with an error message pointing
# at the wrong option entirely.
OWN_FLAGS = ("--calibrate", "--keep-workdirs")


def split_argv(argv):
    own, rest = [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        key = a.split("=", 1)[0]
        if key in OWN_ARGS:
            own.append(a)
            if key not in OWN_FLAGS and "=" not in a and i + 1 < len(argv):
                own.append(argv[i + 1])
                i += 1
        else:
            rest.append(a)
        i += 1
    return own, rest


def parse_own(argv):
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--backends", default="vmx,perf")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--report", default=None)
    # Replay the whole corpus this many times within one arm. >1 checks that a
    # given input reproduces its own hash inside a single session, which is a
    # precondition for cross-backend comparison meaning anything.
    ap.add_argument("--repeat", type=int, default=1)
    # Write stable cores as JSON so separate sessions can be diffed. Only
    # meaningful with --repeat, since a core needs more than one execution.
    ap.add_argument("--save-cores", default=None)
    # Allowed baseline divergence as a fraction. Measured cross-session noise on
    # fs_fuzzer is 0.22%; a decoder dropping traces would be orders of magnitude
    # larger, so 2% separates them with room to spare.
    ap.add_argument("--baseline-tolerance", type=float, default=0.03)
    # Directory to write per-input decoded edge traces. When set, enables
    # trace_cb mode so QEMU writes edges as guest virtual addresses rather
    # than only computing hashed bitmap indices.
    #
    # DIAGNOSTIC MODE, NOT A GATE MODE. trace_cb makes nyx install
    # alt_bitmap_add() as the edge callback, and that writes into the SAME
    # shared bitmap libxdc fills, using a different hash (mix_bits) than
    # libxdc's own. The bitmap a run produces under --dump-edges is therefore a
    # blend of two hash schemes and is not comparable with one produced without
    # it. Use this to find out WHICH guest addresses two backends disagree on,
    # then re-run without it to judge pass or fail.
    ap.add_argument("--dump-edges", default=None)
    # Run each backend TWICE and use each one's own session-to-session
    # difference as the pass threshold, instead of a percentage picked in
    # advance. See compare_calibrated() for why this supersedes
    # --baseline-tolerance as the real criterion. Costs 2x runtime.
    ap.add_argument("--calibrate", action="store_true", default=False)
    # Each session's workdir is removed once it has been read. Keep them when
    # inspecting serial logs or PT dumps by hand, and mind that every one costs
    # about the guest RAM size.
    ap.add_argument("--keep-workdirs", action="store_true", default=False)
    return ap.parse_args(argv)


def corpus_files(path, limit, repeat=1):
    """Enumerate inputs in a stable order.

    Sorted so both arms visit inputs in the same sequence: a mismatch is
    reported by index as well as by name, and an unstable order would make
    those indices meaningless between runs.
    """
    if os.path.isfile(path):
        return [path]
    out = []
    for root, _dirs, files in os.walk(path):
        for f in files:
            out.append(os.path.join(root, f))
    out.sort()
    if limit:
        out = out[:limit]
    return out * repeat if repeat > 1 else out

def read_trace_edges(workdir, qid=1337):
    """Parse the decoded edge trace file written by QEMU's trace_cb mode.

    Returns a list of (from, to, count) int triples, or an empty list if the
    file is missing. Skips malformed lines rather than crashing, since a partial
    trace is more useful than no output at all.

    The file is written by redqueen_trace_flush() and holds one line per unique
    edge in the format "from,to,count" where all three are lowercase hex without
    a 0x prefix. It is truncated and rewritten per execution, so it must be read
    immediately after send_payload() returns, before the next execution starts.
    """
    path = os.path.join(workdir, "redqueen_workdir_%d" % qid, "pt_trace_results.txt")
    if not os.path.exists(path):
        return []

    edges = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != 3:
                # Malformed line, skip it rather than crashing the whole run.
                continue
            try:
                from_addr = int(parts[0], 16)
                to_addr = int(parts[1], 16)
                count = int(parts[2], 16)
                edges.append((from_addr, to_addr, count))
            except ValueError:
                # Not valid hex, skip this line.
                continue
    return edges


# A kAFL workdir costs roughly the guest RAM size, because the root snapshot is
# a full memory image: 538 MiB per session at -m 512. That is cheap once and
# ruinous thirty times. --calibrate alone opens four.
#
# The number is a floor, not a limit. Leave real headroom.
PREFLIGHT_MIB_PER_SESSION = 700


def preflight_space(base_workdir, sessions):
    """Refuse to start if the workdir filesystem cannot hold the sessions.

    Worth a check of its own because of how this fails otherwise. A full tmpfs
    does not produce ENOSPC anywhere legible: QEMU's snapshot writer does a short
    fwrite and trips

      nyx_device_state.c:476: nyx_device_state_serialize:
      Assertion `fwrite(...) == self->state_buf_size' failed

    and the harness reports "qemu failed to start", which reads like a backend
    bug and sent me looking at pt_perf.c. Thirty leftover workdirs from earlier
    runs had filled /dev/shm to 100%.
    """
    parent = os.path.dirname(os.path.abspath(base_workdir.rstrip("/"))) or "/"
    try:
        st = os.statvfs(parent)
    except OSError as e:
        # Not fatal. A missing statvfs is not a reason to refuse to run.
        logger.warning("could not check free space on %s: %s", parent, e)
        return

    avail_mib = (st.f_bavail * st.f_frsize) // (1024 * 1024)
    need_mib = sessions * PREFLIGHT_MIB_PER_SESSION

    if avail_mib < need_mib:
        raise RuntimeError(
            "only %d MiB free on %s but %d session(s) need about %d MiB. "
            "Stale kAFL workdirs from earlier runs are the usual cause; "
            "remove them or point --workdir at a larger filesystem."
            % (avail_mib, parent, sessions, need_mib))

    logger.info("space check: %d MiB free on %s, %d session(s) need ~%d MiB",
                avail_mib, parent, sessions, need_mib)


def drop_workdir(workdir):
    """Remove a finished session's workdir.

    Called only on the success path. A workdir that belongs to a failed run is
    left in place deliberately: serial_1337.log and the PT dumps inside it are
    the only record of why the run failed, and deleting them during cleanup would
    destroy the evidence at exactly the moment it matters.
    """
    try:
        shutil.rmtree(workdir)
    except OSError as e:
        # A leaked workdir is a space problem for the next run, not a reason to
        # discard the measurement this one just produced.
        logger.warning("could not remove workdir %s: %s", workdir, e)


def run_arm(backend, inputs, base_workdir, dump_edges=None, keep_workdir=False):
    """Replay every input under one backend: index -> (hash, exit, edges).

    Keyed by position rather than by path because --repeat intentionally puts the
    same path in the list more than once.

    On guest state: reset relies on config reload=1 (the -R flag, default 1),
    which makes send_payload() enable the aux buffer's reload mode on every
    execution. qemu.reload() is NOT the mechanism; it is a no-op that returns
    True unconditionally, so calling it here would be misleading.

    Do not assume that makes a per-input hash reproducible. Measured on
    fs_fuzzer, 3 seeds replayed 3 times each: 3 of 3 inputs produced varying
    hashes on the stock deployed QEMU, and 2 of 3 on the backend-split build.
    Since the unmodified binary is just as unstable, the variance is the target
    on this host, not the decoder. Use --repeat to establish a target's baseline
    before trusting a mismatch count from it.

    Each arm gets its own workdir. Sharing one would let the first arm's
    bitmap files and PT dumps leak into the second's.
    """
    workdir = "%s_%s" % (base_workdir.rstrip("/"), backend)

    # Dynaconf settings is a process-wide singleton, so the arms cannot each
    # build their own config object; re-point the keys that differ.
    #
    # purge=True makes prepare_working_dir() wipe and recreate, which is what we
    # want per arm. Setting it here rather than calling shutil.rmtree ourselves
    # keeps a single code path responsible for the workdir layout.
    # "stock" means: add nothing. Any other name selects a backend explicitly.
    extra = "" if backend == "stock" else ("-global nyx.pt_backend=%s" % backend)

    settings.update({
        "workdir": workdir,
        "purge": True,
        "resume": False,
        "qemu_extra": extra,
        # Enable trace_cb when dump_edges is requested. This makes QEMU call
        # redqueen_trace_init() to activate the libxdc edge callback, writing
        # decoded edges to pt_trace_results.txt.
        "trace_cb": bool(dump_edges),
    })

    # Creates the full skeleton, including snapshot/, which QEMU's
    # -fast_vm_reload requires up front. A bare os.makedirs(workdir) is not
    # enough: QEMU exits with "fast_vm_reload: path does not exist".
    if not prepare_working_dir(settings):
        raise RuntimeError("could not prepare workdir %s" % workdir)

    logger.info("=== arm %s, workdir %s ===", backend, workdir)

    q = qemu(1337, settings, debug_mode=False, notifiers=True, resume=False)
    if not q.start():
        raise RuntimeError("qemu failed to start for the %s arm" % backend)

    # Arm trace mode if edge dumping is enabled. This must happen after start()
    # succeeds, since the qemu object needs to be fully initialized before it
    # can accept runtime mode changes.
    if dump_edges:
        q.set_trace_mode(True)
        # Create the dump directory if it does not exist yet.
        os.makedirs(dump_edges, exist_ok=True)

    results = {}
    try:
        limit = q.get_payload_limit()
        for n, path in enumerate(inputs):
            payload = read_binary_file(path)
            if len(payload) > limit:
                payload = payload[:limit]
            q.set_payload(payload)
            res = q.send_payload()
            # frozenset of indices with a nonzero count, i.e. edges reached.
            # Insensitive to hit-count jitter, which is what varies here.
            bitmap = res.copy_to_array()
            edges = frozenset(i for i, v in enumerate(bitmap) if v)
            results[n] = (res.hash(), res.exit_reason, edges)

            # Dump the decoded edge trace if requested. Read and write must
            # happen here, after send_payload() but before the next execution,
            # since the trace file is truncated on each run.
            if dump_edges:
                trace_edges = read_trace_edges(workdir, qid=1337)
                # Convert frozenset-of-tuples to a list-of-lists so it is JSON
                # serializable. Keep the int triples as they are.
                dump_obj = {
                    "backend": backend,
                    "index": n,
                    "path": path,
                    "exit": str(res.exit_reason),
                    "edges": [[f, t, c] for f, t, c in trace_edges],
                }
                dump_name = "%s_%d_%s.json" % (backend, n, os.path.basename(path))
                dump_path = os.path.join(dump_edges, dump_name)
                with open(dump_path, "w") as df:
                    json.dump(dump_obj, df)

            if (n + 1) % 100 == 0:
                logger.info("  %s: %d/%d", backend, n + 1, len(inputs))
    finally:
        # Unconditional: an arm left running would clobber the next one's
        # trace source, per the module docstring.
        q.shutdown()

    # Only past the try, so this runs on success and not after an exception.
    # See drop_workdir: a failed run's workdir is the evidence.
    if not keep_workdir:
        drop_workdir(workdir)

    return results


def report_repeats(name, inputs, arm):
    """Check that a path appearing more than once got the same hash each time.

    Only meaningful with --repeat. A failure here means the harness or the guest
    is nondeterministic, and any cross-backend comparison built on it would be
    reporting noise as decoder disagreement.
    """
    seen = {}
    for i, path in enumerate(inputs):
        seen.setdefault(path, []).append((arm[i][0], arm[i][2]))

    repeated = {p: v for p, v in seen.items() if len(v) > 1}
    if not repeated:
        return True

    bad_hash = {p: v for p, v in repeated.items()
                if len(set(h for h, _e in v)) != 1}
    bad_edges = {p: v for p, v in repeated.items()
                 if len(set(e for _h, e in v)) != 1}

    print()
    if not bad_hash:
        print("%s: reproducible, all %d repeated input(s) gave a stable hash"
              % (name, len(repeated)))
        return True

    print("%s: hash NOT reproducible, %d of %d repeated input(s) varied"
          % (name, len(bad_hash), len(repeated)))
    for p, v in list(bad_hash.items())[:10]:
        print("  %-24s %s" % (os.path.basename(p), " ".join(h for h, _e in v)))

    # The distinction that decides whether this target is usable at all.
    if bad_edges:
        print("%s: edge sets ALSO vary on %d input(s); this target cannot "
              "support a differential criterion as is"
              % (name, len(bad_edges)))
        for p, v in list(bad_edges.items())[:10]:
            sizes = " ".join(str(len(e)) for _h, e in v)
            union = len(set().union(*[e for _h, e in v]))
            common = len(set.intersection(*[set(e) for _h, e in v]))
            print("  %-24s sizes: %s  union %d  common %d"
                  % (os.path.basename(p), sizes, union, common))
    else:
        print("%s: but edge SETS are stable on every repeated input, so hit "
              "counts are the only thing varying; compare edge sets instead"
              % name)
    return False


def stable_cores(inputs, arm):
    """path -> (intersection, union) of edge sets over that path's repeats.

    The intersection is the set of edges reached on *every* execution of that
    input, which is reproducible on this target even though the bitmap hash and
    the per-run edge set are not. See the comment above for the measurements
    this is based on.
    """
    by_path = {}
    for i, path in enumerate(inputs):
        by_path.setdefault(path, []).append(arm[i][2])

    cores = {}
    for path, sets in by_path.items():
        cores[path] = (frozenset(set.intersection(*[set(e) for e in sets])),
                       frozenset(set().union(*[set(e) for e in sets])))
    return cores


def session_baseline(cores):
    """Edges in every input's core: the session-global part of coverage.

    DIAGNOSTIC ONLY, not part of the criterion. Two reasons it failed as one:
    subtracting it does not make the remainder portable across sessions (measured
    over four sessions), and it collapses to the empty set if any single input
    has zero coverage, which silently turns signature comparison back into raw
    core comparison. It is still informative for seeing how much of an input's
    coverage is the shared boot path.
    """
    if not cores:
        return frozenset()
    return frozenset(set.intersection(*[set(c) for c, _u in cores.values()]))


def signatures(cores):
    """path -> the input-specific part of its stable core. Diagnostic only.

    Meaningless when session_baseline() is empty; see its docstring.
    """
    base = session_baseline(cores)
    return {path: frozenset(core) - base for path, (core, _u) in cores.items()}


def compare_calibrated(inputs, backends, sessions):
    """The differential criterion, with the threshold measured rather than guessed.

    Why this supersedes the fixed percentage tolerance
    -------------------------------------------------

    The tolerance in compare_cores() was chosen from measurements and still
    failed, for a reason no choice of constant can fix. Measured on fs_fuzzer
    with symbolised guest addresses rather than hashed bitmap indices:

      - Two SAME-BACKEND sessions differ by 50 to 54 edges (vmx vs vmx: 54,
        perf vs perf: 50).
      - The two ARMS differ by 63 edges in the same units.
      - Repeats of one input inside a single session span 126 edges
        (11722, 11846, 11848).

    So the quantity under test is smaller than the noise it is compared against,
    and expressing it as a percentage makes matters worse by dividing a roughly
    constant absolute difference by a varying denominator. The same ~52 edge gap
    scored 2.94% on ext2 (pass) and 3.36% on garbage (fail) in one run, and
    ext4_big flipped from pass to fail between two runs of identical code.

    The fix is to stop guessing the threshold. Run each backend twice and use
    each backend's own cross-session difference as the yardstick:

        cross-arm difference <= CALIB_SLACK * max(within-backend differences)

    That is a control, not a constant. It adapts to a noisy target on its own, it
    cannot be defeated by a denominator, and on a genuinely quiet target it
    tightens automatically. What it gives up is absolute sensitivity: on a target
    this noisy it cannot see a defect smaller than the target's own jitter. That
    is a true statement about the target, and the honest response is to report
    the floor rather than pick a constant that hides it.

    Note the direction of the remaining risk. This criterion can be fooled by a
    defect that is stable WITHIN a backend, because such a defect inflates the
    within-backend and the cross-arm numbers together. Address level inspection
    (--dump-edges) covers that case, and is how the NR filter was checked for
    host leakage. The two are complementary and neither alone is sufficient.

    sessions maps backend -> list of exactly two arm result dicts.
    """
    print()
    print("=== calibrated differential criterion ===")
    print("threshold per input = %.1fx the larger within-backend session difference"
          % CALIB_SLACK)
    print("(a measured control, not a chosen constant; see compare_calibrated)")
    print()

    # Within-backend cores, one per session, so each backend is compared against
    # itself before the arms are compared against each other.
    within = {}
    for be in backends:
        a, b = sessions[be]
        within[be] = (stable_cores(inputs, a), stable_cores(inputs, b))

    ref = backends[0]
    rc = 0
    empty = (frozenset(), frozenset())

    for other in backends[1:]:
        bad, degenerate, ok_count, floors = [], [], 0, []

        for path in sorted(within[ref][0]):
            name = os.path.basename(path)

            ra = within[ref][0].get(path, empty)[0]
            rb = within[ref][1].get(path, empty)[0]
            oa = within[other][0].get(path, empty)[0]
            ob = within[other][1].get(path, empty)[0]

            if not (ra or rb or oa or ob):
                degenerate.append(path)
                print("  %-24s EMPTY on all sessions (proves nothing)" % name)
                continue

            # One arm silent while the other traced is damning regardless of any
            # threshold, so it short circuits.
            if (not (ra or rb)) or (not (oa or ob)):
                bad.append(path)
                print("  %-24s FAIL  one arm produced no coverage at all "
                      "(%s %d/%d, %s %d/%d)"
                      % (name, ref, len(ra), len(rb), other, len(oa), len(ob)))
                continue

            self_ref = len(ra ^ rb)
            self_other = len(oa ^ ob)
            noise = max(self_ref, self_other)

            # Compare session 0 against session 0 so both sides are measured
            # under the same repeat count and input ordering.
            cross = len(ra ^ oa)

            # An absolute floor of 1 stops a target that happens to be perfectly
            # stable in both arms from setting a threshold of zero, where a
            # single edge of any origin would fail the gate.
            threshold = max(1.0, CALIB_SLACK * noise)
            floors.append(noise)

            if cross > threshold:
                bad.append(path)
                verdict = "FAIL"
            else:
                ok_count += 1
                verdict = "ok"

            print("  %-24s %-4s cross %4d  vs threshold %6.1f  (self: %s %d, %s %d)"
                  % (name, verdict, cross, threshold,
                     ref, self_ref, other, self_other))

        print()
        if bad:
            rc = 1
            print("%d input(s) differ between arms by MORE than the same-backend "
                  "control allows." % len(bad))
            print("That is the only form of evidence this target can support for a "
                  "decode difference.")
        else:
            print("all %d comparable input(s): the arms differ no more than each "
                  "backend differs from itself" % ok_count)

        if floors:
            print()
            print("Measured sensitivity floor on this target: a defect smaller than "
                  "about %d edges" % max(floors))
            print("cannot be distinguished from the target's own session-to-session "
                  "noise.")

        if degenerate:
            print("%d input(s) traced nothing anywhere: %s"
                  % (len(degenerate),
                     ", ".join(os.path.basename(p) for p in degenerate)))

    return rc


def compare_cores(inputs, backends, arms, tolerance=0.03):
    """Per-input core agreement within a tolerance. The differential criterion.

    For each input, compare the stable core (edges hit on every repeat) between
    the arms and require the symmetric difference to be at most `tolerance` of
    the core size. See the comment above for why this rather than exact equality
    or baseline normalisation.

    Zero-coverage inputs are called out rather than folded into the arithmetic: a
    0/0 comparison passes trivially and would otherwise inflate the pass count.
    """
    ref_name = backends[0]
    ref_cores = stable_cores(inputs, arms[ref_name])
    rc = 0

    for other_name in backends[1:]:
        other_cores = stable_cores(inputs, arms[other_name])

        print()
        print("=== differential criterion: %s vs %s ===" % (ref_name, other_name))
        print("per-input stable-core agreement, tolerance %.1f%% "
              "(measured cross-session noise on this target: <1%%)"
              % (100.0 * tolerance))
        print()

        bad, degenerate, ok_count = [], [], 0
        for path in sorted(ref_cores):
            a = ref_cores[path][0]
            b = other_cores.get(path, (frozenset(), frozenset()))[0]
            sym = len(a ^ b)
            denom = max(len(a), len(b))

            name = os.path.basename(path)

            # Both empty: nothing was traced on either side. Equal, but it
            # proves nothing, so do not count it as a pass.
            if denom == 0:
                degenerate.append(path)
                print("  %-24s EMPTY on both arms (proves nothing)" % name)
                continue

            frac = float(sym) / denom
            # One side empty while the other is not is the single most damning
            # outcome: a backend produced no coverage at all for an input that
            # demonstrably generates some.
            if len(a) == 0 or len(b) == 0:
                bad.append(path)
                print("  %-24s FAIL  %s=%d  %s=%d  one arm produced nothing"
                      % (name, ref_name, len(a), other_name, len(b)))
                continue

            if frac > tolerance:
                bad.append(path)
                verdict = "FAIL"
            else:
                ok_count += 1
                verdict = "ok"
            print("  %-24s %-4s  %s=%d  %s=%d  diff %d (%.2f%%)  "
                  "only-%s %d  only-%s %d"
                  % (name, verdict, ref_name, len(a), other_name, len(b),
                     sym, 100.0 * frac,
                     ref_name, len(a - b), other_name, len(b - a)))

        print()
        if bad:
            rc = 1
            print("%d of %d input(s) exceed the tolerance. That is a decode "
                  "difference, not jitter." % (len(bad), len(ref_cores)))
        else:
            print("all %d comparable input(s) agree within tolerance" % ok_count)

        if degenerate:
            print("%d input(s) produced no coverage on either arm: %s"
                  % (len(degenerate),
                     ", ".join(os.path.basename(p) for p in degenerate)))
            print("  These were not counted. An input that traces nothing cannot "
                  "distinguish two decoders.")

        # Guard against a vacuous pass: if nothing was comparable, saying
        # "agree" would be actively misleading.
        if ok_count == 0 and not bad:
            print("WARNING: no input produced comparable coverage, so nothing "
                  "was actually verified.")
            rc = 1

    return rc


def save_cores(path, inputs, backends, arms):
    """Dump stable cores to JSON, keyed by backend then input basename.

    Sorted lists rather than sets, so the file is diffable and stable.
    """
    if not path:
        return
    if len(inputs) == len(set(inputs)):
        print("--save-cores ignored: needs --repeat > 1 to form a core")
        return

    out = {}
    for name in backends:
        out[name] = {
            os.path.basename(p): {
                "core": sorted(core),
                "union": sorted(union),
            }
            for p, (core, union) in stable_cores(inputs, arms[name]).items()
        }

    with open(path, "w") as f:
        json.dump(out, f)
    print("wrote stable cores to %s" % path)


def compare(inputs, backends, arms):
    ref_name = backends[0]
    ref = arms[ref_name]
    rc = 0

    for other_name in backends[1:]:
        other = arms[other_name]
        mismatches = [
            (i, p, ref[i], other[i])
            for i, p in enumerate(inputs) if ref[i][0] != other[i][0]
        ]
        edge_mismatches = [
            (i, p) for i, p in enumerate(inputs) if ref[i][2] != other[i][2]
        ]

        print()
        print("=== %s vs %s ===" % (ref_name, other_name))
        print("inputs:     %d" % len(inputs))
        print("matching:   %d" % (len(inputs) - len(mismatches)))
        print("mismatched: %d" % len(mismatches))

        print("edge-set mismatched: %d" % len(edge_mismatches))

        if edge_mismatches:
            rc = 1
            print()
            print("first 20 edge-set mismatches (a real decoder disagreement):")
            for i, path in edge_mismatches[:20]:
                a, b = ref[i][2], other[i][2]
                print("  [%d] %-24s only-%s %d  only-%s %d  common %d"
                      % (i, os.path.basename(path),
                         ref_name, len(a - b), other_name, len(b - a),
                         len(a & b)))

        if mismatches:
            print()
            print("first 20 hash mismatches (may be hit-count jitter only; "
                  "see the edge-set count above):")
            for i, p, (a, ae, _aedges), (b, be, _bedges) in mismatches[:20]:
                print("  [%d] %s" % (i, os.path.basename(p)))
                print("      %-5s %s (%s)" % (ref_name, a, ae))
                print("      %-5s %s (%s)" % (other_name, b, be))

    for name in backends:
        report_repeats(name, inputs, arms[name])

    # The hash and raw-edge comparisons above are advisory on a noisy target.
    # The stable-core comparison is the one whose result is meaningful, so it
    # gets the last word on rc.
    if len(inputs) > len(set(inputs)):
        rc = compare_cores(inputs, backends, arms, own_tolerance[0])
    else:
        print()
        print("note: --repeat was not used, so no stable core could be computed. "
              "On a target with jitter, pass --repeat 4 or more and read the "
              "stable-core comparison rather than the hash mismatch count.")

    # Independent of the comparison above, because two arms that both
    # discard every trace would agree perfectly and still be broken.
    print()
    for name in backends:
        distinct = len(set(r[0] for r in arms[name].values()))
        distinct_edges = len(set(r[2] for r in arms[name].values()))
        print("%s: %d distinct hash(es), %d distinct edge set(s) over %d input(s)"
              % (name, distinct, distinct_edges, len(inputs)))
        if distinct == 1 and len(inputs) > 1:
            print("  WARNING: constant coverage. Either the corpus is "
                  "degenerate or the decoder is discarding traces.")
            rc = 1

    return rc


def main():
    own_argv, kafl_argv = split_argv(sys.argv[1:])
    own = parse_own(own_argv)

    # Reuse kafl's own parser for the target description. The debug
    # subcommand is used because its option set is the one that makes sense
    # for replaying fixed inputs.
    parser = ConfigParserBuilder()()
    # --action is mandatory for the debug subcommand but meaningless here: this
    # script drives the qemu worker directly rather than dispatching to one of
    # debug/core.py's actions. Supply a harmless one so callers do not have to
    # pass a value that has no effect.
    if not any(a.split("=", 1)[0] == "--action" for a in kafl_argv):
        kafl_argv = kafl_argv + ["--action", "single"]
    args = parser.parse_args(["debug"] + kafl_argv)
    update_from_namespace(args)
    setup_basic_logging(settings)
    validate()

    own_tolerance[0] = own.baseline_tolerance

    inputs = corpus_files(own.corpus, own.limit, own.repeat)
    if not inputs:
        print("no inputs found under %s" % own.corpus, file=sys.stderr)
        return 2
    logger.info("replaying %d input(s)", len(inputs))

    backends = [b.strip() for b in own.backends.split(",") if b.strip()]
    base_workdir = settings.workdir

    if own.dump_edges:
        logger.warning("--dump-edges is set: trace_cb rewires the edge callback "
                       "to alt_bitmap_add(), which hashes differently than "
                       "libxdc. Treat the bitmap verdicts below as MEANINGLESS "
                       "and read the dumped address sets instead.")

    if own.calibrate:
        if len(backends) < 2:
            print("--calibrate needs at least two backends to compare",
                  file=sys.stderr)
            return 2
        if own.repeat < 2:
            print("--calibrate needs --repeat >= 2: a stable core is undefined "
                  "from a single execution", file=sys.stderr)
            return 2

        # Two sessions per backend, and the ORDER matters. Interleaving the
        # backends (ref, other, ref, other) rather than grouping them
        # (ref, ref, other, other) keeps a slow drift in machine state, page
        # cache warmth, thermal behaviour, whatever else, from landing entirely
        # on one arm and being read as a backend difference. The within-backend
        # pairs are then separated by the same amount of wall clock as the
        # cross-arm pair, which is the comparison the criterion depends on.
        # Only one session's workdir exists at a time unless --keep-workdirs
        # is set, so the requirement is 1 rather than the 2 * len(backends)
        # sessions the loop opens in total.
        preflight_space(base_workdir,
                        2 * len(backends) if own.keep_workdirs else 1)

        sessions = {be: [] for be in backends}
        for round_no in (0, 1):
            for backend in backends:
                logger.info("=== calibration round %d, backend %s ===",
                            round_no, backend)
                sessions[backend].append(
                    run_arm(backend, inputs,
                            "%s_r%d" % (base_workdir.rstrip("/"), round_no),
                            dump_edges=own.dump_edges,
                            keep_workdir=own.keep_workdirs))

        rc = compare_calibrated(inputs, backends, sessions)

        # Also print the old per-input view from round 0, since the calibrated
        # criterion reports differences without saying how big the cores were.
        for backend in backends:
            report_repeats(backend, inputs, sessions[backend][0])
        return rc

    preflight_space(base_workdir, len(backends) if own.keep_workdirs else 1)

    arms = {}
    for backend in backends:
        arms[backend] = run_arm(backend, inputs, base_workdir,
                                dump_edges=own.dump_edges,
                                keep_workdir=own.keep_workdirs)

    if len(arms) < 2:
        name = backends[0]
        print()
        print("=== single arm: %s ===" % name)
        for i, path in enumerate(inputs):
            h, exit_reason, edges = arms[name][i]
            # Edge count is the stable half of the measurement, so show it
            # next to the hash rather than only in the summary.
            print("  [%d] %-24s %s  %5d edges  (%s)"
                  % (i, os.path.basename(path), h, len(edges), exit_reason))

        distinct = len(set(r[0] for r in arms[name].values()))
        distinct_edges = len(set(r[2] for r in arms[name].values()))
        print()
        print("%s: %d distinct hash(es), %d distinct edge set(s) over %d input(s)"
              % (name, distinct, distinct_edges, len(inputs)))
        report_repeats(name, inputs, arms[name])

        if len(inputs) > len(set(inputs)):
            cores = stable_cores(inputs, arms[name])
            print()
            print("stable cores for %s (edges present on every repeat):" % name)
            for path, (core, union) in sorted(cores.items()):
                pct = 100.0 * len(core) / len(union) if union else 0.0
                print("  %-24s core %d  union %d  stable %.2f%%"
                      % (os.path.basename(path), len(core), len(union), pct))

            # Diagnostic decomposition, not the criterion. Shows how much of
            # each input's core is the shared boot path.
            base = session_baseline(cores)
            print()
            print("baseline shared by every input: %d edges (diagnostic)" % len(base))
            if not base:
                print("  (empty because at least one input has zero coverage, "
                      "so the split below is not meaningful)")
            else:
                print("input-specific remainder (diagnostic, NOT portable "
                      "across sessions):")
                for path, sig in sorted(signatures(cores).items()):
                    print("  %-24s %d edges" % (os.path.basename(path), len(sig)))

        if distinct == 1 and len(inputs) > 1:
            print("  WARNING: constant coverage. Either the corpus is "
                  "degenerate or the decoder is discarding traces.")
            return 1
        save_cores(own.save_cores, inputs, backends, arms)
        print("no second arm requested, so nothing was compared")
        return 0

    save_cores(own.save_cores, inputs, backends, arms)

    rc = compare(inputs, backends, arms)

    if own.report:
        with open(own.report, "w") as f:
            cols = []
            for b in backends:
                cols += ["%s_hash" % b, "%s_edges" % b]
            f.write("input\t" + "\t".join(cols) + "\n")
            for i, p in enumerate(inputs):
                row = [os.path.basename(p)]
                for b in backends:
                    row += [arms[b][i][0], str(len(arms[b][i][2]))]
                f.write("\t".join(row) + "\n")
        print()
        print("report written to %s" % own.report)

    return rc


if __name__ == "__main__":
    sys.exit(main())
