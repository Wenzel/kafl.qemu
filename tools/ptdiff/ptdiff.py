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

# Arguments this script consumes itself. Everything else is handed to kafl's
# own parser untouched, so a target is described exactly as it would be for
# kafl debug and no option list has to be mirrored here.
OWN_ARGS = ("--corpus", "--backends", "--limit", "--report", "--repeat",
            "--save-cores", "--baseline-tolerance")


def split_argv(argv):
    own, rest = [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        key = a.split("=", 1)[0]
        if key in OWN_ARGS:
            own.append(a)
            if "=" not in a and i + 1 < len(argv):
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


def run_arm(backend, inputs, base_workdir):
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
            if (n + 1) % 100 == 0:
                logger.info("  %s: %d/%d", backend, n + 1, len(inputs))
    finally:
        # Unconditional: an arm left running would clobber the next one's
        # trace source, per the module docstring.
        q.shutdown()

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

    arms = {}
    for backend in backends:
        arms[backend] = run_arm(backend, inputs, base_workdir)

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
