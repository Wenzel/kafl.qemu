"""Validate the criterion against known-answer cases, offline.

A criterion nobody has tried to break is just an assertion. The harness has only
ever run one arm, so the comparison code has never actually been exercised, and
it would be easy to ship a tolerance that passes everything.

Two classes of case, using the real saved cores from the varied corpus:

  NEGATIVE (must PASS): two sessions of the SAME backend. Any failure here is a
  false alarm, and a criterion that cries wolf on identical configurations is
  useless in practice because its output gets ignored.

  POSITIVE (must FAIL): synthetic decode faults injected into one side, each
  modelled on a real failure mode of this pipeline:
    - total loss        libxdc returns success while discarding the trace
    - region loss       an NR transition drops a run of packets
    - filter on wrong range   a whole address range's worth of edges missing
    - single edge lost  the smallest possible real fault, to find the detection
                        floor honestly rather than claiming unlimited sensitivity
"""
import glob
import sys
import json

TOL = 0.03

files = sorted(sys.argv[1:]) or sorted(glob.glob('core_*.json'))
if len(files) < 2:
    raise SystemExit('usage: validate_criterion.py core1.json core2.json [...]')
sessions = [(f, json.load(open(f))['vmx']) for f in files]
names = sorted(sessions[0][1])


def cores(sess):
    return {n: set(sess[n]['core']) for n in names}


def criterion(a, b, tol=TOL):
    """Reimplements compare_cores' decision. Returns (passed, per_input)."""
    rows, bad, ok = [], 0, 0
    for n in names:
        ca, cb = a[n], b[n]
        denom = max(len(ca), len(cb))
        if denom == 0:
            rows.append((n, 'EMPTY', 0, 0.0))
            continue
        if not ca or not cb:
            rows.append((n, 'FAIL-one-empty', len(ca ^ cb), 1.0))
            bad += 1
            continue
        sym = len(ca ^ cb)
        frac = float(sym) / denom
        if frac > tol:
            rows.append((n, 'FAIL', sym, frac))
            bad += 1
        else:
            rows.append((n, 'ok', sym, frac))
            ok += 1
    return (bad == 0 and ok > 0), rows


print('=' * 70)
print('NEGATIVE CASES: same backend, different sessions. Must all PASS.')
print('=' * 70)
neg_fail = 0
for i in range(len(sessions)):
    for j in range(i + 1, len(sessions)):
        a, b = cores(sessions[i][1]), cores(sessions[j][1])
        passed, rows = criterion(a, b)
        worst = max((r[3] for r in rows if r[1] != 'EMPTY'), default=0.0)
        print('  %s vs %s: %s (worst divergence %.2f%%)'
              % (files[i].split('/')[-1], files[j].split('/')[-1],
                 'PASS' if passed else 'FALSE ALARM', 100.0 * worst))
        if not passed:
            neg_fail += 1
            for n, v, sym, frac in rows:
                if v.startswith('FAIL'):
                    print('      %-20s %s diff %d (%.2f%%)' % (n, v, sym, 100.0 * frac))
print('  => %d false alarm(s)' % neg_fail)
print()

print('=' * 70)
print('POSITIVE CASES: injected decode faults. Must all FAIL.')
print('=' * 70)
base = cores(sessions[0][1])
other = cores(sessions[1][1])

faults = {}

# 1. Total loss on every input: libxdc discarding traces wholesale.
faults['total loss (all inputs empty)'] = {n: set() for n in names}

# 2. Total loss on a single input only.
f = dict(other)
f['ext2.img'] = set()
faults['total loss (one input)'] = f

# 3. Region loss: drop a contiguous 20% span of the bitmap, which is what losing
#    a run of packets after an NR transition would look like.
f = {}
for n in names:
    c = other[n]
    if c:
        lo, hi = min(c), max(c)
        cut_lo = lo + int((hi - lo) * 0.4)
        cut_hi = lo + int((hi - lo) * 0.6)
        f[n] = {e for e in c if not (cut_lo <= e <= cut_hi)}
    else:
        f[n] = set()
faults['region loss (20% span)'] = f

# 4. 5% of edges lost at random-ish positions (every 20th), modelling a filter
#    programmed on the wrong address range.
f = {n: {e for k, e in enumerate(sorted(other[n])) if k % 20} for n in names}
faults['5% scattered loss'] = f

# 5. Detection floor: exactly one edge removed from one input. Expected to pass,
#    and reported honestly rather than hidden.
f = dict(other)
c = set(other['ext2.img'])
c.discard(sorted(c)[0])
f['ext2.img'] = c
faults['single edge lost (floor check)'] = f

for label, faulty in faults.items():
    passed, rows = criterion(base, faulty)
    detected = not passed
    expect_detect = 'floor check' not in label
    verdict = 'DETECTED' if detected else 'missed'
    mark = 'ok' if (detected == expect_detect) else 'PROBLEM'
    print('  %-34s %-9s [%s]' % (label, verdict, mark))
    if detected:
        n_bad = sum(1 for r in rows if r[1].startswith('FAIL'))
        worst = max((r[3] for r in rows if r[1] != 'EMPTY'), default=0.0)
        print('      %d input(s) flagged, worst divergence %.1f%%'
              % (n_bad, 100.0 * worst))

print()
print('=' * 70)
print('SENSITIVITY: smallest detectable loss on ext2.img (core %d edges)'
      % len(base['ext2.img']))
print('=' * 70)
# Establish the real detection threshold rather than asserting one. Note this is
# measured against a DIFFERENT session, so it includes the cross-session noise
# the criterion has to tolerate; that is the honest number.
for pct in (0.5, 1, 2, 3, 4, 5, 10):
    f = dict(other)
    c = sorted(other['ext2.img'])
    drop = max(1, int(len(c) * pct / 100.0))
    f['ext2.img'] = set(c[drop:])
    passed, _rows = criterion(base, f)
    print('  drop %5.1f%% (%4d edges): %s'
          % (pct, drop, 'detected' if not passed else 'not detected'))
