"""Characterise what is actually stable across N sessions, not just two.

Context: a two-session comparison showed baseline-normalised signatures matching
exactly (sizes 1, 14, 15) and I concluded they were portable. The next run gave
0, 24, 25. So that conclusion was drawn from n=2 on a metric already known to be
noisy, which is not evidence.

This looks at four independent sessions and asks, for each candidate criterion,
whether it holds across ALL of them rather than across one pair:

  1. core            per-input intersection over repeats
  2. signature       core minus session baseline
  3. baseline size   the shared path, as a magnitude
  4. core size       per-input, as a magnitude
  5. core across-session intersection  what survives everywhere

The last is the interesting one. If per-input cores intersect to a large stable
set across every session, that set is a legitimate criterion even if neither the
raw core nor the signature is portable, because it is defined by agreement rather
than by a single session's luck.
"""
import glob
import sys
import json

files = sorted(sys.argv[1:]) or sorted(glob.glob('core_*.json'))
if len(files) < 2:
    raise SystemExit('usage: measure_portability.py core1.json core2.json [...]')
sessions = []
for f in files:
    sessions.append((f, json.load(open(f))['vmx']))

print('sessions: %d' % len(sessions))
names = sorted(sessions[0][1])
print('inputs: %s' % ', '.join(names))
print()


def core(sess, n):
    return set(sess[n]['core'])


def baseline(sess):
    return set.intersection(*[core(sess, n) for n in names])


# --- 1 & 4: raw core -------------------------------------------------------
print('=== raw core sizes per session ===')
for f, sess in sessions:
    print('  %-22s %s' % (f.split('/')[-1],
                          '  '.join('%s=%d' % (n[:8], len(core(sess, n)))
                                    for n in names)))

all_cores_equal = all(
    core(sessions[0][1], n) == core(s, n) for n in names for _f, s in sessions)
print('  core identical across all sessions: %s' % all_cores_equal)
print()

# --- 3: baseline -----------------------------------------------------------
print('=== baseline per session ===')
bases = []
for f, sess in sessions:
    b = baseline(sess)
    bases.append(b)
    print('  %-22s %d edges' % (f.split('/')[-1], len(b)))
base_common = set.intersection(*bases)
base_union = set().union(*bases)
print('  intersection %d, union %d, spread %d'
      % (len(base_common), len(base_union), len(base_union) - len(base_common)))
print()

# --- 2: signatures ---------------------------------------------------------
print('=== signatures per session (core minus that session baseline) ===')
for i, (f, sess) in enumerate(sessions):
    b = bases[i]
    print('  %-22s %s' % (f.split('/')[-1],
                          '  '.join('%s=%d' % (n[:8], len(core(sess, n) - b))
                                    for n in names)))

sig_portable = True
for n in names:
    ref = core(sessions[0][1], n) - bases[0]
    for i, (_f, sess) in enumerate(sessions):
        if core(sess, n) - bases[i] != ref:
            sig_portable = False
print('  signature identical across all sessions: %s' % sig_portable)
print()

# --- 5: the across-session intersection ------------------------------------
print('=== across-session core intersection (agreement-defined) ===')
for n in names:
    sets = [core(s, n) for _f, s in sessions]
    inter = set.intersection(*sets)
    uni = set().union(*sets)
    print('  %-24s intersection %d  union %d  stable %.2f%%'
          % (n, len(inter), len(uni), 100.0 * len(inter) / len(uni) if uni else 0))

# Does that intersection still discriminate between inputs? A criterion that
# collapses every input to the same set proves nothing.
print()
print('=== does the across-session intersection discriminate? ===')
inters = {n: set.intersection(*[core(s, n) for _f, s in sessions]) for n in names}
for i, n1 in enumerate(names):
    for n2 in names[i + 1:]:
        print('  %-16s vs %-16s symmetric difference %d'
              % (n1[:16], n2[:16], len(inters[n1] ^ inters[n2])))

print()
print('=== verdict ===')
if all_cores_equal:
    print('raw core is portable; use it directly')
elif sig_portable:
    print('signature is portable across all %d sessions' % len(sessions))
else:
    print('NEITHER raw core nor signature is portable across %d sessions.'
          % len(sessions))
    print('The across-session intersection above is the fallback: it is defined')
    print('by agreement across sessions, so it is stable by construction.')
    print('Cost: it must be established from N reference sessions of one arm')
    print('before the other arm can be compared against it.')
