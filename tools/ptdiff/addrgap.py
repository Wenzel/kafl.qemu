"""Name the addresses the two arms disagree on.

Until now the gap was 50-odd hashed bitmap indices, which cannot be located in
the guest: kAFL folds each (from,to) pair through a hash and masks it into the
bitmap, so an index carries no address. The trace_cb path emits the pre-hash
(from,to) pairs, so the same disagreement becomes a list of code locations.

The core (edges present in EVERY repeat) is used rather than any single run,
because both arms are individually nondeterministic on this target: a
single-run diff would mix real backend disagreement with per-run jitter.
"""
import glob, json, os, sys, collections

if len(sys.argv) != 2:
    raise SystemExit('usage: addrgap.py dumpdir')
d = sys.argv[1]

def load(backend):
    runs = []
    for p in sorted(glob.glob(os.path.join(d, '%s_*_*.json' % backend))):
        o = json.load(open(p))
        runs.append({(f, t): c for f, t, c in o['edges']})
    return runs

def core(runs):
    if not runs:
        return set()
    s = set(runs[0])
    for r in runs[1:]:
        s &= set(r)
    return s

vr, pr = load('vmx'), load('perf')
print('runs: vmx %d, perf %d' % (len(vr), len(pr)))
for name, runs in (('vmx', vr), ('perf', pr)):
    print('  %s edge counts per run: %s' % (name, [len(r) for r in runs]))

vc, pc = core(vr), core(pr)
print('cores: vmx %d, perf %d' % (len(vc), len(pc)))

only_v = vc - pc
only_p = pc - vc
print('only-vmx %d, only-perf %d, shared %d' % (len(only_v), len(only_p), len(vc & pc)))

def show(label, s, other):
    print()
    print('=== %s (%d) ===' % (label, len(s)))
    for f, t in sorted(s)[:60]:
        # Does the address appear at all on the other side, as either endpoint?
        f_seen = any(f in (a, b) for a, b in other)
        t_seen = any(t in (a, b) for a, b in other)
        print('  %016x -> %016x   from_seen=%d to_seen=%d' % (f, t, f_seen, t_seen))
    if len(s) > 60:
        print('  ... %d more' % (len(s) - 60))

show('only in vmx', only_v, pc)
show('only in perf', only_p, vc)

# Are the disagreements clustered on a handful of source addresses? A boundary
# decoded differently would show a few 'from' addresses with mismatched targets;
# genuinely missing trace data would be scattered.
print()
print('=== clustering by source address ===')
for label, s in (('only-vmx', only_v), ('only-perf', only_p)):
    c = collections.Counter(f for f, _t in s)
    print('  %s: %d distinct source addrs, top: %s'
          % (label, len(c), c.most_common(8)))

# The sharpest question: for edges unique to one arm, does the OTHER arm have an
# edge from the same source to a different target? That is a retargeted branch,
# not a lost one.
print()
print('=== retargeted vs lost ===')
v_by_src = collections.defaultdict(set)
for f, t in vc:
    v_by_src[f].add(t)
p_by_src = collections.defaultdict(set)
for f, t in pc:
    p_by_src[f].add(t)

for label, s, other_by_src in (('only-vmx', only_v, p_by_src),
                               ('only-perf', only_p, v_by_src)):
    retarget = sum(1 for f, _t in s if other_by_src.get(f))
    print('  %s: %d of %d have the same source present on the other arm '
          '(=> retargeted, not lost)' % (label, retarget, len(s)))

# Address ranges tell us whether the extra perf edges are host addresses that
# leaked through NR filtering, or guest addresses.
print()
print('=== address ranges ===')
def rng(label, s):
    if not s:
        print('  %s: empty' % label); return
    a = sorted(set([x for x, _ in s] + [y for _, y in s]))
    print('  %s: %016x .. %016x (%d distinct addrs)' % (label, a[0], a[-1], len(a)))
rng('vmx core', vc)
rng('perf core', pc)
rng('only-vmx', only_v)
rng('only-perf', only_p)
