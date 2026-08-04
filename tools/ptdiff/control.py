"""Control experiment: vmx vs vmx across two sessions.

The perf-only edges were dominated by __do_softirq, rcu_gp_init/cleanup,
timerqueue_add, sysvec_apic_timer_interrupt and friends: asynchronous work whose
occurrence depends on wall-clock timing inside the execution window, not on the
decoder. If that is target nondeterminism rather than a perf defect, then two
SAME-backend sessions must disagree the same way and at a comparable magnitude.

This is the experiment that decides whether the ~50 to 160 edge gap between the
arms is a backend bug at all. Without it, any cross-arm number is uninterpretable,
because the arms cannot share a session (vmx_pt clobbers a live perf session on
every VM exit) and so a cross-arm diff is always also a cross-session diff.
"""
import bisect, glob, json, os, sys, collections

if len(sys.argv) != 5:
    raise SystemExit('usage: control.py dirA dirB System.map backend')
dirA, dirB, mappath, backend = sys.argv[1:5]

EXIT_IP = 0xffffffffffffffff
KERN = 0xffff800000000000

syms = []
for line in open(mappath):
    p = line.split()
    if len(p) >= 3 and p[1] in 'tTwW':
        try:
            syms.append((int(p[0], 16), p[2]))
        except ValueError:
            pass
syms.sort()
addrs = [a for a, _ in syms]

def symname(a):
    i = bisect.bisect_right(addrs, a) - 1
    return syms[i][1] if i >= 0 else '?'

def core(d, be):
    runs = [set((f, t) for f, t, _c in json.load(open(p))['edges'])
            for p in sorted(glob.glob(os.path.join(d, '%s_*_*.json' % be)))]
    if not runs:
        raise SystemExit('no %s dumps in %s' % (be, d))
    s = set(runs[0])
    for r in runs[1:]:
        s &= r
    return s, [len(r) for r in runs]

def kern(s):
    return set(e for e in s if all(a == EXIT_IP or a >= KERN for a in e))

a, asz = core(dirA, backend)
b, bsz = core(dirB, backend)
ak, bk = kern(a), kern(b)
oa, ob = ak - bk, bk - ak

print('%s session A: runs %s, core %d, kernel core %d' % (backend, asz, len(a), len(ak)))
print('%s session B: runs %s, core %d, kernel core %d' % (backend, bsz, len(b), len(bk)))
print()
print('=== SAME BACKEND, different session ===')
print('  shared %d, only-A %d, only-B %d' % (len(ak & bk), len(oa), len(ob)))
print('  only-A is %.2f%% of A, only-B is %.2f%% of B'
      % (100.0 * len(oa) / max(1, len(ak)), 100.0 * len(ob) / max(1, len(bk))))
print()

ASYNC = ('softirq', 'rcu_', 'timer', 'hrtimer', 'apic', 'irqentry', 'error_entry',
         'sched', 'swait', 'jiffies', 'tick_', 'clocksource', 'timekeeping',
         'spin_lock', 'spin_unlock', '_find_next_bit', 'run_timers', 'ktime')

for label, s in (('only-A', oa), ('only-B', ob)):
    c = collections.Counter()
    for f, t in s:
        for x in (f, t):
            if x != EXIT_IP:
                c[symname(x)] += 1
    asy = sum(n for nm, n in c.items() if any(k in nm for k in ASYNC))
    tot = sum(c.values())
    print('=== %s (%d edges) top functions ===' % (label, len(s)))
    for nm, n in c.most_common(15):
        mark = '  [async]' if any(k in nm for k in ASYNC) else ''
        print('  %-40s %4d%s' % (nm, n, mark))
    print('  async-classified: %d of %d address slots (%.0f%%)'
          % (asy, tot, 100.0 * asy / max(1, tot)))
    print()
