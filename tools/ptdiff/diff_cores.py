"""Diff two saved core dumps to find out WHY cross-session cores differ.

The size offset alone is ambiguous. Three hypotheses, with very different
consequences for whether a per-edge criterion can work at all across sessions:

  nested       -> one session simply reached more; a subset criterion survives
  disjoint-ish -> different addresses entirely; per-edge comparison is dead
  fringe-only  -> the difference is edges that were in the OTHER session's
                  union but not its core, i.e. the same flickering fringe
                  rather than anything new. That would mean the cores are
                  consistent and only the repeat count was too low to settle
                  them, which is a tuning problem, not a design problem.

The third is the one worth testing carefully, because it is both the most likely
and the easiest to mistake for the second.
"""
import json

import sys

if len(sys.argv) != 3:
    raise SystemExit('usage: diff_cores.py coresA.json coresB.json')

a = json.load(open(sys.argv[1]))['vmx']
b = json.load(open(sys.argv[2]))['vmx']

for name in sorted(a):
    ca, ua = set(a[name]['core']), set(a[name]['union'])
    cb, ub = set(b[name]['core']), set(b[name]['union'])

    only_a, only_b = ca - cb, cb - ca

    print('=== %s ===' % name)
    print('  core a %d, core b %d' % (len(ca), len(cb)))
    print('  only in a: %d   only in b: %d   common: %d'
          % (len(only_a), len(only_b), len(ca & cb)))

    if not only_a and not only_b:
        verdict = 'IDENTICAL'
    elif not only_a:
        verdict = 'a is a strict SUBSET of b'
    elif not only_b:
        verdict = 'b is a strict SUBSET of a'
    else:
        verdict = 'OVERLAPPING, neither nested'
    print('  verdict: %s' % verdict)

    # The key question for the overlapping case: is the difference confined to
    # the other session's fringe? If every edge unique to a still appears
    # somewhere in b's union, then b saw those edges too, just not on every
    # repeat. Nothing is structurally different; the core is simply undersampled.
    a_in_b_union = len(only_a & ub)
    b_in_a_union = len(only_b & ua)
    print('  of a-only edges, %d/%d appear in b\'s union'
          % (a_in_b_union, len(only_a)))
    print('  of b-only edges, %d/%d appear in a\'s union'
          % (b_in_a_union, len(only_b)))

    truly_new_a = only_a - ub
    truly_new_b = only_b - ua
    print('  edges NEVER seen in the other session: a %d, b %d'
          % (len(truly_new_a), len(truly_new_b)))
    if truly_new_a:
        print('    a-only examples: %s' % sorted(truly_new_a)[:8])
    if truly_new_b:
        print('    b-only examples: %s' % sorted(truly_new_b)[:8])

    # Union comparison: coarser and therefore more likely to be portable.
    print('  union a %d, union b %d, union symmetric-diff %d'
          % (len(ua), len(ub), len(ua ^ ub)))
    print()

# Overall: is the union a portable property even when the core is not?
print('=== summary across inputs ===')
tot_core_sym = sum(len(set(a[n]['core']) ^ set(b[n]['core'])) for n in a)
tot_union_sym = sum(len(set(a[n]['union']) ^ set(b[n]['union'])) for n in a)
tot_never = sum(len((set(a[n]['core']) - set(b[n]['union']))
                    | (set(b[n]['core']) - set(a[n]['union']))) for n in a)
print('core symmetric difference total:  %d' % tot_core_sym)
print('union symmetric difference total: %d' % tot_union_sym)
print('core edges never seen in the other session at all: %d' % tot_never)
if tot_never == 0:
    print('=> every cross-session core difference is undersampling of the '
          'known fringe, NOT new code. Raising --repeat should converge them.')
