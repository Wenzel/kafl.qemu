"""Separate userspace ASLR from real decoder disagreement.

The raw address diff showed pairs like 742150e68e5d vs 7d9e98982e5d: identical
low bits, different high bits. That is the userspace mmap base, re-randomised on
every VM boot. `nokaslr` on the guest cmdline disables KERNEL ASLR only.

This matters well beyond this script. The two arms can never share a session
(vmx_pt clobbers a live perf session on every VM exit), so they can never share
an ASLR base, so ANY userspace edge is guaranteed to hash to a different bitmap
index in the two arms. That inflates every cross-arm bitmap diff by however much
userspace coverage the target has, and it is indistinguishable from a decoder
bug when all you can see is hashed indices.

Kernel addresses (>= 0xffffffff80000000 here, with nokaslr) are stable across
boots and are the only part of the diff that can carry a decoder verdict.
"""
import glob, json, os, sys, collections

if len(sys.argv) != 2:
    raise SystemExit('usage: aslr.py dumpdir')
d = sys.argv[1]
EXIT_IP = 0xffffffffffffffff
KERN = 0xffff800000000000   # anything above this is a kernel address

def load(backend):
    runs = []
    for p in sorted(glob.glob(os.path.join(d, '%s_*_*.json' % backend))):
        runs.append(set((f, t) for f, t, _c in json.load(open(p))['edges']))
    return runs

def core(runs):
    s = set(runs[0])
    for r in runs[1:]:
        s &= r
    return s

def is_user(a):
    return a != EXIT_IP and a < KERN

vc, pc = core(load('vmx')), core(load('perf'))

def split(s):
    user = set(e for e in s if is_user(e[0]) or is_user(e[1]))
    return user, s - user

vu, vk = split(vc)
pu, pk = split(pc)
print('vmx  core %5d = %5d userspace + %5d kernel' % (len(vc), len(vu), len(vk)))
print('perf core %5d = %5d userspace + %5d kernel' % (len(pc), len(pu), len(pk)))

print()
print('=== raw diff, as reported before ===')
print('  only-vmx %d, only-perf %d' % (len(vc - pc), len(pc - vc)))

print()
print('=== KERNEL-ONLY diff, ASLR removed ===')
ov, op = vk - pk, pk - vk
print('  kernel edges: shared %d, only-vmx %d, only-perf %d'
      % (len(vk & pk), len(ov), len(op)))
denom = len(vk)
if denom:
    print('  only-vmx is %.2f%% of the vmx kernel core' % (100.0 * len(ov) / denom))

# Recover each session's userspace base by aligning on the low 12 bits, which
# survive ASLR because mmap is page granular.
print()
print('=== confirming the ASLR hypothesis quantitatively ===')
def user_pages(s):
    out = collections.Counter()
    for f, t in s:
        for a in (f, t):
            if is_user(a):
                out[a >> 12] += 1
    return out
vp, pp = user_pages(vc), user_pages(pc)
print('  distinct userspace pages: vmx %d, perf %d' % (len(vp), len(pp)))
if vp and pp:
    # If the only difference is a constant base, then subtracting the minimum
    # page from each side should make the page sets agree.
    vmin, pmin = min(vp), min(pp)
    vnorm = set(p - vmin for p in vp)
    pnorm = set(p - pmin for p in pp)
    print('  lowest userspace page: vmx %x, perf %x (delta %x)'
          % (vmin, pmin, pmin - vmin))
    inter = len(vnorm & pnorm)
    print('  after subtracting each side\'s own base: %d of %d vmx pages match, '
          '%d of %d perf pages match' % (inter, len(vnorm), inter, len(pnorm)))
    # Also try offset-only matching of full addresses.
    def offs(s):
        return set(a & 0xfff for f, t in s for a in (f, t) if is_user(a))
    print('  distinct page offsets: vmx %d, perf %d, shared %d'
          % (len(offs(vc)), len(offs(pc)), len(offs(vc) & offs(pc))))

print()
print('=== what the kernel-only disagreement actually is ===')
for label, s in (('only-vmx', ov), ('only-perf', op)):
    to_exit = sum(1 for _f, t in s if t == EXIT_IP)
    from_exit = sum(1 for f, _t in s if f == EXIT_IP)
    print('  %s: %d edges, %d end at exit_ip (PGD), %d start at exit_ip (PGE)'
          % (label, len(s), to_exit, from_exit))
print()
print('  first 40 kernel-only-vmx:')
for f, t in sorted(ov)[:40]:
    print('    %016x -> %016x' % (f, t))
print('  first 40 kernel-only-perf:')
for f, t in sorted(op)[:40]:
    print('    %016x -> %016x' % (f, t))
