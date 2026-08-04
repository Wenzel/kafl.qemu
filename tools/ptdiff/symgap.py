"""Symbolise the kernel-only disagreement.

The decisive question the addresses alone cannot answer: perf has MORE kernel
edges than vmx (11684 vs 11588). Two readings, opposite conclusions:

  a) perf sees more real guest coverage, e.g. vmx_pt's hardware filtering drops
     something perf keeps. Good for perf.
  b) perf is leaking HOST execution that NR filtering failed to suppress. Bad,
     and it is the whole reason the NR filter exists.

Symbols separate them, but only if read carefully. The guest boots
/boot/vmlinuz-$(uname -r), i.e. the SAME build the host runs, with nokaslr on
both, so a host address and the equivalent guest address are literally identical
and no address test can tell them apart. What CAN tell them apart is which
FUNCTIONS appear: KVM's own exit handling (vmx_vcpu_run, vmx_handle_exit,
kvm_arch_vcpu_ioctl_run, __vmx_vcpu_run) only ever executes on the host, never in
this guest, which has no nested VM. Finding those in the perf-only set proves
leakage.
"""
import bisect, glob, json, os, sys, collections

if len(sys.argv) != 3:
    raise SystemExit('usage: symgap.py dumpdir System.map')
dumpdir, mappath = sys.argv[1], sys.argv[2]

EXIT_IP = 0xffffffffffffffff
KERN = 0xffff800000000000

syms = []
for line in open(mappath):
    parts = line.split()
    if len(parts) < 3:
        continue
    try:
        addr = int(parts[0], 16)
    except ValueError:
        continue
    if parts[1] in 'tTwW':   # text symbols only
        syms.append((addr, parts[2]))
syms.sort()
addrs = [a for a, _ in syms]
print('loaded %d text symbols from %s' % (len(syms), os.path.basename(mappath)))

def sym(a):
    if a == EXIT_IP:
        return 'EXIT_IP'
    i = bisect.bisect_right(addrs, a) - 1
    if i < 0:
        return '?'
    base, name = syms[i]
    return '%s+0x%x' % (name, a - base)

def symname(a):
    return sym(a).split('+')[0]

def load(backend):
    return [set((f, t) for f, t, _c in json.load(open(p))['edges'])
            for p in sorted(glob.glob(os.path.join(dumpdir, '%s_*_*.json' % backend)))]

def core(runs):
    s = set(runs[0])
    for r in runs[1:]:
        s &= r
    return s

def kernel_only(s):
    return set(e for e in s
               if all(a == EXIT_IP or a >= KERN for a in e))

vc, pc = core(load('vmx')), core(load('perf'))
vk, pk = kernel_only(vc), kernel_only(pc)
ov, op = vk - pk, pk - vk

# The host-only functions. If NR filtering worked perfectly, ZERO of these can
# appear on either arm, because this guest runs no nested VM.
HOST_ONLY = ('vmx_vcpu_run', '__vmx_vcpu_run', 'vmx_handle_exit',
             'kvm_arch_vcpu_ioctl_run', 'vmx_vcpu_enter_exit',
             'kvm_vcpu_ioctl', 'handle_ept_violation', 'vmx_vmexit',
             'kvm_mmu_page_fault', 'vcpu_enter_guest', 'vmx_pt_',
             'kvm_fastpath', 'handle_io', 'vmx_handle_external_intr')

print()
for label, s in (('=== functions in only-vmx (%d edges) ===' % len(ov), ov),
                 ('=== functions in only-perf (%d edges) ===' % len(op), op)):
    print(label)
    c = collections.Counter()
    for f, t in s:
        for a in (f, t):
            if a != EXIT_IP:
                c[symname(a)] += 1
    for name, n in c.most_common(30):
        flag = '  <-- HOST ONLY' if any(h in name for h in HOST_ONLY) else ''
        print('  %-40s %4d%s' % (name, n, flag))
    print('  (%d distinct functions)' % len(c))
    print()

print('=== host-only functions anywhere in each arm core ===')
for label, s in (('vmx', vk), ('perf', pk)):
    hits = collections.Counter()
    for f, t in s:
        for a in (f, t):
            if a == EXIT_IP:
                continue
            n = symname(a)
            if any(h in n for h in HOST_ONLY):
                hits[n] += 1
    if hits:
        print('  %s: LEAKAGE, %s' % (label, dict(hits)))
    else:
        print('  %s: none of the known host-only functions appear' % label)

# KVM module addresses live in the module region, not vmlinux text. Symbols from
# System.map cover vmlinux only, so a module address symbolises as the last
# vmlinux symbol plus a huge offset. Flag that separately.
print()
print('=== addresses beyond the end of vmlinux text (module region?) ===')
last = addrs[-1]
for label, s in (('vmx', vk), ('perf', pk)):
    beyond = set(a for f, t in s for a in (f, t)
                 if a != EXIT_IP and a > last + 0x100000)
    print('  %s: %d addrs above %016x' % (label, len(beyond), last))
    for a in sorted(beyond)[:10]:
        print('      %016x' % a)
