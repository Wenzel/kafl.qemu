/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

/*
The vmx_pt backend: Intel PT via the Nyx KVM module's KVM_VMX_PT_* ioctls.

This is a code move out of pt.c, deliberately kept behaviour identical down
to the ioctl ordering and the ignored return values, so that it stays
reviewable as a move rather than a rewrite. The one structural change is that
the abstract PT_CMD_* codes now arrive as function calls instead of raw ioctl
numbers in a switch, which is what lets a second backend exist at all.

Two framing obligations that this backend gets from the kernel for free, and
which pt_perf.c has to synthesise, are worth naming here because their
absence is the single largest difference between the backends:

  - Each returned region begins at a PSB, so libxdc can synchronise.
  - The 0x55 PT_TRACE_END sentinel is already present past the returned
    length, written by the mapping below and never overwritten because the
    kernel's ToPA never grows into that extra page.
*/

#include "qemu/osdep.h"

#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"

#include "nyx/debug.h"
#include "nyx/pt.h"
#include "nyx/pt_backend.h"
#include "nyx/state/state.h"

#define PT_BUFFER_MMAP_ADDR 0x3ffff0000000

struct vmx_pt_filter_iprs {
	__u64 a;
	__u64 b;
};

static inline int pt_ioctl(int fd, unsigned long request, unsigned long arg)
{
	if (!fd) {
		return -EINVAL;
	}
	return ioctl(fd, request, arg);
}

static void vmx_setup(CPUState *cpu)
{
	int ret;

	if (cpu->pt_fd) {
		return;
	}

	cpu->pt_fd = kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SETUP_FD, (unsigned long)0);
	assert(cpu->pt_fd != -1);
	ret = ioctl(cpu->pt_fd, KVM_VMX_PT_GET_TOPA_SIZE, (unsigned long)0x0);

	if (ret == -1) {
		nyx_abort("ToPA allocation failure. Check kernel logs.\n");
	}

	assert(ret % PAGE_SIZE == 0);
	cpu->pt_mmap = mmap((void *)PT_BUFFER_MMAP_ADDR, ret,
	                    PROT_READ | PROT_WRITE, MAP_SHARED, cpu->pt_fd, 0);
	assert(cpu->pt_mmap != (void *)0xFFFFFFFFFFFFFFFF);
	// add an extra page to have enough space for an additional PT_TRACE_END byte
	assert(mmap(cpu->pt_mmap + ret, 0x1000, PROT_READ | PROT_WRITE,
	            MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1,
	            0) == (void *)(cpu->pt_mmap + ret));

	nyx_debug("=> pt_mmap: %p - %p\n", cpu->pt_mmap, cpu->pt_mmap + ret);

	memset(cpu->pt_mmap + ret, 0x55, 0x1000);
}

static int vmx_enable(CPUState *cpu)
{
	if (!cpu->pt_fd) {
		return 0;
	}

	/* dump for the very last time before enabling VMX_PT ... just in case */
	ioctl(cpu->pt_fd, KVM_VMX_PT_CHECK_TOPA_OVERFLOW, (unsigned long)0);

	if (!ioctl(cpu->pt_fd, KVM_VMX_PT_ENABLE, 0)) {
		cpu->pt_enabled = true;
	}
	return 0;
}

static int vmx_disable(CPUState *cpu)
{
	if (!cpu->pt_fd) {
		return 0;
	}
	/* Returns the byte count directly, which pt.c treats as "decode this". */
	return ioctl(cpu->pt_fd, KVM_VMX_PT_DISABLE, 0);
}

static int vmx_check_overflow(CPUState *cpu)
{
	return ioctl(cpu->pt_fd, KVM_VMX_PT_CHECK_TOPA_OVERFLOW, (unsigned long)0);
}

static int vmx_configure_addr(CPUState *cpu, uint8_t addrn, uint64_t a, uint64_t b)
{
	struct vmx_pt_filter_iprs filter_iprs;

	filter_iprs.a = a;
	filter_iprs.b = b;
	return pt_ioctl(cpu->pt_fd, KVM_VMX_PT_CONFIGURE_ADDR0 + addrn,
	                (unsigned long)&filter_iprs);
}

static int vmx_enable_addr(CPUState *cpu, uint8_t addrn)
{
	return pt_ioctl(cpu->pt_fd, KVM_VMX_PT_ENABLE_ADDR0 + addrn, (unsigned long)0);
}

static int vmx_disable_addr(CPUState *cpu, uint8_t addrn)
{
	/*
	The DISABLE_ADDR ioctl numbers are NOT contiguous: ADDR0/1 are 0xae/0xaf
	but ADDR2/3 are 0xe0/0xe1, so "base + addrn" would compute garbage for 2
	and 3. pt.c's old switch sidestepped this by accident, since it only ever
	added to KVM_VMX_PT_DISABLE_ADDR0 inside a case that had already matched.
	Spell the four out.
	*/
	switch (addrn) {
	case 0:
		return pt_ioctl(cpu->pt_fd, KVM_VMX_PT_DISABLE_ADDR0, (unsigned long)0);
	case 1:
		return pt_ioctl(cpu->pt_fd, KVM_VMX_PT_DISABLE_ADDR1, (unsigned long)0);
	case 2:
		return pt_ioctl(cpu->pt_fd, KVM_VMX_PT_DISABLE_ADDR2, (unsigned long)0);
	case 3:
		return pt_ioctl(cpu->pt_fd, KVM_VMX_PT_DISABLE_ADDR3, (unsigned long)0);
	default:
		return -EINVAL;
	}
}

static int vmx_configure_cr3(CPUState *cpu, uint64_t cr3)
{
	return pt_ioctl(cpu->pt_fd, KVM_VMX_PT_CONFIGURE_CR3, cr3);
}

static int vmx_enable_cr3(CPUState *cpu)
{
	return pt_ioctl(cpu->pt_fd, KVM_VMX_PT_ENABLE_CR3, (unsigned long)0);
}

const pt_backend_t pt_backend_vmx = {
	.name           = "vmx",
	.setup          = vmx_setup,
	.enable         = vmx_enable,
	.disable        = vmx_disable,
	.check_overflow = vmx_check_overflow,
	.configure_addr = vmx_configure_addr,
	.enable_addr    = vmx_enable_addr,
	.disable_addr   = vmx_disable_addr,
	.configure_cr3  = vmx_configure_cr3,
	.enable_cr3     = vmx_enable_cr3,

	/*
	False: vmx_pt traces non-root operation only, so its stream carries no
	PIP NR transitions and NR filtering would suppress all of it.
	*/
	.traces_vmx_root = false,
};
