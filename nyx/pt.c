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
Intel PT policy, shared by every backend.

The mechanism that produces trace bytes lives behind pt_backend_t: either the
Nyx KVM module's ioctls (pt_vmx.c) or a perf_event_open session (pt_perf.c).
Everything here is the same either way: bitmap and redqueen bookkeeping, the
CR3 and IP filter state machine, libxdc setup, and the deferred command slot.

nyx/pt.h is unchanged, so no caller of this file needed touching.
*/

#include "qemu/osdep.h"

#include <libxdc.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "exec/memory.h"
#include "sysemu/cpus.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"
#include "qemu-common.h"
#include "target/i386/cpu.h"

#include "nyx/debug.h"
#include "nyx/file_helper.h"
#include "nyx/helpers.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/interface.h"
#include "nyx/memory_access.h"
#include "nyx/page_cache.h"
#include "nyx/pt.h"
#include "nyx/pt_backend.h"
#include "nyx/redqueen_trace.h"
#include "nyx/state/state.h"
#include "nyx/trace_dump.h"

#ifdef CONFIG_REDQUEEN
#include "nyx/patcher.h"
#include "nyx/redqueen.h"
#include "nyx/redqueen_patch.h"
#endif

/*
The "base + addrn" idiom below depends on these four blocks staying
contiguous and in order. Pin it here so a future reorder of the enum is a
compile error rather than a filter silently programmed on the wrong range.
*/
QEMU_BUILD_BUG_ON(PT_CMD_CONFIGURE_ADDR3 - PT_CMD_CONFIGURE_ADDR0 != 3);
QEMU_BUILD_BUG_ON(PT_CMD_ENABLE_ADDR3 - PT_CMD_ENABLE_ADDR0 != 3);
QEMU_BUILD_BUG_ON(PT_CMD_DISABLE_ADDR3 - PT_CMD_DISABLE_ADDR0 != 3);

pt_backend_kind_t pt_backend_kind = PT_BACKEND_VMX;

const pt_backend_t *pt_backend_get(void)
{
	switch (pt_backend_kind) {
	case PT_BACKEND_PERF:
		return &pt_backend_perf;
	case PT_BACKEND_VMX:
		return &pt_backend_vmx;
	case PT_BACKEND_NONE:
	default:
		return NULL;
	}
}

void pt_backend_select(pt_backend_kind_t kind)
{
	pt_backend_kind = kind;
}

bool pt_backend_kind_from_string(const char *name, pt_backend_kind_t *out)
{
	if (!name) {
		return false;
	}
	if (!strcmp(name, "vmx")) {
		*out = PT_BACKEND_VMX;
		return true;
	}
	if (!strcmp(name, "perf")) {
		*out = PT_BACKEND_PERF;
		return true;
	}
	if (!strcmp(name, "none")) {
		*out = PT_BACKEND_NONE;
		return true;
	}
	return false;
}

const char *pt_backend_kind_to_string(pt_backend_kind_t kind)
{
	switch (kind) {
	case PT_BACKEND_VMX:
		return "vmx";
	case PT_BACKEND_PERF:
		return "perf";
	case PT_BACKEND_NONE:
		return "none";
	default:
		return "invalid";
	}
}

static void pt_set(CPUState *cpu, run_on_cpu_data arg)
{
	asm volatile("" ::: "memory");
}

static inline int pt_cmd_hmp_context(CPUState *cpu, uint64_t cmd)
{
	cpu->pt_ret = -1;
	if (pt_hypercalls_enabled()) {
		nyx_error("HMP commands are ignored if kafl tracing "
		          "mode is enabled (-kafl)!\n");
	} else {
		cpu->pt_cmd = cmd;
		run_on_cpu(cpu, pt_set, RUN_ON_CPU_NULL);
	}
	return cpu->pt_ret;
}

static int pt_cmd(CPUState *cpu, uint64_t cmd, bool hmp_mode)
{
	if (hmp_mode) {
		return pt_cmd_hmp_context(cpu, cmd);
	} else {
		cpu->pt_cmd = cmd;
		pt_pre_kvm_run(cpu);
		return cpu->pt_ret;
	}
}

void pt_dump(CPUState *cpu, int bytes)
{
	if (!(GET_GLOBAL_STATE()->redqueen_state &&
	      GET_GLOBAL_STATE()->redqueen_state->intercept_mode))
	{
		if (GET_GLOBAL_STATE()->in_fuzzing_mode &&
		    GET_GLOBAL_STATE()->decoder_page_fault == false &&
		    GET_GLOBAL_STATE()->decoder && !GET_GLOBAL_STATE()->dump_page)
		{
			GET_GLOBAL_STATE()->pt_trace_size += bytes;
			pt_write_pt_dump_file(cpu->pt_mmap, bytes);
			decoder_result_t result =
			    libxdc_decode(GET_GLOBAL_STATE()->decoder, cpu->pt_mmap, bytes);
			switch (result) {
			case decoder_success:
				break;
			case decoder_success_pt_overflow:
				cpu->intel_pt_run_trashed = true;
				break;
			case decoder_page_fault:
				// nyx_warn("Page not found => 0x%lx\n", libxdc_get_page_fault_addr(GET_GLOBAL_STATE()->decoder));
				GET_GLOBAL_STATE()->decoder_page_fault = true;
				GET_GLOBAL_STATE()->decoder_page_fault_addr =
				    libxdc_get_page_fault_addr(GET_GLOBAL_STATE()->decoder);
				break;
			case decoder_unkown_packet:
				nyx_warn("libxdc_decode returned unknown_packet\n");
				break;
			case decoder_error:
				nyx_warn("libxdc_decode returned decoder_error\n");
				break;
			}
		}
	}
}


int pt_enable(CPUState *cpu, bool hmp_mode)
{
	if (!fast_reload_set_bitmap(get_fast_reload_snapshot())) {
		coverage_bitmap_reset();
	}
	if (GET_GLOBAL_STATE()->trace_mode) {
		redqueen_trace_reset();
		alt_bitmap_reset();
	}
	pt_truncate_pt_dump_file();
	return pt_cmd(cpu, PT_CMD_ENABLE, hmp_mode);
}

int pt_disable(CPUState *cpu, bool hmp_mode)
{
	int r = pt_cmd(cpu, PT_CMD_DISABLE, hmp_mode);
	return r;
}

int pt_set_cr3(CPUState *cpu, uint64_t val, bool hmp_mode)
{
	int r = 0;

	if (val == GET_GLOBAL_STATE()->pt_c3_filter) {
		return 0; // nothing changed
	}

	if (cpu->pt_enabled) {
		return -EINVAL;
	}
	if (GET_GLOBAL_STATE()->pt_c3_filter && GET_GLOBAL_STATE()->pt_c3_filter != val) {
		// nyx_debug_p(PT_PREFIX, "Reconfigure CR3-Filtering!\n");
		GET_GLOBAL_STATE()->pt_c3_filter = val;
		r += pt_cmd(cpu, PT_CMD_CONFIGURE_CR3, hmp_mode);
		r += pt_cmd(cpu, PT_CMD_ENABLE_CR3, hmp_mode);
		return r;
	}
	GET_GLOBAL_STATE()->pt_c3_filter = val;
	r += pt_cmd(cpu, PT_CMD_CONFIGURE_CR3, hmp_mode);
	r += pt_cmd(cpu, PT_CMD_ENABLE_CR3, hmp_mode);
	return r;
}

int pt_enable_ip_filtering(CPUState *cpu, uint8_t addrn, bool redqueen, bool hmp_mode)
{
	int r = 0;

	if (addrn > 3) {
		return -1;
	}

	if (cpu->pt_enabled) {
		return -EINVAL;
	}

	if (GET_GLOBAL_STATE()->pt_ip_filter_a[addrn] >
	    GET_GLOBAL_STATE()->pt_ip_filter_b[addrn])
	{
		nyx_debug_p(PT_PREFIX, "Error (ip_a > ip_b) 0x%lx-0x%lx\n",
		            GET_GLOBAL_STATE()->pt_ip_filter_a[addrn],
		            GET_GLOBAL_STATE()->pt_ip_filter_b[addrn]);
		return -EINVAL;
	}

	if (GET_GLOBAL_STATE()->pt_ip_filter_enabled[addrn]) {
		pt_disable_ip_filtering(cpu, addrn, hmp_mode);
	}

	nyx_debug_p(PT_PREFIX, "Configuring new trace region (addr%d, 0x%lx-0x%lx)\n",
	            addrn, GET_GLOBAL_STATE()->pt_ip_filter_a[addrn],
	            GET_GLOBAL_STATE()->pt_ip_filter_b[addrn]);

	if (GET_GLOBAL_STATE()->pt_ip_filter_configured[addrn] &&
	    GET_GLOBAL_STATE()->pt_ip_filter_a[addrn] != 0 &&
	    GET_GLOBAL_STATE()->pt_ip_filter_b[addrn] != 0)
	{
		r += pt_cmd(cpu, PT_CMD_CONFIGURE_ADDR0 + addrn, hmp_mode);
		/*
		Set the flag before issuing ENABLE, not after. A backend may need to
		read the range table to program the hardware (perf builds one filter
		string covering every enabled range), so the range has to be visible as
		enabled by then. vmx_pt does not care, since its ioctl carries the
		range explicitly.
		*/
		GET_GLOBAL_STATE()->pt_ip_filter_enabled[addrn] = true;
		r += pt_cmd(cpu, PT_CMD_ENABLE_ADDR0 + addrn, hmp_mode);
	}
	return r;
}

void pt_init_decoder(CPUState *cpu)
{
	uint64_t filters[4][2] = { 0 };

	/* TODO time to clean up this code -.- */
	filters[0][0] = GET_GLOBAL_STATE()->pt_ip_filter_a[0];
	filters[0][1] = GET_GLOBAL_STATE()->pt_ip_filter_b[0];
	filters[1][0] = GET_GLOBAL_STATE()->pt_ip_filter_a[1];
	filters[1][1] = GET_GLOBAL_STATE()->pt_ip_filter_b[1];
	filters[2][0] = GET_GLOBAL_STATE()->pt_ip_filter_a[2];
	filters[2][1] = GET_GLOBAL_STATE()->pt_ip_filter_b[2];
	filters[3][0] = GET_GLOBAL_STATE()->pt_ip_filter_a[3];
	filters[3][1] = GET_GLOBAL_STATE()->pt_ip_filter_b[3];

	assert(GET_GLOBAL_STATE()->decoder == NULL);
	assert(GET_GLOBAL_STATE()->shared_bitmap_ptr != NULL);
	assert(GET_GLOBAL_STATE()->shared_bitmap_size != 0);
	GET_GLOBAL_STATE()->decoder =
	    libxdc_init(filters, (void *(*)(void *, uint64_t, bool *))page_cache_fetch2,
	                GET_GLOBAL_STATE()->page_cache,
	                GET_GLOBAL_STATE()->shared_bitmap_ptr,
	                GET_GLOBAL_STATE()->shared_bitmap_size);

	if (GET_GLOBAL_STATE()->decoder == (void*)-1) {
		nyx_abort("libxdc_init() has failed ...\n");
	}

	/*
	Tell the decoder to keep only VMX non-root execution when the backend's
	stream contains both halves.

	A host wide perf event records the host kernel and KVM's own exit handling
	alongside guest execution. Those addresses are not in the guest page
	cache, so disassembling them page faults, and any coverage they did
	produce would be host noise in the bitmap. vmx_pt traces non-root only and
	emits no PIP to key on, so it must leave this off.
	*/
	const pt_backend_t *backend = pt_backend_get();
	if (backend && backend->traces_vmx_root) {
		libxdc_enable_nr_filter(GET_GLOBAL_STATE()->decoder, true);
		nyx_debug("PT: libxdc NR filtering enabled for the %s backend\n",
		          backend->name);
	}

	libxdc_register_bb_callback(GET_GLOBAL_STATE()->decoder,
	                            (void (*)(void *, disassembler_mode_t, uint64_t,
	                                      uint64_t))redqueen_callback,
	                            GET_GLOBAL_STATE()->redqueen_state);

	alt_bitmap_init(GET_GLOBAL_STATE()->shared_bitmap_ptr,
	                GET_GLOBAL_STATE()->shared_bitmap_size);
}

int pt_disable_ip_filtering(CPUState *cpu, uint8_t addrn, bool hmp_mode)
{
	int r = 0;
	switch (addrn) {
	case 0:
	case 1:
	case 2:
	case 3:
		/*
		Clear the flag before issuing DISABLE, for the same reason
		pt_enable_ip_filtering sets it before ENABLE: a backend that rebuilds
		its filter from the range table must not still see this range as
		enabled.
		*/
		if (GET_GLOBAL_STATE()->pt_ip_filter_enabled[addrn]) {
			GET_GLOBAL_STATE()->pt_ip_filter_enabled[addrn] = false;
		}
		r = pt_cmd(cpu, PT_CMD_DISABLE_ADDR0 + addrn, hmp_mode);
		break;
	default:
		r = -EINVAL;
	}
	return r;
}

void pt_kvm_init(CPUState *cpu)
{
	cpu->pt_cmd     = 0;
	cpu->pt_enabled = false;
	cpu->pt_fd      = 0;

	cpu->pt_decoder_state = NULL;

	cpu->reload_pending       = false;
	cpu->intel_pt_run_trashed = false;
}

pthread_mutex_t pt_dump_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
Run one deferred command against the selected backend.

Returns the ioctl style result. Byte counts from DISABLE are handled here
rather than by the caller so that the "decode what came back" rule lives in
one place.
*/
static void pt_dispatch_cmd(CPUState *cpu, const pt_backend_t *backend)
{
	int      ret     = 0;
	uint8_t  addrn;
	uint64_t a, b;

	switch (cpu->pt_cmd) {
	case PT_CMD_ENABLE:
		ret = backend->enable(cpu);
		break;

	case PT_CMD_DISABLE:
		ret = backend->disable(cpu);
		if (ret > 0) {
			pt_dump(cpu, ret);
			cpu->pt_enabled = false;
		}
		break;

	case PT_CMD_CONFIGURE_ADDR0:
	case PT_CMD_CONFIGURE_ADDR1:
	case PT_CMD_CONFIGURE_ADDR2:
	case PT_CMD_CONFIGURE_ADDR3:
		addrn = cpu->pt_cmd - PT_CMD_CONFIGURE_ADDR0;
		a     = GET_GLOBAL_STATE()->pt_ip_filter_a[addrn];
		b     = GET_GLOBAL_STATE()->pt_ip_filter_b[addrn];
		ret   = backend->configure_addr(cpu, addrn, a, b);
		break;

	case PT_CMD_ENABLE_ADDR0:
	case PT_CMD_ENABLE_ADDR1:
	case PT_CMD_ENABLE_ADDR2:
	case PT_CMD_ENABLE_ADDR3:
		ret = backend->enable_addr(cpu, cpu->pt_cmd - PT_CMD_ENABLE_ADDR0);
		break;

	case PT_CMD_DISABLE_ADDR0:
	case PT_CMD_DISABLE_ADDR1:
	case PT_CMD_DISABLE_ADDR2:
	case PT_CMD_DISABLE_ADDR3:
		ret = backend->disable_addr(cpu, cpu->pt_cmd - PT_CMD_DISABLE_ADDR0);
		break;

	case PT_CMD_CONFIGURE_CR3:
		ret = backend->configure_cr3(cpu, GET_GLOBAL_STATE()->pt_c3_filter);
		break;

	case PT_CMD_ENABLE_CR3:
		ret = backend->enable_cr3(cpu);
		break;

	default:
		nyx_warn("PT: unknown deferred command %d ignored\n", cpu->pt_cmd);
		break;
	}

	(void)ret;
}

void pt_pre_kvm_run(CPUState *cpu)
{
	const pt_backend_t *backend = pt_backend_get();

	if (!backend) {
		return;
	}

	pthread_mutex_lock(&pt_dump_mutex);

	if (GET_GLOBAL_STATE()->patches_disable_pending) {
		// nyx_debug_p(REDQUEEN_PREFIX, "patches disable\n");
		assert(false); /* remove this branch */
		GET_GLOBAL_STATE()->patches_disable_pending = false;
	}

	if (GET_GLOBAL_STATE()->patches_enable_pending) {
		// nyx_debug_p(REDQUEEN_PREFIX, "patches enable\n");
		assert(false); /* remove this branch */
		GET_GLOBAL_STATE()->patches_enable_pending = false;
	}


	if (GET_GLOBAL_STATE()->redqueen_enable_pending) {
		// nyx_debug_p(REDQUEEN_PREFIX, "rq enable\n");
		if (GET_GLOBAL_STATE()->redqueen_state) {
			enable_rq_intercept_mode(GET_GLOBAL_STATE()->redqueen_state);
		}
		GET_GLOBAL_STATE()->redqueen_enable_pending = false;
	}

	if (GET_GLOBAL_STATE()->redqueen_disable_pending) {
		// nyx_debug_p(REDQUEEN_PREFIX, "rq disable\n");
		if (GET_GLOBAL_STATE()->redqueen_state) {
			disable_rq_intercept_mode(GET_GLOBAL_STATE()->redqueen_state);
		}
		GET_GLOBAL_STATE()->redqueen_disable_pending = false;
	}

	if (GET_GLOBAL_STATE()->pt_trace_mode || GET_GLOBAL_STATE()->pt_trace_mode_force)
	{
		/*
		Lazy setup, on the vCPU thread. That matters for the perf backend: an
		event opened with pid 0 is scoped to the calling thread, and this is
		the only PT entry point guaranteed to run there.
		*/
		backend->setup(cpu);

		if (cpu->pt_cmd) {
			pt_dispatch_cmd(cpu, backend);
			cpu->pt_cmd = 0;
			cpu->pt_ret = 0;
		}
	}
	pthread_mutex_unlock(&pt_dump_mutex);
}

void pt_handle_overflow(CPUState *cpu)
{
	const pt_backend_t *backend = pt_backend_get();
	int                 overflow;

	if (!backend) {
		return;
	}

	pthread_mutex_lock(&pt_dump_mutex);
	overflow = backend->check_overflow(cpu);
	if (overflow > 0) {
		pt_dump(cpu, overflow);
	}
	pthread_mutex_unlock(&pt_dump_mutex);
}

void pt_post_kvm_run(CPUState *cpu)
{
	if (GET_GLOBAL_STATE()->pt_trace_mode || GET_GLOBAL_STATE()->pt_trace_mode_force)
	{
		pt_handle_overflow(cpu);
	}
}
