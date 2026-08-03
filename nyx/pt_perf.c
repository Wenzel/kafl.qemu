/*

Copyright (C) 2026 Intel Corporation

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
Intel PT via perf_event_open, as an alternative to the Nyx KVM module.

Why this can work at all: with kvm_intel's pt_mode at 0 (PT_MODE_SYSTEM,
the default, and the only value available on kernels that compile the
module parameter out) KVM does not swap RTIT_CTL across VM entry, and it
clears the PT_CONCEAL_PIP and PT_USE_GPA controls. So a host wide PT event
keeps tracing across VMXON and records guest execution into the host's own
AUX buffer, with PIP packets left visible. That requires IA32_VMX_MISC bit
14 ("tracing post VMXON"), which the preflight below checks, because
without it intel_pt_handle_vmx() pauses tracing and the failure is silent:
traces come back merely truncated rather than erroring.

Three things the Nyx kernel module did for us that perf will not, each
handled below and each capable of producing silently empty coverage rather
than an error if skipped:

  1. Guest only tracing. A host wide event also records the host kernel,
     KVM's own exit handling, and every other guest. Handled by telling
     libxdc to filter on the PIP NR bit (see libxdc_enable_nr_filter).

  2. A PSB at the start of every region. Mainline pt.c clears
     RTIT_STATUS.PacketByteCnt only on an event's first start, so a
     re-enabled region does not begin at a PSB and libxdc, which searches
     for one and discards everything before it, would return success with
     zero coverage. Handled by prepending a synthetic PSB and PSBEND.

  3. The 0x55 PT_TRACE_END sentinel past the end of the trace, which libxdc
     asserts on. Handled when staging.

Plus one thing vmx_pt never had to consider: the AUX area is a ring, so a
region can wrap and must be joined in order.
*/

#include "qemu/osdep.h"

#include <libxdc.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "sysemu/kvm.h"

#include "nyx/debug.h"
#include "nyx/pt.h"
#include "nyx/pt_backend.h"
#include "nyx/state/state.h"

#define PT_PMU_TYPE_PATH "/sys/bus/event_source/devices/intel_pt/type"
#define PT_CAPS_DIR      "/sys/bus/event_source/devices/intel_pt/caps/"
#define PT_PARANOID_PATH "/proc/sys/kernel/perf_event_paranoid"
#define PT_MODE_PATH     "/sys/module/kvm_intel/parameters/pt_mode"

/*
Match vmx_pt's ToPA capacity so that overflow behaviour is comparable
between the two backends. vmx_pt allocates TOPA_MAIN_ORDER 10 plus
TOPA_FALLBACK_ORDER 4, which is 4 MiB + 64 KiB; perf requires a power of two
number of AUX pages, so round to 4 MiB.
*/
#define PT_PERF_AUX_PAGES 1024
#define PT_PERF_BASE_PAGES 2 /* metadata page plus one data page */

/*
RTIT_CTL bits as exposed through attr.config. Read from the PMU's format
directory rather than trusted blindly; see perf_pt_read_config_bits().
*/
#define PT_CFG_PT       (1ULL << 0)
#define PT_CFG_BRANCH   (1ULL << 13)
#define PT_CFG_NORETCOMP (1ULL << 11)

/* 8 times PSB (02 82) then PSBEND (02 23). See SDM 33.4.2.17 / 33.4.2.18. */
static const uint8_t pt_psb_header[18] = {
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x23,
};

typedef struct pt_perf_cpu_state {
	int fd;

	struct perf_event_mmap_page *base;
	size_t                       base_size;

	uint8_t *aux;
	size_t   aux_size;

	/*
	The decode buffer published as cpu->pt_mmap. Sized for the whole AUX area
	plus the synthetic header plus a slack page for the sentinel, so a full
	ring can always be staged in one piece.
	*/
	uint8_t *staging;
	size_t   staging_size;

	bool enabled;

	/* Diagnostics, reported once at teardown rather than per iteration. */
	uint64_t regions;
	uint64_t bytes_total;
	uint64_t wrapped_regions;
	uint64_t truncated_regions;
} pt_perf_cpu_state_t;

static bool     perf_pt_preflight_done;
static uint32_t perf_pt_pmu_type;
static unsigned perf_pt_num_address_ranges;
static bool     perf_pt_has_cr3_filtering;
static bool     perf_pt_cr3_write_path;

static long perf_event_open_syscall(struct perf_event_attr *attr,
                                    pid_t                   pid,
                                    int                     cpu,
                                    int                     group_fd,
                                    unsigned long           flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static bool read_u64_file(const char *path, uint64_t *out)
{
	FILE    *f = fopen(path, "r");
	uint64_t v;

	if (!f) {
		return false;
	}
	if (fscanf(f, "%" SCNu64, &v) != 1) {
		fclose(f);
		return false;
	}
	fclose(f);
	*out = v;
	return true;
}

static bool read_cap(const char *name, uint64_t *out)
{
	char path[256];

	snprintf(path, sizeof(path), PT_CAPS_DIR "%s", name);
	return read_u64_file(path, out);
}

/*
Read IA32_VMX_MISC bit 14 through /dev/cpu/0/msr.

Without this bit the CPU pauses tracing across VMXON, so guest execution is
simply absent from the trace. The kernel handles that case by pausing the
event rather than failing it, which means the symptom is a short trace and
an empty bitmap, not an error. Refusing to start is far better than
producing plausible looking zero coverage for an entire campaign.

If the MSR cannot be read (no msr module, or insufficient privilege) this
returns true with a warning rather than failing: the check is a safety net,
and requiring root to read an MSR would be a worse requirement than the one
it protects against. The condition it guards is a property of the CPU
model, and every Skylake or later part that kAFL targets has it set.
*/
static bool perf_pt_check_vmx_misc(void)
{
	uint64_t val;
	int      fd;
	ssize_t  n;

	fd = open("/dev/cpu/0/msr", O_RDONLY);
	if (fd < 0) {
		nyx_warn("perf PT: cannot open /dev/cpu/0/msr (%s); skipping the "
		         "IA32_VMX_MISC bit 14 check. If guest coverage comes back "
		         "empty, verify 'tracing post VMXON' support on this part.\n",
		         strerror(errno));
		return true;
	}

	n = pread(fd, &val, sizeof(val), 0x485 /* IA32_VMX_MISC */);
	close(fd);

	if (n != (ssize_t)sizeof(val)) {
		nyx_warn("perf PT: cannot read IA32_VMX_MISC; skipping the bit 14 "
		         "check.\n");
		return true;
	}

	if (!(val & (1ULL << 14))) {
		nyx_error("perf PT: IA32_VMX_MISC bit 14 is clear (0x%lx). This CPU "
		          "pauses Intel PT across VMXON, so guest execution would be "
		          "absent from the trace and coverage would be silently "
		          "empty. Use the vmx backend on this host.\n", val);
		return false;
	}

	nyx_debug("perf PT: IA32_VMX_MISC=0x%lx, tracing post VMXON supported\n", val);
	return true;
}

/*
Require kvm_intel's pt_mode to be 0 (PT_MODE_SYSTEM).

In system mode the guest's RTIT_CTL is left alone and one host wide PT
session sees both root and non-root execution, which is exactly what this
backend decodes. In host-guest mode (pt_mode=1) the CPU maintains separate
ToPA buffers per side and the guest's output would never reach our AUX ring.

Absence of the sysfs file is a pass, not a failure, and that is the normal
case rather than an edge case: upstream commit aa0d42cacf09 wrapped the
module_param in #ifdef CONFIG_BROKEN in response to CVE-2024-53135, so on
any current kernel pt_mode is hardwired to PT_MODE_SYSTEM and deliberately
not exposed. A readable file therefore means an older or patched kernel
where the value can actually be something else, so that is the only case
worth reading.
*/
static bool perf_pt_check_pt_mode(void)
{
	uint64_t v;

	if (!read_u64_file(PT_MODE_PATH, &v)) {
		nyx_debug("perf PT: %s absent, so pt_mode is hardwired to "
		          "PT_MODE_SYSTEM\n", PT_MODE_PATH);
		return true;
	}

	if (v != 0) {
		nyx_error("perf PT: kvm_intel pt_mode is %lu, not 0 (PT_MODE_SYSTEM). "
		          "In host-guest mode the guest writes its own ToPA buffer and "
		          "its trace never reaches this event, so coverage would be "
		          "silently empty. Reload kvm_intel with pt_mode=0.\n", v);
		return false;
	}

	nyx_debug("perf PT: kvm_intel pt_mode=0 (PT_MODE_SYSTEM)\n");
	return true;
}

/*
Probe whether this kernel honours attr.config2 as IA32_RTIT_CR3_MATCH.

The write path is out of tree, so detect it rather than assume it. Vanilla
pt_event_valid() has no config2 branch at all and PMUs reject unknown
config2 bits, so an unpatched kernel fails this open with EINVAL while a
patched one accepts it.

Done once at startup on a throwaway event, because the alternative is
discovering it at the first pt_set_cr3() call, which happens well into a
campaign and after the fuzzer has already reported itself as running. There
is no software fallback for CR3, so late detection means a wasted run.

A non-EINVAL failure is reported as "unknown" rather than "absent": if the
open failed for an unrelated reason the probe simply did not answer, and
claiming the patch is missing would send the reader after the wrong problem.
*/
static bool perf_pt_probe_cr3_write_path(void)
{
	struct perf_event_attr attr;
	long                   fd;

	if (!perf_pt_has_cr3_filtering) {
		return false;
	}

	memset(&attr, 0, sizeof(attr));
	attr.size     = sizeof(attr);
	attr.type     = perf_pt_pmu_type;
	attr.config   = PT_CFG_PT | PT_CFG_BRANCH | PT_CFG_NORETCOMP;
	attr.disabled = 1;

	/*
	A syntactically valid but harmless match value: bits 4:0 of the MSR are
	reserved and must be zero, so 0x1000 exercises the accept path without
	depending on any real guest CR3.
	*/
	attr.config2 = 0x1000;

	fd = perf_event_open_syscall(&attr, 0, -1, -1, 0);
	if (fd >= 0) {
		close((int)fd);
		return true;
	}

	if (errno == EINVAL) {
		nyx_debug("perf PT: attr.config2 rejected with EINVAL, so this kernel "
		          "lacks the IA32_RTIT_CR3_MATCH write path\n");
	} else {
		nyx_warn("perf PT: the CR3 write path probe could not be answered "
		         "(%s). Treating it as unavailable.\n", strerror(errno));
	}
	return false;
}

/*
Startup gate. Everything checked here produces silently degraded coverage
rather than a visible error if it is wrong, which is why each one is checked
up front and reported once instead of being discovered from a bad campaign.
*/
static bool perf_pt_preflight(void)
{
	uint64_t v;

	if (perf_pt_preflight_done) {
		return true;
	}

	if (!read_u64_file(PT_PMU_TYPE_PATH, &v)) {
		nyx_error("perf PT: %s not readable. The intel_pt PMU is not present, "
		          "so this host cannot use the perf backend.\n", PT_PMU_TYPE_PATH);
		return false;
	}
	perf_pt_pmu_type = (uint32_t)v;

	if (read_u64_file(PT_PARANOID_PATH, &v) && v > 1) {
		nyx_error("perf PT: perf_event_paranoid is %lu; opening a PT event that "
		          "includes kernel and guest execution needs <= 1 (or "
		          "CAP_PERFMON). Lowering it is a host wide policy change, so "
		          "it is deliberately not done here:\n"
		          "\tsudo sysctl -w kernel.perf_event_paranoid=1\n", v);
		return false;
	}

	if (!perf_pt_check_pt_mode()) {
		return false;
	}

	if (!perf_pt_check_vmx_misc()) {
		return false;
	}

	perf_pt_num_address_ranges = 0;
	if (read_cap("num_address_ranges", &v)) {
		perf_pt_num_address_ranges = (unsigned)v;
	}

	perf_pt_has_cr3_filtering = false;
	if (read_cap("cr3_filtering", &v)) {
		perf_pt_has_cr3_filtering = (v != 0);
	}

	perf_pt_cr3_write_path = perf_pt_probe_cr3_write_path();

	nyx_debug("perf PT: pmu type=%u num_address_ranges=%u cr3_filtering=%d "
	          "cr3_write_path=%d\n",
	          perf_pt_pmu_type, perf_pt_num_address_ranges,
	          (int)perf_pt_has_cr3_filtering, (int)perf_pt_cr3_write_path);

	if (perf_pt_has_cr3_filtering && !perf_pt_cr3_write_path) {
		/*
		A warning, not a failure. A target that never calls pt_set_cr3 (a
		single process guest, or an A/B run comparing address range coverage
		only) is still perfectly valid on this kernel, so refusing to start
		would block work that does not need CR3. The abort lives in
		perf_configure_cr3(), at the point where the missing capability
		actually matters.
		*/
		nyx_warn("perf PT: this CPU supports CR3 filtering but the kernel does "
		         "not accept attr.config2, so pt_set_cr3() will fail. Targets "
		         "needing per process filtering require the "
		         "IA32_RTIT_CR3_MATCH write path patch.\n");
	}

	perf_pt_preflight_done = true;
	return true;
}

/*
Refuse to run alongside vmx_pt.

vmx_pt puts RTIT_CTL on the VMX MSR autoload list with TraceEn cleared, so
once any vCPU has issued KVM_VMX_PT_ENABLE every VM exit silently kills a
live host perf session. It never calls x86_add_exclusive, so perf sees no
EBUSY and issues no warning: the trace just stops. Since both backends are
compiled in, assert that the vmx side was never set up on this vCPU.
*/
static void perf_pt_assert_no_vmx(CPUState *cpu)
{
	if (cpu->pt_fd) {
		nyx_abort("perf PT: a vmx_pt fd is already open on this vCPU. vmx_pt "
		          "clears RTIT_CTL.TraceEn on every VM exit, which would kill "
		          "this perf session with no error reported. The two backends "
		          "must be serialised, never concurrent.\n");
	}
}

static pt_perf_cpu_state_t *perf_state(CPUState *cpu)
{
	return (pt_perf_cpu_state_t *)cpu->pt_decoder_state;
}

static void perf_setup(CPUState *cpu)
{
	pt_perf_cpu_state_t   *st;
	struct perf_event_attr attr;
	long                   fd;

	if (cpu->pt_decoder_state) {
		return;
	}

	if (!perf_pt_preflight()) {
		nyx_abort("perf PT: preflight failed, refusing to start. See the "
		          "message above.\n");
	}
	perf_pt_assert_no_vmx(cpu);

	st = g_new0(pt_perf_cpu_state_t, 1);

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = perf_pt_pmu_type;

	/*
	PT + BranchEn + DisRETC, and deliberately nothing else.

	CYCEn, MTCEn and TSCEn stay clear because libxdc rejects the packets they
	produce: it returns decoder_unkown_packet on the first TSC or MTC and
	stops. This was measured against real perf captures, which carry TSC by
	default and stop decoding early for exactly this reason. vmx_pt disables
	the same three, so this also keeps the two backends comparable.
	*/
	attr.config = PT_CFG_PT | PT_CFG_BRANCH | PT_CFG_NORETCOMP;

	attr.disabled = 1;

	/*
	exclude_kernel must stay 0: guest execution is recorded while the host is
	in ring 0, so excluding kernel would exclude everything we want.

	exclude_guest and exclude_host are deliberately not set. This PMU ignores
	them (measured: no effect), and setting them would suggest a guarantee
	that does not exist. Host and guest separation is done by the decoder via
	the PIP NR bit instead.
	*/
	attr.exclude_kernel = 0;

	/*
	pid 0 means "the calling thread". This is called from pt_pre_kvm_run(),
	which already runs on the vCPU thread, so the event is correctly scoped
	with no tid plumbing. cpu -1 means "any CPU", which is required for a
	thread scoped event and also means the trace follows the vCPU thread if
	the scheduler migrates it.
	*/
	fd = perf_event_open_syscall(&attr, 0, -1, -1, 0);
	if (fd < 0) {
		nyx_abort("perf PT: perf_event_open failed: %s\n", strerror(errno));
	}
	st->fd = (int)fd;

	st->base_size = PT_PERF_BASE_PAGES * getpagesize();
	st->base      = mmap(NULL, st->base_size, PROT_READ | PROT_WRITE, MAP_SHARED,
	                     st->fd, 0);
	if (st->base == MAP_FAILED) {
		nyx_abort("perf PT: mmap of the base area failed: %s\n", strerror(errno));
	}

	st->aux_size          = (size_t)PT_PERF_AUX_PAGES * getpagesize();
	st->base->aux_offset  = st->base_size;
	st->base->aux_size    = st->aux_size;

	/*
	PROT_WRITE on the AUX mapping is load bearing, not incidental. With write
	access perf runs the buffer in "stop when full" mode and honours
	aux_tail, so a buffer that fills is reported as truncated and is
	detectable. A read only mapping selects snapshot mode, where the kernel
	ignores aux_tail and overwrites older bytes silently, which for a fuzzer
	means losing coverage without ever being told.
	*/
	st->aux = mmap(NULL, st->aux_size, PROT_READ | PROT_WRITE, MAP_SHARED,
	               st->fd, st->base_size);
	if (st->aux == MAP_FAILED) {
		nyx_abort("perf PT: mmap of the AUX area failed: %s\n", strerror(errno));
	}

	/*
	Worst case staging: the whole ring, the synthetic header, and a page of
	slack that holds the sentinel. Sizing for the whole ring means staging
	never has to truncate, so a large region is a slow iteration rather than
	lost coverage.
	*/
	st->staging_size = sizeof(pt_psb_header) + st->aux_size + getpagesize();
	st->staging      = g_malloc0(st->staging_size);

	memcpy(st->staging, pt_psb_header, sizeof(pt_psb_header));

	cpu->pt_decoder_state = st;

	/*
	pt.c decodes from cpu->pt_mmap, so pointing it at the staging buffer lets
	pt_dump(), the trace dump file, redqueen and the page fault retry path all
	work unmodified.
	*/
	cpu->pt_mmap = st->staging;

	nyx_debug("perf PT: fd=%d aux=%zu KiB staging=%zu KiB\n", st->fd,
	          st->aux_size / 1024, st->staging_size / 1024);
}

/*
Copy [tail, head) out of the AUX ring into the staging buffer, behind the
synthetic PSB header, and terminate it with the sentinel.

Returns the total decodable length, which is what pt.c hands to libxdc.
*/
static int perf_stage_region(pt_perf_cpu_state_t *st, uint64_t tail, uint64_t head)
{
	uint64_t available = head - tail;
	size_t   off       = sizeof(pt_psb_header);
	uint64_t begin, end;

	if (available == 0) {
		return 0;
	}

	if (available > st->aux_size) {
		/*
		More was produced than the ring can hold, so the oldest bytes are
		already gone and the remaining stream does not begin at a packet
		boundary. Decoding it would resynchronise at some arbitrary offset and
		attribute the result to this iteration. Take the most recent ring's
		worth and record it as truncated so the caller can flag the run.
		*/
		st->truncated_regions++;
		tail      = head - st->aux_size;
		available = st->aux_size;
	}

	begin = tail % st->aux_size;
	end   = head % st->aux_size;

	if (begin < end || end == 0) {
		memcpy(st->staging + off, st->aux + begin, available);
		off += available;
	} else {
		/* Wrapped: tail to the end of the ring, then the ring start to head. */
		size_t first = st->aux_size - begin;

		st->wrapped_regions++;
		memcpy(st->staging + off, st->aux + begin, first);
		off += first;
		memcpy(st->staging + off, st->aux, (size_t)end);
		off += (size_t)end;
	}

	/*
	libxdc asserts on this byte at data[len] and requires it to be excluded
	from the length. vmx_pt got it from the kernel; here it is ours to write.
	*/
	st->staging[off] = PT_TRACE_END;

	st->regions++;
	st->bytes_total += off;

	return (int)off;
}

/*
Consume everything currently in the ring and advance the tail.

The tail is only ever moved all the way to head. Partial consumption would
leave a region whose start is not a packet boundary, and since no re-enabled
region begins at a PSB there would be nothing for libxdc to resynchronise
against.
*/
static int perf_consume(pt_perf_cpu_state_t *st)
{
	uint64_t head, tail;
	int      len;

	/*
	The kernel writes aux_head from another context, so the read has to be
	ordered against the copy that follows it, otherwise the copy could observe
	bytes the head has not yet published.
	*/
	head = __atomic_load_n(&st->base->aux_head, __ATOMIC_ACQUIRE);
	tail = st->base->aux_tail;

	if (head == tail) {
		return 0;
	}

	len = perf_stage_region(st, tail, head);

	__atomic_store_n(&st->base->aux_tail, head, __ATOMIC_RELEASE);

	return len;
}

static int perf_enable(CPUState *cpu)
{
	pt_perf_cpu_state_t *st = perf_state(cpu);

	if (!st) {
		return 0;
	}

	/*
	Drop whatever accumulated since the last iteration without decoding it.
	It belongs to no input: it is host execution between iterations plus the
	tail of the previous run, which was already decoded. vmx_pt's enable path
	does the equivalent by calling CHECK_TOPA_OVERFLOW first.
	*/
	__atomic_store_n(&st->base->aux_tail,
	                 __atomic_load_n(&st->base->aux_head, __ATOMIC_ACQUIRE),
	                 __ATOMIC_RELEASE);

	if (ioctl(st->fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		nyx_error("perf PT: PERF_EVENT_IOC_ENABLE failed: %s\n", strerror(errno));
		return -1;
	}

	st->enabled     = true;
	cpu->pt_enabled = true;
	return 0;
}

static int perf_disable(CPUState *cpu)
{
	pt_perf_cpu_state_t *st = perf_state(cpu);

	if (!st || !st->enabled) {
		return 0;
	}

	if (ioctl(st->fd, PERF_EVENT_IOC_DISABLE, 0) < 0) {
		nyx_error("perf PT: PERF_EVENT_IOC_DISABLE failed: %s\n", strerror(errno));
		return 0;
	}
	st->enabled = false;

	return perf_consume(st);
}

/*
The mid run drain, called from pt_post_kvm_run() on every VM exit.

Unlike the vmx_pt equivalent this does not ask the kernel whether anything
overflowed; it simply reports what is pending. Draining on every exit rather
than only near capacity keeps each staged region small, which matters because
staging here is a memcpy that vmx_pt did not have to pay for.
*/
static int perf_check_overflow(CPUState *cpu)
{
	pt_perf_cpu_state_t *st = perf_state(cpu);

	if (!st) {
		return 0;
	}
	return perf_consume(st);
}

/*
Hardware IP range filtering, best effort by design.

libxdc already receives all four ranges from pt_init_decoder() and applies
them in software, so it is authoritative for which addresses land in the
bitmap. Hardware ranges only reduce trace volume. This part exposes
num_address_ranges 2 against vmx_pt's 4 slots, so ranges beyond the hardware
limit are left to the software filter and the fact is logged once. Returning
an error instead would fail targets that configure more ranges than this CPU
happens to have, for no correctness gain.

Programming is deferred: PERF_EVENT_IOC_SET_FILTER takes the complete filter
string for the event, so individual ranges cannot be set one at a time. The
range table lives in global state, and enable_addr rebuilds the whole string
from it.
*/
static int perf_configure_addr(CPUState *cpu, uint8_t addrn, uint64_t a, uint64_t b)
{
	(void)cpu;
	(void)a;
	(void)b;

	if (addrn >= perf_pt_num_address_ranges) {
		nyx_debug("perf PT: range %u exceeds the %u hardware ranges on this "
		          "part; libxdc's software filter covers it.\n", addrn,
		          perf_pt_num_address_ranges);
	}
	return 0;
}

static int perf_program_filters(CPUState *cpu)
{
	pt_perf_cpu_state_t *st = perf_state(cpu);
	char                 filter[512];
	size_t               used = 0;
	unsigned             programmed = 0;

	if (!st) {
		return 0;
	}

	for (unsigned i = 0; i < INTEL_PT_MAX_RANGES; i++) {
		uint64_t a, b;

		if (programmed >= perf_pt_num_address_ranges) {
			break;
		}
		if (!GET_GLOBAL_STATE()->pt_ip_filter_enabled[i]) {
			continue;
		}

		a = GET_GLOBAL_STATE()->pt_ip_filter_a[i];
		b = GET_GLOBAL_STATE()->pt_ip_filter_b[i];
		if (a == 0 || b <= a) {
			continue;
		}

		used += snprintf(filter + used, sizeof(filter) - used, "%sfilter 0x%lx/0x%lx",
		                 programmed ? "," : "", a, b - a);
		if (used >= sizeof(filter)) {
			nyx_warn("perf PT: filter string overflow, leaving the remaining "
			         "ranges to libxdc's software filter\n");
			return 0;
		}
		programmed++;
	}

	if (programmed == 0) {
		return 0;
	}

	if (ioctl(st->fd, PERF_EVENT_IOC_SET_FILTER, filter) < 0) {
		/*
		Not fatal: this is a volume optimisation and libxdc still filters in
		software, so coverage stays correct. Say so rather than aborting.
		*/
		nyx_warn("perf PT: SET_FILTER(\"%s\") failed: %s. Continuing with the "
		         "software filter only; traces will be larger.\n", filter,
		         strerror(errno));
		return 0;
	}

	nyx_debug("perf PT: hardware IP filter set to \"%s\"\n", filter);
	return 0;
}

static int perf_enable_addr(CPUState *cpu, uint8_t addrn)
{
	(void)addrn;
	return perf_program_filters(cpu);
}

static int perf_disable_addr(CPUState *cpu, uint8_t addrn)
{
	(void)addrn;
	/* Global state has already been updated by pt.c, so rebuild from it. */
	return perf_program_filters(cpu);
}

/*
Hardware CR3 filtering, via attr.config2.

This needs the out of tree patch that wires attr.config2 to
IA32_RTIT_CR3_MATCH. Unlike the IP ranges there is no software fallback:
libxdc has no notion of CR3, so a host without the patch cannot filter by
process at all, and a fuzzer that silently traces every process in the guest
would fold unrelated coverage into one bitmap. Hence the hard failure.

config2 can only be set at open time, so the event is closed and reopened.
That is acceptable because pt.c refuses to change the CR3 filter while
tracing is enabled (pt_set_cr3 returns EINVAL if cpu->pt_enabled), so this
only ever runs between iterations.
*/
static int perf_configure_cr3(CPUState *cpu, uint64_t cr3)
{
	pt_perf_cpu_state_t   *st = perf_state(cpu);
	struct perf_event_attr attr;
	long                   fd;

	if (!st) {
		return -EINVAL;
	}

	if (!perf_pt_has_cr3_filtering) {
		nyx_abort("perf PT: this CPU reports cr3_filtering=0, so filtering by "
		          "CR3 is impossible in hardware and libxdc cannot do it in "
		          "software. Coverage would mix every process in the guest.\n");
	}

	memset(&attr, 0, sizeof(attr));
	attr.size           = sizeof(attr);
	attr.type           = perf_pt_pmu_type;
	attr.config         = PT_CFG_PT | PT_CFG_BRANCH | PT_CFG_NORETCOMP;
	attr.config2        = cr3;
	attr.disabled       = 1;
	attr.exclude_kernel = 0;

	fd = perf_event_open_syscall(&attr, 0, -1, -1, 0);
	if (fd < 0) {
		if (errno == EINVAL && cr3 != 0) {
			nyx_abort("perf PT: perf_event_open with attr.config2=0x%lx was "
			          "refused with EINVAL. This kernel most likely lacks the "
			          "IA32_RTIT_CR3_MATCH write path patch, so CR3 filtering "
			          "is unavailable and there is no software fallback.\n", cr3);
		}
		nyx_abort("perf PT: reopening the event for CR3 filtering failed: %s\n",
		          strerror(errno));
	}

	/*
	Swap the fd and remap. The staging buffer is deliberately kept, so
	cpu->pt_mmap does not move and nothing upstream needs to know this
	happened.
	*/
	munmap(st->aux, st->aux_size);
	munmap(st->base, st->base_size);
	close(st->fd);

	st->fd   = (int)fd;
	st->base = mmap(NULL, st->base_size, PROT_READ | PROT_WRITE, MAP_SHARED,
	                st->fd, 0);
	if (st->base == MAP_FAILED) {
		nyx_abort("perf PT: base remap after the CR3 reopen failed: %s\n",
		          strerror(errno));
	}
	st->base->aux_offset = st->base_size;
	st->base->aux_size   = st->aux_size;

	st->aux = mmap(NULL, st->aux_size, PROT_READ | PROT_WRITE, MAP_SHARED,
	               st->fd, st->base_size);
	if (st->aux == MAP_FAILED) {
		nyx_abort("perf PT: AUX remap after the CR3 reopen failed: %s\n",
		          strerror(errno));
	}

	st->enabled = false;

	/* The filter string does not survive a reopen. */
	perf_program_filters(cpu);

	nyx_debug("perf PT: CR3 filter programmed via attr.config2=0x%lx\n", cr3);
	return 0;
}

static int perf_enable_cr3(CPUState *cpu)
{
	/*
	Nothing to do: config2 was applied when the event was opened, and the
	kernel sets RTIT_CTL.CR3EN whenever config2 is nonzero. The separate
	configure and enable steps exist because the vmx_pt ioctl interface split
	them.
	*/
	(void)cpu;
	return 0;
}

const pt_backend_t pt_backend_perf = {
	.name           = "perf",
	.setup          = perf_setup,
	.enable         = perf_enable,
	.disable        = perf_disable,
	.check_overflow = perf_check_overflow,
	.configure_addr = perf_configure_addr,
	.enable_addr    = perf_enable_addr,
	.disable_addr   = perf_disable_addr,
	.configure_cr3  = perf_configure_cr3,
	.enable_cr3     = perf_enable_cr3,

	/*
	True: a host wide event records VMX root operation too, so libxdc must be
	told to keep only non-root execution.
	*/
	.traces_vmx_root = true,
};
