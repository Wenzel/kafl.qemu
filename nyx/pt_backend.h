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

#ifndef PT_BACKEND_H
#define PT_BACKEND_H

#include <stdbool.h>
#include <stdint.h>

/*
The seam between kAFL's Intel PT policy and the mechanism that actually
produces trace bytes.

Everything above this line (bitmap reset, CR3 and IP filter bookkeeping,
libxdc setup, redqueen, the page fault retry loop) is identical for every
backend and stays in pt.c. Everything below it is either the vmx_pt ioctl
interface against the Nyx KVM module (pt_vmx.c) or a host wide
perf_event_open session (pt_perf.c).

The contract every backend owes pt.c:

  - After setup(), cpu->pt_mmap points at a readable buffer, and a call to
    disable() or check_overflow() returning N means bytes [0, N) of that
    buffer are a decodable PT stream with libxdc's 0x55 sentinel already
    present at offset N. pt_dump() then hands exactly that to libxdc.

  - Byte counts are the sole return channel for "there is trace to decode".
    Zero or negative means nothing to do, matching what the vmx_pt ioctls
    already returned, so pt.c's existing checks are unchanged.
*/

typedef enum pt_backend_kind {
	/*
	NONE is today's nyx_no_pt_mode PT behaviour: the capability probe found
	no Nyx KVM module, so there is no trace source and the pre/post hooks in
	kvm-all.c must not run. It is deliberately value 0 so a zeroed KVMState
	starts out with PT disabled rather than enabled.
	*/
	PT_BACKEND_NONE = 0,
	PT_BACKEND_VMX,
	PT_BACKEND_PERF,
} pt_backend_kind_t;

/*
Abstract command codes for the deferred command slot in cpu->pt_cmd.

pt.c used to store raw KVM_VMX_PT_* ioctl numbers here, which silently tied
the deferral mechanism to one backend. These replace them. The contiguous
ADDR blocks are kept so the existing "base + addrn" idiom in pt.c still
works; the static asserts in pt.c pin that assumption.

Note the deferral only actually defers in HMP mode, where the command has to
be bounced onto the vCPU thread via run_on_cpu(). On the fuzzing path
pt_cmd() invokes pt_pre_kvm_run() directly and synchronously, which is why a
perf backend may open its event with pid=0 and get correct thread scoping
for free.
*/
typedef enum pt_cmd_code {
	PT_CMD_NONE = 0,

	PT_CMD_ENABLE,
	PT_CMD_DISABLE,

	PT_CMD_CONFIGURE_ADDR0,
	PT_CMD_CONFIGURE_ADDR1,
	PT_CMD_CONFIGURE_ADDR2,
	PT_CMD_CONFIGURE_ADDR3,

	PT_CMD_ENABLE_ADDR0,
	PT_CMD_ENABLE_ADDR1,
	PT_CMD_ENABLE_ADDR2,
	PT_CMD_ENABLE_ADDR3,

	PT_CMD_DISABLE_ADDR0,
	PT_CMD_DISABLE_ADDR1,
	PT_CMD_DISABLE_ADDR2,
	PT_CMD_DISABLE_ADDR3,

	PT_CMD_CONFIGURE_CR3,
	PT_CMD_ENABLE_CR3,
} pt_cmd_code_t;

typedef struct pt_backend {
	const char *name;

	/*
	Acquire the trace source for this vCPU and publish the decode buffer as
	cpu->pt_mmap. Called lazily from pt_pre_kvm_run() on the vCPU thread,
	which matters for perf: an event opened with pid=0 is scoped to the
	calling thread, so opening it anywhere else would trace the wrong thread.
	Must be idempotent; pt.c calls it on every pass.
	*/
	void (*setup)(CPUState *cpu);

	int (*enable)(CPUState *cpu);

	/*
	Stop tracing and return the number of decodable bytes now in
	cpu->pt_mmap, or <= 0 for none.
	*/
	int (*disable)(CPUState *cpu);

	/*
	Return decodable bytes available without stopping the trace, or <= 0.
	This is the mid-run drain that keeps a fuzzing iteration from
	overflowing the hardware buffer.
	*/
	int (*check_overflow)(CPUState *cpu);

	int (*configure_addr)(CPUState *cpu, uint8_t addrn, uint64_t a, uint64_t b);
	int (*enable_addr)(CPUState *cpu, uint8_t addrn);
	int (*disable_addr)(CPUState *cpu, uint8_t addrn);

	int (*configure_cr3)(CPUState *cpu, uint64_t cr3);
	int (*enable_cr3)(CPUState *cpu);

	/*
	True when the backend's trace stream interleaves VMX root (host)
	execution with non-root (guest) execution, so libxdc has to be told to
	filter on the PIP NR bit.

	A host wide perf event sees both halves in one byte stream. vmx_pt does
	not: it restricts tracing to non-root operation in hardware via the VMX
	MSR autoload list, so its stream is guest only and enabling NR filtering
	on it would suppress everything, because it emits no PIP to key on.
	*/
	bool traces_vmx_root;
} pt_backend_t;

/* Selected once at startup from the -nyx-pt-backend option plus the KVM
 * capability probe; read everywhere else. */
extern pt_backend_kind_t pt_backend_kind;

const pt_backend_t *pt_backend_get(void);
void pt_backend_select(pt_backend_kind_t kind);

/* Parse the option string. Returns false and leaves *out untouched on an
 * unrecognised name, so the caller can produce its own diagnostic. */
bool pt_backend_kind_from_string(const char *name, pt_backend_kind_t *out);
const char *pt_backend_kind_to_string(pt_backend_kind_t kind);

extern const pt_backend_t pt_backend_vmx;
extern const pt_backend_t pt_backend_perf;

#endif
