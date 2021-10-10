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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "hw/qdev-properties.h"
#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "sysemu/kvm.h"
#include "migration/migration.h"
#include "qemu/error-report.h"
#include "qemu/event_notifier.h"
#include "qom/object_interfaces.h"
#include "chardev/char-fe.h"
#include "sysemu/hostmem.h"
#include "sysemu/qtest.h"
#include "qapi/visitor.h"
#include "exec/ram_addr.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include "pt.h"
#include "nyx/hypercall.h"
#include "nyx/interface.h"
#include "nyx/debug.h"
#include "nyx/synchronization.h"
#include "nyx/snapshot/devices/state_reallocation.h"
#include "nyx/memory_access.h"
#include <sys/ioctl.h>
#include "nyx/state.h"
#include "nyx/sharedir.h"
#include "nyx/helpers.h"

#include <time.h>

#include "redqueen.h"

#define CONVERT_UINT64(x) (uint64_t)(strtoull(x, NULL, 16))

#define TYPE_KAFLMEM "kafl"
#define KAFLMEM(obj) \
		OBJECT_CHECK(kafl_mem_state, (obj), TYPE_KAFLMEM)

uint32_t kafl_bitmap_size = DEFAULT_KAFL_BITMAP_SIZE;

static void pci_kafl_guest_realize(DeviceState *dev, Error **errp);

typedef struct kafl_mem_state {
	DeviceState parent_obj;

	Chardev *kafl_chr_drv_state;
	CharBackend chr;

	char* sharedir;

	char* workdir; 
	uint32_t worker_id;
	
	char* redqueen_workdir;
	char* data_bar_fd_0;
	char* data_bar_fd_1;
	char* data_bar_fd_2;
	char* bitmap_file;

	char* filter_bitmap[4];
	char* ip_filter[4][2];

	uint64_t bitmap_size;

	bool debug_mode; 	/* support for hprintf */
	bool notifier;
	bool dump_pt_trace;

	bool redqueen;
	
} kafl_mem_state;

static void kafl_guest_event(void *opaque, QEMUChrEvent event){
}

static void send_char(char val, void* tmp_s){
	kafl_mem_state *s = tmp_s;

	assert(val == KAFL_PING);
	__sync_synchronize();

	qemu_chr_fe_write(&s->chr, (const uint8_t *) &val, 1);
}

static int kafl_guest_can_receive(void * opaque){
	return sizeof(int64_t);
}

static kafl_mem_state* state = NULL;

static void init_send_char(kafl_mem_state* s){
	state = s;
}

bool interface_send_char(char val){

	if(state){
		send_char(val, state);
		return true;
	}
	return false;
}

static void kafl_guest_receive(void *opaque, const uint8_t * buf, int size){
	int i;				
	for(i = 0; i < size; i++){
		switch(buf[i]){
			case KAFL_PING:
				//fprintf(stderr, "Protocol - RECV: KAFL_PING\n");
				synchronization_unlock();
				break;
			case '\n':
				break;
			case 'E':
				exit(0);
			default:
				break;
				assert(false);
		}
	}
}

static int kafl_guest_create_memory_bar(kafl_mem_state *s, int region_num, uint64_t bar_size, const char* file, Error **errp){
	void * ptr;
	int fd;
	struct stat st;
	
	fd = open(file, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, bar_size) == 0);
	stat(file, &st);
	QEMU_PT_PRINTF(INTERFACE_PREFIX, "new shm file: (max size: %lx) %lx", bar_size, st.st_size);
	
	assert(bar_size == st.st_size);
	ptr = mmap(0, bar_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (ptr == MAP_FAILED) {
		error_setg_errno(errp, errno, "Failed to mmap memory");
		return -1;
	}

	switch(region_num){
		case 1:	pt_setup_program((void*)ptr);
				break;
		case 2:	
				GET_GLOBAL_STATE()->shared_payload_buffer_fd = fd;
				GET_GLOBAL_STATE()->shared_payload_buffer_size = bar_size;
				break;
	}

	init_send_char(s);

	return 0;
}

static void kafl_guest_setup_bitmap(kafl_mem_state *s, char* filename, uint32_t bitmap_size){
	void * ptr;
	int fd;
	struct stat st;
	
	fd = open(filename, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, bitmap_size) == 0);
	stat(filename, &st);
	assert(bitmap_size == st.st_size);
	ptr = mmap(0, bitmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	GET_GLOBAL_STATE()->shared_bitmap_ptr = (void*)ptr;
	GET_GLOBAL_STATE()->shared_bitmap_fd = fd;
	GET_GLOBAL_STATE()->shared_bitmap_size = bitmap_size-DEFAULT_KAFL_IJON_BITMAP_SIZE;
	GET_GLOBAL_STATE()->shared_ijon_bitmap_size = DEFAULT_KAFL_IJON_BITMAP_SIZE;
}

static bool verify_workdir_state(kafl_mem_state *s, Error **errp){

	char* workdir = s->workdir;
	uint32_t id = s->worker_id;
	char* tmp;

	if (!folder_exits(workdir)){
		fprintf(stderr, "%s does not exist...\n", workdir);
		return false;
	}

	set_workdir_path(workdir);

	assert(asprintf(&tmp, "%s/dump/", workdir) != -1);
	if (!folder_exits(tmp)){
		mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}

	assert(asprintf(&tmp, "%s/interface_%d", workdir, id) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/payload_%d", workdir, id) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	}
	else {
		kafl_guest_create_memory_bar(s, 2, PAYLOAD_SIZE, tmp, errp);
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/bitmap_%d", workdir, id) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	} else {
		kafl_guest_setup_bitmap(s, tmp, s->bitmap_size);
	}
	free(tmp);


	assert(asprintf(&tmp, "%s/page_cache.lock", workdir) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr, "%s does not exist...", tmp);
		free(tmp);
		return false;
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/page_cache.addr", workdir) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr, "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/page_cache.dump", workdir) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/page_cache", workdir) != -1);
	init_page_cache(tmp);

	assert(asprintf(&tmp, "%s/redqueen_workdir_%d/", workdir, id) != -1);
	if (!folder_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	}
	else {
		setup_redqueen_workdir(tmp);
	}
	free(tmp);

	init_redqueen_state();

  if(s->dump_pt_trace){
	  assert(asprintf(&tmp, "%s/pt_trace_dump_%d", workdir, id) != -1);
    pt_open_pt_trace_file(tmp);
    free(tmp);
  }


	assert(asprintf(&tmp, "%s/aux_buffer_%d", workdir, id) != -1);
	/*
	if (file_exits(tmp)){
		QEMU_PT_PRINTF(INTERFACE_PREFIX, "%s does not already exists...", tmp);
		free(tmp);
		return false;
	}
	else {
		init_aux_buffer(tmp);
	}
	*/
	init_aux_buffer(tmp);
	free(tmp);


	return true;
}

#define KVM_VMX_PT_GET_ADDRN				_IO(KVMIO,	0xe9)

static void check_range(uint8_t i){
	int ret = 0;
	int kvm = open("/dev/dell", O_RDWR | O_CLOEXEC);
	ret = ioctl(kvm, KVM_VMX_PT_GET_ADDRN, NULL);

	if(ret == -1){
		QEMU_PT_PRINTF(INTERFACE_PREFIX, "ERROR: Multi range tracing is not supported! Please upgrade your kernel to 4.20-rc4!\n");
		abort();
	}

	if(ret < (i+1)){
		QEMU_PT_PRINTF(INTERFACE_PREFIX, "ERROR: CPU supports only %d IP filters!\n", ret);
		abort();
	}
	close(kvm);
}

static bool verify_sharedir_state(kafl_mem_state *s, Error **errp){

	char* sharedir = s->sharedir;

	if (!folder_exits(sharedir)){
		QEMU_PT_PRINTF(INTERFACE_PREFIX, "%s does not exist...", sharedir);
		return false;
	}
	return true;
}


static void pci_kafl_guest_realize(DeviceState *dev, Error **errp){
	uint64_t tmp0, tmp1;
	kafl_mem_state *s = KAFLMEM(dev);

	if(s->bitmap_size <= 0){
		s->bitmap_size = DEFAULT_KAFL_BITMAP_SIZE;
	}

	assert((uint32_t)s->bitmap_size > (0x1000 + DEFAULT_KAFL_IJON_BITMAP_SIZE));
	assert((((uint32_t)s->bitmap_size-DEFAULT_KAFL_IJON_BITMAP_SIZE) & (((uint32_t)s->bitmap_size-DEFAULT_KAFL_IJON_BITMAP_SIZE) - 1)) == 0 );

	if(s->worker_id == 0xFFFF){
		fprintf(stderr, "Invalid worker id...\n");
		abort();
	}

	if (!s->workdir || !verify_workdir_state(s, errp)){
		fprintf(stderr, "Invalid work dir...\n");
		abort();
	}

	if (!s->sharedir || !verify_sharedir_state(s, errp)){
		fprintf(stderr,  "Invalid sharedir...\n");
		//abort();
	}
	else{
		sharedir_set_dir(GET_GLOBAL_STATE()->sharedir, s->sharedir);
	}

	if(&s->chr)
		qemu_chr_fe_set_handlers(&s->chr, kafl_guest_can_receive, kafl_guest_receive, kafl_guest_event, NULL, s, NULL, true);

	for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(s->ip_filter[i][0] && s->ip_filter[i][1]){
			if(i >= 1){
				check_range(i);
			}
			tmp0 = CONVERT_UINT64(s->ip_filter[i][0]);
			tmp1 = CONVERT_UINT64(s->ip_filter[i][1]);
			if (tmp0 < tmp1){
				//if(s->filter_bitmap[i]){
				//	tmp = kafl_guest_setup_filter_bitmap(s, s->filter_bitmap[i], (uint64_t)(s->bitmap_size));
				//}
				pt_setup_ip_filters(i, tmp0, tmp1);
			}
		}
	}

	if(s->debug_mode){
		GET_GLOBAL_STATE()->enable_hprintf = true;
	}

	if(s->notifier){
		enable_notifies();
	}

	pt_setup_enable_hypercalls();
	init_crash_handler();
}

static Property kafl_guest_properties[] = {
	DEFINE_PROP_CHR("chardev", kafl_mem_state, chr),

	DEFINE_PROP_STRING("sharedir", kafl_mem_state, sharedir),


	DEFINE_PROP_STRING("workdir", kafl_mem_state, workdir),
	DEFINE_PROP_UINT32("worker_id", kafl_mem_state, worker_id, 0xFFFF),

	/* 
	 * Since DEFINE_PROP_UINT64 is somehow broken (signed/unsigned madness),
	 * let's use DEFINE_PROP_STRING and post-process all values by strtol...
	 */
	DEFINE_PROP_STRING("ip0_a", kafl_mem_state, ip_filter[0][0]),
	DEFINE_PROP_STRING("ip0_b", kafl_mem_state, ip_filter[0][1]),
	DEFINE_PROP_STRING("ip1_a", kafl_mem_state, ip_filter[1][0]),
	DEFINE_PROP_STRING("ip1_b", kafl_mem_state, ip_filter[1][1]),
	DEFINE_PROP_STRING("ip2_a", kafl_mem_state, ip_filter[2][0]),
	DEFINE_PROP_STRING("ip2_b", kafl_mem_state, ip_filter[2][1]),
	DEFINE_PROP_STRING("ip3_a", kafl_mem_state, ip_filter[3][0]),
	DEFINE_PROP_STRING("ip3_b", kafl_mem_state, ip_filter[3][1]),


	DEFINE_PROP_UINT64("bitmap_size", kafl_mem_state, bitmap_size, DEFAULT_KAFL_BITMAP_SIZE),
	DEFINE_PROP_BOOL("debug_mode", kafl_mem_state, debug_mode, false),
	DEFINE_PROP_BOOL("crash_notifier", kafl_mem_state, notifier, true),
	DEFINE_PROP_BOOL("dump_pt_trace", kafl_mem_state, dump_pt_trace, false),


	DEFINE_PROP_END_OF_LIST(),
};

static void kafl_guest_class_init(ObjectClass *klass, void *data){
	DeviceClass *dc = DEVICE_CLASS(klass);
	//PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
	dc->realize = pci_kafl_guest_realize;
	//k->class_id = PCI_CLASS_MEMORY_RAM;
	dc->props = kafl_guest_properties;
	set_bit(DEVICE_CATEGORY_MISC, dc->categories);
	dc->desc = "KAFL Inter-VM shared memory";
}

static void kafl_guest_init(Object *obj){
}

static const TypeInfo kafl_guest_info = {
	.name          = TYPE_KAFLMEM,
	.parent        = TYPE_DEVICE,
	.instance_size = sizeof(kafl_mem_state),
	.instance_init = kafl_guest_init,
	.class_init    = kafl_guest_class_init,
};

static void kafl_guest_register_types(void){
	type_register_static(&kafl_guest_info);
}

type_init(kafl_guest_register_types)
