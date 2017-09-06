/*
 * Copyright 2014,2015 International Business Machines
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LIBOCXL_INTERNAL_H
#define _LIBOCXL_INTERNAL_H

#include <libocxl.h>
#include <dirent.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>

#define EVENT_QUEUE_MAX 3

enum libocxl_req_state {
	LIBOCXL_REQ_IDLE,
	LIBOCXL_REQ_REQUEST,
	LIBOCXL_REQ_PENDING
};

struct int_req {
	volatile enum libocxl_req_state state;
	volatile uint16_t max;
};

struct open_req {
	volatile enum libocxl_req_state state;
	volatile uint8_t context;
};

struct attach_req {
	volatile enum libocxl_req_state state;
	volatile uint64_t wed;
};

struct mmio_req {
	volatile enum libocxl_req_state state;
	volatile uint8_t type;
	volatile uint32_t addr;
	uint64_t data;
};

struct ocxl_irq {
        uint16_t irq;
        uint64_t id;
	struct ocxl_afu *afu;
	struct ocxl_irq *_next;
};

struct ocxl_waitasec {
	ocxl_event_type type;
	uint16_t size;
	uint16_t process_element;
	uint16_t reserved1;
};

struct mem_req {
	volatile enum libocxl_req_state state;
	volatile uint8_t type;
	volatile uint64_t addr;
	volatile uint64_t size;
	volatile uint64_t be;
	uint8_t *data;
};

// struct ocxl_afu_h {
struct ocxl_afu {
	pthread_t thread;
	pthread_mutex_t event_lock;
	pthread_mutex_t waitasec_lock;
	ocxl_event *events[EVENT_QUEUE_MAX];
	struct ocxl_waitasec *waitasec;
  //    int adapter;
        uint64_t ppc64_amr;
	char *id;
        ocxl_identifier ocxl_id;
        uint8_t bus;
        uint8_t dev;
        uint8_t fcn;
	uint16_t context;
	uint16_t map;
  //	uint16_t position;
	uint8_t dbg_id;
	int fd;
	int opened;
	int attached;
	int mapped;
	int global_mapped;
	int lpc_mapped;
	int pipe[2];
        long mmio_length;  // this pasid stride
        long mmio_offset;  // this pasid mmio offset - f(pasid, per pasid stride, per pasid mmio offset)
	uint16_t cr_device;
	uint16_t cr_vendor;
        int irq_count;
	struct int_req int_req;
	struct open_req open;
	struct attach_req attach;
	struct mmio_req mmio;
	struct mem_req mem;
	struct ocxl_irq *irq;
	struct ocxl_afu *_head;
	struct ocxl_afu *_next;
        struct ocxl_afu *_next_adapter; // ???
};

struct ocxl_adapter_h {
	DIR *enum_dir;
	struct dirent *enum_ent;
	char *sysfs_path;
	long oppa_major;
	long oppa_minor;
	long ocse_version;
	int fd;
	char *id;
	uint16_t map;
	uint16_t mask;
	uint16_t position;
	struct ocxl_adapter_h *_head;
	struct ocxl_adapter_h *_next;
	struct ocxl_afu *afu_list;
};

#endif
