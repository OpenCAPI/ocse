/*
 * Copyright 2014,2017 International Business Machines
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
	volatile uint8_t cmd;
	volatile uint64_t addr;
	volatile uint64_t size;
	volatile uint64_t be;
	uint8_t *data;
	uint8_t *datab;
};

typedef struct ocxl_afu ocxl_afu;

// ocxl_mmio_area contains information for all memory regions of the afu
//   global mmio
//   per pasid mmio
//   lpc system memory
//   lpc special purpose memory
typedef struct ocxl_mmio_area {
        char *start;         // The first addressable byte of the area
        size_t length;       // The size of the area in bytes
        ocxl_mmio_type type; // The type of the area
         void *ocxl_ea;  // the address of the area that we malloc to imitate lpc space 
        ocxl_afu *afu;       // The AFU this MMIO area belongs to
} ocxl_mmio_area;

// ocxl_ea_area contains translation information for translated addresses requested by the afu
//   EA
//   TA (which are modeled by reflecting back the EA
//   MH - memory hit hint (not supported until OpenCAPI 5.0)
//   Page size
typedef struct ocxl_ea_area {
        uint64_t ea;        // the effective address for which we want the translation
        uint64_t ta;        // the translated address for the given ea
        uint64_t pa;        // the physical address in LPC memory - not supported
        uint8_t mh;         // memory hit - not supported
        uint8_t pg_size;    // not supported
        uint8_t kill_xlate_pending;
        struct ocxl_ea_area *_next;
} ocxl_ea_area;

// ocxl_cache_line_proxy contains cache state information for addresses cached by the afu
//   EA
//   Cache state
//   host_tag
// Notes:
// - what happens if host shares non-64byte aligned object with afu.  may not be able "protect" the 64 byte aligned ea that comes back
// - should the cache proxy be associated with the afu or with the instance of libocxl?  for now, with afu
typedef struct ocxl_cache_line_proxy {
        uint64_t ea;                    // the effective address of the line that the afu is going to cache
        uint16_t size;
        uint8_t cache_state;            // the cache state that we have decided to give back to the AFU
        uint8_t synonym_detected;       // gets set by synonym_detected, cleared when the afu returns synonym_done
        uint8_t ef_expected;            // gets set if get a cacheable request and the next host tag sent to us matches this host_tag
        uint32_t host_tag;              // the host_tag that we give back to the afu for subsequent cache ops
        struct ocxl_afu *afu;
        struct ocxl_cache_line_proxy *_next_line;
} ocxl_cache_line_proxy;

// ocxl_cache_page_proxy contains cache state information for the pages of the lines cached by the afu
//   EA
//   Cache state
//   host_tag
// Notes:
// - what happens if host shares non-64byte aligned object with afu.  may not be able "protect" the 64 byte aligned ea that comes back
// - should the cache proxy be associated with the afu or with the instance of libocxl?  for now, with afu
typedef struct ocxl_cache_page_proxy {
        uint64_t ea;                    // the effective address of the page in which the line is that the afu is going to cache
        uint16_t size;                  // page size?
        uint8_t castout_required;       // gets set by force evict, cleared when the afu has castout[.push] all the lines in the page
        struct ocxl_afu *afu;
        struct ocxl_cache_line_proxy *_next_line;
        struct ocxl_cache_page_proxy *_next_page;
} ocxl_cache_page_proxy;

// struct ocxl_afu_h {
struct ocxl_afu {
	pthread_t thread;
	pthread_mutex_t event_lock;
	ocxl_event *events[EVENT_QUEUE_MAX];
        uint64_t ppc64_amr;
	char *id;
        ocxl_identifier ocxl_id;
        uint8_t bus;
        uint8_t dev;
        uint8_t fcn;
	uint16_t device_id;
	uint16_t vendor_id;
        uint8_t afu_version_major;
        uint8_t afu_version_minor;
	ocxl_mmio_area global_mmio;
	ocxl_mmio_area per_pasid_mmio;
        uint32_t mmio_count;
        uint32_t mmio_max;
        ocxl_mmio_area mmios[4];
        uint64_t mem_base_address;
        uint8_t mem_size;
	uint16_t context;
	uint16_t map;  
	uint8_t dbg_id;
	int fd;
	int opened;
	int attached;
	int mapped;
	int global_mapped;
	int lpc_mapped;
	int lpc_special_mapped;
	int pipe[2];
        int irq_count;
	struct int_req int_req;
	struct open_req open;
	struct attach_req attach;
	struct mmio_req mmio;
	struct mem_req mem;
	struct ocxl_irq *irq;
        ocxl_ea_area *eas;
};

#endif
