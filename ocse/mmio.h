/*
 * Copyright 2014,2019 International Business Machines
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

#ifndef _MMIO_H_
#define _MMIO_H_

#include <pthread.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>

#include "ocse_t.h"
//#include "client.h"
//#include "parms.h"
//#include "ocl.h"
#include "../common/tlx_interface.h"
#include "../common/utils.h"

#define MMIO_FULL_RANGE 0x4000000
#define PSA_MASK             0x00FFFFFFFFFFFFFFL
#define PSA_REQUIRED         0x0100000000000000L
#define PROCESS_PSA_REQUIRED 0x0200000000000000L
#define FOUR_K 0x1000
#define CXL_MMIO_BIG_ENDIAN 0x1
#define CXL_MMIO_LITTLE_ENDIAN 0x2
#define CXL_MMIO_HOST_ENDIAN 0x3
#define CXL_MMIO_ENDIAN_MASK 0x3


struct mmio *mmio_init(struct AFU_EVENT *afu_event, int timeout, char *afu_name,
		       FILE * dbg_fp, uint8_t dbg_id);

int read_afu_config(struct ocl *ocl, uint8_t bus, pthread_mutex_t * lock);

struct mmio_event *add_kill_xlate_event(struct mmio *mmio, struct client *client,
				     uint64_t ea, uint8_t pg_size, uint8_t cmd_flag, uint16_t bdf,
				     uint32_t pasid);

struct mmio_event *add_mmio(struct mmio *mmio, uint32_t rnw, uint32_t dw,
			    uint64_t addr, uint64_t data);

void send_mmio(struct mmio *mmio);

//void handle_mmio_ack(struct mmio *mmio);

void handle_ap_resp(struct mmio *mmio);

void handle_ap_resp_data(struct mmio *mmio);

void handle_mmio_map(struct mmio *mmio, struct client *client);

struct mmio_event *handle_kill_xlate(struct mmio *mmio, struct client *client);

struct mmio_event *handle_mmio(struct mmio *mmio, struct client *client,
			       int rnw, int dw, int global);

struct mmio_event *handle_mmio_done(struct mmio *mmio, struct client *client);


struct mmio_event *handle_mem(struct mmio *mmio, struct client *client,
			      int rnw, int region, int be_valid);

struct mmio_event *handle_afu_amo(struct mmio *mmio, struct client *client,
			      int rnw, int region, int cmd);

struct mmio_event *handle_kill_xlate(struct mmio *mmio, struct client *client);

struct mmio_event *handle_capp_cache_cmd(struct mmio *mmio, struct client *client);

struct mmio_event *handle_force_evict(struct mmio *mmio, struct client *client);

#endif				/* _MMIO_H_ */
