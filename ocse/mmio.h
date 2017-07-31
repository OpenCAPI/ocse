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

#ifndef _MMIO_H_
#define _MMIO_H_

#include <pthread.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>

#include "client.h"
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


// need to abstract dw - add a size element
// need to allow for dl and dp - add dl and dp elements
struct mmio_event {
	uint32_t rnw;
	uint32_t dw;    // TODO remove this ?  Maybe, we need to know 4/8 byte mmio  cmd_pL is an encoded length
	uint32_t eb_rd; // TODO remove this
	uint32_t cfg;
	uint64_t cmd_data;
	uint64_t cmd_PA;
	uint16_t cmd_CAPPtag;
	uint8_t cmd_opcode;
	uint8_t cmd_pL;
	uint8_t cmd_TorR;  //may not need this
	uint8_t cmd_rd_cnt;
  // parallel records for general capp commands
        uint8_t ack;    // use this to hold the ack value for the message back to libocxl
        uint8_t be_valid;  // use this to let us know whether or not to use the byte enable
        uint32_t size;  // if size = 0, we use dw to imply size
        uint8_t *data;  // if size = 0, we use cmd_data as the data field
        uint64_t be;  // if be_valid, use this as the byte enable in the command
        uint8_t cmd_dL;     // dL, dP, and pL are encoded from either size or dw in send_mmio
        uint8_t cmd_dP;
	enum ocse_state state;
	struct mmio_event *_next;
};


struct afu_cfg_sp {
        uint16_t cr_device;
        uint16_t cr_vendor;
        uint32_t PASID_CP;
        uint32_t PASID_CTL_STS;
        uint32_t OCAPI_TL_CP;
        uint32_t OCAPI_TL_REVID;
        uint32_t OCAPI_TL_VERS;
        uint32_t OCAPI_TL_TMP_CFG;
        uint32_t OCAPI_TL_TX_RATE;
        uint32_t OCAPI_TL_MAXAFU;
        uint32_t FUNC_CFG_CP;
        uint32_t FUNC_CFG_REVID;
        uint32_t FUNC_CFG_MAXAFU;
        uint32_t AFU_INFO_CP;
        uint32_t AFU_INFO_REVID;
        uint32_t AFU_INFO_INDEX;
        uint32_t AFU_CTL_CP_0;
        uint32_t AFU_CTL_REVID_4;
        uint32_t AFU_CTL_EN_RST_INDEX_8;
        uint32_t AFU_CTL_WAKE_TERM_C;
        uint32_t AFU_CTL_PASID_LEN_10;
        uint32_t AFU_CTL_PASID_BASE_14;
        uint32_t AFU_CTL_ACTAG_LEN_EN_S;
        uint32_t AFU_CTL_ACTAG_BASE;
        uint32_t global_MMIO_offset_high;
        uint32_t global_MMIO_offset_low;
        uint32_t global_MMIO_BAR;
        uint32_t global_MMIO_size;
        uint32_t pp_MMIO_offset_high;
        uint32_t pp_MMIO_offset_low;
        uint32_t pp_MMIO_BAR;
        uint32_t pp_MMIO_stride;
	uint32_t num_ints_per_process;
	uint32_t num_of_processes;
};

struct mmio {
	struct AFU_EVENT *afu_event;
	struct afu_cfg_sp cfg;
	struct mmio_event *list;
	char *afu_name;
	FILE *dbg_fp;
	uint8_t dbg_id;
	uint32_t flags;
	int timeout;
};

struct mmio *mmio_init(struct AFU_EVENT *afu_event, int timeout, char *afu_name,
		       FILE * dbg_fp, uint8_t dbg_id);

int read_afu_config(struct mmio *mmio, pthread_mutex_t * lock);

struct mmio_event *add_mmio(struct mmio *mmio, uint32_t rnw, uint32_t dw,
			    uint64_t addr, uint64_t data);

void send_mmio(struct mmio *mmio);

void handle_mmio_ack(struct mmio *mmio, uint32_t parity_enabled);

void handle_mmio_map(struct mmio *mmio, struct client *client);

struct mmio_event *handle_mmio(struct mmio *mmio, struct client *client,
			       int rnw, int dw, int eb_rd, int global);

struct mmio_event *handle_mmio_done(struct mmio *mmio, struct client *client);


struct mmio_event *handle_mem(struct mmio *mmio, struct client *client,
			      int rnw, int region, int be_valid);

#endif				/* _MMIO_H_ */
