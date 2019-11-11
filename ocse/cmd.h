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

#ifndef _CMD_H_
#define _CMD_H_

#include <stdint.h>
#include <stdio.h>

#include "ocse_t.h"
//#include "ocl.h"
//#include "client.h"
//#include "mmio.h"
//#include "parms.h"
#include "../common/tlx_interface.h"

#define TOTAL_PAGES_CACHED 64
#define PAGE_WAYS 4
#define LOG2_WAYS 2		// log2(PAGE_WAYS) = log2(4) = 2
#define PAGE_ENTRIES (TOTAL_PAGES_CACHED / PAGE_WAYS)
#define LOG2_ENTRIES 4		// log2(PAGE_ENTRIES) = log2(64/4) = log2(16) = 4
#define PAGE_ADDR_BITS 12
#define PAGE_MASK 0xFFF
#define BAD_OPERAND_SIZE 2
#define BAD_ADDR_OFFSET 3

struct cmd *cmd_init(struct AFU_EVENT *afu_event, struct parms *parms,
		     struct mmio *mmio, volatile enum ocse_state *state,
		     char *afu_name, FILE * dbg_fp, uint8_t dbg_id);

// void handle_vc1_cmd(struct cmd *cmd,  uint32_t latency);
void handle_vc2_cmd(struct ocl *ocl, struct cmd *cmd,  uint32_t latency);
void handle_vc3_cmd(struct cmd *cmd,  uint32_t latency);

//void handle_buffer_data(struct cmd *cmd);

void handle_mem_write(struct cmd *cmd);

void handle_buffer_write(struct ocl *ocl, struct cmd *cmd);

void handle_afu_tlx_cmd_data_read(struct cmd *cmd);

void handle_afu_tlx_write_cmd(struct cmd *cmd);

void handle_castout(struct cmd *cmd, struct mmio *mmio);

void handle_upgrade_state(struct cmd *cmd);

void handle_touch(struct cmd *cmd);

void handle_sync(struct cmd *cmd);

void handle_interrupt(struct cmd *cmd);

void handle_mem_return(struct cmd *cmd, struct cmd_event *event, int fd);

void handle_ca_mem_return(struct ocl *ocl, struct cmd *cmd, struct cmd_event *cmd_event, int fd);

void handle_aerror(struct cmd *cmd, struct cmd_event *event, int fd);

void handle_response(struct cmd *cmd);

void handle_write_be_or_amo(struct cmd *cmd);

void handle_xlate_intrp_pending_sent(struct cmd *cmd);

void handle_pending_kill_xlate_sent(struct cmd *cmd);

int client_cmd(struct cmd *cmd, struct client *client);

void handle_kill_done(struct cmd *cmd, struct mmio *mmio);

#endif				/* _CMD_H_ */
