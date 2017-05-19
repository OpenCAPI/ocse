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

/*
 * Description: cmd.c
 *
 *  This file contains the code for handling commands from the AFU.  This
 *  includes parity checking the command, generating buffer writes or reads as
 *  well as the final response for the command.  The handle_cmd() function is
 *  periodically called by ocl code.  If a command is received from the AFU
 *  then parity and credits check will occur to see if the command is valid.
 *  If those checks pass then _parse_cmd() is called to determine the command
 *  type.  Depending on command type either _add_interrupt(), _add_touch(),
 *  _add_unlock(), _add_read(), _add_write() or _add_other() will be called to
 *  format the tracking event properly.  Each of these functions calls
 *  _add_cmd() which will randomly insert the command in the list.
 *
 *  Once an event is in the list then the event will be service in random order
 *  by the periodic calling by ocl code of the functions: handle_interrupt(),
 *  handle_response(), handle_buffer_write(), handle_buffer_data() and
 *  handle_touch().  The state field is used to track the progress of each
 *  event until is fully completed and removed from the list completely.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>

#include "cmd.h"
#include "mmio.h"
#include "../common/debug.h"
#include "../common/utils.h"

#define IRQ_MASK       0x00000000000007FFL
#define CACHELINE_MASK 0xFFFFFFFFFFFFFFC0L

// Initialize cmd structure for tracking AFU command activity
struct cmd *cmd_init(struct AFU_EVENT *afu_event, struct parms *parms,
		     struct mmio *mmio, volatile enum ocse_state *state,
		     char *afu_name, FILE * dbg_fp, uint8_t dbg_id)
{
	int i, j;
	struct cmd *cmd;

	cmd = (struct cmd *)calloc(1, sizeof(struct cmd));
	if (!cmd) {
		perror("malloc");
		exit(-1);
	}

	cmd->afu_event = afu_event;
	cmd->mmio = mmio;
	cmd->parms = parms;
	cmd->ocl_state = state;
	cmd->credits = parms->credits;
	cmd->pagesize = parms->pagesize;
	cmd->page_entries.page_filter = ~((uint64_t) PAGE_MASK);
	cmd->page_entries.entry_filter = 0;
	for (i = 0; i < LOG2_ENTRIES; i++) {
		cmd->page_entries.entry_filter <<= 1;
		cmd->page_entries.entry_filter += 1;
	}
	cmd->page_entries.entry_filter <<= PAGE_ADDR_BITS;
	for (i = 0; i < PAGE_ENTRIES; i++) {
		for (j = 0; j < PAGE_WAYS; j++) {
			cmd->page_entries.valid[i][j] = 0;
		}
	}
	cmd->afu_name = afu_name;
	cmd->dbg_fp = dbg_fp;
	cmd->dbg_id = dbg_id;
	return cmd;
}

// find a client that has a matching pasid and bdf.  return pointer to client
static struct client *_find_client_by_pasid_and_bdf(struct cmd *cmd, uint16_t cmd_bdf, uint32_t cmd_pasid)
{
  // search the client array in cmd for a matching pasid and bdf
  // return NULL for no matching client
  // cmd->client[i]->pasid and bdr, right?
  int32_t i;

  for (i = 0; i < cmd->max_clients; i++) {
    if (cmd->client[i] != NULL) {
      if ( ( cmd->client[i]->bdf == cmd_bdf ) && (cmd->client[i]->pasid == cmd_pasid ) ) {
	  return cmd->client[i];
      }
    }
  }
  return NULL;
}

// find a client that has a matching actag.  return pointer to client
static int32_t _find_client_by_actag(struct cmd *cmd, uint16_t cmd_actag)
{
  // search the client array in cmd for a matching pasid and bdf
  // return -1 for no matching client
  // cmd->client[i]->pasid and bdr, right?
  int32_t i;

  for (i = 0; i < cmd->max_clients; i++) {
    if (cmd->client[i] != NULL) {
      if ( cmd->client[i]->actag == cmd_actag ) {
	  return i;
      }
    }
  }
  return -1;
}

static void _print_event(struct cmd_event *event)
{
	printf("Command event: client=");
	switch (event->state) {
	case CLIENT_VALID:
		printf("VALID ");
		break;
	default:
		printf("NONE ");
	}
	switch (event->type) {
	case CMD_READ:
		printf("READ");
		break;
	case CMD_WRITE:
		printf("WRITE");
		break;
	case CMD_TOUCH:
		printf("TOUCH");
		break;
	case CMD_INTERRUPT:
		printf("INTERRUPT");
		break;
	default:
		printf("OTHER");
	}
	printf(" tag=%02x", event->tag);
	printf(" context=%d", event->context);
	printf(" addr=0x%016" PRIx64 "\n\t", event->addr);
	printf(" size=0x%x", event->size);
	printf(" state=");
	switch (event->state) {
	case MEM_TOUCH:
		printf("TOUCH");
		break;
	case MEM_TOUCHED:
		printf("TOUCHED");
		break;
	case MEM_BUFFER:
		printf("BUFFER");
		break;
	case MEM_REQUEST:
		printf("REQUEST");
		break;
	case MEM_RECEIVED:
		printf("RECEIVED");
		break;
	case MEM_DONE:
		printf("DONE");
		break;
	default:
		printf("IDLE");
	}
//	printf(" Resp=0x%x Unlock=%d Restart=%d\n", event->resp,
//	       event->unlock, (event->command == TLX_COMMAND_RESTART));
}

// Update all pending responses at once to new state
static void _update_pending_resps(struct cmd *cmd, uint32_t resp)
{
	struct cmd_event *event;
	event = cmd->list;
	while (event) {
		if (event->state == MEM_IDLE) {
			event->state = MEM_DONE;
			event->resp = resp;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
					 event->context, event->resp);
		}
		event = event->_next;
	}
}

static struct client *_get_client(struct cmd *cmd, struct cmd_event *event)
{
	// Make sure cmd and client are still valid
	if ((cmd == NULL) || (cmd->client == NULL) ||
	    (event->context >= cmd->max_clients))
		return NULL;

	// Abort if client disconnected
	if (cmd->client[event->context] == NULL) {
		event->resp = TLX_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
	}
	return cmd->client[event->context];
}

// Add new command to list
static void _add_cmd(struct cmd *cmd, uint32_t context, uint32_t afutag,
		     uint32_t command, enum cmd_type type,
		     uint64_t addr, uint16_t size, enum mem_state state,
		     uint32_t resp, uint8_t unlock , uint8_t cmd_data_is_valid)

{
	struct cmd_event **head;
	struct cmd_event *event;

	if (cmd == NULL)
		return;
	event = (struct cmd_event *)calloc(1, sizeof(struct cmd_event));
	event->context = context;
	event->command = command;
	event->tag = 0; // remove this someday...
	event->afutag = afutag;
	event->type = type;
	event->addr = addr;
	event->size = size;
	event->state = state;
	event->resp = resp;
	// Temporary hack for now, as we don't touch/look @ TLX_SPAP reg
	if (event->resp == TLX_RESPONSE_CONTEXT)
		event->resp_extra = 1;
	else
		event->resp_extra = 0;
	event->unlock = unlock;
	// make sure data buffer is big enough to hold 256B (MAX memory transfer for OpenCAPI 3.0)
	event->data = (uint8_t *) malloc(CACHELINE_BYTES * 4);
	memset(event->data, 0xFF, CACHELINE_BYTES * 4);
	// lgt may not need cpl xfers to go and parity
	event->cpl_xfers_to_go = 0;  //init this to 0 (used for DMA read multi completion flow)
	event->parity = (uint8_t *) malloc(DWORDS_PER_CACHELINE / 8);
	memset(event->parity, 0xFF, DWORDS_PER_CACHELINE / 8);

	// Test for client disconnect
	if (_get_client(cmd, event) == NULL) {
		event->resp = TLX_RESPONSE_FAILED;
		event->state = MEM_DONE;
	}

	head = &(cmd->list);
	while ((*head != NULL) && !allow_reorder(cmd->parms))
		head = &((*head)->_next);
	event->_next = *head;
	*head = event;
	debug_msg("_add_cmd:created cmd_event @ 0x%016"PRIx64":command=0x%02x, size=0x%04x, type=0x%02x, tag=0x%04x, state=0x%03x", event, event->command, event->size, event->type, event->afutag, event->state );
	debug_cmd_add(cmd->dbg_fp, cmd->dbg_id, afutag, context, command);
	// Check to see if event->cmd_data_is_valid is, and if so, set event->buffer_data
	// TODO check to see if data is bad...if so, what???
	if (cmd_data_is_valid) {
		cmd->buffer_read = event;
		printf("Getting ready to copy first chunk of write data to buffer....and size=0x%x .\n", size);
		if (size > 64) {
			memcpy((void *)&(event->data[0]), (void *)&(cmd->afu_event->afu_tlx_cdata_bus), 64);
			event->dpartial +=64;
			event->state = MEM_BUFFER;
		 }
		else  {
			memcpy((void *)&(event->data[0]), (void *)&(cmd->afu_event->afu_tlx_cdata_bus), size);
			event->state = MEM_RECEIVED;
			}
	
	}

}

// Format and add interrupt to command list
/* static void _add_interrupt(struct cmd *cmd, uint32_t handle, uint32_t tag, */
/* 			   uint32_t command, uint32_t abort, uint16_t irq) */
/* { */
/* 	uint32_t resp = TLX_RESPONSE_DONE; */
/* 	enum cmd_type type = CMD_INTERRUPT; */

/* 	if (!irq || (irq > cmd->client[handle]->max_irqs)) { */
/* 		warn_msg("AFU issued interrupt with illegal source id"); */
/* 		resp = TLX_RESPONSE_FAILED; */
/* 		type = CMD_OTHER; */
/* 		goto int_done; */
/* 	} */
/* 	// Only track first interrupt until software reads event */
/* 	if (!cmd->irq) */
/* 		cmd->irq = irq; */
/*  int_done: */
/* 	_add_cmd(cmd, handle, tag, command, abort, type, (uint64_t) irq, 0, */
/* 		 MEM_IDLE, resp, 0); */
/* } */

// Format and add misc. command to list
static void _add_other(struct cmd *cmd, uint16_t actag, uint32_t afutag,
		       uint32_t cmd_opcode, uint32_t resp)
{
        int32_t context;
 
        context = _find_client_by_actag(cmd, actag);
	_add_cmd(cmd, context, afutag, cmd_opcode, CMD_OTHER, 0, 0, MEM_DONE,
		 resp, 0, 0);
}

// Check address alignment
static int _aligned(uint64_t addr, uint32_t size)
{
	// Check valid size
        // that is, size must be a power of 2
	if ((size == 0) || (size & (size - 1))) {
		warn_msg("AFU issued command with invalid size %d", size);
		return 0;
	}
	// Check aligned address
	if (addr & (size - 1)) {
		warn_msg("AFU issued command with unaligned address %016"
			 PRIx64, addr);
		return 0;
	}

	return 1;
}


// Format and add new p9 commands to list

/* static void _add_caia2(struct cmd *cmd, uint32_t handle, uint32_t tag, */
/* 		       uint32_t command, uint32_t abort, uint64_t addr) */
/* { */
/* 	uint32_t resp = TLX_RESPONSE_DONE; */
/* 	enum cmd_type type = CMD_CAIA2; */
/* 	enum mem_state state = MEM_DONE; */

/* /\* 	switch (command) { */
/* 		case TLX_COMMAND_CAS_E_4B: */
/* 		case TLX_COMMAND_CAS_NE_4B: */
/* 		case TLX_COMMAND_CAS_U_4B: */
/* 			//printf("in _add_caia2 for cmd_CAS 4B, address is 0x%016"PRIX64 "\n", addr); */
/* 			// Check command size and address */
/* 			if (!_aligned(addr, 16)) { */
/* 				_add_other(cmd, handle, tag, command, abort, */
/* 			  	 TLX_RESPONSE_FAILED); */
/* 			return; */
/* 			} */
/* 			type = CMD_CAS_4B; */
/* 			state = MEM_IDLE; */
/* 			break; */
/* 		case TLX_COMMAND_CAS_E_8B: */
/* 		case TLX_COMMAND_CAS_NE_8B: */
/* 		case TLX_COMMAND_CAS_U_8B: */
/* 			//printf("in _add_caia2 for cmd_CAS 8B, address is 0x%016"PRIX64 "\n", addr); */
/* 			// Check command size and address */
/* 			if (!_aligned(addr,16)) { */
/* 			_add_other(cmd, handle, tag, command, abort, */
/* 			   	TLX_RESPONSE_FAILED); */
/* 			return; */
/* 			} */
/* 			type = CMD_CAS_8B; */
/* 			state = MEM_IDLE; */
/* 			break; */
/* 		case TLX_COMMAND_XLAT_RD_P0: */
/* 	rc =  afu_tlx_read_cmd_and_data(cmd->afu_event, */
/*   		    &cmd_opcode, &cmd_actag, */
/*   		    &cmd_stream_id, &cmd_ea_or_obj, */
/*  		    &cmd_afutag, &cmd_dl, */
/*   		    &cmd_pl, */
/* #ifdef TLX4 */
/* 		    &cmd_os, */
/* #endif */
/* 		    &cmd_be, &cmd_flag, */
/*  		    &cmd_endian, &cmd_bdf, */
/*   	  	    &cmd_pasid, &cmd_pg_size, &cmd_data_is_valid, */
/*  		    dptr, &cdata_bad); */
/* 			type = CMD_XLAT_RD; */
/* 			state = DMA_ITAG_REQ; */
/* 			break; */
/* 		case TLX_COMMAND_XLAT_WR_P0: */
/* 			type = CMD_XLAT_WR; */
/* 			state = DMA_ITAG_REQ; */
/* 			break; */
/* 		case TLX_COMMAND_XLAT_RD_TOUCH: */
/* 			type = CMD_XLAT_RD_TOUCH; */
/* 			//state = DMA_ITAG_REQ; */
/* 			state = MEM_IDLE; */
/* 			break; */
/* 		case TLX_COMMAND_XLAT_WR_TOUCH: */
/* 			type = CMD_XLAT_WR_TOUCH; */
/* 			//state = DMA_ITAG_REQ; */
/* 			state = MEM_IDLE; */
/* 			break; */
/* 		case TLX_COMMAND_ITAG_ABRT_RD: */
/* 			type = CMD_ITAG_ABRT_RD; */
/* 			state = DMA_ITAG_REQ; */
/* 			break; */
/* 		case TLX_COMMAND_ITAG_ABRT_WR: */
/* 			type = CMD_ITAG_ABRT_WR; */
/* 			state = DMA_ITAG_REQ; */
/* 			break; */
/* 		default: */
/* 			warn_msg("Unsupported command 0x%04x", cmd); */
/* 			break; */

/* 	} *\/ */
/* 	_add_cmd(cmd, handle, tag, command, abort, type, addr, 0, state, */
/* 		 resp, 0 ); */
/* } */

// Format and add memory touch to command list
/* static void _add_touch(struct cmd *cmd, uint32_t handle, uint32_t tag, */
/* 		       uint32_t command, uint32_t abort, uint64_t addr, */
/* 		       uint32_t size, uint8_t unlock) */
/* { */
/* 	// Check command size and address */
/* 	if (!_aligned(addr, size)) { */
/* 		_add_other(cmd, handle, tag, command, abort, */
/* 			   TLX_RESPONSE_FAILED); */
/* 		return; */
/* 	} */
/* 	_add_cmd(cmd, handle, tag, command, abort, CMD_TOUCH, addr, */
/* 		 CACHELINE_BYTES, MEM_IDLE, TLX_RESPONSE_DONE, unlock); */
/* } */

// Format and add unlock to command list
/* static void _add_unlock(struct cmd *cmd, uint32_t handle, uint32_t tag, */
/* 			uint32_t command, uint32_t abort) */
/* { */
/* 	_add_cmd(cmd, handle, tag, command, abort, CMD_OTHER, 0, 0, MEM_DONE, */
/* 		 TLX_RESPONSE_DONE, 0); */
/* } */

// format a read_pe command and add it to the command list
/* static void _add_read_pe(struct cmd *cmd, uint32_t handle, uint32_t tag, */
/* 		      uint32_t command, uint32_t abort, uint64_t addr, */
/* 		      uint32_t size) */
/* { */
/*         // ultimately, this generates a return on the write buffer interface of the cacheline representing the pe */
/*         // pe struct is basically all 0 except for WED */
/*         // what parms does read_pe really need? */
/*         // maybe only the handle and the tag */
/*         // Check command size and address - not used in read_pe */
/* 	// if (!_aligned(addr, size)) { */
/* 	// 	_add_other(cmd, handle, tag, command, abort, */
/* 	//		   TLX_RESPONSE_FAILED); */
/* 	//	return; */
/* 	// } */
/* 	// Reads will be added to the list and will next be processed */
/* 	// in the function handle_buffer_write() */
/* 	// should this just call handle_buffer_write_pe??? */
/*         //printf( "in _add_read_pe \n" ); */
/* 	_add_cmd(cmd, handle, tag, command, abort, CMD_READ_PE, addr, size, */
/* 		 MEM_IDLE, TLX_RESPONSE_DONE, 0); */
/* } */

// Format and add memory read to command list
static void _assign_actag(struct cmd *cmd, uint16_t cmd_bdf, uint32_t cmd_pasid, uint16_t actag)
{
  struct client *client;
  // search the client array in cmd for a matching pasid and bdf.  fill in the actag field.
  client = _find_client_by_pasid_and_bdf(cmd, cmd_bdf, cmd_pasid);
  if (client == NULL) {
    // some kind of error and return...  no way to respond to afu, so just a message???
    return;
  }
  client->actag = actag;
  return;
}

// Format and add memory read to command list
static void _add_read(struct cmd *cmd, uint16_t actag, uint16_t afutag,
		      uint8_t cmd_opcode, uint8_t *cmd_ea_or_obj, uint32_t size)
{
        int32_t context;
        int64_t addr;
 
        // convert 68 bit ea/obj to 64 bit addr
        // for ap read commands, ea_or_obj is a 64 bit thing...
        memcpy( (void *)&addr, (void *)&(cmd_ea_or_obj[0]), sizeof(int64_t));

	// Check command size and address
	if (!_aligned(addr, size)) {
	  _add_other(cmd, actag, afutag, cmd_opcode,
			   TLX_RESPONSE_FAILED);
		return;
	}

        // convert actag to a context - search the client array contained in cmd for a client with matching actag
	context = _find_client_by_actag(cmd, actag);

	// Reads will be added to the list and will next be processed
	// in the function handle_buffer_write()
	_add_cmd(cmd, context, afutag, cmd_opcode, CMD_READ, addr, size,
		 MEM_IDLE, TLX_RESPONSE_DONE, 0, 0);
}

// Format and add memory write to command list
static void _add_write(struct cmd *cmd, uint16_t actag, uint16_t afutag,
		      uint8_t cmd_opcode, uint8_t *cmd_ea_or_obj, uint32_t size, uint8_t cmd_data_is_valid)
{
        int32_t context;
        int64_t addr;
 
        // convert 68 bit ea/obj to 64 bit addr
        // for ap write commands, ea_or_obj is a 64 bit thing...
        memcpy( (void *)&addr, (void *)&(cmd_ea_or_obj[0]), sizeof(int64_t));


	// Check command size and address
	if (!_aligned(addr, size)) {
	  _add_other(cmd, actag, afutag, cmd_opcode,
			   TLX_RESPONSE_FAILED);
		return;
	}

	// Also need to check with libocxl to be sure the address AFU sent us is in user's space
	// TODO create new OCSE_ADDR_VALID cmd, send to lib0cxl, set status to MEM_CHECK and 
	// wait for response.
	//

        // convert actag to a context - search the client array contained in cmd for a client with matching actag
	context = _find_client_by_actag(cmd, actag);

	// Command data comes over with the command, so now we need to read it from event and put it in buffer??
	// Then, next step is to make the memory write request?
	
	// Writes will be added to the list and will next be processed
	// in the function handle_buffer_read(), now known as handle_afu_tlx_cmd_data_read
	 
	_add_cmd(cmd, context, afutag, cmd_opcode, CMD_WRITE, addr, size,
		 MEM_IDLE, TLX_RESPONSE_DONE, 0, cmd_data_is_valid);
	printf("MADE IT BACK FROM ADD CMD IN ADD WRITE !\n");
}

/* static void _add_write(struct cmd *cmd, uint32_t handle, uint32_t tag, */
/* 		       uint32_t command, uint32_t abort, uint64_t addr, */
/* 		       uint32_t size, uint8_t unlock) */
/* { */
/* 	// Check command size and address */
/* 	if (!_aligned(addr, size)) { */
/* 		_add_other(cmd, handle, tag, command, abort, */
/* 			   TLX_RESPONSE_FAILED); */
/* 		return; */
/* 	} */
/* 	// Writes will be added to the list and will next be processed */
/* 	// in the function handle_touch() */
/* 	_add_cmd(cmd, handle, tag, command, abort, CMD_WRITE, addr, size, */
/* 		 MEM_IDLE, TLX_RESPONSE_DONE, unlock); */
/* } */

// Determine what type of command to add to list
static void _parse_cmd(struct cmd *cmd,
		       uint8_t cmd_opcode, uint16_t cmd_actag,
		       uint8_t cmd_stream_id, uint8_t *cmd_ea_or_obj,
		       uint16_t cmd_afutag, uint8_t cmd_dl,
		       uint8_t cmd_pl,
#ifdef TLX4
		       uint8_t cmd_os,
#endif
		       uint64_t cmd_be, uint8_t cmd_flag,
		       uint8_t cmd_endian, uint16_t cmd_bdf,
		       uint32_t cmd_pasid, uint8_t cmd_pg_size, uint8_t cmd_data_is_valid,
		       uint8_t *cdata_bus, uint8_t cdata_bad)
{
	//uint16_t irq = (uint16_t) (addr & IRQ_MASK);
	//uint8_t unlock = 0;
	// TODO FIX THIS WHEN WE DETERMINE #OF CONTEXTS
	//if (handle >= cmd->mmio->cfg.num_of_processes) {
	//	_add_other(cmd, handle, tag, command, abort,
	//		   TLX_RESPONSE_CONTEXT);
	//	return;
	//}
 
        // how do we model stream_id?

        // Based on the cmd_opcode we have received from the afu, add a cmd_event to the list associated with our cmd struct
	switch (cmd_opcode) {
		// assign actag to map an actag to a pasid/bdf (a context for us)
	case AFU_CMD_ASSIGN_ACTAG:
		printf("YES! AFU cmd is ASSIGN_ACTAG!!!!\n");
                _assign_actag( cmd, cmd_bdf, cmd_pasid, cmd_actag );
		break;
		// Memory Reads
	case AFU_CMD_RD_WNITC:
	case AFU_CMD_RD_WNITC_N:
		printf("YES! AFU cmd is some sort of read!!!!\n");
		// calculate size from dl
		_add_read(cmd, cmd_actag, cmd_afutag, cmd_opcode, cmd_ea_or_obj, dl_to_size( cmd_dl ));
		break;
	case AFU_CMD_PR_RD_WNITC:
	case AFU_CMD_PR_RD_WNITC_N:
		printf("YES! AFU cmd is some sort of read!!!!\n");
		// calculate size from pl
		_add_read(cmd, cmd_actag, cmd_afutag, cmd_opcode, cmd_ea_or_obj, pl_to_size( cmd_pl ));
		break;
		// Memory Writes
	case AFU_CMD_DMA_W:
	case AFU_CMD_DMA_W_N:
		printf("YES! AFU cmd is some sort of write!!!!\n");
		_add_write(cmd, cmd_actag, cmd_afutag, cmd_opcode, cmd_ea_or_obj, dl_to_size(cmd_dl), cmd_data_is_valid);
		break;
	case AFU_CMD_DMA_PR_W:
	case AFU_CMD_DMA_PR_W_N:
		printf("YES! AFU cmd is some sort of write!!!!\n");
		_add_write(cmd, cmd_actag, cmd_afutag, cmd_opcode, cmd_ea_or_obj, pl_to_size( cmd_pl), cmd_data_is_valid);
		break;
		// Memory Writes with Byte Enable - Let's deal with this later.....
	//case AFU_CMD_DMA_W_BE;
	//case AFU_CMD_DMA_W_BE_N;
	//	printf("YES! AFU cmd is some sort of write w/BE!!!!\n");
	//	_add_write_be(cmd, cmd_actag, cmd_afutag, cmd_opcode, cmd_ea_or_obj, cmd_be, cmd_data_is_valid);
	//	break;
	/*		// Interrupt
	case TLX_COMMAND_INTREQ:
		_add_interrupt(cmd, handle, tag, command, abort, irq);
		break;
		// Restart
	case TLX_COMMAND_RESTART:
		_add_other(cmd, handle, tag, command, abort, TLX_RESPONSE_DONE);
		break;
		// Cacheline lock
	case TLX_COMMAND_LOCK:
		_update_pending_resps(cmd, TLX_RESPONSE_NLOCK);
		cmd->locked = 1;
		cmd->lock_addr = addr & CACHELINE_MASK;
		_add_touch(cmd, handle, tag, command, abort, addr, size, 0);
		break;
		// Memory Reads
	case TLX_COMMAND_READ_CL_LCK:
		_update_pending_resps(cmd, TLX_RESPONSE_NLOCK);
		_update_pending_resps(cmd, TLX_RESPONSE_NLOCK);
		cmd->locked = 1;
		cmd->lock_addr = addr & CACHELINE_MASK;
	case TLX_COMMAND_READ_CL_RES:
		if (!cmd->locked)
		cmd->res_addr = addr & CACHELINE_MASK;
		// Cacheline unlock
	case TLX_COMMAND_UNLOCK:
		_add_unlock(cmd, handle, tag, command, abort);
		break;
		// Memory Writes
	case TLX_COMMAND_WRITE_UNLOCK:
		unlock = 1;
	case TLX_COMMAND_WRITE_C:
		if (!unlock)
			cmd->res_addr = 0L;
	case TLX_COMMAND_WRITE_MI:
	case TLX_COMMAND_WRITE_MS:
	case TLX_COMMAND_WRITE_INJ:
		if (!(latency % 2) || (latency > 3))
			error_msg("Write with invalid br_lat=%d", latency);
		_add_write(cmd, handle, tag, command, abort, addr, size,
			   unlock);
		break;
		// Treat these as memory touch to test for valid addresses
	case TLX_COMMAND_EVICT_I:
		if (cmd->locked && cmd->res_addr) {
			_add_other(cmd, handle, tag, command, abort,
				   TLX_RESPONSE_NRES);
			break;
		}
	case TLX_COMMAND_PUSH_I:
	case TLX_COMMAND_PUSH_S:
		if (cmd->locked) {
			_add_other(cmd, handle, tag, command, abort,
				   TLX_RESPONSE_NLOCK);
			break;
		}
	case TLX_COMMAND_TOUCH_I:
	case TLX_COMMAND_TOUCH_S:
	case TLX_COMMAND_TOUCH_M:
	case TLX_COMMAND_FLUSH:
		_add_touch(cmd, handle, tag, command, abort, addr, size,
			   unlock);
		break;
	case TLX_COMMAND_READ_PE:	/
		_add_read_pe(cmd, handle, tag, command, abort, addr, size);
		break;
	case TLX_COMMAND_CAS_E_4B:
	case TLX_COMMAND_CAS_NE_4B:
	case TLX_COMMAND_CAS_U_4B:
	case TLX_COMMAND_CAS_E_8B:
	case TLX_COMMAND_CAS_NE_8B:
	case TLX_COMMAND_CAS_U_8B:
	case TLX_COMMAND_XLAT_RD_P0:
	case TLX_COMMAND_XLAT_WR_P0:
	case TLX_COMMAND_XLAT_RD_TOUCH:
	case TLX_COMMAND_XLAT_WR_TOUCH:
	case TLX_COMMAND_ITAG_ABRT_RD:
	case TLX_COMMAND_ITAG_ABRT_WR:
		_add_caia2(cmd, handle, tag, command, abort,addr);
		break; */
	default:
		warn_msg("Unsupported command 0x%04x", cmd);
		_add_other(cmd, cmd_actag, cmd_afutag, cmd_opcode, TLX_RESPONSE_FAILED);
		break;
	}
}

// Report parity error on some command bus
static void _cmd_parity_error(const char *msg, uint64_t value, uint8_t parity)
{
	error_msg("Command %s parity error 0x%04" PRIx64 ",%d", msg, value,
		  parity);
}

// See if a command was sent by AFU and process if so
void handle_cmd(struct cmd *cmd, uint32_t latency)
{
	struct cmd_event *event;
	uint64_t cmd_be;
	uint32_t cmd_pasid, command, size, abort, handle;
	uint16_t cmd_actag, cmd_afutag, cmd_bdf;
	uint8_t  cmd_ea_or_obj[9]; 
	uint8_t  cmd_opcode, cmd_stream_id, cmd_dl, cmd_pl, cmd_flag, cmd_endian, cmd_pg_size, cmd_data_is_valid, cdata_bad, fail;
#ifdef TLX4
	uint8_t cmd_os;
#endif
	unsigned char cdata_bus[64];
	uint8_t * dptr = cdata_bus;
	int rc;

	if (cmd == NULL)
		return;

	// Check for command from AFU
	// maybe read command and data separately to facilitate the parse_cmd and handle_buffer_data separation a 
	// little bit later in this routine
	rc =  afu_tlx_read_cmd_and_data(cmd->afu_event,
  		    &cmd_opcode, &cmd_actag,
  		    &cmd_stream_id, &cmd_ea_or_obj[0],
 		    &cmd_afutag, &cmd_dl,
  		    &cmd_pl,
#ifdef TLX4
		    &cmd_os,
#endif
		    &cmd_be, &cmd_flag,
 		    &cmd_endian, &cmd_bdf,
  	  	    &cmd_pasid, &cmd_pg_size, &cmd_data_is_valid,
 		    dptr, &cdata_bad);


	//rc = tlx_get_command(cmd->afu_event, &command, &command_parity, &tag,
	//		     &tag_parity, &address, &address_parity, &size,
	//		     &abort, &handle, &cpagesize

	// No command ready */
	if (rc != TLX_SUCCESS) 
		return;

	debug_msg("%s:COMMAND actag=0x%02x afutag=0x%04x cmd=0x%x BDF=0x%x addr=0x%016"PRIx64 " cmd_data_is_valid= 0x%x ", cmd->afu_name,
		  cmd_actag, cmd_afutag, cmd_opcode, cmd_bdf, cmd_pasid, cmd_data_is_valid);

	// Is AFU running?
/*	if (*(cmd->ocl_state) != OCSE_RUNNING) {
		//warn_msg("Command without jrunning, tag=0x%02x", tag);
		error_msg("Command without jrunning, tag=0x%02x", tag);
		return;
	} */

	// Check credits and parse - not any more

	// Client not connected - some of this we don't know until a bit later...
	//if ((cmd == NULL) || (cmd->client == NULL) ||
	//   (handle >= cmd->max_clients) || ((cmd->client[handle]) == NULL)) {
	//	_add_other(cmd_opcode, handle, tag, command, abort,
	//		   TLX_RESPONSE_FAILED);
	//	return;
	//}

	// Client is flushing new commands - do we still do this??
	//if ((cmd->client[handle]->flushing == FLUSH_FLUSHING) &&
	//    (command != TLX_COMMAND_RESTART)) {
	//	_add_other(cmd, handle, tag, command, abort,
	//		   TLX_RESPONSE_FLUSHED);
	//	return;
	//}

	// Check for duplicate afutag - not now, maybe check for dup actag at some point??
	event = cmd->list;
	while (event != NULL) {
		if (event->afutag == cmd_afutag) {
			error_msg("Duplicate afutag 0x%04x", cmd_afutag);
			return;
		}
		event = event->_next;
	}

	// Parse command- 	//
	// should we add a "parse_data" routine?  Perhaps reuse handle_buffer_data...
	// the idea would be that we call parse cmd only if the command was valid
	// then, we would call parse data if data is valid
	// parse_data would search the cmd event list that is waiting for data
	// how does it know?  dl and pl can be used to calculate the number of beats (including this one) 
	// required to get all the data.  parse cmd set a state (DATA_PENDING) and a beat count
	// parse data would find the DATA_PENDING, append the data to the data buffer and decrement the beat count
	// once all the data is in, parse data would set the state to something else (MEM_RECEIVED) to trigger the 
	// OCSE_MEMORY_WRITE message.  
	// parse data sounds a little bit like handle_buffer_read sort of...  Actually, more like handle_buffer_data
	// Did we have a state for collecting data from the buffer read interface before?  
	// we could reuse that.  MEM_BUFFER was the interim state.
	_parse_cmd(cmd, cmd_opcode, cmd_actag, cmd_stream_id, cmd_ea_or_obj, cmd_afutag, cmd_dl, cmd_pl,
#ifdef TLX4
		   cmd_os,
#endif
		   cmd_be, cmd_flag, cmd_endian, cmd_bdf, cmd_pasid, cmd_pg_size, cmd_data_is_valid, dptr, cdata_bad);
}

// Handle randomly selected pending read by either generating early buffer
// write with bogus data, send request to client for real data or do final
// buffer write with valid data after it has been received from client.
// lgt:  in opencapi, we don't really have a separate buffer write.  Instead,
// when get the data back from the host, we just send it with the response.
// should we defer some of this to handle_response?  Or should we process
// the data and response here and also free the event?
void handle_buffer_write(struct cmd *cmd)
{
	struct cmd_event *event;
	struct client *client;
	uint8_t buffer[11];  // 1 message byte + 2 size bytes + 8 address bytes
	uint64_t *addr;
	uint16_t *size;
	//int quadrant, byte;

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	//printf( "handle_buffer_write \n" );
	// Randomly select a pending read or read_pe (or none)
	// for now, make sure allow_reorder_parms is not allowed.
	// lgt: if we want to free the cmd event later, we should find the event with the same method as handle_response...
	// lgt: decided to put the call to tlx_afu_send_resp_and_data in the handle_response routine since it will also free the cmd event
	//      so here we just set MEM_DONE and TLX_RESPONSE_DONE for the event that we selected
	event = cmd->list;
	while ( event != NULL ) {
	        if ( ( event->type == CMD_READ ) &&
		     ( event->state != MEM_DONE ) &&
		     ( ( event->client_state != CLIENT_VALID ) ) ) { // || ( !allow_reorder( cmd->parms ) ) ) ) {
			break;
		}
	        /* if ( ( ( event->type == CMD_CAS_4B ) || ( event->type == CMD_CAS_8B ) ) && */
		/*      ( event->state == MEM_CAS_RD ) && */
		/*      ( ( event->client_state != CLIENT_VALID ) || */
		/*        !allow_reorder( cmd->parms ) ) ) { */
		/* 	break; */
		/* } */
		event = event->_next;
	}

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	printf( "handle_buffer_write: we've picked a non-NULL event and the client is still there \n" );

	// after the client returns data with a call to the function _handle_mem_read,
	// we need to generate one or more capp responses.  We need to chunk data into 64 byte pieces
	// to honor the txl/afu interface.
	// in ocse, we will always send responses with all the data appropriate for the response we generate
	// see handle_response
	// for partial read, we can probabaly just return data as we have already inserted the data into 
	// the appropriate place in the event->data buffer
	// for "full" reads, we need to chunk data
	// use tlx_afu_send_resp_and_data, for each 64B chunk - look at the old pslse dma code...
	// concerns
	//    chunk spacing
	//    interleaving
	//    and so on.
	if ((event->state == MEM_RECEIVED) && ((event->type == CMD_READ) || (event->type == CMD_READ_PE))) {
	  if ( (event->command == AFU_CMD_PR_RD_WNITC) || (event->command == AFU_CMD_PR_RD_WNITC_N) ) {
	    // we can just complete the event and let handle_response send the response and 64 bytes of data back
	    event->resp = TLX_RESPONSE_DONE;
	    event->state = MEM_DONE;
	  } else if ( (event->command == AFU_CMD_RD_WNITC) || (event->command == AFU_CMD_RD_WNITC_N) ) {
	    // we need to send back 1 or more 64B response
	    // we can:
	    //    send a complete response, with all the data
	    //    send partial responses, in any order, with aligned partial data (vary dl and dp in the response
	    //       power will likely send back chunks in <= 128 B responses...
	    //    responses can come back in any order
	    // I'm thinking ocse decides what response to send and whether or not to split it. 
	    // and sends all the data associated with the selected response.
	    // then tlx_interface/afu_driver forward the response portion and hold the data in a fifo linked list of 64 B values.
	    // then when the afu does a resp_rd_req of some resp_rd_cnt, tlx_interaface/afu_driver just starts pumping values out of the 
	    // fifo.  This method actually works for partial read as well as the minimum size of a split response is 64 B.
	    // it is the afu's responsiblity to manage resp_rd_cnt correctly, and this is not information for us to check
	    // anything other than an overrun (i.e. resp_rd_req of an empty fifo, or resp_rd_cnt exceeds the amount of data in the fifo)
	      event->resp = TLX_RESPONSE_DONE;
	      event->state = MEM_DONE;
          } else {
	    // unsupport read command message
	  }
	}

                if (event->state == MEM_CAS_RD) {
		  buffer[0] = (uint8_t) OCSE_MEMORY_READ;
		  // buffer[1] = (uint8_t) event->size;  // size now consumes 2 bytes
		  size = (uint16_t *)&(buffer[1]);
		  *size = htons(event->size);
		  addr = (uint64_t *) & (buffer[3]);
		  *addr = htonll(event->addr);
		  event->abort = &(client->abort);
		  debug_msg("%s:MEMORY READ FOR CAS afutag=0x%02x size=%d addr=0x%016"PRIx64,
			    cmd->afu_name, event->afutag, event->size, event->addr);
		  if (put_bytes(client->fd, 10, buffer, cmd->dbg_fp,
				cmd->dbg_id, event->context) < 0) {
		    client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		  }
		  event->state = MEM_REQUEST;
		  client->mem_access = (void *)event;
		  return; //exit immediately
		}

	if (event->state != MEM_IDLE)
		return;

	// lgt removed code that would send bogus data to the afu.  doesn't happen in opencapi

	if (client->mem_access == NULL) {
	        // if read:
		// Send read request to client, set client->mem_access
		// to point to this event blocking any other memory
		// accesses to client until data is returned by call
		// to the _handle_mem_read() function.
	        // if read_pe:
		// build data and parity to represent pe
	        // set event->state to mem_received
                if (event->type == CMD_READ) {
		  buffer[0] = (uint8_t) OCSE_MEMORY_READ;
		  // buffer[1] = (uint8_t) event->size;  // size now consumes 2 bytes
		  // addr = (uint64_t *) & (buffer[2]);
		  size = (uint16_t *)&(buffer[1]);
		  *size = htons(event->size);
		  addr = (uint64_t *) & (buffer[3]);
		  *addr = htonll(event->addr);
		  event->abort = &(client->abort);
		  debug_msg("%s:MEMORY READ afutag=0x%04x size=%d addr=0x%016"PRIx64,
			    cmd->afu_name, event->afutag, event->size, event->addr);
		  if (put_bytes(client->fd, 11, buffer, cmd->dbg_fp,
				cmd->dbg_id, event->context) < 0) {
		    client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		  }
		  event->state = MEM_REQUEST;
		  debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->afutag,
				   event->context);
		  client->mem_access = (void *)event;
		}
		// lgt remove read_pe command code - no such command in opencapi
	}
}

// Handle pending write data from AFU
void handle_afu_tlx_cmd_data_read(struct cmd *cmd)
{
	struct cmd_event *event;
	struct client *client;
	uint64_t *addr;
	unsigned char cdata_bus[64];
	uint8_t * dptr = cdata_bus;
	uint8_t cmd_data_is_valid, cdata_bad;
	uint8_t *buffer;
	int rc;

	// Check that cmd struct is valid buffer read is available
	if ((cmd == NULL) || (cmd->buffer_read == NULL))
		return;
	printf("IN handle_afu_tlx_cmd_data \n");
	//First, let's look to see if any one is in MEM_BUFFER state...data still coming over the interface (should only be ONE @time)
	// or if anyone is in MEM_RECEIVED...all data is here & ready to go (should only be ONE of these @time)
	event = cmd->list;
	while (event != NULL) {
		if ((event->type == CMD_WRITE) && 
			((event->state == MEM_RECEIVED) || (event->state == MEM_BUFFER))) { 
 	printf("Here in handle_afu_tlx_cmd_data_read  and we have a write cmd to process\n");
		   // (event->state == MEM_TOUCHED) &&
		   // ((event->client_state != CLIENT_VALID) ||
		   //  !allow_reorder(cmd->parms))) {
			break;
		}
		//Randomly select a pending CAS (or none)
	/*	if (((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) &&
		    (event->state == MEM_IDLE) &&
		    ((event->client_state != CLIENT_VALID) ||
		     !allow_reorder(cmd->parms))) {
			//printf("sending buffer read request for CAS smd \n");
			break;
		} */
		event = event->_next;
	}

	// Test for client disconnect
	//if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
	if (event == NULL) 
		return;
	if (event->state == MEM_BUFFER) {
	rc = afu_tlx_read_cmd_data(cmd->afu_event, &cmd_data_is_valid, dptr,  &cdata_bad);
	if (rc == TLX_SUCCESS) {
		if (cmd_data_is_valid) {
			debug_msg("Ready to copy another chunk of write data to buffer....and total read so far=0x%x .\n", event->dpartial);
			if ((event->size - event->dpartial) > 64) {
				memcpy((void *)&(event->data[event->size - event->dpartial]), (void *)&(cmd->afu_event->afu_tlx_cdata_bus), 64);
				event->dpartial +=64;
				event->state = MEM_BUFFER;
			 }
			else  {
				memcpy((void *)&(event->data[event->size - event->dpartial]), (void *)&(cmd->afu_event->afu_tlx_cdata_bus), (event->size - event->dpartial));
				event->state = MEM_RECEIVED;
				}
	
		}
	} else
		return;

	return;

        } else // event->state=MEM_RECEIVED 
		{	if ((client = _get_client(cmd, event)) == NULL)
		return;
	//cmd->buffer_read = event;
	if (client->mem_access != NULL) {
		debug_msg("client->mem_access NOT NULL so can't send MEMORY write for afutag=0x%x yet!!!!!", event->afutag);
		return;
	}

	// Send buffer read request to AFU.  Setting cmd->buffer_read
	// will block any more buffer read requests until buffer read
	// data is returned and handled in handle_buffer_data().
	debug_msg("%s:BUFFER READY TO GO TO CLIENT afutag=0x%04x addr=0x%016"PRIx64, cmd->afu_name,
		  event->afutag, event->addr);
	if (event->type == CMD_WRITE) {
		buffer = (uint8_t *) malloc(event->size + 11);
		buffer[0] = (uint8_t) OCSE_MEMORY_WRITE;
		buffer[1] = (uint8_t) ((event->size & 0x0F00) >>8);
		buffer[2] = (uint8_t) (event->size & 0xFF);
		addr = (uint64_t *) & (buffer[3]);
		*addr = htonll(event->addr);
		memcpy(&(buffer[11]), &(event->data[0]), event->size);
		event->abort = &(client->abort);
		debug_msg("%s: MEMORY WRITE afutag=0x%02x size=%d addr=0x%016"PRIx64" port=0x%2x",
		  	cmd->afu_name, event->afutag, event->size, event->addr, client->fd);
		if (put_bytes(client->fd, event->size + 11, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}
	}
	event->state = MEM_DONE;  //we rely on something in ocl to clear client->mem_access but how do we set it??
	cmd->buffer_read = NULL;
	client->mem_access = (void *)event;
        }

/*	if (tlx_buffer_read(cmd->afu_event, event->tag, event->addr,
			    CACHELINE_BYTES) == TLX_SUCCESS) {
		cmd->buffer_read = event;
		debug_cmd_buffer_read(cmd->dbg_fp, cmd->dbg_id, event->tag);
		event->state = MEM_BUFFER;
	} */
}

// Handle  pending dma0 write - check is done here to make sure that
// dma transaction stays within a 4k page. If not, simulation ends w/error.
// Transactions up to 512B are supported.
void handle_dma0_write(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint64_t *addr;
	uint8_t *buffer;

	// Check that cmd struct is valid
	if (cmd == NULL)
		return;

	// Send any ready write data to client immediately
	head = &cmd->list;
	while (*head != NULL) {
		if ((((*head)->type == CMD_DMA_WR) || ((*head)->type == CMD_DMA_WR_AMO)) &&
		    ((*head)->state == DMA_OP_REQ))
			break;
	if (((*head)->type == CMD_DMA_WR_AMO) && ((*head)->state == DMA_MEM_RESP))
 			goto amo_wb;

		head = &((*head)->_next);
	}
	event = *head;


	// Test for client disconnect or nothing to do....
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;
	// Check that memory request can be driven to client
	if (client->mem_access != NULL) {
		printf("client->mem_access NOT NULL!!!!! \n");
		return;
	}
	// check to make sure transaction will stay within a 4K boundary
	if ((event->addr+0x1000) <= (event->addr+(uint64_t)event->dsize))
		error_msg ("TRANSACTION CROSSES 4K BOUNDARY - WILL CAUSE PCI BUS ERROR!!!! boundary= 0x%016"PRIx64" last byte= 0x%016"PRIx64,
			 (event->addr+0x1000), (event->addr +event->dsize));
	else
		debug_msg ("TRANSACTION IS GOOD TO GO !!!! boundary= 0x%016"PRIx64" last byte= 0x%016"PRIx64,
			 (event->addr+0x1000), (event->addr +event->dsize));
	debug_msg("%s:DMA0 WRITE BUFFER itag=0x%02x addr=0x%016"PRIx64" port=0x%2x", cmd->afu_name,
		  event->itag, event->addr, client->fd);
	// Send data to client and clear event to allow
	// the next buffer read to occur.  The request will now await
	// confirmation from the client that the memory write was
	// successful before generating a response.
	if (event->type == CMD_DMA_WR) {
		buffer = (uint8_t *) malloc(event->dsize + 11);
		buffer[0] = (uint8_t) OCSE_DMA0_WR;
		buffer[1] = (uint8_t) ((event->dsize & 0x0F00) >>8);
		buffer[2] = (uint8_t) (event->dsize & 0xFF);
		addr = (uint64_t *) & (buffer[3]);
		*addr = htonll(event->addr);
		memcpy(&(buffer[11]), &(event->data[0]), event->dsize);
		event->abort = &(client->abort);
		debug_msg("%s:DMA0 MEMORY WRITE utag=0x%02x size=%d addr=0x%016"PRIx64" port=0x%2x",
		  	cmd->afu_name, event->utag, event->dsize, event->addr, client->fd);
		if (put_bytes(client->fd, event->dsize + 11, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}
	} else { // event->type == CMD_DMA_WR_AMO
		buffer = (uint8_t *) malloc(27);
		buffer[0] = (uint8_t) OCSE_DMA0_WR_AMO;
		buffer[1] = (uint8_t) event->dsize;
		addr = (uint64_t *) & (buffer[2]);
		*addr = htonll(event->addr);
		buffer[10] = event->atomic_op;
		memcpy(&(buffer[11]), &(event->data[0]), 16);
		event->abort = &(client->abort);
		debug_msg("%s:DMA0 MEMORY WRITE for AMO utag=0x%02x size=%d addr=0x%016"PRIx64" port=0x%2x",
		  	cmd->afu_name, event->utag, event->dsize, event->addr, client->fd);
		if (put_bytes(client->fd, 27, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}
	}

	// create a separate function to do the sent utag status
	event->state = DMA_SEND_STS;
	client->mem_access = (void *)event;
	return;

amo_wb: event = *head;
debug_msg ("event->atomic_op = 0x%x ", event->atomic_op);
	if ((event->atomic_op & 0x3f) < 0x20) {
	//randomly decide not to return data yet
		if (!allow_resp(cmd->parms))
			return;

		event->cpl_type = 4; //always 4 for atomic completion response
		event->cpl_byte_count = event->dsize; // not valid for AMO but we do it anyway for debug
		event->cpl_laddr = (uint32_t) (event->cpl_laddr & 0x000000000000000C);
		debug_msg("%s:DMA0 AMO FETCH DATA WB  utag=0x%02x size=%d addr=0x%016"PRIx64 ,
		  	cmd->afu_name, event->utag, event->dsize, event->addr);

/*		if (tlx_dma0_cpl_bus_write(cmd->afu_event, event->utag, event->cpl_type,
			event->dsize, event->cpl_laddr, event->cpl_byte_count,
			event->data) == TLX_SUCCESS) {
			debug_msg("%s:DMA0 CPL BUS WRITE utag=0x%02x", cmd->afu_name,
				  event->utag);
			event->resp = TLX_RESPONSE_DONE;
			//event->state = DMA_CPL_SENT;
			//see if this fixes the core dumps
			event->state = MEM_DONE;
			} else
				printf ("looks like we didn't have success writing cpl data? \n");
*/
		}
		return;

}


// Send UTAG SENT via DMA port back to AFU
void handle_dma0_sent_sts(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;

	// Check that cmd struct is valid
	if (cmd == NULL)
		return;

	// look for any pending sent_utag_sts to send to AFU
	head = &cmd->list;
	while (*head != NULL) {
		if ((((*head)->type == CMD_DMA_WR) || ((*head)->type == CMD_DMA_WR_AMO)) &&
		    ((*head)->state == DMA_SEND_STS))
			break;
		head = &((*head)->_next);
	}
	event = *head;

	// Test for client disconnect or nothing to do....
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	event->sent_sts = 0x1;
/* 	if (tlx_dma0_sent_utag(cmd->afu_event, event->utag, event->sent_sts)
				      == TLX_SUCCESS) {
		debug_msg("%s:DMA0 SENT UTAG STS, state now DMA_MEM_RESP FOR DMA_WR utag=0x%02x",
			 cmd->afu_name, event->utag);
		//state goes to MEM_DONE when Memory ACK is received back from client
		event->state = DMA_MEM_RESP;

	} else
		debug_msg("%s:DMA0 SENT UTAG STS not SENT, still DMA_SEND_STS FOR DMA_WR utag=0x%02x",
		 cmd->afu_name, event->utag); */
}

// Handle randomly selected pending DMA0 read, send request to client for real data
//  or do final write to AFU w/valid data after it is received from client.
void handle_dma0_read(struct cmd *cmd)
{
	struct cmd_event *event;
	struct client *client;
	uint8_t buffer[10];
	uint64_t *addr;
	//int quadrant, byte;

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;


	// Randomly select a pending dma0 read (or none)
	event = cmd->list;
	while (event != NULL) {
	        if ((event->type == CMD_DMA_RD) &&
		    (event->state == DMA_CPL_PARTIAL) &&
		    ((event->client_state != CLIENT_VALID) ||
		     !allow_reorder(cmd->parms))) {
			break;
		}
	        if ((event->type == CMD_DMA_RD) &&
		    (event->state != DMA_CPL_SENT) &&
		    ((event->client_state != CLIENT_VALID) ||
		     !allow_reorder(cmd->parms))) {
			break;
		}
		event = event->_next;
	}

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;
	// After the client returns data with a call to the function
	// _handle_mem_read() issue dma0 completion bus
	// write with valid data and
	// prepare for response.
	if ((event->state == DMA_CPL_PARTIAL) || (event->state == DMA_MEM_RESP)) {
	//randomly decide not to return data yet only if this isn't a multi-cycle cpl in progress
		if ((event->state == DMA_MEM_RESP) && (!allow_resp(cmd->parms)))
			return;

		if (event->cpl_xfers_to_go == 0) {
			if (event->state == DMA_MEM_RESP)  {  //start of transaction
				event->cpl_byte_count = event->dsize;
				event->cpl_laddr = (uint32_t) (event->addr & 0x00000000000003FF);
			}
		/*	if (event->cpl_byte_count <= 128) { // Single cycle single completion flow
				event->cpl_type = 0; //always 0 for read up to 128bytes
				event->cpl_size = event->cpl_byte_count;;
				//event->cpl_byte_count = event->dsize;
				//event->cpl_laddr = (uint32_t) (event->addr & 0x00000000000003FF);
				if (tlx_dma0_cpl_bus_write(cmd->afu_event, event->utag, event->cpl_type,
					event->cpl_size, event->cpl_laddr, event->cpl_byte_count,
					event->data) == TLX_SUCCESS) {
						debug_msg("%s:DMA0 CPL BUS WRITE utag=0x%02x", cmd->afu_name,
				  		event->utag);
						int line = 0;
						for (quadrant = 0; quadrant < 4; quadrant++) {
							DPRINTF("DEBUG: Q%d 0x", quadrant);
							for (byte = line; byte < line+32; byte++) {
								DPRINTF("%02x", event->data[byte]);
							}
							DPRINTF("\n");
							line +=32;
						}
					event->resp = TLX_RESPONSE_DONE;
					event->state = DMA_CPL_SENT;
				}  */
			} else	if (event->cpl_byte_count <= 512) { //Multi cycle single completion flow
			// need way to lock DMA bus so nothing else goes out over it until this transaction completes? TODO
					event->cpl_xfers_to_go = 1;
					event->cpl_type = 0; //always 0 for first xfer of 128bytes
					event->cpl_size = 128;
					//event->cpl_byte_count = event->dsize;
					//event->cpl_laddr = (uint32_t) (event->addr & 0x00000000000003FF);
				/*	if (tlx_dma0_cpl_bus_write(cmd->afu_event, event->utag, event->cpl_type,
						event->cpl_size, event->cpl_laddr, event->cpl_byte_count,
						event->data) == TLX_SUCCESS) {
							debug_msg("%s:DMA0 CPL BUS WRITE utag=0x%02x", cmd->afu_name,
				  			event->utag);
							int line = 0;
							for (quadrant = 0; quadrant < 4; quadrant++) {
								DPRINTF("DEBUG: Q%d 0x", quadrant);
								for (byte = line; byte < line+32; byte++) {
									DPRINTF("%02x", event->data[byte]);
								}
								DPRINTF("\n");
								line +=32;
							}
					event->state = DMA_CPL_PARTIAL;
					}
				} else
					error_msg ("ERROR: REQ FOR DMA xfer > 512B we should not be here!!!"); */
			} else  {  //  second pass thru
				// be sure to unlock the DMA bus after this gets loaded into afu_event struct TODO
				event->cpl_xfers_to_go = 0;
				event->cpl_type = 1; //1 for last cycle, nothing valid but cpl_type, data and utag
				// tlx_dma0_cpl_bus_write will make adjustments to correct cpl_size & laddr
				event->cpl_size = event->dsize;
				event->cpl_byte_count = event->dsize;
				event->cpl_laddr = (uint32_t) (event->addr & 0x00000000000003FF);
			/*	if (tlx_dma0_cpl_bus_write(cmd->afu_event, event->utag, event->cpl_type,
					event->cpl_size, event->cpl_laddr, event->cpl_byte_count,
					event->data) == TLX_SUCCESS) {
						debug_msg("%s:DMA0 CPL BUS WRITE utag=0x%02x", cmd->afu_name,
				  		event->utag);
						int line = 128;
						for (quadrant = 0; quadrant < 4; quadrant++) {
							DPRINTF("DEBUG: Q%d 0x", quadrant);
							for (byte = line; byte < line+32; byte++) {
								DPRINTF("%02x", event->data[byte]);
							}
							DPRINTF("\n");
							line +=32;
						}
				} */
				if (event->cpl_byte_count == event->cpl_size) {  //this was last transfer
					event->resp = TLX_RESPONSE_DONE;
					event->state = DMA_CPL_SENT;
					}
				else  { //dec byte count, inc addr for next transfer
					event->cpl_byte_count -= 256;
					if (event->cpl_byte_count < 128)// last transfer will be single cycle
						event->cpl_size = event->cpl_byte_count;
					event->cpl_laddr +=256;

				}
		}
	}

	if (event->state != DMA_OP_REQ)
		return;

	if (client->mem_access == NULL) {
	        // if read:
		// Send read request to client, set client->mem_access
		// to point to this event blocking any other memory
		// accesses to client until data is returned by call
		// to the _handle_mem_read() function.
                if (event->type == CMD_DMA_RD) {
		  buffer[0] = (uint8_t) OCSE_DMA0_RD;
		  buffer[1] = (uint8_t) ((event->dsize & 0x0F00) >>8);
		  buffer[2] = (uint8_t) (event->dsize & 0xFF);
		 // buffer[1] = (uint8_t) event->dsize;
		  addr = (uint64_t *) & (buffer[3]);
		  *addr = htonll(event->addr);
		  event->abort = &(client->abort);
		  debug_msg("%s:DMA0 MEMORY READ utag=0x%02x size=%d addr=0x%016"PRIx64" port = 0x%2x",
			    cmd->afu_name, event->utag, event->dsize, event->addr, client->fd);
		  if (put_bytes(client->fd, 11, buffer, cmd->dbg_fp,
				cmd->dbg_id, event->context) < 0) {
		    client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		  }
		// Now need to send UTAG SENT via DMA port back to AFU
/*	if (tlx_dma0_sent_utag(cmd->afu_event, event->utag, event->sent_sts)
				      == TLX_SUCCESS) {
			debug_msg("%s:DMA0 SENT UTAG STS, state now DMA_MEM_REQ FOR DMA_RD utag=0x%02x", cmd->afu_name,
				  event->utag);

		  event->state = DMA_MEM_REQ;
		 // debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag,
		//		   event->context);
		  client->mem_access = (void *)event;
                    } */
		}
 	}
}


// Handle randomly selected memory touch
void handle_touch(struct cmd *cmd)
{
	struct cmd_event *event;
	struct client *client;
	uint8_t buffer[10];
	uint64_t *addr;
	uint16_t *size;

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	// Randomly select a pending touch (or none)
	event = cmd->list;
	while (event != NULL) {
		if (((event->type == CMD_XLAT_RD_TOUCH) || (event->type == CMD_XLAT_WR_TOUCH))
		    && (event->state == MEM_IDLE)
		    && ((event->client_state != CLIENT_VALID)
			|| !allow_reorder(cmd->parms))) {
			break;
		}

		if (((event->type == CMD_TOUCH) || (event->type == CMD_WRITE))
		    && (event->state == MEM_IDLE)
		    && ((event->client_state != CLIENT_VALID)
			|| !allow_reorder(cmd->parms))) {
			break;
		}
		event = event->_next;
	}

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	// Check that memory request can be driven to client
	if (client->mem_access != NULL)
		return;

	// Send memory touch request to client
	buffer[0] = (uint8_t) OCSE_MEMORY_TOUCH;
	//buffer[1] = (uint8_t) event->size;
	//addr = (uint64_t *) & (buffer[2]);
	size = (uint16_t *)&(buffer[1]);
	*size = htons(event->size);
	addr = (uint64_t *) & (buffer[3]);
	*addr = htonll(event->addr & CACHELINE_MASK);
	event->abort = &(client->abort);
	debug_msg("%s:MEMORY TOUCH tag=0x%02x addr=0x%016"PRIx64, cmd->afu_name,
		  event->tag, event->addr);
	if (put_bytes(client->fd, 10, buffer, cmd->dbg_fp, cmd->dbg_id,
		      event->context) < 0) {
		client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	}
	event->state = MEM_TOUCH;
	client->mem_access = (void *)event;
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
}

// Send pending interrupt to client as soon as possible
void handle_interrupt(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint16_t irq;
	uint8_t buffer[3];

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	// Send any interrupts to client immediately
	head = &cmd->list;
	while (*head != NULL) {
		if (((*head)->type == CMD_INTERRUPT) &&
		    ((*head)->state == MEM_IDLE))
			break;
		head = &((*head)->_next);
	}
	event = *head;

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	// Send interrupt to client
	buffer[0] = OCSE_INTERRUPT;
	irq = htons(cmd->irq);
	memcpy(&(buffer[1]), &irq, 2);
	event->abort = &(client->abort);
	debug_msg("%s:INTERRUPT irq=%d", cmd->afu_name, cmd->irq);
	if (put_bytes(client->fd, 3, buffer, cmd->dbg_fp, cmd->dbg_id,
		      event->context) < 0) {
		client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	}
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
	event->state = MEM_DONE;
}

void handle_buffer_data(struct cmd *cmd, uint32_t parity_enable)
{
	uint8_t *parity_check;
	int rc = 0;
	struct cmd_event *event;
	int quadrant, byte;

	// Has struct been initialized?
	if ((cmd == NULL) || (cmd->buffer_read == NULL))
		return;

	// Check if buffer read data has returned from AFU
	event = cmd->buffer_read;
	/* rc = tlx_get_buffer_read_data(cmd->afu_event, event->data,
				      event->parity); */
	if (rc == TLX_SUCCESS) {
		debug_msg("%s:BUFFER READ tag=0x%02x", cmd->afu_name,
			  event->tag);
		for (quadrant = 0; quadrant < 4; quadrant++) {
			DPRINTF("DEBUG: Q%d 0x", quadrant);
			for (byte = 0; byte < CACHELINE_BYTES / 4; byte++) {
				DPRINTF("%02x", event->data[byte]);
			}
			DPRINTF("\n");
		}
	debug_msg("handle_buffer_data parity_enable is 0x%x ", parity_enable);
		if (parity_enable) {
			parity_check =
			    (uint8_t *) malloc(DWORDS_PER_CACHELINE / 8);
			generate_cl_parity(event->data, parity_check);
			if (strncmp((char *)event->parity,
				    (char *)parity_check,
				    DWORDS_PER_CACHELINE / 8)) {
				error_msg("Buffer read parity error tag=0x%02x",
					  event->tag);
			}
			free(parity_check);
		}
		// Free buffer interface for another event
		cmd->buffer_read = NULL;
		if ((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) {
			event->state = MEM_CAS_OP;
			//printf("HANDLE_BUFFER_DATA read in op1/op2 \n");
			return;
		}
		// Randomly decide to not send data to client yet
		if (!event->buffer_activity && allow_buffer(cmd->parms)) {
			event->state = MEM_TOUCHED;
			event->buffer_activity = 1;
			return;
		}

		event->state = MEM_RECEIVED;
	}

}

void handle_mem_write(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint64_t *addr;
	uint16_t *size;
	uint8_t *buffer;
	uint64_t offset;

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	// Send any ready write data to client immediately
	head = &cmd->list;
	while (*head != NULL) {
		if (((*head)->type == CMD_WRITE) &&
		    ((*head)->state == MEM_RECEIVED))
			break;
	//	if ((((*head)->type == CMD_CAS_4B) || ((*head)->type == CMD_CAS_8B)) &&
	//	    ((*head)->state == MEM_CAS_WR))
	//		break;
		head = &((*head)->_next);
	}
	event = *head;

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	// Check that memory request can be driven to client
	if (client->mem_access != NULL)
		return;

	// Send data to client and clear event to allow
	// the next buffer read to occur.  The request will now await
	// confirmation from the client that the memory write was
	// successful before generating a response.  The client
	// response will cause a call to either handle_aerror() or
	// handle_mem_return().
	buffer = (uint8_t *) malloc(event->size + 11);
	offset = event->addr & ~CACHELINE_MASK;
	buffer[0] = (uint8_t) OCSE_MEMORY_WRITE;
	//buffer[1] = (uint8_t) event->size;
	//addr = (uint64_t *) & (buffer[2]);
	size = (uint16_t *)&(buffer[1]);
	*size = htons(event->size);
	addr = (uint64_t *) & (buffer[3]);
	*addr = htonll(event->addr);
	memcpy(&(buffer[10]), &(event->data[offset]), event->size);
	event->abort = &(client->abort);
	debug_msg("%s:MEMORY WRITE tag=0x%04x size=%d addr=0x%016"PRIx64,
		  cmd->afu_name, event->afutag, event->size, event->addr);
	if (put_bytes(client->fd, event->size + 10, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) {
		client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	}
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
	  	//printf ("handle_mem_write1: event->type is %2x, event->state is 0x%3x \n", event->type, event->state);
	if ((event->type != CMD_CAS_4B) && (event->type != CMD_CAS_8B))
		event->state = MEM_REQUEST;
	  	//printf ("handle_mem_write2: event->type is %2x, event->state is 0x%3x \n", event->type, event->state);
	client->mem_access = (void *)event;
}

// Handle data returning from client for memory read
static void _handle_mem_read(struct cmd *cmd, struct cmd_event *event, int fd)
{
	uint8_t data[MAX_LINE_CHARS];
	uint64_t offset = event->addr & ~CACHELINE_MASK;

	// printf ("_handle_mem_read: event->type is %2x, event->state is 0x%3x \n", event->type, event->state);
	if ((event->type == CMD_READ) ||
		 (((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) && event->state != MEM_CAS_WR)) {
	        printf ("_handle_mem_read: CMD_READ \n" );
		// Client is returning data from memory read
		printf("_handle_mem_read: before get bytes silent \n");
		if (get_bytes_silent(fd, event->size, data, cmd->parms->timeout,
			     event->abort) < 0) {
	        	debug_msg("%s:_handle_mem_read failed afutag=0x%04x size=%d addr=0x%016"PRIx64,
				  cmd->afu_name, event->afutag, event->size, event->addr);
			//event->resp = TLX_RESPONSE_DERROR;
			if ((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B))
			//	event->resp = TLX_RESPONSE_CAS_INV;
			event->state = MEM_DONE;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
			return;
		}
		printf("_handle_mem_read: AFTER get bytes silent \n");
		// we used to put the data in the event->data at the offset implied by the address
		// should we still do that?  It might depend on the the actual ap command that we received.
		memcpy((void *)&(event->data[offset]), (void *)&data, event->size);
		// parity is no long required. although we might want to set the bad data indicator for 
		// bad machine path simulations.
		generate_cl_parity(event->data, event->parity);
		event->state = MEM_RECEIVED;
	}
        // have to expect data back from some AMO ops
	else if ((event->type == CMD_DMA_RD) || (event->type == CMD_DMA_WR_AMO)) {
		// Client is returning data from DMA memory read
                // printf( "_handle_mem_read: CMD_DMA_RD or CMD_DMA_WR_AMO \n" );
		if (get_bytes_silent(fd, event->dsize, data, cmd->parms->timeout,
			     event->abort) < 0) {
	        	debug_msg("%s:_handle_dma0_mem_read failed tag=0x%02x size=%d addr=0x%016"PRIx64,
				  cmd->afu_name, event->tag, event->dsize, event->addr);
			//event->resp = TLX_RESPONSE_DERROR;
			event->state = MEM_DONE;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
			return;
		}
		// DMA return data goes at offset 0 in the event data instead of some other offset.
                // should we clear event->data first?
		memcpy((void *)event->data, (void *)&data, event->dsize);
		event->state = DMA_MEM_RESP;

	}
}

// Calculate page address in cached index for translation
static void _calc_index(struct cmd *cmd, uint64_t * addr, uint64_t * index)
{
	*addr &= cmd->page_entries.page_filter;
	*index = *addr & cmd->page_entries.entry_filter;
	*index >>= PAGE_ADDR_BITS;
}

// Update age of translation entries and create new entry if needed
static void _update_age(struct cmd *cmd, uint64_t addr)
{
	uint64_t index;
	int i, set, age, oldest, empty;

	_calc_index(cmd, &addr, &index);
	set = age = oldest = 0;
	empty = PAGE_WAYS;
	for (i = 0; i < PAGE_WAYS; i++) {
		if (cmd->page_entries.valid[index][i] &&
		    (cmd->page_entries.entry[index][i] != addr)) {
			cmd->page_entries.age[index][i]++;
			if (cmd->page_entries.age[index][i] > age) {
				age = cmd->page_entries.age[index][i];
				oldest = i;
			}
		}
		if (!cmd->page_entries.valid[index][i] && (empty == PAGE_WAYS)) {
			empty = i;
		}
		if (cmd->page_entries.valid[index][i] &&
		    (cmd->page_entries.entry[index][i] == addr)) {
			cmd->page_entries.age[index][i] = 0;
			set = 1;
		}
	}

	// Entry found and updated
	if (set)
		return;

	// Empty slot exists
	if (empty < PAGE_WAYS) {
		cmd->page_entries.entry[index][empty] = addr;
		cmd->page_entries.valid[index][empty] = 1;
		cmd->page_entries.age[index][empty] = 0;
		return;
	}
	// Evict oldest entry and replace with new entry
	cmd->page_entries.entry[index][oldest] = addr;
	cmd->page_entries.valid[index][oldest] = 1;
	cmd->page_entries.age[index][oldest] = 0;
}

// Determine if page translation is already cached
static int _page_cached(struct cmd *cmd, uint64_t addr)
{
	uint64_t index;
	int i, hit;

	_calc_index(cmd, &addr, &index);
	i = hit = 0;
	while ((i < PAGE_WAYS) && cmd->page_entries.valid[index][i] &&
	       (cmd->page_entries.entry[index][i] != addr)) {
		i++;
	}

	// Hit entry
	if ((i < PAGE_WAYS) && cmd->page_entries.valid[index][i])
		hit = 1;

	return hit;
}

// Decide what to do with a client memory acknowledgement
void handle_mem_return(struct cmd *cmd, struct cmd_event *event, int fd)
{
	struct client *client;

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	debug_msg("%s:MEMORY ACK tag=0x%02x addr=0x%016"PRIx64, cmd->afu_name,
		  event->tag, event->addr);

	// Randomly cause paged response
	if (((event->type != CMD_WRITE) || (event->state != MEM_REQUEST)) &&
	    (client->flushing == FLUSH_NONE) && !_page_cached(cmd, event->addr)
	    && allow_paged(cmd->parms)) {
		if (event->type == CMD_READ)
			_handle_mem_read(cmd, event, fd);
		//event->resp = TLX_RESPONSE_PAGED;
		event->state = MEM_DONE;
		client->flushing = FLUSH_PAGED;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	_update_age(cmd, event->addr);
	if ((event->type == CMD_READ) ||
		 (((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) && event->state != MEM_CAS_WR))
		_handle_mem_read(cmd, event, fd);
 	// have to account for AMO fetch cmds with returned data
 	else if (event->type == CMD_DMA_RD)
		_handle_mem_read(cmd, event, fd);
 	else if (event->type == CMD_DMA_WR_AMO) {
                 if ((event->atomic_op & 0x3f) < 0x20)
			_handle_mem_read(cmd, event, fd);
		 else
			event->state = MEM_DONE;
		}
	else if ((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B))
			event->state = MEM_DONE;

	else if (event->type == CMD_TOUCH)
		event->state = MEM_DONE;
	else if (event->state == MEM_TOUCH)	// Touch before write
		event->state = MEM_TOUCHED;
	else			// Write after touch
		event->state = MEM_DONE;
	debug_cmd_return(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
}

// Mark memory event as address error in preparation for response
void handle_aerror(struct cmd *cmd, struct cmd_event *event)
{
//	event->resp = TLX_RESPONSE_AERROR;
	event->state = MEM_DONE;
	debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
			 event->context, event->resp);
}

void _handle_op1_op2_load(struct cmd *cmd, struct cmd_event *event)
{

	memcpy((char *)&event->cas_op1, (char *)event->data, sizeof(uint64_t));
	printf("op1 bytes 1-8 are 0x%016" PRIx64 " \n", event->cas_op1);
	//event->cas_op1 = ntohll (event->cas_op1);
	//printf("op1 bytes 1-8 are 0x%016" PRIx64 " \n", event->cas_op1);
	memcpy((char *)&event->cas_op2, (char *)event->data+8, sizeof(uint64_t));
	printf("op2 bytes 1-8 are 0x%016" PRIx64 " \n", event->cas_op2);
	//event->cas_op2 = ntohll (event->cas_op2);
	//printf("op2 bytes 1-8 are 0x%016" PRIx64 " \n", event->cas_op2);

}

void _handle_cas_op(struct cmd *cmd, struct cmd_event *event)
{
	//uint32_t lvalue, op_A, op_1, op_2;
	//uint64_t offset, op_Al;
	//unsigned char op_size;
/*
	offset = event->addr & ~CACHELINE_MASK;
	if (event->type == CMD_CAS_4B) {
		op_size = 4;
		memcpy((char *) &lvalue, (void *)&(event->data[offset]), op_size);
		op_A = (uint32_t)(lvalue);
		op_1 = (uint32_t) event->cas_op1;
		op_2 = (uint32_t) event->cas_op2;
		debug_msg("op_A is %08"PRIx32 " and op_1 is %08"PRIx32, op_A, op_1);
		if ((event->command == TLX_COMMAND_CAS_U_4B)  ||
		   ((event->command == TLX_COMMAND_CAS_E_4B) && (op_A == op_1 )) ||
		   ((event->command == TLX_COMMAND_CAS_NE_4B) && (op_A != op_1))) {
			memcpy((char *)(&event->data[offset]), (char *) &event->cas_op2, op_size);
			if (event->command == TLX_COMMAND_CAS_E_4B)
				event->resp = TLX_RESPONSE_COMP_EQ;
			else if (event->command == TLX_COMMAND_CAS_NE_4B)
				event->resp = TLX_RESPONSE_COMP_NEQ;
			else if ((event->command == TLX_COMMAND_CAS_U_4B) && (op_A == op_1))
				  event->resp = TLX_RESPONSE_COMP_EQ;
				else
				  event->resp = TLX_RESPONSE_COMP_NEQ;
			event->state = MEM_CAS_WR;
			debug_msg("HANDLE_CAS_OP CAS_U or CAS_E_4B IS EQUAL or CAS_NE_4B NOT EQUAL");
		} else	{
			if (event->command == TLX_COMMAND_CAS_E_4B)
				event->resp = TLX_RESPONSE_COMP_NEQ;
			else
				event->resp = TLX_RESPONSE_COMP_EQ;
			event->state = MEM_DONE;
			debug_msg("HANDLE_CAS_OP CAS_E_4B NOT EQUAL or CAS_NE_4B IS EQUAL");
		}
	} else if (event->type == CMD_CAS_8B) {
		op_size = 8;
		debug_msg("op_1l is %016"PRIx64, event->cas_op1);
		debug_msg("op_2l is %016"PRIx64, event->cas_op2);
		memcpy((char *)&op_Al, (void *)&(event->data[offset]), op_size);
		debug_msg("op_Al is %016"PRIx64 " and op_1 is %016"PRIx64, op_Al,event->cas_op1);
		if ((event->command == TLX_COMMAND_CAS_U_8B)  ||
		   ((event->command == TLX_COMMAND_CAS_E_8B) && (op_Al == event->cas_op1 )) ||
		   ((event->command == TLX_COMMAND_CAS_NE_8B) && (op_Al != event->cas_op1))) {
			memcpy((char *)&event-> data[offset], (char *) &event->cas_op2, op_size);
			if (event->command == TLX_COMMAND_CAS_E_8B)
				event->resp = TLX_RESPONSE_COMP_EQ;
			else if (event->command == TLX_COMMAND_CAS_NE_8B)
				event->resp = TLX_RESPONSE_COMP_NEQ;
			else if ((event->command == TLX_COMMAND_CAS_U_8B) && (op_Al == event->cas_op1))
				  event->resp = TLX_RESPONSE_COMP_EQ;
				else
				  event->resp = TLX_RESPONSE_COMP_NEQ;
			event->state = MEM_CAS_WR;
			debug_msg("HANDLE_CAS_OP CAS_U or CAS_E_8B IS EQUAL or CAS_NE_8B NOT EQUAL");
		} else	{
			if (event->command == TLX_COMMAND_CAS_E_8B)
				event->resp = TLX_RESPONSE_COMP_NEQ;
			else
				event->resp = TLX_RESPONSE_COMP_EQ;
			event->state = MEM_DONE;
			debug_msg("HANDLE_CAS_OP CAS_E_8B NOT EQUAL or CAS_NE_8B IS EQUAL");

	} */
}


void handle_caia2_cmds(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
//	uint32_t this_itag;
//	unsigned char need_a_tag;


	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	// Look for any cmds to process
	head = &cmd->list;
	while (*head != NULL) {
	  	//printf ("handle_caia2_cmds: head->type is %2x, head->state is 0x%3x \n", (*head)->type, (*head)->state);
	//first look for  CAS commands
		if (((*head)->type == CMD_CAS_4B) || ((*head)->type == CMD_CAS_8B))
			break;
	// next look for xlat read/write requests
		if ((((*head)->type == CMD_XLAT_RD) &&
		    ((*head)->state == DMA_ITAG_REQ)) |
		 (((*head)->type == CMD_XLAT_WR) &&
		    ((*head)->state == DMA_ITAG_REQ)))
			break;
	//next look for itag read/write abort requests
		if ((((*head)->type == CMD_ITAG_ABRT_RD) && ((*head)->state == MEM_TOUCHED)) |
		  (((*head)->type == CMD_ITAG_ABRT_WR) && ((*head)->state == MEM_TOUCHED)))
			break;
	//next look for itag read/write touch requests
		if ((((*head)->type == CMD_XLAT_RD_TOUCH) && ((*head)->state != MEM_DONE)) |
		  (((*head)->type == CMD_XLAT_WR_TOUCH) && ((*head)->state != MEM_DONE)))
			break;
	// finally look for incoming DMA op requests
		if (((*head)->state == DMA_PENDING) || ((*head)->state == DMA_PARTIAL))
			goto dmaop_chk;
		head = &((*head)->_next);
	}
	event = *head;


// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;
	//Process XLAT cmds and get them ready for handle_response to deal with
/*	switch (event->command) {
		// request read data from AFU buffer interface to get op1/op2,
		// read cache line pointed to by EA. Compare op1 & [EA] and
		// if required, update cacheline with op2 and write back to EA
		// return appropriate resp code to AFU
		case TLX_COMMAND_CAS_E_4B:
		case TLX_COMMAND_CAS_NE_4B:
		case TLX_COMMAND_CAS_U_4B:
		case TLX_COMMAND_CAS_E_8B:
		case TLX_COMMAND_CAS_NE_8B:
		case TLX_COMMAND_CAS_U_8B:
			event->size = CACHELINE_BYTES; // got to set up for cacheline read/write no matter what
			if (event->state == MEM_CAS_OP)  {
				_handle_op1_op2_load(cmd, event);
				event->state = MEM_CAS_RD;
				//printf("HANDLE_CAIA2_CMDS read in op1/op2 \n");
			} else if (event->state == MEM_RECEIVED) {
				//printf("HANDLE_CAIA2_CMDS calling handle cas op \n");
				_handle_cas_op(cmd, event);}
			break;
		case TLX_COMMAND_XLAT_RD_P0:
			need_a_tag = 1;
			while (need_a_tag == 1)  {
				this_itag = (rand() % 256);
				head = &cmd->list;
				while (*head != NULL) {
					if ((*head)->itag == this_itag)
						break;
					head = &((*head)->_next);
					}
				if (*head == NULL)   // didn't find this tag so okay to use
					break;
				 else debug_msg("itag already in use!! Have to choose another value");
				}

			event->itag = this_itag;
			event->port = 0;
			//printf("in handle_caia2 for xlat_rd, address is 0x%016"PRIX64 "\n", event->addr);
			cmd->afu_event->response_dma0_itag = event->itag;
			cmd->afu_event->response_dma0_itag_parity = generate_parity(event->itag, ODD_PARITY);
			info_msg("dma0_itag for read is 0x%x", event->itag);
			event->state = DMA_ITAG_RET;
			break;
		case TLX_COMMAND_XLAT_WR_P0:
			need_a_tag = 1;
			while (need_a_tag == 1)  {
				this_itag = ((rand() % 256) + 256);
				head = &cmd->list;
				while (*head != NULL) {
					if ((*head)->itag == this_itag)
						break;
					head = &((*head)->_next);
					}
				if (*head == NULL)   // didn't find this tag so okay to use
					break;
				else debug_msg("itag already in use!! Have to choose another value");
				}

			event->itag = this_itag;
			event->port = 0;
			//printf("in handle_caia2 for xlat_wr, address is 0x%016"PRIX64 "\n", event->addr);
			cmd->afu_event->response_dma0_itag = event->itag;
			cmd->afu_event->response_dma0_itag_parity = generate_parity(event->itag, ODD_PARITY);
			info_msg("dma0_itag for write is 0x%x", event->itag);
			event->state = DMA_ITAG_RET;
			break;
		case TLX_COMMAND_ITAG_ABRT_RD:
			// if tag is in reserved state, go ahead and abort
			// otherwise, send back FAIL and warn msg
			this_itag = event->addr;
			debug_msg("NOW IN TLX_COMMAND_ITAG_ABRT_RD with this_itag = 0x%x ", this_itag);
			// Look for a matching itag to process immediately
			// check to see if dma op already started
			head = &cmd->list;
			while (*head != NULL) {
				debug_msg ("in handle_caia2_cmds, processing ITAG abt read : head->type is %2x, head->state is 0x%x, head->itag is 0x%3x ", (*head)->type, (*head)->state, (*head)->itag);
				if (((*head)->state == DMA_ITAG_RET) &&
		    			((*head)->itag == this_itag))
					break;
				if (((*head)->state == DMA_PENDING) &&
		    			((*head)->itag == this_itag))
					break;
				head = &((*head)->_next);
			}
			if (*head == NULL) {  // didn't find this tag OR didn;t find in abortable state so fail
				event->resp = TLX_RESPONSE_FAILED;
				event->state = MEM_DONE;
				warn_msg("WRONG TAG or STATE: failed attempt to abort read dma0_itag 0x%x", event->itag);
				return;
				}
				// adjust credits count in tlx_interface, not here
				(*head)->state = MEM_DONE;
				event->resp = TLX_RESPONSE_DONE;
				event->state = MEM_DONE;
				info_msg("dma0_itag  0x%x for read aborted", this_itag);
				break;
		case TLX_COMMAND_ITAG_ABRT_WR:
			// if tag is in reserved state, go ahead and abort
			// otherwise, send back FAIL and warn msg
			this_itag = event->addr;
			debug_msg("NOW IN TLX_COMMAND_ITAG_ABRT_WR with this_itag = 0x%x ", this_itag);
			// Look for a matching itag to process immediately
			// check to see if dma op already started
			head = &cmd->list;
			while (*head != NULL) {
				debug_msg ("in handle_caia2_cmds, processing ITAG abt write : head->type is %2x, head->state is 0x%x, head->itag is 0x%3x ", (*head)->type, (*head)->state, (*head)->itag);
				if (((*head)->state == DMA_ITAG_RET) &&
		    			((*head)->itag == this_itag))
					break;
				if (((*head)->state == DMA_PENDING) &&
		    			((*head)->itag == this_itag))
					break;
				head = &((*head)->_next);
			}
			if (*head == NULL) {  // didn't find this tag OR not in abortable state so fail
				event->resp = TLX_RESPONSE_FAILED;
				event->state = MEM_DONE;
				warn_msg("WRONG TAG or STATE: failed attempt to abort write dma0_itag 0x%x", event->itag);
				return;
				}
				// will adjust credits count in tlx_interface, not here
				(*head)->state = MEM_DONE;
		   		event->resp = TLX_RESPONSE_DONE;
				event->state = MEM_DONE;
				info_msg("dma0_itag  0x%x for write aborted", this_itag);
				break;
		case TLX_COMMAND_XLAT_RD_TOUCH:
		   	event->resp = TLX_RESPONSE_DONE;
			event->state = MEM_DONE;
			info_msg("XLAT_RD_TOUCH command doesn't return itag");
			break;
		case TLX_COMMAND_XLAT_WR_TOUCH:
		   	event->resp = TLX_RESPONSE_DONE;
			event->state = MEM_DONE;
			info_msg("XLAT_WR_TOUCH command doesn't return itag ");
			break;
		default:
			warn_msg("Unsupported command 0x%04x", cmd);
			break;

	} */
	return;
//here we search list of events to find one that has matching ITAG, then process
	dmaop_chk: event = *head;
	/*	if (cmd->afu_event->dma0_dvalid == 1)  {
	if (event == NULL)
		printf ("why is event null but dma0_dvalid ??? \n");
	this_itag = cmd->afu_event->dma0_req_itag;
	// Look for a matching itag to process immediately
	head = &cmd->list;
	while (*head != NULL) {
		debug_msg ("in handle_caia2 cmds in dmaop_ck: head->type is %2x, head->itag is 0x%3x ", (*head)->type, (*head)->itag);
		if ((((*head)->type == CMD_XLAT_RD) &&
		    ((*head)->itag == this_itag)) |
		 (((*head)->type == CMD_XLAT_WR) &&
		    ((*head)->itag == this_itag)))
			break;
		head = &((*head)->_next);
	}
	if (*head != NULL) {
		event = *head;
		//Fill in event and set up for next steps
		event->itag = cmd->afu_event->dma0_req_itag;
		event->utag = cmd->afu_event->dma0_req_utag;
		event->dtype = cmd->afu_event->dma0_req_type;
		event->dsize = cmd->afu_event->dma0_req_size;
		// If DMA read, set up for subsequent handle_dma_mem_read
		if (event->dtype == DMA_DTYPE_RD_REQ) {
			event->state = DMA_OP_REQ;
			event->type = CMD_DMA_RD;
		// check to make sure transaction will stay within a 4K boundary
		if ((event->addr+0x1000) <= (event->addr+(uint64_t)event->dsize))
			warn_msg("TRANSACTION WILL BE FRAGMENTED, it crosses 4K boundary!!! boundary= 0x%016"PRIx64" last byte= 0x%016"PRIx64,
			(event->addr+0x1000), (event->addr +event->dsize));
		else
			debug_msg("TRANSACTION IS GOOD TO GO !!!! boundary= 0x%016"PRIx64" last byte= 0x%016"PRIx64,
			 (event->addr+0x1000), (event->addr +event->dsize));
			}
		// If DMA write, pull data in and set up for subsequent handle dma_mem_write
		// ALSO send over any AMO cmds that come across as dma wr
		if ((event->dtype == DMA_DTYPE_WR_REQ_128) && (event->dsize <= 128))  {
			debug_msg("copy to event buffer for write dma data  <= 128B type 1");
			event->state = DMA_OP_REQ;
			event->type = CMD_DMA_WR;
		  	memcpy((void *)&(event->data[0]), (void *)&(cmd->afu_event->dma0_req_data), event->dsize);
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x size=0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dsize);
			}
		if ((event->dtype == DMA_DTYPE_WR_REQ_128) && (event->dsize > 128))  {
			debug_msg("FIRST copy to event buffer for write dma data  > 128B type 1");
			event->state = DMA_PARTIAL;
			event->type = CMD_DMA_WR;
		  	memcpy((void *)&(event->data[0]), (void *)&(cmd->afu_event->dma0_req_data), 128);
			event->dpartial = 128;
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x total xfeed =0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dpartial);
			}
		if ((event->dtype == DMA_DTYPE_WR_REQ_MORE) && ((event->dsize - event->dpartial) > 128))  {
			debug_msg("copy to event buffer for write dma data  > 128B type 2");
			event->state = DMA_PARTIAL;
			event->type = CMD_DMA_WR;
		  	memcpy((void *)&(event->data[event->dpartial]), (void *)&(cmd->afu_event->dma0_req_data), 128);
			event->dpartial += 128;
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x total xfered =0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dpartial);
			}
		if ((event->dtype == DMA_DTYPE_WR_REQ_MORE) && ((event->dsize - event->dpartial) <= 128))  {
			debug_msg("FINAL copy to event buffer for write dma data  > 128B type 2");
			event->state = DMA_OP_REQ;
			event->type = CMD_DMA_WR;
		  	memcpy((void *)&(event->data[event->dsize - event->dpartial]), (void *)&(cmd->afu_event->dma0_req_data),
				 (event->dsize - event->dpartial));
			event->dpartial += (event->dsize - event->dpartial);;
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x total xfered =0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dpartial);
			}
		if ((event->dtype == DMA_DTYPE_ATOMIC) && (event->type == CMD_XLAT_RD))
			error_msg("%s:INVALID REQ: DMA AMO W/XLAT_RD ITAG ITAG = 0x%3x DTYPE = %d ", cmd->afu_name, this_itag, event->dtype);
		if ((event->dtype == DMA_DTYPE_ATOMIC) && (event->type == CMD_XLAT_WR))  {
			event->state = DMA_OP_REQ;
			event->type = CMD_DMA_WR_AMO;
			event->atomic_op = cmd->afu_event->dma0_atomic_op;
		  	memcpy((void *)&(event->data[0]), (void *)&(cmd->afu_event->dma0_req_data), 16);
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x size=0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dsize);
			}

		} else {
		error_msg("%s: DMA REQUEST RECEIVED WITH UNKNOWN/INVALID ITAG = 0x%3x", cmd->afu_name, this_itag); }
	cmd->afu_event->dma0_dvalid = 0;
	} */
//printf("cmd->afu_event->dma0_dvalid is 0x%2x \n", cmd->afu_event->dma0_dvalid);
   	return;
}

// Send a randomly selected pending response back to AFU
void handle_response(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint8_t resp_dl, resp_dp;
	int rc;

	// Select a random pending response (or none)
	client = NULL;
	head = &cmd->list;
	while (*head != NULL) {
	  //debug_msg( "%s:RESPONSE examine event @ 0x%016" PRIx64 ", command=0x%x, tag=0x%08x, type=0x%02x, state=0x%02x, resp=0x%x",
	  //	   cmd->afu_name,
	  //	   (*head),
	  //	   (*head)->command,
	  //	   (*head)->tag,
	  //	   (*head)->type,
	  //	   (*head)->state,
	  //	   (*head)->resp );
		// Fast track error responses
	/*	if ( ( (*head)->resp == TLX_RESPONSE_PAGED ) ||
		     ( (*head)->resp == TLX_RESPONSE_NRES ) ||
		     ( (*head)->resp == TLX_RESPONSE_NLOCK ) ||
		     ( (*head)->resp == TLX_RESPONSE_FAILED ) ||
		     ( (*head)->resp == TLX_RESPONSE_FLUSHED ) ) {
			event = *head;
			debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ",drive response because resp is TLX_RESPONSE_error", cmd->afu_name, (*head) );
			goto drive_resp;
		} */
		// if (dma write and we've sent utag sent status AND it wasn't AMO that has pending cpl resp),
		// OR (dma write and it was AMO and we've sent cpl resp)
		// OR (itag was aborted),  we can remove this event
		if ( ( ( (*head)->type == CMD_DMA_WR )     && ( (*head)->state == MEM_DONE ) ) ||
		     ( ( (*head)->type == CMD_DMA_WR_AMO ) && ( (*head)->state == MEM_DONE ) ) ||
		     ( ( (*head)->type == CMD_XLAT_WR )    && ( (*head)->state == MEM_DONE ) ) ) {
			//  update dma0_wr_credits IF CMD_DMA_WR or CMD_DMA_WR_AM0
			//if ((*head)->type != CMD_XLAT_WR)
			//	cmd->dma0_wr_credits++;
			event = *head;
			*head = event->_next;
			debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", free event and skip response because dma write related is done",
				   cmd->afu_name, event );
			free(event->data);
			free(event->parity);
			free(event);
		        //printf("in handle_response and finally freeing original xlat/dma write event \n");
			return;
		} else if ( ( ( (*head)->type == CMD_DMA_RD )  && ( (*head)->state == DMA_CPL_SENT ) ) ||
			    ( ( (*head)->type == CMD_XLAT_RD ) && ( (*head)->state == MEM_DONE ) ) ) {
		        // if dma read and we've send completion data OR itag aborted , we can remove this event
			//  update dma0_rd_credits IF CMD_DMA_RD
			//if ((*head)->type != CMD_XLAT_RD)
			//	cmd->dma0_rd_credits++;
			event = *head;
			*head = event->_next;
			debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", free event and skip response because dma read related is CPL or DONE",
				   cmd->afu_name, event );
			free(event->data);
			free(event->parity);
			free(event);
	                //printf("in handle_response and finally freeing original xlat/dma read event \n");
			return;
		}


		if ( ( (*head)->type == CMD_XLAT_RD ) ||
		     ( (*head)->type == CMD_XLAT_WR ) ) {
				if ((*head)->state == DMA_ITAG_RET) {
					event = *head;
					event->resp = TLX_RESPONSE_DONE;
					debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", drive response because xlat type state was DMA_ITAG_RET",
						   cmd->afu_name, event );
					goto drive_resp;
				} else {
					debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", skip response because xlat type state was not DMA_ITAG_RET",
						   cmd->afu_name, (*head) );
					return;
				}
		}


		// if the state of the event is mem_done, we can potentially stop the loop and send a response for it.
		// if we not allowing reordering, we'll break the loop and use this event.
		// don't allow reordering while we sort this out.
		if ( ( (*head)->state == MEM_DONE ) ) { // && !allow_reorder(cmd->parms)) {
		  //debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", drive response because MEM_DONE",
		  //	   cmd->afu_name, (*head) );
		  break;
		}
		
		head = &((*head)->_next);
	}

	event = *head;

	// Randomly decide not to drive response yet - skip this for now
	// if ( ( event == NULL ) || ( ( event->client_state == CLIENT_VALID ) && 
	// 			    ( !allow_resp(cmd->parms) ) ) ) {
	//      debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 "skipped because suppressed by allow_resp", cmd->afu_name, event );
	// 	return;
	// }

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL)) {
	  //debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 " skipped because event or client NULL", cmd->afu_name, event );
	  // maybe we should free it too???
	  return;
	}

	// Send response, remove command from list and free memory
/*	if ((event->resp == TLX_RESPONSE_PAGED) ||
	    (event->resp == TLX_RESPONSE_AERROR) ||
	    (event->resp == TLX_RESPONSE_DERROR)) {
	        debug_msg( "%s:RESPONSE flushing events because this one is an error", cmd->afu_name );
		client->flushing = FLUSH_FLUSHING;
		_update_pending_resps(cmd, TLX_RESPONSE_FLUSHED);
	} */

 drive_resp:
	// debug - dump the event we picked...
	debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", command=0x%x, tag=0x%08x, type=0x%02x, state=0x%02x, resp=0x%x",
		   cmd->afu_name,
		   event,
		   event->command,
		   event->afutag,
		   event->type,
		   event->state,
		   event->resp );


	// lgt: this should probably be tlx_afu_send_resp_and_data
	//      the trick is going to be how do we deal with the various sizes of data
	//      do we transmit it all to afu_driver and let afu_driver partition it up? Yes
	//      do we buffer it in tlx_interface somehow? could be a good altenate
	// lgt: build the appropriate response for the event we selected
	if ( (event->command == AFU_CMD_DMA_W) || (event->command == AFU_CMD_DMA_W_N) ||
		(event->command == AFU_CMD_DMA_PR_W) || event->command == AFU_CMD_DMA_PR_W_N ) {
		
		if ( (event->command == AFU_CMD_DMA_W) || (event->command == AFU_CMD_DMA_W_N) ) {
			resp_dp = 0;
	    		resp_dl = size_to_dl( event->size );
		} else {
	    		resp_dp = 0;
	   		resp_dl = 64;
		}
	    rc = tlx_afu_send_resp( cmd->afu_event, 
					     TLX_RSP_WRITE_RESP, 
					     event->afutag, 
					     0, // resp_code - not really used for a good response
					     0, // resp_pg_size - not used by response, 
					     resp_dl,
	// one day have to add the conditional stuff for ocapi 4
					     resp_dp,
						0);

	// rc = tlx_response(cmd->afu_event, event->tag, event->resp, 1, 0, 0, cmd->pagesize, event->resp_extra);
	} else if ( (event->command == AFU_CMD_PR_RD_WNITC) || (event->command == AFU_CMD_PR_RD_WNITC_N) ) {
	    // we can just send the 64 bytes of data back
	    // and complete the event
	    rc = tlx_afu_send_resp_and_data( cmd->afu_event, 
					     TLX_RSP_READ_RESP, 
					     event->afutag, 
					     0, // resp_code - not really used for a good response
					     0, // resp_pg_size - not used by response, 
					     1, // for partials, dl is 1 (64 B)
					     0, // for partials, dp is 0 (the 0th part)
					     0, // resp_addr_tag, - not used by response
					     0, // resp_data_bdi - not used by response
					     event->data ) ; // data in this case is already at the proper offset in the 64 B data packet
	} else if ( (event->command == AFU_CMD_RD_WNITC) || (event->command == AFU_CMD_RD_WNITC_N) ) {
	    // we can:
	    //    send a complete response, with all the data
	    //    send partial responses, in any order, with aligned partial data (vary dl and dp in the response
	    //       power will likely send back chunks in <= 128 B responses...
	    //    responses can come back in any order
	    // I'm thinking ocse decides what response to send and whether or not to split it. 
	    // and sends all the data associated with the selected response.
	    // then tlx_interface/afu_driver forward the response portion and hold the data in a fifo linked list of 64 B values.
	    // then when the afu does a resp_rd_req of some resp_rd_cnt, tlx_interaface/afu_driver just starts pumping values out of the 
	    // fifo.  This method actually works for partial read as well as the minimum size of a split response is 64 B.
	    // it is the afu's responsiblity to manage resp_rd_cnt correctly, and this is not information for us to check
	    // anything other than an overrun (i.e. resp_rd_req of an empty fifo, or resp_rd_cnt exceeds the amount of data in the fifo)
	    resp_dl = size_to_dl( event->size );

	    // i don't think we can get a bad dl since we calculated size from dl in the first place...
	    // if ( resp_dl < 0 ) {
	    //   printf( "handle_response: invalid size\n" );
	    //   /* die somehow */ 
	    // }
		      
	    rc = tlx_afu_send_resp_and_data( cmd->afu_event, 
					     TLX_RSP_READ_RESP, 
					     event->afutag, 
					     0, // resp_code - not really used for a good response
					     0, // resp_pg_size - not used by response, 
					     resp_dl, // for partials, dl is 1 (64 B) - need to calculate dl from size or keep dl and dp around from initial command
					     0, // for partials, dp is 0 (the 0th part)
					     0, // resp_addr_tag, - not used by response
					     0, // resp_data_bdi - not used by good response
					     event->data ) ; // data in this case is already the complete length
	}
	   
	if (rc == TLX_SUCCESS) {
		debug_msg("%s:RESPONSE event @ 0x%016" PRIx64 ", sent tag=0x%02x code=0x%x", cmd->afu_name,
			  event, event->afutag, event->resp);
		debug_cmd_response(cmd->dbg_fp, cmd->dbg_id, event->tag);
		// if ( ( client != NULL ) && ( event->command == TLX_COMMAND_RESTART ) )
		// 	client->flushing = FLUSH_NONE;
		// if this was an xlat cmd, don't want to free the event so add code to check - HMP
	        if ( ( event->type == CMD_XLAT_RD ) ||
		     ( event->type == CMD_XLAT_WR ) ) {
		  debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", set state dma pending and tag to deadbeef",
			     cmd->afu_name,
			     event );
		  event->state = DMA_PENDING;
		  // do this to "free" the tag since AFU thinks it's free now
		  event->tag = 0xdeadbeef;
		  printf("DMA_PENDING set for event \n");
		  cmd->credits++;
		} else {
	          debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", free event",
			     cmd->afu_name,
			     event );
		  *head = event->_next;
		  free(event->data);
		  free(event->parity);
		  free(event);
		  cmd->credits++;
		}
	} else {
		  debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", _response() faled",
			     cmd->afu_name,
			     event );
	}
}

int client_cmd(struct cmd *cmd, struct client *client)
{
	int rc = 0;
	struct cmd_event *event = cmd->list;

	while (event != NULL) {
		if (event->context != client->context) {
			// Event is not for this client
			event = event->_next;
			continue;
		}
		if ((client->state == CLIENT_NONE) &&
		    (event->state != MEM_DONE)) {
			// Client dropped, terminate event
			event->state = MEM_DONE;
			if ((event->type == CMD_READ) ||
			    (event->type == CMD_WRITE) ||
			    (event->type == CMD_TOUCH)) {
				event->resp = TLX_RESPONSE_FAILED;
			}
			event = event->_next;
			continue;
		}
		if (client->state == CLIENT_VALID) {
			// Event is for client in valid state
			return 1;
		}
		event = event->_next;
	}
	return rc;
}
