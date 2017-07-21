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

  debug_msg("_find_client_by_pasid_and_bdf: seeking client with bdf=0x%04x; pasid=0x%08x", cmd_bdf, cmd_pasid );
  for (i = 0; i < cmd->max_clients; i++) {
    if (cmd->client[i] != NULL) {
      debug_msg("_find_client_by_pasid_and_bdf: client i=%d; bdf=0x%04x; pasid=0x%08x", i, cmd->client[i]->bdf, cmd->client[i]->pasid );
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
  	  debug_msg("_find_client_by_actag:  client with actag=0x%04x; i=0x%x", cmd_actag, i );
	  return i;
      }
    }
  }
  return -1;
}

//DO we keep and reuse?
/* static void _print_event(struct cmd_event *event)
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
} */

// Update all pending responses at once to new state - do we KEEP?
/*static void _update_pending_resps(struct cmd *cmd, uint32_t resp)
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
} */

static struct client *_get_client(struct cmd *cmd, struct cmd_event *event)
{
	// Make sure cmd and client are still valid
	if ((cmd == NULL) || (cmd->client == NULL) ||
	    (event->context >= cmd->max_clients))
		return NULL;

	// Abort if client disconnected
	//if (cmd->client[event->context] == NULL) {
	if (cmd->client[event->context] < 0) {
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
		     uint32_t resp, uint8_t unlock , uint8_t cmd_data_is_valid,
		     uint64_t wr_be, uint8_t cmd_flag, uint8_t cmd_endian)

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
	event->wr_be = wr_be;
	event->cmd_flag = cmd_flag;
	event->cmd_endian = cmd_endian;

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
		printf("Getting ready to copy first chunk of write data to buffer & add=0x%016"PRIx64" & size=0x%x .\n", event->addr, size);
		// alway copy 64 bytes...
		memcpy((void *)&(event->data[0]), (void *)&(cmd->afu_event->afu_tlx_cdata_bus), 64);
		// for type = cmd_interrupt, event->state is already correctly set to MEM_IDLE
		if (event->type != CMD_INTERRUPT) {
		  if (size > 64) {
		    // but if size is greater that 64, we have to gather more data
		    event->dpartial =64;
		    event->state = MEM_BUFFER;
		  }
		  else  {
		    event->state = MEM_RECEIVED;
		    event->dpartial =0;
		  }
		}
	
	}

}

// Format and add interrupt to command list

 static void _add_interrupt(struct cmd *cmd, uint16_t actag, uint16_t afutag, 
 			   uint8_t cmd_opcode, uint8_t *cmd_ea_or_obj, uint16_t size, uint8_t cmd_data_is_valid, uint8_t cmd_flag) 
 { 
 	//uint32_t resp = TLX_RSP_INTRP_RESP; 
 	uint32_t resp= 0; //FOR NOW, always a good response
 	//enum cmd_type type = CMD_INTERRUPT; 
        uint32_t context;
        uint64_t addr;
 
        context = _find_client_by_actag(cmd, actag);
	if (context < 0) warn_msg( "_add_interrupt: actag does not match a client" );

	memcpy( (void *)&addr, (void *)&(cmd_ea_or_obj[0]), sizeof(uint64_t));
 
        // setting MEM_IDLE will tell handle_interrupt to send req to libocxl 
        if (cmd_opcode == AFU_CMD_WAKE_HOST_THRD)
		_add_cmd(cmd, context, afutag, cmd_opcode, CMD_WAKE_HOST_THRD, addr, size, MEM_IDLE,
		 resp, 0, cmd_data_is_valid, 0, cmd_flag, 0);
	else  //must be some type of INTR request
		_add_cmd(cmd, context, afutag, cmd_opcode, CMD_INTERRUPT, addr, size, MEM_IDLE,
		 resp, 0, cmd_data_is_valid, 0, cmd_flag, 0);
 } 

// Format and add misc. command to list
static void _add_other(struct cmd *cmd, uint16_t actag, uint32_t afutag,
		       uint32_t cmd_opcode, uint32_t resp)
{
        int32_t context;
 
        context = _find_client_by_actag(cmd, actag);
	_add_cmd(cmd, context, afutag, cmd_opcode, CMD_OTHER, 0, 0, MEM_DONE,
		 resp, 0, 0, 0, 0, 0);
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


// Format and add memory xlate touch to command list
 static void _add_xlate_touch(struct cmd *cmd, uint16_t actag, uint16_t afutag, 
 			   uint8_t cmd_opcode, uint8_t *cmd_ea_or_obj, uint8_t cmd_flag) 
 { 
        int64_t addr;
	uint32_t size = 64;
        // convert 68 bit ea/obj to 64 bit addr
        // for ap write commands, ea_or_obj is a 64 bit thing...
        memcpy( (void *)&addr, (void *)&(cmd_ea_or_obj[0]), sizeof(int64_t));
 	// Check command size and address */
 	if (!_aligned(addr, size)) { 
 		_add_other(cmd, actag, afutag, cmd_opcode, 
 			   0xc0); 
 		return; 
 	} 
        int32_t context;
        context = _find_client_by_actag(cmd, actag);
	// TODO actually do something. For now, we always send back long backoff resp (0x04)
	_add_cmd(cmd, context, afutag, cmd_opcode, CMD_TOUCH, addr, 0, MEM_DONE,
		 0x04, 0, 0, 0, 0, 0);
 } 


// Format and add memory read to command list
static void _assign_actag(struct cmd *cmd, uint16_t cmd_bdf, uint32_t cmd_pasid, uint16_t actag)
{
  struct client *client;
  // search the client array in cmd for a matching pasid and bdf.  fill in the actag field.
  client = _find_client_by_pasid_and_bdf(cmd, cmd_bdf, cmd_pasid);
  if (client == NULL) {
    // some kind of error and return...  no way to respond to afu, so just a message???
    debug_msg("_assign_actag: client not found with bdf=0x%04x; pasid=0x%08x", cmd_bdf, cmd_pasid );
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
 
	
	debug_msg("_add_read:entered" );
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

	debug_msg("_add_read:calling _add_cmd context=%d; command=0x%02x; addr=0x%016"PRIx64"; size=0x%04x; afutag=0x%04x", 
		context, cmd_opcode, addr, size, afutag );
	// Reads will be added to the list and will next be processed
	// in the function handle_buffer_write()
	_add_cmd(cmd, context, afutag, cmd_opcode, CMD_READ, addr, size,
		 MEM_IDLE, TLX_RESPONSE_DONE, 0, 0, 0, 0, 0);
}

// Format and add AMO read or write to command list
static void _add_amo(struct cmd *cmd, uint16_t actag, uint16_t afutag,
		      uint8_t cmd_opcode, enum cmd_type type, uint8_t *cmd_ea_or_obj, 
		      uint8_t cmd_pl, uint8_t cmd_data_is_valid, uint8_t cmd_flag, uint8_t cmd_endian)
{
        int32_t context, size, sizecheck;
        int64_t addr;
 
        // convert 68 bit ea/obj to 64 bit addr
        // for ap write commands, ea_or_obj is a 64 bit thing...
        memcpy( (void *)&addr, (void *)&(cmd_ea_or_obj[0]), sizeof(int64_t));
	// check cmd_pl  size. Only certain values are valid
	// TODO NOTE: Expect to get 64B un data buffer, with 16B of data payload starting
	// at address offset. When data goes over to libocxl we extract and send 16B ALWAYS
	// for AMO_WR and AMO_RW unless told elsewise. AMO_RD has no immediate data

	size = 16;
  	switch (cmd_pl) {
  		case 2: 
  		case 3:
			if ((cmd_opcode == AFU_CMD_AMO_RW) || (cmd_opcode == AFU_CMD_AMO_RW_N))  {
				if (cmd_flag >= 0x8)  {
					warn_msg("AMO_RW has invalid cmd_pl:%d", cmd_pl);
					size= -1;
				}
			} 
			if (cmd_pl == 2)
				sizecheck = 4;
			else sizecheck = 8;
			break;
 
  		case 6:
  		case 7:	
			if ((cmd_opcode == AFU_CMD_AMO_W) || (cmd_opcode == AFU_CMD_AMO_W_N))  {
				warn_msg("AMO_WR has invalid cmd_pl:%d", cmd_pl);
				size= -1;
			}
			if (cmd_pl == 6)
				sizecheck = 4;
			else sizecheck = 8;
    			break;
  		default:
    			warn_msg("AMO with Unsupported pl: %d", cmd_pl);
    			size = -1;
    			break;
  		}
	if ( size == -1) {
	debug_msg("AMO CMD FAILED SIZE CHECKS cmd_pl= 0x%x, cmd_flag=0x%x !!! ", cmd_pl, cmd_flag);
	  _add_other(cmd, actag, afutag, cmd_opcode,
			   TLX_RESPONSE_FAILED);
		return;
	}
	// Check command size and address
	if (!_aligned(addr, sizecheck )) {
	debug_msg("AMO CMD FAILED ADDR ALIGN CHECKS!!! ");
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

	// Command data comes over with the command for amo_rw and amo_w, so now we need to read it from event
	// Then, next step is to send over to client/libocxl for processing
	
	_add_cmd(cmd, context, afutag, cmd_opcode, type, addr, (uint16_t)sizecheck,
		 MEM_IDLE, TLX_RESPONSE_DONE, 0, cmd_data_is_valid, 0, cmd_flag, cmd_endian);
}



// Format and add memory write to command list
static void _add_write(struct cmd *cmd, uint16_t actag, uint16_t afutag,
		      uint8_t cmd_opcode, uint8_t *cmd_ea_or_obj, 
		      uint32_t size, uint8_t cmd_data_is_valid, uint64_t cmd_be)
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

        // convert actag to a context - search the client array contained in cmd for a client with matching actag
	context = _find_client_by_actag(cmd, actag);

	// Command data comes over with the command, so read it from event and put it in buffer in add_cmd
	// Then, next step is to make the memory write request?
	
	// Longer Writes will be added to the list and will next be processed
	// in handle_afu_tlx_cmd_data_read
	// TODO add CAPI4 BE opcodes to if
	debug_msg("_add_write:calling _add_cmd context=%d; command=0x%02x; addr=0x%016"PRIx64"; size=0x%04x; afutag=0x%04x", 
		context, cmd_opcode, addr, size, afutag );
	if ((cmd_opcode == AFU_CMD_DMA_W_BE) || (cmd_opcode == AFU_CMD_DMA_W_BE_N))
		_add_cmd(cmd, context, afutag, cmd_opcode, CMD_WR_BE, addr, size,
			 MEM_IDLE, TLX_RESPONSE_DONE, 0, cmd_data_is_valid, cmd_be, 0, 0);
	else
		_add_cmd(cmd, context, afutag, cmd_opcode, CMD_WRITE, addr, size,
			 MEM_IDLE, TLX_RESPONSE_DONE, 0, cmd_data_is_valid, 0, 0, 0);
}


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
		debug_msg("YES! AFU cmd is ASSIGN_ACTAG!!!!\n");
                _assign_actag( cmd, cmd_bdf, cmd_pasid, cmd_actag );
		break;
		// Memory Reads
	case AFU_CMD_RD_WNITC:
	case AFU_CMD_RD_WNITC_N:
		debug_msg("YES! AFU cmd is some sort of read!!!!\n");
		// calculate size from dl
		_add_read(cmd, cmd_actag, cmd_afutag, cmd_opcode,
			 cmd_ea_or_obj, dl_to_size( cmd_dl ));
		break;
	case AFU_CMD_PR_RD_WNITC:
	case AFU_CMD_PR_RD_WNITC_N:
		debug_msg("YES! AFU cmd is some sort of partial read!!!!\n");
		// calculate size from pl
		_add_read(cmd, cmd_actag, cmd_afutag, cmd_opcode, 
			 cmd_ea_or_obj, pl_to_size( cmd_pl ));
		break;
		// Memory Writes
	case AFU_CMD_DMA_W:
	case AFU_CMD_DMA_W_N:
		debug_msg("YES! AFU cmd is some sort of write!!!!\n");
		_add_write(cmd, cmd_actag, cmd_afutag, cmd_opcode, 
			  cmd_ea_or_obj, dl_to_size( cmd_dl ), cmd_data_is_valid, 0);
		break;
	case AFU_CMD_DMA_PR_W:
	case AFU_CMD_DMA_PR_W_N:
		debug_msg("YES! AFU cmd is some sort of partial write!!!!\n");
		_add_write(cmd, cmd_actag, cmd_afutag, cmd_opcode,
			  cmd_ea_or_obj, pl_to_size( cmd_pl ), cmd_data_is_valid, 0);
		break;
		// Memory Writes with Byte Enable 
	case AFU_CMD_DMA_W_BE:
	case AFU_CMD_DMA_W_BE_N:
		debug_msg("YES! AFU cmd is some sort of write w/BE!!!!\n");
		_add_write(cmd, cmd_actag, cmd_afutag, cmd_opcode, 
			  cmd_ea_or_obj, 64, cmd_data_is_valid, cmd_be);
		break;
		// AMO reads and writes
	case AFU_CMD_AMO_RD:
	case AFU_CMD_AMO_RD_N:
		debug_msg("YES! AFU cmd is some sort of AMO read!!!!\n");
		_add_amo(cmd, cmd_actag, cmd_afutag, cmd_opcode, CMD_AMO_RD, 
			  cmd_ea_or_obj, cmd_pl, cmd_data_is_valid, cmd_flag, cmd_endian);
		break;
	case AFU_CMD_AMO_RW:
	case AFU_CMD_AMO_RW_N:
		debug_msg("YES! AFU cmd is some sort of AMO read/write w/cmd_pl= 0x%x!!!!\n", cmd_pl);
		_add_amo(cmd, cmd_actag, cmd_afutag, cmd_opcode, CMD_AMO_RW, 
			  cmd_ea_or_obj, cmd_pl, cmd_data_is_valid, cmd_flag, cmd_endian);
		break;
	case AFU_CMD_AMO_W:
	case AFU_CMD_AMO_W_N:
		debug_msg("YES! AFU cmd is some sort of AMO read or write!!!!");
		_add_amo(cmd, cmd_actag, cmd_afutag, cmd_opcode, CMD_AMO_WR, 
			  cmd_ea_or_obj, cmd_pl, cmd_data_is_valid, cmd_flag, cmd_endian);
		break;
		// Interrupt
	case AFU_CMD_INTRP_REQ_D: // not sure POWER supports this one?
		debug_msg("YES! AFU cmd is  INTRPT REQ WITH DATA");
		_add_interrupt(cmd, cmd_actag, cmd_afutag, cmd_opcode,
			  cmd_ea_or_obj, pl_to_size( cmd_pl), cmd_data_is_valid, cmd_flag);
		break;
	case AFU_CMD_INTRP_REQ:
	case AFU_CMD_WAKE_HOST_THRD:
		debug_msg("YES! AFU cmd is either INTRPT REQ or WAKE HOST THREAD");
		_add_interrupt(cmd, cmd_actag, cmd_afutag, cmd_opcode,
			  cmd_ea_or_obj, 0, cmd_data_is_valid, cmd_flag);
	// TODO what about stream_id ?
		break;
	case AFU_CMD_NOP:
		debug_msg("NOP CMD - No response needed");
		break;
	case AFU_CMD_XLATE_TOUCH:
	case AFU_CMD_XLATE_TOUCH_N:
		debug_msg("YES! AFU cmd is some kind of XLATE_TOUCH\n");
		_add_xlate_touch(cmd, cmd_actag, cmd_afutag, cmd_opcode,
			  cmd_ea_or_obj, cmd_flag);
		break;
	default:
		warn_msg("Unsupported command 0x%04x", cmd_opcode);
		_add_other(cmd, cmd_actag, cmd_afutag, cmd_opcode, TLX_RESPONSE_FAILED);
		break;
	}
}

// Report parity error on some command bus - Do we KEEP?
/*static void _cmd_parity_error(const char *msg, uint64_t value, uint8_t parity)
{
	error_msg("Command %s parity error 0x%04" PRIx64 ",%d", msg, value,
		  parity);
} */

// See if a command was sent by AFU and process if so
void handle_cmd(struct cmd *cmd, uint32_t latency)
{
	struct cmd_event *event;
	uint64_t cmd_be;
	uint32_t cmd_pasid;
	uint16_t cmd_actag, cmd_afutag, cmd_bdf;
	uint8_t  cmd_ea_or_obj[9]; 
	uint8_t  cmd_opcode, cmd_stream_id, cmd_dl, cmd_pl, cmd_flag, cmd_endian, cmd_pg_size, cmd_data_is_valid, cdata_bad;
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

	// int i;
	// printf( "handle_cmd:cmd->afu_event->afu_tlx_cdata_bus=0x" ); for (i=0; i<64; i++) printf("%02x",cmd->afu_event->afu_tlx_cdata_bus[i]); printf("\n");
	// printf( "handle_cmd:dptr=0x" ); for (i=0; i<64; i++) printf("%02x",dptr[i]); printf("\n");
	// printf( "handle_cmd:cdata_bus=0x" ); for (i=0; i<64; i++) printf("%02x",cdata_bus[i]); printf("\n");
	
	//rc = tlx_get_command(cmd->afu_event, &command, &command_parity, &tag,
	//		     &tag_parity, &address, &address_parity, &size,
	//		     &abort, &handle, &cpagesize

	// No command ready */
	if (rc != TLX_SUCCESS) 
		return;

	//	debug_msg( "%s:COMMAND actag=0x%02x afutag=0x%04x cmd=0x%x BDF=0x%x addr=0x%016"PRIx64 " cmd_data_is_valid= 0x%x ", 
	debug_msg( "%s:COMMAND actag=0x%02x afutag=0x%04x cmd=0x%x cmd_data_is_valid= 0x%x ", 
		   cmd->afu_name,
		   cmd_actag, 
		   cmd_afutag, 
		   cmd_opcode, 
		   cmd_data_is_valid );

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

	// Check for duplicate afutag 
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
	if ((event->state == MEM_RECEIVED) && (event->type == CMD_READ)) {
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
          	} //else {
	    	// unsupport read command message
	  	//	}
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
	        debug_msg("Setting client->mem_access in handle_buffer_write");
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
	            debug_msg("Setting client->mem_access in handle_buffer_write 2");
		}
	}
}

// Handle pending write data from AFU
void handle_afu_tlx_cmd_data_read(struct cmd *cmd)
{
	struct cmd_event *event;
	struct client *client;
	uint64_t *addr;
	uint64_t offset;
	unsigned char cdata_bus[64];
	uint8_t * dptr = cdata_bus;
	uint8_t cmd_data_is_valid, cdata_bad;
	uint8_t *buffer;
	int rc;

	// Check that cmd struct is valid buffer read is available
	if ((cmd == NULL) || (cmd->buffer_read == NULL))
		return;
	//printf("IN handle_afu_tlx_cmd_data \n");
	//First, let's look to see if any one is in MEM_BUFFER state...data still coming over the interface (should only be ONE @time)
	// or if anyone is in MEM_RECEIVED...all data is here & ready to go (should only be ONE of these @time)
	event = cmd->list;
	while (event != NULL) {
		if ((event->type == CMD_WRITE) && 
			((event->state == MEM_RECEIVED) || (event->state == MEM_BUFFER))) { 
		   // (event->state == MEM_TOUCHED) &&
		   // ((event->client_state != CLIENT_VALID) ||
		   //  !allow_reorder(cmd->parms))) {
			break;
		}
		event = event->_next;
	}

	// Test for client disconnect
	//if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
	if (event == NULL) 
		return;
			int i;
	if (event->state == MEM_BUFFER) {
	rc = afu_tlx_read_cmd_data(cmd->afu_event, &cmd_data_is_valid, dptr,  &cdata_bad);
	if (rc == TLX_SUCCESS) {
		if (cmd_data_is_valid) {
			debug_msg("Copy another chunk of write data to buffer & addr=0x%016"PRIx64"& total read so far=0x%x .\n", event->addr, event->dpartial);
			if ((event->size - event->dpartial) > 64) {
				memcpy((void *)&(event->data[event->dpartial]), (void *)&(cmd->afu_event->afu_tlx_cdata_bus), 64);
			debug_msg("SHOULD BE INTERMEDIATE COPY");
			for ( i = 0; i < 64; i++ ) printf("%02x",cmd->afu_event->afu_tlx_cdata_bus[i]); printf( "\n" ); 

				event->dpartial +=64;
				event->state = MEM_BUFFER;
			 }
			else  {
				memcpy((void *)&(event->data[event->dpartial]), (void *)&(cmd->afu_event->afu_tlx_cdata_bus), (event->size - event->dpartial));
			debug_msg("SHOULD BE FINAL COPY and event->dpartial=0x%x", event->dpartial);
			for ( i = 0; i < 64; i++ ) printf("%02x",cmd->afu_event->afu_tlx_cdata_bus[i]); printf( "\n" ); 
				event->state = MEM_RECEIVED;
				}
	
		}
	} else
		return;

	return;

        } else { // event->state=MEM_RECEIVED 
		if ((client = _get_client(cmd, event)) == NULL)
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
			if (event->size <=32) {
				offset = event->addr & ~CACHELINE_MASK;
				debug_msg("partial write: size=0x%x and offset=0x%x", event->size, offset);
				memcpy(&(buffer[11]), &(event->data[offset]), event->size);
			} else
				memcpy(&(buffer[11]), &(event->data[0]), event->size);
			event->abort = &(client->abort);
			debug_msg("%s: MEMORY WRITE afutag=0x%02x size=%d addr=0x%016"PRIx64" port=0x%2x",
		  		cmd->afu_name, event->afutag, event->size, event->addr, client->fd);
			if (put_bytes(client->fd, event->size + 11, buffer, cmd->dbg_fp,
		      		cmd->dbg_id, client->context) < 0) {
				client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
			}
		}
		event->state = DMA_MEM_RESP;  //we can't set MEM_DONE until we get ACK back from client (or else SEG FAULT)
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

// Handle  pending write_be or atomic op - send them to client for execution
// client will return response value for some AMO ops (state will be set to AMO_MEM_RESP)
void handle_write_be_or_amo(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint64_t offset;
	uint64_t *addr, *wr_be;
	uint16_t *size;
	uint8_t *buffer;

	// Check that cmd struct is valid
	if (cmd == NULL)
		return;

	// Send any ready write_be or AMO cmds to client immediately
	head = &cmd->list;
	while (*head != NULL) {
	  	//printf ("handle_write_be_or_amo: head->type is %2x, head->state is 0x%3x \n", (*head)->type, (*head)->state);
		if ((((*head)->type == CMD_WR_BE) || ((*head)->type == CMD_AMO_WR) ||
		    ((*head)->type == CMD_AMO_RW)) &&
		    ((*head)->state == MEM_RECEIVED))
			break;
		if (((*head)->type == CMD_AMO_RD)  && 
		   ((*head)->state == MEM_RECEIVED))  // TODO change this later, we did get data but it's not used
			break;

		head = &((*head)->_next);
	}
	event = *head;

	// Test for client disconnect or nothing to do....
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;
	// Check that memory request can be driven to client
	if (client->mem_access != NULL) {
		debug_msg("handle_write_be_or_amo: Can't send to client bc client->mem_access not NULL...retry later");
		return;
	}
	// Send cmd & data (if available) to client/libocxl to process
	// The request will now await confirmation from the client that the memory write/op was
	// successful before generating a response.
	if (event->type == CMD_WR_BE) {
		buffer = (uint8_t *) malloc(event->size + 19);
		buffer[0] = (uint8_t) OCSE_WR_BE;
		size = (uint16_t *)&(buffer[1]);
		*size = htons(event->size); //value of size alwayz 64 for this cmd
		addr = (uint64_t *) & (buffer[3]);
		*addr = htonll(event->addr);
		wr_be = (uint64_t *) & (buffer[11]);
		*wr_be = htonll(event->wr_be);
		memcpy(&(buffer[19]), &(event->data[0]), event->size);
		event->abort = &(client->abort);
		debug_msg("%s:WRITE_BE wr_be=0x%016"PRIx64" size=%d addr=0x%016"PRIx64" port=0x%2x",
		  	cmd->afu_name, event->wr_be, event->size, event->addr, client->fd);
		if (put_bytes(client->fd, event->size + 19, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) 
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	} else if (event->type == CMD_AMO_WR || event->type == CMD_AMO_RW) { //these have data from cdata_bus
				
		offset = event->addr & ~CACHELINE_MASK;
			buffer = (uint8_t *) malloc(28);
		if (event->type == CMD_AMO_WR) 
			buffer[0] = (uint8_t) OCSE_AMO_WR;
		 else // (event->type == CMD_AMO_RW)
			buffer[0] = (uint8_t) OCSE_AMO_RW;
		buffer[1] = (uint8_t)event->size;
		//size = (uint16_t *)&(buffer[1]);
		//*size = htons(event->size);
		addr = (uint64_t *) & (buffer[2]);
		*addr = htonll(event->addr);
		buffer[10] = event->cmd_flag;
		buffer[11] = event->cmd_endian;
		memcpy(&(buffer[12]), &(event->data[offset]), 16);
		event->abort = &(client->abort);

		debug_msg("%s:AMO_WR or AMO_RW cmd_flag=0x%02x size=%d addr=0x%016"PRIx64" port=0x%2x",
		  	cmd->afu_name, event->cmd_flag, event->size, event->addr, client->fd);
		if (put_bytes(client->fd, 28, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) 
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	} else if (event->type == CMD_AMO_RD ) {  //these have no data, use just memory ops. Still need op_size though
		buffer = (uint8_t *) malloc(12); //or 13??
		buffer[0] = (uint8_t) OCSE_AMO_RD;
		buffer[1] = (uint8_t)event->size;
		//size = (uint16_t *)&(buffer[1]);
		//*size = htons(event->size);
		addr = (uint64_t *) & (buffer[2]);
		*addr = htonll(event->addr);
		buffer[10] = event->cmd_flag;
		buffer[11] = event->cmd_endian;
		event->abort = &(client->abort);

		debug_msg("%s:AMO_RD cmd_flag=0x%02x size=%d addr=0x%016"PRIx64" port=0x%2x",
		  	cmd->afu_name, event->cmd_flag, event->size, event->addr, client->fd);
		if (put_bytes(client->fd, 12, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) 
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}


	client->mem_access = (void *)event;
	debug_msg("Setting client->mem_access in handle_write_be_or_amo");
	return;


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
	debug_msg("Setting client->mem_access in handle_touch");
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
}

// Send pending interrupt to client as soon as possible
void handle_interrupt(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	// uint16_t irq;
	uint64_t offset;
	uint16_t byte_count;
	uint8_t buffer[45];

	debug_msg( "ocse:handle_interrupt:" );

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;
	debug_msg( "ocse:handle_interrupt:valid cmd available" );

	// Send any interrupts to client immediately
	head = &cmd->list;
	while (*head != NULL) {
		if ((((*head)->type == CMD_INTERRUPT) || ((*head)->type == CMD_WAKE_HOST_THRD)) &&
		    (((*head)->state == MEM_IDLE) || ((*head)->state == MEM_RECEIVED)))
			break;
		head = &((*head)->_next);
	}
	event = *head;

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL)) 
		return;
	// Send interrupt or wake_host_thread request to client
	if (event->type == CMD_WAKE_HOST_THRD)
		buffer[0] = OCSE_WAKE_HOST_THREAD;
	else if (event->command == AFU_CMD_INTRP_REQ_D) 
			buffer[0] = OCSE_INTERRUPT_D;
		else
			buffer[0] = OCSE_INTERRUPT;

	memcpy(&(buffer[1]), &event->cmd_flag, 1);
	memcpy(&(buffer[2]), &event->addr, 8);
	byte_count = 10;

	if (event->command == AFU_CMD_INTRP_REQ_D) {
		offset = event->addr & ~CACHELINE_MASK;
		memcpy(&(buffer[10]), &event->size, 2);
		byte_count += 2;
		memcpy(&(buffer[12]), &(event->data[offset]), event->size);
		byte_count += event->size;
	}

	// do we still need this event->abort???
	event->abort = &(client->abort);

	debug_msg( "ocse:handle_interrupt: cmd=0x%02x cmd_flag=%d addr=0x%016"PRIx64, 
		   event->command, 
		   event->cmd_flag, 
		   event->addr );

	if (put_bytes(client->fd, byte_count, buffer, cmd->dbg_fp, cmd->dbg_id,
		      event->context) < 0) {
		client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	}
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);

	// this assumes the wake host thread finds a thread
	// should add a path for a negative response from libocxl application
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
	client->mem_access = (void *)event;
	debug_msg("Setting client->mem_access in handle_mem_write");
}

// Handle data returning from client for memory read
static void _handle_mem_read(struct cmd *cmd, struct cmd_event *event, int fd)
{
	uint8_t data[MAX_LINE_CHARS];
	uint64_t offset = event->addr & ~CACHELINE_MASK;

	// printf ("_handle_mem_read: event->type is %2x, event->state is 0x%3x \n", event->type, event->state);
	if (event->type == CMD_READ) { 
	        //printf ("_handle_mem_read: CMD_READ \n" );
		// Client is returning data from memory read
		if (get_bytes_silent(fd, event->size, data, cmd->parms->timeout,
			     event->abort) < 0) {
	        	debug_msg("%s:_handle_mem_read failed afutag=0x%04x size=%d addr=0x%016"PRIx64,
				  cmd->afu_name, event->afutag, event->size, event->addr);
			//event->resp = TLX_RESPONSE_DERROR;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
			return;
		}
		// we used to put the data in the event->data at the offset implied by the address
		// should we still do that?  It might depend on the the actual ap command that we received.
		memcpy((void *)&(event->data[offset]), (void *)&data, event->size);
		// parity is no long required. although we might want to set the bad data indicator for 
		// bad machine path simulations.
		generate_cl_parity(event->data, event->parity);
		event->state = MEM_RECEIVED;
	}
        // have to expect data back from some AMO ops
	else if ((event->type == CMD_AMO_RD) || (event->type == CMD_AMO_RW)) {
		// Client is returning data from AMO memory read
                 debug_msg( "_handle_mem_read: AFU_CMD_AMO_RD or AFU_CMD_AMP_RW \n" );
		if (get_bytes_silent(fd, event->size, data, cmd->parms->timeout,
			     event->abort) < 0) {
	        	debug_msg("%s:_handle_amo_mem_read failed tag=0x%02x size=%d addr=0x%016"PRIx64,
				  cmd->afu_name, event->afutag, event->size, event->addr);
			//event->resp = TLX_RESPONSE_DERROR;
			event->state = MEM_DONE;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
			return;
		}
		// DMA return data goes at offset 0 in the event data instead of some other offset.
                // should we clear event->data first?
		memcpy((void *)&(event->data[offset]), (void *)&data, event->size);
	        debug_msg("%s:_handle_amo_mem_read DONE tag=0x%02x size=%d addr=0x%016"PRIx64,
			  cmd->afu_name, event->afutag, event->size, event->addr);
		event->state = MEM_DONE;

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
	// TODO update this entire section to work for new AMO_RD and AMO_RW that return data!!
	//if ((event->type == CMD_READ) ||
	//	 (((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) && event->state != MEM_CAS_WR))
	if (event->type == CMD_READ) 
		_handle_mem_read(cmd, event, fd);
	if (event->type == CMD_WRITE) 
		event->state = MEM_DONE;
 	// have to account for AMO RD or RW cmds with returned data
 	//else if (event->type == CMD_DMA_RD)
	//	_handle_mem_read(cmd, event, fd);
	else if ((event->type == CMD_AMO_RD) || (event->type == CMD_AMO_RW)) {
		// Client is returning data from AMO memory read or rw
                 debug_msg( "_handle_mem_return: CMD_DMA_RD or CMD_DMA_WR_AMO " );
		_handle_mem_read(cmd,event,fd);
		// have to set size back 
		if (event->size == 4)
			event->size = 2;
		else 
			event->size = 3;
		  }
	//else if ((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B))
	//		event->state = MEM_DONE;

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

// Send a randomly selected pending response back to AFU
void handle_response(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint8_t resp_dl, resp_dp;
	int rc = 0;

	// Select a random pending response (or none)
	client = NULL;
	head = &cmd->list;
	while (*head != NULL) {
		// if the state of the event is mem_done, we can potentially stop the loop and send a response for it.
		// if we not allowing reordering, we'll break the loop and use this event.
		// don't allow reordering while we sort this out.
		if ( ( (*head)->state == MEM_DONE ) ) { // && !allow_reorder(cmd->parms)) 
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

 //`drive_resp:
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
		(event->command == AFU_CMD_AMO_W) || (event->command == AFU_CMD_AMO_W_N) ||
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
	} else if ( (event->command == AFU_CMD_PR_RD_WNITC) || (event->command == AFU_CMD_PR_RD_WNITC_N) || 
		    (event->command == AFU_CMD_AMO_RD) || (event->command == AFU_CMD_AMO_RD_N) ||
		    (event->command == AFU_CMD_AMO_RW) || (event->command == AFU_CMD_AMO_RW_N) ) {
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
	} else if ( (event->command == AFU_CMD_RD_WNITC) || (event->command == AFU_CMD_RD_WNITC_N) ){
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
	} else if ((event->command == AFU_CMD_INTRP_REQ ) || (event->command == AFU_CMD_INTRP_REQ_D)) {
  		rc = tlx_afu_send_resp( cmd->afu_event,TLX_RSP_INTRP_RESP,event->afutag, 
					     event->resp, // resp_code - right now always a good response
					     0, 0, 0, 0);
	} else if (event->command == AFU_CMD_WAKE_HOST_THRD ) {
  		rc = tlx_afu_send_resp( cmd->afu_event,TLX_RSP_WAKE_HOST_RESP,event->afutag, 
					     event->resp, // resp_code - right now always a good response
					     0, 0, 0, 0);
	} else if ((event->command == AFU_CMD_XLATE_TOUCH ) || (event->command == AFU_CMD_XLATE_TOUCH_N )) {
  		rc = tlx_afu_send_resp( cmd->afu_event,TLX_RSP_TOUCH_RESP,event->afutag, 
					     event->resp, // resp_code - right now always a pending(0x4) or fail(0xc) response
					     0, 0, 0, 0);
		}
	   
	if (rc == TLX_SUCCESS) {
		debug_msg("%s:RESPONSE event @ 0x%016" PRIx64 ", sent tag=0x%02x code=0x%x", cmd->afu_name,
			  event, event->afutag, event->resp);
		debug_cmd_response(cmd->dbg_fp, cmd->dbg_id, event->tag);
		// if ( ( client != NULL ) && ( event->command == TLX_COMMAND_RESTART ) )
		// 	client->flushing = FLUSH_NONE;
		// if this was an xlat cmd, don't want to free the event so add code to check - HMP
	        //if ( ( event->type == CMD_XLAT_RD ) ||
		//     ( event->type == CMD_XLAT_WR ) ) {
		//  debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", set state dma pending and tag to deadbeef",
		//	     cmd->afu_name,
		//	     event );
		//  event->state = DMA_PENDING;
		  // do this to "free" the tag since AFU thinks it's free now
		//  event->tag = 0xdeadbeef;
		//  printf("DMA_PENDING set for event \n");
		//  cmd->credits++;
	//	} else {
	          debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", free event",
			     cmd->afu_name,
			     event );
		  *head = event->_next;
		  free(event->data);
		  free(event->parity);
		  free(event);
		  cmd->credits++;
	//	}
	} else {
		  debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", _response() failed",
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
