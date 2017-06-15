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
 * Description: mmio.c
 *
 *  This file contains the code for MMIO access to the AFU including the
 *  AFU configuration space.  Only one MMIO access is legal at a time.  So each
 *  client only tracks up to one mmio_access at a time.  However, since a
 *  "directed mode" AFU may have multiple clients attached the mmio struct
 *  tracks multiple mmio accesses with the element "list."  As MMIO requests
 *  are received from clients they are added to the list and handled in FIFO
 *  order.  The _add_event() function places each new MMIO event on the list
 *  as they are received from a client.  The ocl code will periodically call
 *  send_mmio() which will drive the oldest pending MMIO command event to the AFU.
 *  That event is put in PENDING state which blocks the OCL from sending any
 *  further MMIO until this MMIO event completes.  When the ocl code detects
 *  the MMIO response it will call handle_mmio_ack().  This function moves
 *  the list head to the next event so that the next MMIO request can be sent.
 *  However, the event still lives and the client will still point to it.  When
 *  the ocl code next calls handle_mmio_done for that client it will return the
 *  acknowledge as well as any data to the client.  At that point the event
 *  memory will be freeded.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include "../common/debug.h"
#include "mmio.h"

// Initialize MMIO tracking structure
struct mmio *mmio_init(struct AFU_EVENT *afu_event, int timeout, char *afu_name,
		       FILE * dbg_fp, uint8_t dbg_id)
{
	struct mmio *mmio = (struct mmio *)calloc(1, sizeof(struct mmio));
	if (!mmio)
		return mmio;
	mmio->afu_event = afu_event;
	mmio->list = NULL;
	mmio->afu_name = afu_name;
	mmio->dbg_fp = dbg_fp;
	mmio->dbg_id = dbg_id;
	mmio->timeout = timeout;
	return mmio;
}

// Add new MMIO event
static struct mmio_event *_add_event(struct mmio *mmio, struct client *client,
				     uint32_t rnw, uint32_t dw, int global, uint64_t addr,
				     uint32_t cfg, uint64_t data)
{
	struct mmio_event *event;
	struct mmio_event **list;
	uint16_t context;

	// Add new event in IDLE state
	event = (struct mmio_event *)malloc(sizeof(struct mmio_event));
	if (!event)
		return event;
	event->rnw = rnw;
	event->dw = dw;
	if (client == NULL)  {
	  // is this case where cfg = 1, that is, we want to read config space?
	  // yes, when we do mmios to config space, we force client to null
	  event->cmd_PA = addr;
	} else {
	  // for OpenCAPI, the mmio space is split into global and per pasid
	  // the global parm controls how we adjust the offset prior to adding the event
	  //   global = 1 means we offset based on the global mmio offset from the configuration
	  //   global = 0 means we want to send the offset adjusted by the per pasid mmio offset, per pasid mmio stride, and client index
	  //   for now, we are assuming the client index (context) maps directly to a pasid.  
	  //        we could be more creative and relocate the pasid base and pasid length supported to 
	  //        provide more verification coverage
	  if (global == 1) {
	    // global mmio offset + offset
	    // TODO offset is NOW 64b, comprised of offset_high & offset_low
	    event->cmd_PA = mmio->cfg.global_MMIO_offset_low + addr;
	  } else {
	    // per pasid mmio offset + (client context * stride) + offset
	    // TODO offset is NOW 64b, comprised of offset_high & offset_low
	    event->cmd_PA = mmio->cfg.pp_MMIO_offset_low + (mmio->cfg.pp_MMIO_stride * client->context) + addr;
	  }
	}
	// event->addr = addr;
	event->cfg = cfg;
	event->cmd_data = data;
	event->state = OCSE_IDLE;
	event->_next = NULL;

	// debug the mmio and print the input address and the translated address
	// debug_msg("_add_event: %s: WRITE%d word=0x%05x (0x%05x) data=0x%s",
	 debug_msg("_add_event:: WRITE word=0x%05x (0x%05x) data=0x%x",
	 //	  mmio->afu_name, event->dw ? 64 : 32,
	 	  event->cmd_PA, addr, event->cmd_data);

	// Add to end of list
	list = &(mmio->list);
	while (*list != NULL)
		list = &((*list)->_next);
	*list = event;
	if (cfg)
		context = -1;
	else
		context = client->context;
	debug_mmio_add(mmio->dbg_fp, mmio->dbg_id, context, rnw, dw, addr);

	return event;
}

// Add AFU config space (config_rd, config_wr) access event
static struct mmio_event *_add_cfg(struct mmio *mmio, uint32_t rnw,
				    uint32_t dw, uint64_t addr, uint64_t data)
{
        return _add_event(mmio, NULL, rnw, dw, 0, addr, 1, data);
}

// Add AFU MMIO (non-config) access event
static struct mmio_event *_add_mmio(struct mmio *mmio, struct client *client,
				    uint32_t rnw, uint32_t dw, int global, uint64_t addr,
				    uint64_t data)
{
	return _add_event(mmio, client, rnw, dw, global, addr, 0, data);
}

static void _wait_for_done(enum ocse_state *state, pthread_mutex_t * lock)
{
	while (*state != OCSE_DONE)	/* infinite loop */
		lock_delay(lock);
}

// Read the AFU config_record, extended capabilities (if any), PASID extended capabilities,
// OpenCAPI TL extended capabilities, AFU info extended capabilites (AFU descriptor)
// and AFU control information extended capabilities and keep a copy
int read_afu_config(struct mmio *mmio, pthread_mutex_t * lock)
{
//	For now, we "know" where things are, so just queue up reads...
//      TODO write back pasid length enabled ( = pasid length supported )
//	TODO change to read capabilities pointers and use offsets to index
//	TODO relocate and write back pasid base
//      TODO write back pasid length enabled ( < pasid length supported )

	printf("In read_descriptor and WON'T BE ABLE TO SEND CMD UNTIL AFU GIVES US INITIAL CREDIT!!\n");
	uint8_t   afu_tlx_cmd_credits_available;
	uint8_t   afu_tlx_resp_credits_available;
	#define AFU_DESC_DATA_VALID 0x80000000

	printf("before read initial credits \n");
	//if (afu_tlx_read_initial_credits(mmio->afu_event, &afu_tlx_cmd_credits_available,
	 //&afu_tlx_resp_credits_available) != TLX_SUCCESS)
	//	printf("NO CREDITS FROM AFU!!\n");
	while (afu_tlx_read_initial_credits(mmio->afu_event, &afu_tlx_cmd_credits_available,
	 &afu_tlx_resp_credits_available) != TLX_SUCCESS){
	  //infinite loop
	  sleep(1);
	}
	printf("afu_tlx_cmd_credits_available is %d, afu_tlx_resp_credits_available is %d \n",
		afu_tlx_cmd_credits_available, afu_tlx_resp_credits_available);

 	struct mmio_event *event00, *event110, *event114, *event200, *event204,
	    *event20c, *event224, *event26c, *event300, *event304, *event308,
	    *event400, *event404, *event408, *event40c, *event410,
	    *event500, *event504, *event508, *event50c, *event510, *event514,
	    *event518, *event51c;

	uint64_t cmd_pa;
	cmd_pa = 0x00000000cdef0000; // per Lance, only need BDF for config
	// Queue mmio reads - these go out in order, gated (eventually) by credits
	event00 = _add_cfg(mmio, 1, 0, cmd_pa, 0L);
	event110 = _add_cfg(mmio, 1, 0, cmd_pa + 0x110, 0L);
	event114 = _add_cfg(mmio, 1, 0, cmd_pa + 0x114, 0L);
	event200 = _add_cfg(mmio, 1, 0, cmd_pa + 0x200, 0L);
	event204 = _add_cfg(mmio, 1, 0, cmd_pa + 0x204, 0L);
	event20c = _add_cfg(mmio, 1, 0, cmd_pa + 0x20c, 0L);
	event224 = _add_cfg(mmio, 1, 0, cmd_pa + 0x224, 0L);
	event26c = _add_cfg(mmio, 1, 0, cmd_pa + 0x26c, 0L);
	event300 = _add_cfg(mmio, 1, 0, cmd_pa + 0x300, 0L);
	event304 = _add_cfg(mmio, 1, 0, cmd_pa + 0x304, 0L);
	event308 = _add_cfg(mmio, 1, 0, cmd_pa + 0x308, 0L);
	//  AFU info DVSEC is NOW at 0x400
	event400 = _add_cfg(mmio, 1, 0, cmd_pa + 0x400, 0L);
	event404 = _add_cfg(mmio, 1, 0, cmd_pa + 0x404, 0L);
	event408 = _add_cfg(mmio, 1, 0, cmd_pa + 0x408, 0L);
	// this means afu_desc offset reg is 0x40c & data is 0x410
	event500 = _add_cfg(mmio, 1, 0, cmd_pa + 0x500, 0L);
	event504 = _add_cfg(mmio, 1, 0, cmd_pa + 0x504, 0L);
	// we read 0x508 later on, right before writing it with ENABLE
	//event508 = _add_cfg(mmio, 1, 0, cmd_pa + 0x508, 0L);
	event50c = _add_cfg(mmio, 1, 0, cmd_pa + 0x50c, 0L);
	event510 = _add_cfg(mmio, 1, 0, cmd_pa + 0x510, 0L);
	event514 = _add_cfg(mmio, 1, 0, cmd_pa + 0x514, 0L);
	event518 = _add_cfg(mmio, 1, 0, cmd_pa + 0x518, 0L);
	event51c = _add_cfg(mmio, 1, 0, cmd_pa + 0x51c, 0L);

	// Store data from reads

	_wait_for_done(&(event00->state), lock);
	mmio->cfg.cr_device = (uint16_t) ((event00->cmd_data >> 16) & 0x0000FFFF);
	mmio->cfg.cr_vendor = (uint16_t) (event00->cmd_data & 0x0000FFFF);
        debug_msg("%x:%x CR dev & vendor", mmio->cfg.cr_device, mmio->cfg.cr_vendor);
        debug_msg("%x:%x CR dev & vendor swapped", ntohs(mmio->cfg.cr_device),ntohs(mmio->cfg.cr_vendor));
	free(event00);

	// Read Process Addr Space ID (PASID) Extended Capability
	_wait_for_done(&(event110->state), lock);
	mmio->cfg.PASID_CP = event110->cmd_data;
	free(event110);

	_wait_for_done(&(event114->state), lock);
	mmio->cfg.PASID_CTL_STS = event114->cmd_data;
	free(event114);

	// Read OpenCAPI Transport Layer DVSEC
	_wait_for_done(&(event200->state), lock);
	mmio->cfg.OCAPI_TL_CP = event200->cmd_data;
	free(event200);

	_wait_for_done(&(event204->state), lock);
	mmio->cfg.OCAPI_TL_REVID = event204->cmd_data;
	free(event204);

	_wait_for_done(&(event20c->state), lock);
	mmio->cfg.OCAPI_TL_VERS = event20c->cmd_data;
	free(event20c);

	_wait_for_done(&(event224->state), lock);
	mmio->cfg.OCAPI_TL_TMP_CFG = event224->cmd_data;
	free(event224);

	_wait_for_done(&(event26c->state), lock);
	mmio->cfg.OCAPI_TL_TX_RATE = event26c->cmd_data;
	free(event26c);

	// Read Function Configuration DVSEC
	_wait_for_done(&(event300->state), lock);
	mmio->cfg.FUNC_CFG_CP = event300->cmd_data;
	free(event300);

	_wait_for_done(&(event304->state), lock);
	mmio->cfg.FUNC_CFG_REVID = event304->cmd_data;
	free(event304);

	_wait_for_done(&(event308->state), lock);
	mmio->cfg.FUNC_CFG_MAXAFU = event308->cmd_data;
	debug_msg("FUNC_CFG_MAXAFU is 0x%x ", mmio->cfg.FUNC_CFG_MAXAFU);
	free(event308);

	// Read AFU Information DVSEC
	_wait_for_done(&(event400->state), lock);
	mmio->cfg.AFU_INFO_CP = event400->cmd_data;
	free(event400);

	_wait_for_done(&(event404->state), lock);
	mmio->cfg.AFU_INFO_REVID = event404->cmd_data;
	free(event404);

	_wait_for_done(&(event408->state), lock);
	mmio->cfg.AFU_INFO_INDEX = event408->cmd_data;
	free(event408);

	// we can't read the AFU descriptor indirect regs like this,
	// will read them later
	//
	//Read AFU Control DVSEC
	_wait_for_done(&(event500->state), lock);
	mmio->cfg.AFU_CTL_CP_0 = event500->cmd_data;
	free(event500);

	_wait_for_done(&(event504->state), lock);
	mmio->cfg.AFU_CTL_REVID_4 = event504->cmd_data;
	free(event504);

	// we read 0x508 later on, right before writing it with ENABLE
	
	_wait_for_done(&(event50c->state), lock);
	mmio->cfg.AFU_CTL_WAKE_TERM_C = event50c->cmd_data;
	free(event50c);

	// Read pasid_len and use that value as num_of_processes
	// also write that value back to PASID_EN (later on in code)
	_wait_for_done(&(event510->state), lock);
	mmio->cfg.AFU_CTL_PASID_LEN_10 = event510->cmd_data;
	debug_msg("AFU_CTL_PASID_LEN IS 0x%x ", mmio->cfg.AFU_CTL_PASID_LEN_10);
	mmio->cfg.num_of_processes =  (event510->cmd_data & 0x0000001f); 
	free(event510);

	_wait_for_done(&(event514->state), lock);
	mmio->cfg.AFU_CTL_PASID_BASE_14 = event514->cmd_data;
	free(event514);

	_wait_for_done(&(event518->state), lock);
	mmio->cfg.AFU_CTL_ACTAG_LEN_EN_S = event518->cmd_data;
	debug_msg("AFU_CTL_ACTAG_LEN_EN_S IS 0x%x ", mmio->cfg.AFU_CTL_ACTAG_LEN_EN_S);
	// TODO  setting bits[27:16] to set # of actags allowed
	//mmio->cfg.num_ints_per_process =  (event518->cmd_data & 0x0000ffff); 
	// WHAT DO WE NOW Use as num_ints_per_process????
	free(event518);

	_wait_for_done(&(event51c->state), lock);
	mmio->cfg.AFU_CTL_ACTAG_BASE = event51c->cmd_data;
	// TODO  setting bits[11:0] to set actag base
	free(event51c);

	// To read AFU descriptor values, first write to cmd_pa + 0x40c with
	// [31] = 0 [30:0] = 4B offset of Descriptor data to read
	// Next, read cmd_pa + 0x40c and test bit[31]
	// if 0, read again
	// if 1, read cmd_pa+0x410 to get afu descriptor data
	// New (5/9/17) Cofig spec has updated Global & PerProcess MMIO fields, now
	// PerPASID MMIO Offset low & Bar (0x30), PerPASID MMIO Offset high (0x34)
	// and PerPASID MMIO Size (0x38)


	event40c = _add_event(mmio, NULL, 0, 0, 0, cmd_pa+0x40c, 1, 0x000028);
	printf("Just sent config_wr, will wait for read_req then send data \n");
        _wait_for_done(&(event40c->state), lock);
	free(event40c);
	printf("waiting for AFU to set [31] to 1 in addr 0x40c \n");
	event40c = _add_cfg(mmio, 1, 0, cmd_pa + 0x40c, 0L);
        _wait_for_done(&(event40c->state), lock);

	// Uncomment the while statement to get multiple reads on 0x40c
	while ((event40c->cmd_data & AFU_DESC_DATA_VALID) == 0) {
		event40c = _add_cfg(mmio, 1, 0, cmd_pa + 0x40c, 0L);
        	_wait_for_done(&(event40c->state), lock);
	}

	printf("AFU finally set [31] to 1 in addr 0x40c \n");
	free(event40c);
	event410 = _add_cfg(mmio, 1, 0, cmd_pa + 0x410, 0L);
        _wait_for_done(&(event410->state), lock);
	// first read gives us per pasid MMIO offset low & per pasid MMIO BAR
	mmio->cfg.pp_MMIO_offset_low = (event410->cmd_data & 0xFFFFFFF8);
	debug_msg("per process MMIO offset is 0x%x ", mmio->cfg.pp_MMIO_offset_low);
	mmio->cfg.pp_MMIO_BAR = (event410->cmd_data & 0x00000007);
	debug_msg("per process MMIO BAR is 0x%x ", mmio->cfg.pp_MMIO_BAR);
	free(event410);
	event40c = _add_event(mmio, NULL, 0, 0, 0, cmd_pa+0x40c, 1, 0x000034);
	printf("Just sent config_wr, will wait for read_req then send data \n");
        _wait_for_done(&(event40c->state), lock);
	free(event40c);

	printf("sent config write now do config read \n");
	event40c = _add_cfg(mmio, 1, 0, cmd_pa + 0x40c, 0L);
        _wait_for_done(&(event40c->state), lock);
	// Uncomment the while statement to get multiple reads on 0x2ac
	while ((event40c->cmd_data & AFU_DESC_DATA_VALID) == 0) {
		event40c = _add_cfg(mmio, 1, 0, cmd_pa + 0x40c, 0L);
        	_wait_for_done(&(event40c->state), lock);
	}
	free(event40c);

	event410 = _add_cfg(mmio, 1, 0, cmd_pa + 0x410, 0L);
        _wait_for_done(&(event410->state), lock);
	// second read gives us per process MMIO stride
	mmio->cfg.pp_MMIO_offset_high = event410->cmd_data;
	debug_msg("per process MMIO offset_high is 0x%x ", mmio->cfg.pp_MMIO_offset_high);
	free(event410);

	event40c = _add_event(mmio, NULL, 0, 0, 0, cmd_pa+0x40c, 1, 0x000038);
	printf("Just sent config_wr, will wait for read_req then send data \n");
        _wait_for_done(&(event40c->state), lock);
	free(event40c);

	printf("sent config write now do config read \n");
	event40c = _add_cfg(mmio, 1, 0, cmd_pa + 0x40c, 0L);
        _wait_for_done(&(event40c->state), lock);
	// Uncomment the while statement to get multiple reads on 0x2ac
	while ((event40c->cmd_data & AFU_DESC_DATA_VALID) == 0) {
		event40c = _add_cfg(mmio, 1, 0, cmd_pa + 0x40c, 0L);
        	_wait_for_done(&(event40c->state), lock);
	}
	free(event40c);

	event410 = _add_cfg(mmio, 1, 0, cmd_pa + 0x410, 0L);
        _wait_for_done(&(event410->state), lock);
	// second read gives us per process MMIO stride
	mmio->cfg.pp_MMIO_stride = event410->cmd_data;
	debug_msg("per process MMIO stride is 0x%x ", mmio->cfg.pp_MMIO_stride);
	free(event410);

	// Now set PASID Length Enabled to be same as PASID Length Supported
	// Rest of bits in reg are RO so just mask in value and write back
	event510 = _add_event(mmio, NULL, 0, 0, 0, cmd_pa+0x510, 1, (mmio->cfg.AFU_CTL_PASID_LEN_10 | (mmio->cfg.num_of_processes << 8)));
	printf("Just sent config_wr for setting PASID Length Enabled, will wait for read_req then send data \n");
        _wait_for_done(&(event510->state), lock);
	free(event510);
	

	//Now set enable bit in AFU Control DVSEC

	event508 = _add_cfg(mmio, 1, 0, cmd_pa + 0x508, 0L);
        _wait_for_done(&(event508->state), lock);
	// first read and then mask in the enable bit [25] and write back
	mmio->cfg.AFU_CTL_EN_RST_INDEX_8 = event508->cmd_data;
	debug_msg("AFU_CTL_EN_RST_INDEX is 0x%x ", mmio->cfg.AFU_CTL_EN_RST_INDEX_8);
	free(event508);

	// Test read after write to make sure test_afu is working

	event508 = _add_event(mmio, NULL, 0, 0, 0, cmd_pa+0x508, 1, (mmio->cfg.AFU_CTL_EN_RST_INDEX_8 | 0x02000000));
	printf("Just sent config_wr for AFU ENABLE, will wait for read_req then send data \n");
        _wait_for_done(&(event508->state), lock);
	free(event508);

	printf("sent config write now do additional config read to test \n");
	event308 = _add_cfg(mmio, 1, 0, cmd_pa + 0x308, 0L);
        _wait_for_done(&(event308->state), lock);
	debug_msg("FUNC_CFG_MAXAFU is 0x%x ", event308->cmd_data);
	free(event308);
	return 0;
}

// Send pending MMIO event to AFU; use config_read or config_write for descriptor
// for MMIO use cmd_pr_rd_mem or cmd_pr_wr_mem
void send_mmio(struct mmio *mmio)
{
	struct mmio_event *event;
	char type[7];
	unsigned char ddata[17];
	unsigned char null_buff[64] = {0};
	unsigned char tdata_bus[64];
	char data[17];
#ifdef TLX4
	uint8_t cmd_os;
#endif
	uint8_t  cmd_byte_cnt;
	uint64_t offset;

	event = mmio->list;

	// Check for valid event
	if ((event == NULL) || (event->state == OCSE_PENDING))
		return;

	if (event->cfg) {
		sprintf(type, "CONFIG");
	// Attempt to send config_rd or config_wr to AFU
		if (event->rnw && tlx_afu_send_cmd(mmio->afu_event,
			TLX_CMD_CONFIG_READ, 0xdead, 0, 2, 0, 0, 0, event->cmd_PA) == TLX_SUCCESS) {
			debug_msg("%s:%s READ%d word=0x%05x", mmio->afu_name, type,
			  	event->dw ? 64 : 32, event->cmd_PA);
			debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->cfg,
				event->rnw, event->dw, event->cmd_PA);
			event->state = OCSE_PENDING;
		}

		if (!event->rnw) { // CONFIG write - two part operation
			// restricted by spec to pL of 1, 2, or 4 bytes HOWEVER
			// We now have to offset the data into a 64B buffer and send it
			if (event->state == OCSE_RD_RQ_PENDING) {
				memcpy(tdata_bus, null_buff, 64); //not sure if we always have to do this, but better safe than...
				uint8_t * dptr = tdata_bus;;
				//memcpy(ddata, &(event->cmd_data), 4);
				// FOR NOW we only do 4B config writes
			  	offset = event->cmd_PA & 0x000000000000003F ;
				memcpy(dptr +offset, &(event->cmd_data), 4);
				//if (tlx_afu_send_cmd_data(mmio->afu_event, 4, 0, dptr) == TLX_SUCCESS) {
				if (tlx_afu_send_cmd_data(mmio->afu_event, 64, 0, dptr) == TLX_SUCCESS) {
					if (event->dw)
						sprintf(data, "%016" PRIx64, event->cmd_data);
					else
						sprintf(data, "%08" PRIx32, (uint32_t) event->cmd_data);
					debug_msg("%s:%s WRITE%d word=0x%05x data=0x%s offset=0x%x",
						mmio->afu_name, type, event->dw ? 64 : 32,
			  			event->cmd_PA, data, offset);
					debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->cfg,
						event->rnw, event->dw, event->cmd_PA);
					event->state = OCSE_PENDING;
					printf("got rd_req and sent data, now wait for cmd resp from AFU \n");
				}
       	 		} else if ( tlx_afu_send_cmd(mmio->afu_event,
				TLX_CMD_CONFIG_WRITE, 0xbeef,0, 2, 0, 0, 0, event->cmd_PA) == TLX_SUCCESS) {
					event->state = OCSE_RD_RQ_PENDING;
					printf("sent wr cmd, now wait for rd_req from AFU \n"); }
		}
       	}  else   {  // if not a CONFIG, then must be MMIO rd/wr
		sprintf(type, "MMIO");

		// calculate event->pL from event->dw
		// calculate cmd_byte_cnt from event->dw
		if (event->dw == 1) {
		  // pl = 3 ::= 8 bytes
		  event->cmd_pL = 3;
		  cmd_byte_cnt = 8;
		} else {
		  // pl = 2 ::= 4 bytes
		  event->cmd_pL = 2;
		  cmd_byte_cnt = 4;
		}

		// Attempt to send mmio to AFU
		if (event->rnw && tlx_afu_send_cmd(mmio->afu_event,
			TLX_CMD_PR_RD_MEM, 0xcafe, 0, event->cmd_pL, 0, 0, 0, event->cmd_PA) == TLX_SUCCESS) {
			debug_msg("%s:%s READ%d word=0x%05x", mmio->afu_name, type,
			  	event->dw ? 64 : 32, event->cmd_PA);
			debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->cfg,
					event->rnw, event->dw, event->cmd_PA);
			event->state = OCSE_PENDING;
		}
		if (!event->rnw) { // MMIO write - two part operation
			// We only do 4B or 8B MMIO writes - caller has to specify in pL, HOWEVER
			// We now have to offset the data into a 64B buffer and send it
			if (event->state == OCSE_RD_RQ_PENDING) {
				memcpy(tdata_bus, null_buff, 64); //not sure if we always have to do this, but better safe than...
				uint8_t * dptr = tdata_bus;;
			  	offset = event->cmd_PA & 0x000000000000003F ;
				memcpy(dptr +offset, &(event->cmd_data), cmd_byte_cnt);
				//memcpy(ddata, &(event->cmd_data), cmd_byte_cnt);
				//if (tlx_afu_send_cmd_data(mmio->afu_event, cmd_byte_cnt, 0, dptr) == TLX_SUCCESS) {
				if (tlx_afu_send_cmd_data(mmio->afu_event, 64, 0, dptr) == TLX_SUCCESS) {
				  if (event->dw)
				    sprintf(data, "%016" PRIx64, event->cmd_data);
				  else
				    sprintf(data, "%08" PRIx32, (uint32_t) event->cmd_data);
				  debug_msg("%s:%s WRITE%d word=0x%05x data=0x%s offset=0x%x",
					    mmio->afu_name, type, event->dw ? 64 : 32,
					    event->cmd_PA, data, offset);
				  debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->cfg,
						  event->rnw, event->dw, event->cmd_PA);
				  event->state = OCSE_PENDING;
				  printf("got rd_req and sent data, now wait for cmd resp from AFU \n");
				}
       	 		} else if ( tlx_afu_send_cmd(mmio->afu_event,
				TLX_CMD_PR_WR_MEM, 0xbead, 0, event->cmd_pL, 0, 0, 0, event->cmd_PA) == TLX_SUCCESS) {
					event->state = OCSE_RD_RQ_PENDING;
					printf("sent mmio_pr_wr cmd, now wait for rd_req from AFU \n"); }
				}
	}
}

// Handle MMIO ack if returned by AFU
void handle_mmio_ack(struct mmio *mmio, uint32_t parity_enabled)
{
	uint64_t read_data;
	int rc;
//	char data[17];
	char type[7];
	uint8_t afu_resp_opcode, resp_dl,resp_dp, resp_data_is_valid, resp_code, rdata_bad;
	uint16_t resp_capptag;
	uint8_t *  rdata;
	unsigned char   rdata_bus[64];
	int offset, length;

	// handle config and mmio responses
	// length can be calculated from the mmio->list->dw or cmd_pL
	// location of data in rdata_bus is address aligned based on mmio->list->cmd_PA
	// that is, mask off the high order address bits to form the offset - keep the low order 6 bits.

	rdata = rdata_bus;

	// needs to be modified to return 64 bytes and extract the 4/8 we want?
	rc = afu_tlx_read_resp_and_data(mmio->afu_event,
	 	&afu_resp_opcode, &resp_dl,
	   	&resp_capptag, &resp_dp,
	    	&resp_data_is_valid, &resp_code, rdata_bus, &rdata_bad);

	if (rc == TLX_SUCCESS) {
	  // should we scan the mmio list looking for a matching CAPPtag here? Not yet, assume in order responses
	  // but we can check it...
			debug_mmio_ack(mmio->dbg_fp, mmio->dbg_id);
			if (!mmio->list || (mmio->list->state != OCSE_PENDING)) {
				warn_msg("Unexpected MMIO ack from AFU");
				return;
			}

			// check the CAPPtag - later

			if (mmio->list->cfg) {
				sprintf(type, "CONFIG");
			} else {
				sprintf(type, "MMIO");
			}

			debug_msg("IN handle_mmio_ack and resp_capptag = %x and resp_code = %x! ",
				resp_capptag, resp_code);

			if (resp_data_is_valid) {
			  // extract data from address aligned offset in vector
			  offset = mmio->list->cmd_PA & 0x000000000000003F ;
			  if (mmio->list->cmd_pL == 0x02) {
			    length = 4;
			  } else {
			    length = 8;
			  }
			  memcpy(&read_data, &rdata_bus[offset], length);
			  debug_msg("%s:%s CMD RESP offset=%d length=%d data=0x%x code=0x%x", mmio->afu_name, type, offset, length,
				    read_data, resp_code );
			} else {
				debug_msg("%s:%s CMD RESP code=0x%x", mmio->afu_name, type, resp_code);
				}

		// Keep data for MMIO reads
		if (mmio->list->rnw)
				mmio->list->cmd_data = read_data;
		mmio->list->state = OCSE_DONE;
		mmio->list = mmio->list->_next;
		}

}

// Handle MMIO map request from client
void handle_mmio_map(struct mmio *mmio, struct client *client)
{
	uint32_t flags;
	uint8_t ack = OCSE_MMIO_ACK;
	int fd = client->fd;

	// Check for errors
/*	if (!(mmio->cfg.PerProcessPSA & PSA_REQUIRED)) {
		warn_msg("Problem State Area Required bit not set");
		ack = OCSE_MMIO_FAIL;
		goto map_done;
	} */
	if (get_bytes_silent(fd, 4, (uint8_t *) & flags, mmio->timeout,
			     &(client->abort)) < 0) {
	        debug_msg("%s:handle_mmio_map failed context=%d",
			  mmio->afu_name, client->context);
		client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		warn_msg("Socket failure with client context %d",
			 client->context);
		ack = OCSE_MMIO_FAIL;
		goto map_done;
	}
	// Check flags value and set
	// For now, we assume that the global and per pasid areas have the same endianness
	if (!mmio->flags) {
		mmio->flags = ntohl(flags);
	} else if (mmio->flags != ntohl(flags)) {
		warn_msg("Set conflicting mmio endianess for AFU");
		ack = OCSE_MMIO_FAIL;
	}

	if (ack == OCSE_MMIO_ACK) {
		debug_mmio_map(mmio->dbg_fp, mmio->dbg_id, client->context);
	}

 map_done:
	// Send acknowledge to client
	if (put_bytes(fd, 1, &ack, mmio->dbg_fp, mmio->dbg_id, client->context)
	    < 0) {
		client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	}
}

// Add mmio write event of register at offset to list
static struct mmio_event *_handle_mmio_write(struct mmio *mmio,
					     struct client *client, int dw, int global)
{
	struct mmio_event *event;
	uint32_t offset;
	uint64_t data64;
	uint32_t data32;
	uint64_t data;
	int fd = client->fd;

	if (get_bytes_silent(fd, 4, (uint8_t *) & offset, mmio->timeout,
			     &(client->abort)) < 0) {
		goto write_fail;
	}
	offset = ntohl(offset);
	if (dw) {
		if (get_bytes_silent(fd, 8, (uint8_t *) & data64, mmio->timeout,
				     &(client->abort)) < 0) {
			goto write_fail;
		}
		// Convert data from client from little endian to host
		data = ntohll(data64);
	} else {
		if (get_bytes_silent(fd, 4, (uint8_t *) & data32, mmio->timeout,
				     &(client->abort)) < 0) {
			goto write_fail;
		}
		// Convert data from client from little endian to host
		data32 = ntohl(data32);
		data = (uint64_t) data32;
		data <<= 32;
		data |= (uint64_t) data32;
	}
	// in OpenCAPI, don't shift the offset...  in pcie days, we used to shift right 2 bits with offset / 4
	event = _add_mmio(mmio, client, 0, dw, global, offset, data);
	return event;

 write_fail:
	// Socket connection is dead
	debug_msg("%s:_handle_mmio_write failed context=%d",
		  mmio->afu_name, client->context);
	client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	return NULL;
}

// Add mmio read event of register at offset to list
static struct mmio_event *_handle_mmio_read(struct mmio *mmio,
					    struct client *client, int dw, int global)
{
	struct mmio_event *event;
	uint32_t offset;
	int fd = client->fd;

	if (get_bytes_silent(fd, 4, (uint8_t *) & offset, mmio->timeout,
			     &(client->abort)) < 0) {
		goto read_fail;
	}
	offset = ntohl(offset);
	// in OpenCAPI, don't shift the offset...  in pcie days, we used to shift right 2 bits with offset / 4
	event = _add_mmio(mmio, client, 1, dw, global, offset, 0);
	return event;

 read_fail:
	// Socket connection is dead
	debug_msg("%s:_handle_mmio_read failed context=%d",
		  mmio->afu_name, client->context);
	client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	return NULL;
}

// Add mmio read event of error buffer at offset to list
static struct mmio_event *_handle_mmio_read_eb(struct mmio *mmio,
					    struct client *client, int dw)
{
	struct mmio_event *event;
	uint32_t offset;
	int fd = client->fd;

	if (get_bytes_silent(fd, 4, (uint8_t *) & offset, mmio->timeout,
			     &(client->abort)) < 0) {
		goto read_fail;
	}
	offset = ntohl(offset);
        //offset = offset + (uint32_t)mmio->cfg.AFU_EB_offset;
        debug_msg("offset for eb read is %x\n", offset);
//	event = _add_event(mmio, client, 1, dw, offset>>2, 1, 0);
	event = _add_cfg(mmio, 1, dw, offset>>2, 0);
//        _wait_for_done(&(event->state), ocl->lock);
	return event;

 read_fail:
	// Socket connection is dead
	debug_msg("%s:_handle_mmio_read failed context=%d",
		  mmio->afu_name, client->context);
	client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	return NULL;
}


// Handle MMIO request from client
struct mmio_event *handle_mmio(struct mmio *mmio, struct client *client,
			       int rnw, int dw, int eb_rd, int global)
{
	uint8_t ack;

	// Only allow MMIO access when client is valid
	if (client->state != CLIENT_VALID) {
		ack = OCSE_MMIO_FAIL;
		if (put_bytes(client->fd, 1, &ack, mmio->dbg_fp, mmio->dbg_id,
			      client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}
		return NULL;
	}

	if (eb_rd)
		return _handle_mmio_read_eb(mmio, client, dw);

	if (rnw)
		return _handle_mmio_read(mmio, client, dw, global);
	else
		return _handle_mmio_write(mmio, client, dw, global);
}

// Handle MMIO done
struct mmio_event *handle_mmio_done(struct mmio *mmio, struct client *client)
{
	struct mmio_event *event;
	uint64_t data64;
	uint32_t data32;
	uint8_t *buffer;
	int fd = client->fd;

	// Is there an MMIO event pending?
	event = (struct mmio_event *)client->mmio_access;
	if (event == NULL)
		return NULL;

	// MMIO event not done yet
	if (event->state != OCSE_DONE)
		return event;

	if (event->rnw) {
		// Return acknowledge with read data
		if (event->dw) {
			buffer = (uint8_t *) malloc(9);
			buffer[0] = OCSE_MMIO_ACK;
			data64 = htonll(event->cmd_data);
			memcpy(&(buffer[1]), &data64, 8);
			if (put_bytes(fd, 9, buffer, mmio->dbg_fp, mmio->dbg_id,
				      client->context) < 0) {
				client_drop(client, TLX_IDLE_CYCLES,
					    CLIENT_NONE);
			}
		} else {
			buffer = (uint8_t *) malloc(5);
			buffer[0] = OCSE_MMIO_ACK;
			data32 = htonl(event->cmd_data);
			memcpy(&(buffer[1]), &data32, 4);
			if (put_bytes(fd, 5, buffer, mmio->dbg_fp, mmio->dbg_id,
				      client->context) < 0) {
				client_drop(client, TLX_IDLE_CYCLES,
					    CLIENT_NONE);
			}
		}
	} else {
		// Return acknowledge for write
		printf("READY TO SEND OCSE_MMIO_ACK to client!!!!\n");
		buffer = (uint8_t *) malloc(1);
		buffer[0] = OCSE_MMIO_ACK;
		if (put_bytes(fd, 1, buffer, mmio->dbg_fp, mmio->dbg_id,
			      client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}
	}
	debug_mmio_return(mmio->dbg_fp, mmio->dbg_id, client->context);
	free(event);
	free(buffer);

	return NULL;
}

//int dedicated_mode_support(struct mmio *mmio)
//{
//	return ((mmio->cfg.req_prog_model & PROG_MODEL_MASK) ==
//		PROG_MODEL_DEDICATED);
//}

//int directed_mode_support(struct mmio *mmio)
//{
//	return ((mmio->cfg.req_prog_model & PROG_MODEL_MASK) ==
//		PROG_MODEL_DIRECTED);
//}
