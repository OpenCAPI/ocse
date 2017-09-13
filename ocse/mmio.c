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
	event->size = 0;  // part of the new fields
	event->be_valid = 0;  // part of the new fields
	event->data = NULL;
	event->be = 0;
	event->cmd_dL = 0;
	event->cmd_dP = 0;
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
	 debug_msg("_add_event:: WRITE word=0x%016lx (0x%016lx) data=0x%016lx",
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

// create a new _add_mem_event function that will use size instead of dw.
// Add new mmio event for general memory transfer
static struct mmio_event *_add_mem_event(struct mmio *mmio, struct client *client,
				     uint32_t rnw, uint32_t size, int region, uint64_t addr,
				     uint8_t *data, uint32_t be_valid, uint64_t be)
{
	struct mmio_event *event;
	struct mmio_event **list;
	uint16_t context;

	// Add new event in IDLE state
	event = (struct mmio_event *)malloc(sizeof(struct mmio_event));
	if (!event)
		return event;
	event->cfg = 0;
	event->rnw = rnw;
	event->be_valid = be_valid;
	event->dw = 0;
	event->size = size;  // part of the new fields
	event->data = data;
	event->be = be;
	if (client == NULL)  {
	  // is this case where cfg = 1, that is, we want to read config space?
	  // yes, when we do mmios to config space, we force client to null
	  event->cmd_PA = addr;
	} else {
	  // for OpenCAPI, the memory space is split into LPC, global and per pasid
	  // the region parm controls how we adjust the offset prior to adding the event
	  // technically, all of these should be adjusted by the BAR specified in the configuration... ocse assumes a BA of 0
	  //   region = 0 means we are LPC memory and offset is unadjusted
	  //   region = 1 means we adjust offset based on the global mmio offset from the configuration
	  //   region = 2 means we want to send the offset adjusted by the per pasid mmio offset, per pasid mmio stride, and client index
	  //   for now, we are assuming the client index (context) maps directly to a pasid.  
	  //        we could be more creative and relocate the pasid base and pasid length supported to 
	  //        provide more verification coverage
	  if (region == 0) {
	    // lpc area
	    event->cmd_PA = addr;
	  } else if (region == 1) {
	    // global mmio offset + offset
	    // TODO offset is NOW 64b, comprised of offset_high & offset_low
	    event->cmd_PA = mmio->cfg.global_MMIO_offset_low + addr;
	  } else {
	    // per pasid mmio offset + (client context * stride) + offset
	    // TODO offset is NOW 64b, comprised of offset_high & offset_low
	    event->cmd_PA = mmio->cfg.pp_MMIO_offset_low + (mmio->cfg.pp_MMIO_stride * client->context) + addr;
	  }
	}
	event->state = OCSE_IDLE;
	event->_next = NULL;

	debug_msg("_add_mem_event:: rnw=%d, access word=0x%016lx (0x%016lx)", event->rnw, event->cmd_PA, addr);

	// Add to end of list
	list = &(mmio->list);
	while (*list != NULL)
		list = &((*list)->_next);
	*list = event;
	if (event->cfg)
		context = -1;
	else
		context = client->context;
	debug_mmio_add(mmio->dbg_fp, mmio->dbg_id, context, rnw, size, addr);

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

// Add AFU general memory access command event
static struct mmio_event *_add_mem(struct mmio *mmio, struct client *client,
				    uint32_t rnw, uint32_t size, int region, uint64_t addr,
				   uint8_t *data, uint32_t be_valid, uint64_t be)
{
  return _add_mem_event(mmio, client, rnw, size, region, addr, data, be_valid, be);
}

static void _wait_for_done(enum ocse_state *state, pthread_mutex_t * lock)
{
	while (*state != OCSE_DONE)	/* infinite loop */
		lock_delay(lock);
}

// Read the AFU descriptor template 0 from the afu information DVSEC
// pass in the address of the afu descriptor offset register
//         the offset of the descriptor requested
// returns an mmio event with the data from the requested offset
static struct mmio_event *_read_afu_descriptor(struct mmio *mmio, uint64_t addr, uint64_t offset, pthread_mutex_t * lock)
{
  struct mmio_event *event0c;
  struct mmio_event *event10;

  #define AFU_DESC_DATA_VALID 0x80000000
  #define FUNCTION_CFG_OFFSET 0x0000000000010000; // per spec, each function has some config space 


  // step 1: write the offset of the descriptor that we want in the afu descriptor register
  debug_msg("_read_afu_descriptor: AFU descriptor offset 0x%016lx indirect read", offset);
  debug_msg("   AFU Information DVSEC write 0x%08x @ 0x%016lx", offset, addr);
  event0c = _add_cfg(mmio, 0, 0, addr, offset);
  _wait_for_done(&(event0c->state), lock);
  debug_msg("   AFU Information DVSEC write 0x%08x @ 0x%016lx complete", offset, addr);
  free(event0c);

  // step 2: read the afu descriptor offset register looking for the data valid bit to become 1
  event0c = _add_cfg(mmio, 1, 0, addr, 0L);
  _wait_for_done(&(event0c->state), lock);
  debug_msg("   AFU Information DVSEC read @ 0x%016lx = 0x%08x", addr, event0c->cmd_data);
  
  while ((event0c->cmd_data & AFU_DESC_DATA_VALID) == 0) {
    free(event0c);
    event0c = _add_cfg(mmio, 1, 0, addr, 0L);
    _wait_for_done(&(event0c->state), lock);
    debug_msg("   AFU Information DVSEC read @ 0x%016lx = 0x%08x", addr, event0c->cmd_data);
  }
  free(event0c);
  debug_msg("   AFU descriptor offset 0x%016lx indirect read ready", offset);

  // step 3: read the data from the afu descriptor data register
  event10 = _add_cfg(mmio, 1, 0, addr + 4, 0L);  // assuming the data register is adjacent to the offset register
  _wait_for_done(&(event10->state), lock);
  debug_msg("   AFU Information DVSEC afu descriptor data read 0x%08x @ 0x%016lx complete", event10->cmd_data, addr + 4);

  return event10;
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
	uint8_t   cfg_tlx_credits_available;
	uint8_t   afu_tlx_resp_credits_available;
	int f;
	#define AFU_DESC_DATA_VALID 0x80000000

	printf("before read initial credits \n");
	//if (afu_tlx_read_initial_credits(mmio->afu_event, &afu_tlx_cmd_credits_available,
	 //&afu_tlx_resp_credits_available) != TLX_SUCCESS)
	//	printf("NO CREDITS FROM AFU!!\n");
	while (afu_tlx_read_initial_credits(mmio->afu_event, &afu_tlx_cmd_credits_available,
	 &cfg_tlx_credits_available, &afu_tlx_resp_credits_available) != TLX_SUCCESS){
	  //infinite loop
	  sleep(1);
	} 
	printf("afu_tlx_cmd_credits_available= %d, cfg_tlx_credits_available= %d, afu_tlx_resp_credits_availabler= %d \n",
		afu_tlx_cmd_credits_available, cfg_tlx_credits_available,
		afu_tlx_resp_credits_available);

 	struct mmio_event *event00, *event100, *event104, *event200, *event204,
	    *event20c, *event224, *event26c, *event300, *event304, *event308,
	    *event400, *event404, *event408, *event40c, *event410,
	  *event500, *event504, /* *event508, */ *event50c, *event510, *event514,
	    *event518, *event51c;

 	struct mmio_event *event_r, *event_w;

	uint64_t cmd_pa_f0, cmd_pa_f1, cmd_pa_func_offset;
	cmd_pa_f0 = 0x0000000050000000; // per spec,  BDF for config (0x5000 for func0 )
	cmd_pa_f1 = 0x0000000050010000; // only need BDF for config (0x5001 for func1, 0x5002 for func2, etc)
	cmd_pa_func_offset = 0x0;  

// start of the new stuff
// step 1: read the config space header at each function offset. If  we get a cfg_read_error or read all 00s
// that means there isn't a function for that offset
printf("START OF NEW STUFF \n");
	uint64_t next_one;
	uint16_t cr_dev, cr_ven;
	uint16_t ec_id, ec_off;
	uint8_t more = 0;;
	struct mmio_event *eventa, *eventb, *eventc;
	//mmio->fun_array = malloc ( 8 * sizeof (struct fun_cfg_sp *));
	for (f = 0; f < 8; f++ ) {
		debug_msg("_read_config_space_header:  offset 0x%016lx ", cmd_pa_func_offset);
		eventa  = _add_cfg(mmio, 1, 0, cmd_pa_f0 + cmd_pa_func_offset, 0L);          // opencapi configuration header
  		_wait_for_done(&(eventa->state), lock);
		cr_dev = (uint16_t) ((eventa->cmd_data >> 16) & 0x0000FFFF);
		cr_ven = (uint16_t) (eventa->cmd_data & 0x0000FFFF);
		//mmio->fun_array[f].cr_device = (uint16_t) ((eventa->cmd_data >> 16) & 0x0000FFFF);
	//	mmio->fun_array[f].cr_vendor = (uint16_t) (eventa->cmd_data & 0x0000FFFF);
		free(eventa);
       		//info_msg("OpenCAPI Configuration header for function %d  %04x:%04x CR dev & vendor", f, mmio->fun_array[f].cr_device, mmio->fun_array[f].cr_vendor);
       		info_msg("OpenCAPI Configuration header for function %d  %04x:%04x CR dev & vendor", f, cr_dev, cr_ven);
		// skip for now, but eventually read offset + 0x04 and possibly offset + 0x34 to get capabilites info
		if ((cr_dev != 0 ) || (cr_ven != 0)) {
			info_msg("READ EXTENDED CAPABILITIES");	
			next_one = 0x100;  
		// Read extended capabilities - offset + 0x100  [31:20] next ec offset, [7:0] this ec ID
		   eventb  = _add_cfg(mmio, 1, 0, cmd_pa_f0 + cmd_pa_func_offset + next_one, 0L);         // extended capabilities
  		   _wait_for_done(&(eventb->state), lock);
		   ec_id = (uint16_t)(eventb->cmd_data & 0x000000FF);
		   ec_off = (uint16_t)((eventb->cmd_data & 0xFFF00000) >> 20);
		   free(eventb);
		   more = 1;
		   while (more) {
			switch (ec_id) 	{
				case 0x03: info_msg("Found a DSN extended capability 0x%04x  with offset 0x%04x", ec_id, ec_off);
					   // skip for now
					   break;
				case 0x1b: info_msg("Found a PASID extended capability 0x%04x  with offset 0x%04x", ec_id, ec_off);
					   //eventc = _add_cfg(mmio, 1, 0, cmd_pa_func_offset + next_one + 4, 0L); 
					   //_wait_for_done(&(eventc->state), lock);
					   //mmio->fun_array[f].PASID_CTL_STS = eventc->cmd_data;
					   //free(eventc);
					   //info_msg("PASID EC 0x04 is 0x%08x ", mmio->fun_array[f].PASID_CTL_STS);
					   break;
					   // if ec ID == 0x23, this is OpenCAPI DVSEC: read DVSEC id to learn more
				case 0x23: info_msg("Found a OpenCAPI DVSEC extended capability 0x%04x with offset 0x%04x", ec_id, ec_off);
					   eventc = _add_cfg(mmio, 1, 0, cmd_pa_func_offset + next_one + 8, 0L); 
					   _wait_for_done(&(eventc->state), lock);
					   info_msg(" DVSEC ID 0x08 is 0x%08x ", eventc->cmd_data);
					   switch (eventc->cmd_data & 0x0000FFFF) {
						   case 0xF000:  info_msg("Found OpenCAPI TL DVSEC ");
								 break;
						   case 0xF001:  info_msg("Found FUNCTION DVSEC 0x%08x ", eventc->cmd_data);
								 break;
						   case 0xF003:  info_msg("Found AFU INFO DVSEC ");
							         break;
						   case 0xF004:  info_msg("Found AFU CTL  DVSEC ");
							         break;
						   case 0xF0F0:  info_msg("Found VENDOR SPECIFIC DVSEC 0x%08x ", eventc->cmd_data);
								 break;
						   default:      info_msg ("FOUND something UNEXPECTED in DVSEC 0x%08x ", eventc->cmd_data);
								 break;
					  	 } // end of switch dvsec id	
					   	 free(eventc);
					   break;
				default:   info_msg ("FOUND something UNEXPECTED in EC 0x%016lx ", ec_id);
					   break;

			} // end of switch ec id
			if (ec_off != 0) {
				next_one = (uint64_t) ec_off ;
				info_msg("NEXT_ONE IS 0x%016lx ", next_one);
				eventb  = _add_cfg(mmio, 1, 0, cmd_pa_f0 + cmd_pa_func_offset + next_one, 0L);  
  				_wait_for_done(&(eventb->state), lock);
				ec_id = (uint16_t)(eventb->cmd_data & 0x000000FF);
		   		ec_off = (uint16_t)((eventb->cmd_data & 0xFFF00000) >> 20);
				free(eventb);
				}
			else  
				more = 0;
		   } // end of more on ec_id/DVSEC loop

		} // end of read ec loop
  		cmd_pa_func_offset += FUNCTION_CFG_OFFSET;
} // end of read function csh loop
printf("END OF NEW STUFF \n");

// end of the new stuff
	// Queue mmio reads - these go out in order, gated (eventually) by credits
	event200 = _add_cfg(mmio, 1, 0, cmd_pa_f0 + 0x200, 0L); // transport layer DVSEC from function 0
	event204 = _add_cfg(mmio, 1, 0, cmd_pa_f0 + 0x204, 0L); // transport layer DVSEC 
	event20c = _add_cfg(mmio, 1, 0, cmd_pa_f0 + 0x20c, 0L); // transport layer DVSEC
	event224 = _add_cfg(mmio, 1, 0, cmd_pa_f0 + 0x224, 0L); // transport layer DVSEC
	event26c = _add_cfg(mmio, 1, 0, cmd_pa_f0 + 0x26c, 0L); // transport layer DVSEC

	event00  = _add_cfg(mmio, 1, 0, cmd_pa_f1, 0L);          // opencapi configuration header... of funtion1

	event100 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x100, 0L); // Process Address Space ID Extended Capability
	event104 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x104, 0L); // Process Address Space ID Extended Capability

	event300 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x300, 0L); // function  DVSEC
	event304 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x304, 0L); // function  DVSEC
	event308 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x308, 0L); // function  DVSEC

	event400 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x400, 0L); // afu information dvsec
	event404 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x404, 0L); // afu information dvsec
	event408 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x408, 0L); // afu information dvsec
	// this means afu_desc offset reg is 0x40c & data is 0x410

	event500 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x500, 0L); // afu control dvsec
	event504 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x504, 0L); // afu control dvsec
	// we read 0x508 later on, right before writing it with ENABLE
	//event508 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x508, 0L);
	event50c = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x50c, 0L); // afu control dvsec
	event510 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x510, 0L); // afu control dvsec
	event514 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x514, 0L); // afu control dvsec
	event518 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x518, 0L); // afu control dvsec
	event51c = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x51c, 0L); // afu control dvsec

	// Store data from reads

	//
	// Read OpenCAPI Transport Layer DVSEC
	//
	_wait_for_done(&(event200->state), lock);
	mmio->cfg.OCAPI_TL_CP = event200->cmd_data;
	info_msg("OCTL DVSEC 0x00 is 0x%08x ", mmio->cfg.OCAPI_TL_CP);
	free(event200);

	_wait_for_done(&(event204->state), lock);
	mmio->cfg.OCAPI_TL_REVID = event204->cmd_data;
	info_msg("OCTL DVSEC 0x04 is 0x%08x ", mmio->cfg.OCAPI_TL_REVID);
	free(event204);

	_wait_for_done(&(event20c->state), lock);
	mmio->cfg.OCAPI_TL_VERS = event20c->cmd_data;
	info_msg("OCTL DVSEC 0x0c is 0x%08x ", mmio->cfg.OCAPI_TL_VERS);
	free(event20c);

	_wait_for_done(&(event224->state), lock);
	mmio->cfg.OCAPI_TL_TMP_CFG = event224->cmd_data;
	info_msg("OCTL DVSEC 0x24 is 0x%08x ", mmio->cfg.OCAPI_TL_TMP_CFG);
	free(event224);

	_wait_for_done(&(event26c->state), lock);
	mmio->cfg.OCAPI_TL_TX_RATE = event26c->cmd_data;
	info_msg("OCTL DVSEC 0x6c is 0x%08x ", mmio->cfg.OCAPI_TL_TX_RATE);
	free(event26c);

	//
	// Read device id and vendor id from OpenCAPI Conifiguration header
	//
	_wait_for_done(&(event00->state), lock);
        info_msg("OpenCAPI Configuration header %04x:%04x CR dev & vendor", mmio->cfg.cr_device, mmio->cfg.cr_vendor);
        // debug_msg("OpenCAPI Configuration header %04x:%04x CR dev & vendor swapped", ntohs(mmio->cfg.cr_device),ntohs(mmio->cfg.cr_vendor));
	mmio->cfg.cr_device = (uint16_t) ((event00->cmd_data >> 16) & 0x0000FFFF);
	mmio->cfg.cr_vendor = (uint16_t) (event00->cmd_data & 0x0000FFFF);
 	free(event00);

	//
	// Read Process Addr Space ID (PASID) Extended Capability
	//
	_wait_for_done(&(event100->state), lock);
	mmio->cfg.PASID_CP = event100->cmd_data;
	info_msg("PASID EC 0x00 is 0x%08x ", mmio->cfg.PASID_CP);
	free(event100);

	_wait_for_done(&(event104->state), lock);
	mmio->cfg.PASID_CTL_STS = event104->cmd_data;
	info_msg("PASID EC 0x04 is 0x%08x ", mmio->cfg.PASID_CTL_STS);
	free(event104);

	//
	// Read Function Configuration DVSEC
	//
	_wait_for_done(&(event300->state), lock);
	mmio->cfg.FUNC_CFG_CP = event300->cmd_data;
	info_msg("Function DVSEC 0x00 is 0x%08x ", mmio->cfg.FUNC_CFG_CP);
	free(event300);

	_wait_for_done(&(event304->state), lock);
	mmio->cfg.FUNC_CFG_REVID = event304->cmd_data;
	info_msg("Function DVSEC 0x04 is 0x%08x ", mmio->cfg.FUNC_CFG_REVID);
	free(event304);

	_wait_for_done(&(event308->state), lock);
	mmio->cfg.FUNC_CFG_MAXAFU = event308->cmd_data;
	info_msg("Function DVSEC 0x08 (maxafu) is 0x%08x ", mmio->cfg.FUNC_CFG_MAXAFU);
	free(event308);

	//
	// Read AFU Information DVSEC
	//
	_wait_for_done(&(event400->state), lock);
	mmio->cfg.AFU_INFO_CP = event400->cmd_data;
	info_msg("AFU Information DVSEC 0x00 is 0x%08x ", mmio->cfg.AFU_INFO_CP);
	free(event400);

	_wait_for_done(&(event404->state), lock);
	mmio->cfg.AFU_INFO_REVID = event404->cmd_data;
	info_msg("AFU Information DVSEC 0x04 is 0x%08x ", mmio->cfg.AFU_INFO_REVID);
	free(event404);

	_wait_for_done(&(event408->state), lock);
	mmio->cfg.AFU_INFO_INDEX = event408->cmd_data;
	info_msg("AFU Information DVSEC 0x08 is 0x%08x ", mmio->cfg.AFU_INFO_INDEX);
	free(event408);

	// we can't read the AFU descriptor indirect regs like this,
	// will read them later

	//
	//Read AFU Control DVSEC
	//
	_wait_for_done(&(event500->state), lock);
	mmio->cfg.AFU_CTL_CP_0 = event500->cmd_data;
	info_msg("AFU Control DVSEC 0x00 is 0x%08x ", mmio->cfg.AFU_CTL_CP_0);
	free(event500);

	_wait_for_done(&(event504->state), lock);
	mmio->cfg.AFU_CTL_REVID_4 = event504->cmd_data;
	info_msg("AFU Control DVSEC 0x04 is 0x%08x ", mmio->cfg.AFU_CTL_REVID_4);
	free(event504);

	// we read 0x508 later on, right before writing it with ENABLE
	
	_wait_for_done(&(event50c->state), lock);
	mmio->cfg.AFU_CTL_WAKE_TERM_C = event50c->cmd_data;
	info_msg("AFU Control DVSEC 0x0c is 0x%08x ", mmio->cfg.AFU_CTL_WAKE_TERM_C);
	free(event50c);

	// Read pasid_len and use that value as num_of_processes
	// also write that value back to PASID_EN (later on in code)
	_wait_for_done(&(event510->state), lock);
	mmio->cfg.AFU_CTL_PASID_LEN_10 = event510->cmd_data;
	info_msg("AFU Control DVSEC 0x10 (PASID_LEN) is 0x%08x ", mmio->cfg.AFU_CTL_PASID_LEN_10);
	mmio->cfg.num_of_processes =  (event510->cmd_data & 0x0000001f); 
	free(event510);

	_wait_for_done(&(event514->state), lock);
	mmio->cfg.AFU_CTL_PASID_BASE_14 = event514->cmd_data;
	info_msg("AFU Control DVSEC 0x14 (PASID_base) is 0x%08x ", mmio->cfg.AFU_CTL_PASID_BASE_14);
	free(event514);

	_wait_for_done(&(event518->state), lock);
	mmio->cfg.AFU_CTL_ACTAG_LEN_EN_S = event518->cmd_data;
	info_msg("AFU Control DVSEC 0x18 (ACTAG_LEN) is 0x%08x ", mmio->cfg.AFU_CTL_ACTAG_LEN_EN_S);
	// TODO  setting bits[27:16] to set # of actags allowed
	// mmio->cfg.num_ints_per_process =  (event518->cmd_data & 0x0000ffff); 
	// interrupts are now a contract between the application and the accelerator - we are not involved
	free(event518);

	_wait_for_done(&(event51c->state), lock);
	mmio->cfg.AFU_CTL_ACTAG_BASE = event51c->cmd_data;
	info_msg("AFU Control DVSEC 0x1c (ACTAG_BASE) is 0x%08x ", mmio->cfg.AFU_CTL_ACTAG_BASE );
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

	// first afu descriptor indirect read gives us per pasid MMIO offset low & per pasid MMIO BAR
	debug_msg("AFU descriptor offset 0x30 indirect read");
	debug_msg("   AFU Information DVSEC write 0x%08x @ 0x%016lx", 0x00000030, cmd_pa_f1+0x40c);
	event40c = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x40c, 1, 0x00000030);
        _wait_for_done(&(event40c->state), lock);
	debug_msg("   AFU Information DVSEC write 0x%08x @ 0x%016lx complete", 0x00000030, cmd_pa_f1+0x40c);
	free(event40c);

	event40c = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x40c, 0L);
 	_wait_for_done(&(event40c->state), lock);
	debug_msg("   AFU Information DVSEC read @ 0x%016lx = 0x%08x", cmd_pa_f1+0x40c, event40c->cmd_data);

	while ((event40c->cmd_data & AFU_DESC_DATA_VALID) == 0) {
	        free(event40c);
		event40c = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x40c, 0L);
        	_wait_for_done(&(event40c->state), lock);
		debug_msg("   AFU Information DVSEC read @ 0x%016lx = 0x%08x", cmd_pa_f1+0x40c, event40c->cmd_data);
	}

	free(event40c);
	debug_msg("AFU descriptor offset 0x30 indirect read ready");

	event410 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x410, 0L);
        _wait_for_done(&(event410->state), lock);
	debug_msg("   AFU Information DVSEC afu descriptor data read 0x%08x @ 0x%016lx complete", event410->cmd_data, cmd_pa_f1+0x410);

	mmio->cfg.pp_MMIO_offset_low = (event410->cmd_data & 0xFFFFFFF8);
	info_msg("per process MMIO offset (low) is 0x%x ", mmio->cfg.pp_MMIO_offset_low);
	mmio->cfg.pp_MMIO_BAR = (event410->cmd_data & 0x00000007);
	info_msg("per process MMIO BAR is 0x%x ", mmio->cfg.pp_MMIO_BAR);
	free(event410);

	// second afu descriptor indirect read gives us per pasid MMIO offset high
	debug_msg("AFU descriptor offset 0x34 indirect read");
	debug_msg("   AFU Information DVSEC write 0x%08x @ 0x%016lx", 0x00000034, cmd_pa_f1+0x40c);
	event40c = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x40c, 1, 0x00000034);
        _wait_for_done(&(event40c->state), lock);
	debug_msg("   AFU Information DVSEC write 0x%08x @ 0x%016lx complete", 0x00000034, cmd_pa_f1+0x40c);
	free(event40c);

	event40c = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x40c, 0L);
        _wait_for_done(&(event40c->state), lock);
	debug_msg("   AFU Information DVSEC read @ 0x%016lx = 0x%08x", cmd_pa_f1+0x40c, event40c->cmd_data);

	while ((event40c->cmd_data & AFU_DESC_DATA_VALID) == 0) {
	        free(event40c);
		event40c = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x40c, 0L);
        	_wait_for_done(&(event40c->state), lock);
		debug_msg("   AFU Information DVSEC read @ 0x%016lx = 0x%08x", cmd_pa_f1+0x40c, event40c->cmd_data);
	}
	free(event40c);
	debug_msg("AFU descriptor offset 0x34 indirect read ready");

	event410 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x410, 0L);
        _wait_for_done(&(event410->state), lock);
	debug_msg("   AFU Information DVSEC afu descriptor data read 0x%08x @ 0x%016lx complete", event410->cmd_data, cmd_pa_f1+0x410);

	mmio->cfg.pp_MMIO_offset_high = event410->cmd_data;
	info_msg("per process MMIO offset (high) is 0x%x ", mmio->cfg.pp_MMIO_offset_high);
	free(event410);

	// third afu descriptor indirect read gives us per process MMIO stride
	debug_msg("AFU descriptor offset 0x38 indirect read");
	debug_msg("   AFU Information DVSEC write 0x%08x @ 0x%016lx", 0x00000038, cmd_pa_f1+0x40c);
	event40c = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x40c, 1, 0x00000038);
        _wait_for_done(&(event40c->state), lock);
	debug_msg("   AFU Information DVSEC write 0x%08x @ 0x%016lx complete", 0x00000038, cmd_pa_f1+0x40c);
	free(event40c);

	event40c = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x40c, 0L);
        _wait_for_done(&(event40c->state), lock);
	debug_msg("   AFU Information DVSEC read @ 0x%016lx = 0x%08x", cmd_pa_f1+0x40c, event40c->cmd_data);

	// Uncomment the while statement to get multiple reads on 0x2ac
	while ((event40c->cmd_data & AFU_DESC_DATA_VALID) == 0) {
	        free(event40c);
		event40c = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x40c, 0L);
        	_wait_for_done(&(event40c->state), lock);
		debug_msg("   AFU Information DVSEC read @ 0x%016lx = 0x%08x", cmd_pa_f1+0x40c, event40c->cmd_data);
	}

	free(event40c);
	debug_msg("AFU descriptor offset 0x38 indirect read ready");

	event410 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x410, 0L);
        _wait_for_done(&(event410->state), lock);
	debug_msg("   AFU Information DVSEC afu descriptor data read 0x%08x @ 0x%016lx complete", event410->cmd_data, cmd_pa_f1+0x410);

	// third read gives us per process MMIO stride
	mmio->cfg.pp_MMIO_stride = event410->cmd_data;
	info_msg("per process MMIO stride is 0x%x ", mmio->cfg.pp_MMIO_stride);
	free(event410);

	//
	// lets make the indirect read a subroutine because we are go do it several times
	//     get the "name", 6 reads to get all 24 bytes.
	//     get the per process mmio info, 3 reads
	//
	// read part1 to 6 of the name
	int i, j;
	uint64_t name_offset = 0x04;
	uint64_t name_stride = 0x04;
	for (i = 0; i < 6; i++ ) {
	  event410 = _read_afu_descriptor( mmio, cmd_pa_f1+0x40c, name_offset, lock );
	  for ( j = 0; j < name_stride; j++ ) {
	    mmio->cfg.name_space[(i*name_stride)+j] = ((uint8_t *)&event410->cmd_data)[j];
	  }
	  name_offset = name_offset + name_stride;
	  free( event410 );
	}
	mmio->cfg.name_space[24] = 0; // make sure name space is null terminated
	info_msg("name space is %s ", mmio->cfg.name_space);

	// things we have to write to enable an afu operation
	//    OpenCAPI Configuration Header 0x10 = bar0 low
	//    OpenCAPI Configuration Header 0x14 = bar0 high
	//    OpenCAPI Configuration Header 0x04[1] = Memory Space
	//    function dvsec 0x0c[11:0] = function actag length enabled
	//    afu control dvsec 0x0c[24] = enable afu
	//    afu control dvsec 0x10[12:8] = pasid length enabled
	//    afu control dvsec 0x18[12:8] = actag length enabled
	//

	// 
	// Set configuration space header bar and memory space
	//
	// Set BAR0 low 0x10 = 0x00000000 for now - could "randomize" based on size that comes back from a read
	debug_msg("OpenCAPI Configuration Header data write 0x%08x @ 0x%016lx", ( 0x00000000 ), cmd_pa_f1+0x10);
	event_w = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x10, 1, ( 0x00000000 )); // set to 0
        _wait_for_done(&(event_w->state), lock);
	free(event_w);

	// Set BAR0 high 0x14 = 0x00000000 for now - could "randomize" based on size that comes back from a read
	debug_msg("OpenCAPI Configuration Header data write 0x%08x @ 0x%016lx", ( 0x00000000 ), cmd_pa_f1+0x14);
	event_w = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x14, 1, ( 0x00000000 )); // set to 0
        _wait_for_done(&(event_w->state), lock);
	free(event_w);

	// Set Memory Space bit 0x04[1] in OpenCAPI Conifiguration header to allow the afu to decode addresses using the BAR registers
	event_r = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x04, 0L);          // opencapi configuration header... of funtion1
        _wait_for_done(&(event_r->state), lock);
	debug_msg("OpenCAPI Configuration Header data read 0x%08x @ 0x%016lx complete", event_r->cmd_data, cmd_pa_f1+0x04);

	debug_msg("OpenCAPI Configuration Header data write 0x%08x @ 0x%016lx", ( event_r->cmd_data | 0x00000002 ), cmd_pa_f1+0x04);
	event_w = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x04, 1, ( event_r->cmd_data | 0x00000002 )); // set bit 1
        _wait_for_done(&(event_w->state), lock);
	free(event_r);
	free(event_w);

	// 
	// Now set PASID Length Enabled to be same as PASID Length Supported
	// 
	event_r = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x510, 0L);
        _wait_for_done(&(event_r->state), lock);
	debug_msg("AFU Control DVSEC write read 0x%08x @ 0x%016lx complete", event_r->cmd_data, cmd_pa_f1+0x510);

	debug_msg("AFU Control DVSEC write 0x%08x @ 0x%016lx", ( event_r->cmd_data | ( event_r->cmd_data << 8 ) ), cmd_pa_f1+0x510);
	event_w = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x510, 1, ( event_r->cmd_data | ( event_r->cmd_data << 8 ) ) );
        _wait_for_done(&(event_w->state), lock);
	free(event_r);
	free(event_w);
	
	// 
	// Now set actag Length Enabled to be same as actag Length Supported in two places!
	// 
	event_r = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x518, 0L);
        _wait_for_done(&(event_r->state), lock);
	debug_msg("AFU Control DVSEC write read 0x%08x @ 0x%016lx complete", event_r->cmd_data, cmd_pa_f1+0x518);

	debug_msg("AFU Control DVSEC write 0x%08x @ 0x%016lx", ( event_r->cmd_data | ( event_r->cmd_data << 16 ) ), cmd_pa_f1+0x518);
	event_w = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x518, 1, ( event_r->cmd_data | ( event_r->cmd_data << 16 ) ) );
        _wait_for_done(&(event_w->state), lock);
	free(event_w);
	
	debug_msg("Function DVSEC write 0x%08x @ 0x%016lx", ( event_r->cmd_data ), cmd_pa_f1+0x30c);
	event_w = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x30c, 1, ( event_r->cmd_data  ) );
        _wait_for_done(&(event_w->state), lock);
	free(event_w);
	free(event_r);
	
	//
	// Now set enable bit in AFU Control DVSEC
	// first read data at 0x50c, and on in the enable bit [24] and write back
	//
	event_r = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x50c, 0L);  // was 508
        _wait_for_done(&(event_r->state), lock);
	debug_msg("AFU Control data read 0x%08x @ 0x%016lx complete", event_r->cmd_data, cmd_pa_f1 + 0x50c );

	mmio->cfg.AFU_CTL_EN_RST_INDEX_8 = event_r->cmd_data;
	debug_msg("AFU_CTL_EN_RST_INDEX is 0x%08x ", mmio->cfg.AFU_CTL_EN_RST_INDEX_8);

	debug_msg("OpenCAPI Configuration Header data write 0x%08x @ 0x%016lx", ( mmio->cfg.AFU_CTL_EN_RST_INDEX_8 | 0x0100000 ), cmd_pa_f1+0x50c);
	// event_w = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x50c, 1, (mmio->cfg.AFU_CTL_EN_RST_INDEX_8 | 0x01000000)); // set bit 24
	event_w = _add_event(mmio, NULL, 0, 0, 0, cmd_pa_f1+0x50c, 1, 0x01000000 ); // short term fix
        _wait_for_done(&(event_w->state), lock);
	free(event_r);
	free(event_w);

	// Test read after write to make sure test_afu is working
	debug_msg("One last read to make sure");
	event308 = _add_cfg(mmio, 1, 0, cmd_pa_f1 + 0x308, 0L);
        _wait_for_done(&(event308->state), lock);
	debug_msg("AFU Function DVSEC data read 0x%08x @ 0x%016lx complete", event308->cmd_data, cmd_pa_f1 + 0x308 );
	free(event308);
	return 0;
}

// modify to check command and use size, dl dp and stuff...
// Send pending MMIO event to AFU; use config_read or config_write for descriptor
// for MMIO use cmd_pr_rd_mem or cmd_pr_wr_mem
void send_mmio(struct mmio *mmio)
{
	struct mmio_event *event;
	char type[7];
	//unsigned char ddata[17];
	unsigned char null_buff[64] = {0};
	unsigned char tdata_bus[64];
	char data[17];
#ifdef TLX4
	uint8_t cmd_os;
#endif
	uint8_t  cmd_byte_cnt;
	uint64_t offset;

	// debug_msg( "ocse:send_mmio:" );

	event = mmio->list;

	// Check for valid event
	if ((event == NULL) || (event->state == OCSE_PENDING))
		return;

	// debug_msg( "ocse:send_mmio:valid command exists" );
	event->ack = OCSE_MMIO_ACK;
	if (event->cfg) {
	        debug_msg( "ocse:send_mmio:mmio to config space" );
		sprintf(type, "CFG");
		// Attempt to send config_rd or config_wr to AFU
		if (event->rnw) { //for config reads, no data to send
			if ( tlx_afu_send_cfg_cmd_and_data(mmio->afu_event,
			TLX_CMD_CONFIG_READ, 0xdead, 0, 2, 0, 0, 0, event->cmd_PA,
			0,0) == TLX_SUCCESS) {
				debug_msg("%s:%s READ%d word=0x%05x", mmio->afu_name, type,
			  	 	event->dw ? 64 : 32, event->cmd_PA);
				debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->cfg,
					event->rnw, event->dw, event->cmd_PA);
				event->state = OCSE_PENDING;
			}
		} else { //for config writes and we ALWAYS send 32BYTES of data
			// restricted by spec to pL of 1, 2, or 4 bytes HOWEVER
			// We now have to offset the data into a 32B buffer and send it
			memcpy(tdata_bus, null_buff, 32); //not sure if we always have to do this, but better safe than...
			uint8_t * dptr = tdata_bus;;
			 offset = event->cmd_PA & 0x0000000000000003 ;
			memcpy(dptr +offset, &(event->cmd_data), 4);
			if ( tlx_afu_send_cfg_cmd_and_data(mmio->afu_event,
				TLX_CMD_CONFIG_WRITE, 0xbeef, 0, 2, 0, 0, 0, event->cmd_PA,
				0,dptr) == TLX_SUCCESS) {
						sprintf(data, "%08" PRIx32, (uint32_t) event->cmd_data);
					debug_msg("%s:%s WRITE%d word=0x%05x data=0x%s offset=0x%x",
						mmio->afu_name, type,  32,
			  			event->cmd_PA, data, offset);
					debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->cfg,
						event->rnw, event->dw, event->cmd_PA);
					event->state = OCSE_PENDING;
				}
			}

       	}  else   {  // if not a CONFIG, then must be memory access MMIO rd/wr
	        if ( event->size == 0 ) {
                  // we have the old mmio style
		  debug_msg( "ocse:send_mmio:mmio to mmio space" );
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

		  // fix the data pointer for the write command later
		  event->data = (uint8_t *)&(event->cmd_data);

		} else {
		  // we have the new general memory style
		  debug_msg( "ocse:send_mmio:mmio to LPC space" );
		  sprintf(type, "MEM");
		  event->ack = OCSE_LPC_ACK;

		  // calculate event->pL, dL, and dP from event->dw
		  // calculate cmd_byte_cnt from event->size
		  cmd_byte_cnt = event->size;
		  event->cmd_pL = 0;
		  event->cmd_dL = 0;
		  event->cmd_dP = 0;
		  switch (event->size) {
		  case 1:
		    break;
		  case 2:
		    event->cmd_pL = 1;
		    break;
		  case 4:
		    event->cmd_pL = 2;
		    break;
		  case 8:
		    event->cmd_pL = 3;
		    break;
		  case 16:
		    event->cmd_pL = 4;
		    break;
		  case 32:
		    event->cmd_pL = 5;
		    break;
		  case 64:
		    event->cmd_dL= 1;
		    break;
		  case 128:
		    event->cmd_dL= 2;
		    break;
		  case 256:
		    event->cmd_dL= 3;
		    break;
		  default:
		    warn_msg( "send_mmio: Invalid size given %d", event->size );
		  }

		}
		
		if (event->rnw) { // read
		  if (cmd_byte_cnt < 64) { // partial
		    if (tlx_afu_send_cmd(mmio->afu_event,
					 TLX_CMD_PR_RD_MEM, 0xcafe, event->cmd_dL, event->cmd_pL, 0, 0, 0, event->cmd_PA) == TLX_SUCCESS) {
		      debug_msg("%s:%s READ%d word=0x%05x", mmio->afu_name, type, event->dw ? 64 : 32, event->cmd_PA);
		      debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->cfg, event->rnw, event->dw, event->cmd_PA);
		      event->state = OCSE_PENDING;
		    }
		  } else { // full
		    if (tlx_afu_send_cmd(mmio->afu_event,
					 TLX_CMD_RD_MEM, 0xefac, event->cmd_dL, event->cmd_pL, 0, 0, 0, event->cmd_PA) == TLX_SUCCESS) {
		      debug_msg("%s:%s READ size=%d offset=0x%05x", mmio->afu_name, type, cmd_byte_cnt, event->cmd_PA);
		      debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->cfg, event->rnw, event->dw, event->cmd_PA);
		      event->state = OCSE_PENDING;
		    }
		  }
		} else { // write - 2 part operation
		  if (event->state == OCSE_RD_RQ_PENDING) { // part 2 - send the data
		    // we can send 1, 2, 4, 8, 16, 32, 64, 128, or 256 bytes of data
		    // sizes less that 64 are embedded in a 64 byte value at the offset implied by cmd_PA
		    // sizes greater than 64 are not yet supported, but the idea is they would either be sent in a number of 64 byte
		    // packets or as a total packet to be dispursed by tlx_interface somehow...
		    // init a 64 byte space
		    memcpy(tdata_bus, null_buff, 64); //not sure if we always have to do this, but better safe than...
		    uint8_t * dptr = tdata_bus;
		    uint8_t BDI = 0;

		    offset = event->cmd_PA & 0x000000000000003F ;  // this works for addresses >= 64 too
		    memcpy( dptr+offset, event->data, cmd_byte_cnt);  // copy the data to the tdata buffer
	  	    // TODO finish this bid_resp_err code in sprinti
		    //if ( allow_bdi_resp_err(event->cmd->parms)) {
		    //		debug_msg("send_mmio: we've decided to BDI the cmd data  \n");
		    //		BDI = 1;
		    //} else
			BDI = 0;


		    if (tlx_afu_send_cmd_data(mmio->afu_event, 64, BDI, dptr) == TLX_SUCCESS) {
		      /* if (event->dw) */
		      /* 	sprintf(data, "%016" PRIx64, event->cmd_data); */
		      /* else */
		      /* 	sprintf(data, "%08" PRIx32, (uint32_t) event->cmd_data); */
		      /* debug_msg("%s:%s WRITE%d word=0x%05x data=0x%s offset=0x%x", */
		      /* 		mmio->afu_name, type, event->dw ? 64 : 32, */
		      /* 		event->cmd_PA, data, offset); */
		      debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->cfg,
				      event->rnw, event->dw, event->cmd_PA);
		      event->state = OCSE_PENDING;
		      debug_msg("send_mmio: got rd_req and sent data, now wait for cmd resp from AFU"); 
		    }
		  } else { // part 1 - send the command
		    if (cmd_byte_cnt < 64) { // partial
		      if (tlx_afu_send_cmd(mmio->afu_event,
					   TLX_CMD_PR_WR_MEM, 0xbead, event->cmd_dL, event->cmd_pL, 0, 0, 0, event->cmd_PA) == TLX_SUCCESS) {
			event->state = OCSE_RD_RQ_PENDING;
		      }
		    } else { // full
		      if (event->be_valid == 0) {
			if (tlx_afu_send_cmd(mmio->afu_event,
					     TLX_CMD_WRITE_MEM, 0xdaeb, event->cmd_dL, event->cmd_pL, 0, 0, 0, event->cmd_PA) == TLX_SUCCESS) {
			  event->state = OCSE_RD_RQ_PENDING;
			}
		      } else {
			if (tlx_afu_send_cmd(mmio->afu_event,
					     TLX_CMD_WRITE_MEM_BE, 0xbebe, event->cmd_dL, event->cmd_pL, event->be, 0, 0, event->cmd_PA) == TLX_SUCCESS) {
			  event->state = OCSE_RD_RQ_PENDING;
			}
		      }
		    }
		    debug_msg("send_mmio: sent write command, now wait for rd_req from AFU \n"); 
		  }
		}
		// Attempt to send mmio to AFU
		if (!event->rnw) { // MMIO write - two part operation
		}
	}
}

// Handle MMIO ack if returned by AFU
void handle_mmio_ack(struct mmio *mmio, uint32_t parity_enabled)
{
	int rc;
//	char data[17];
	char type[7];
	uint8_t afu_resp_opcode, resp_dl,resp_dp, resp_data_is_valid, resp_code, rdata_bad;
	uint16_t resp_capptag;
	uint32_t cfg_read_data = 0;
        uint64_t read_data; // data can now be up to 64 bytes, not just upto 8
	uint8_t *  rdata;
	unsigned char   rdata_bus[64];
	unsigned char   cfg_rdata_bus[4];
	unsigned char   mem_data[64];
	int offset, length;

	int i;

	// handle config and mmio responses
	// length can be calculated from the mmio->list->dw or cmd_pL
	// location of data in rdata_bus is address aligned based on mmio->list->cmd_PA
	// that is, mask off the high order address bits to form the offset - keep the low order 6 bits.

	rdata = rdata_bus;

	// needs to be modified to return 64 bytes and extract the 4/8 we want?
	
	if (mmio->list->cfg) {
		if (mmio->list->rnw) {
			rdata = cfg_rdata_bus;
			rc = afu_tlx_read_cfg_resp_and_data (mmio->afu_event,
							     &afu_resp_opcode, &resp_dl,&resp_capptag, 0xdead, &resp_dp,
							     &resp_data_is_valid, &resp_code, rdata_bus, &rdata_bad);
		} else {
			rc = afu_tlx_read_cfg_resp_and_data (mmio->afu_event,
							     &afu_resp_opcode, &resp_dl,&resp_capptag, 0xbeef, &resp_dp,
							     &resp_data_is_valid, &resp_code, 0, 0);
		}

	} else {
	        rc = afu_tlx_read_resp_and_data(mmio->afu_event,
						&afu_resp_opcode, &resp_dl,
						&resp_capptag, &resp_dp,
						&resp_data_is_valid, &resp_code, rdata_bus, &rdata_bad);
	}

	// this section needs to handle lpc memory data
	// send_mmio set mmio.ack field with the type of ack we need to send back to libocxl (mmio or lpc)
	// we can leverage that to decide how do interpret the data and respective size information
	// the data will always come in the 64 byte buffer.
	// we only want to send the exact size of the data back to libocxl
	// we get the data from the offset implied by the PA.
	if (rc == TLX_SUCCESS) {
	      //
              // at this point, we have 64 bytes of data in rdata_bus
	      //
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
	      } else if ( mmio->list->size == 0 ) {
		    sprintf(type, "MMIO");
	      } else {
	            sprintf(type, "MEM");
	      }

	      debug_msg("IN handle_mmio_ack and resp_capptag = %x and resp_code = %x! ", resp_capptag, resp_code);
	      mmio->list->resp_code = resp_code;  //save this to send back to libocxl/client
	      mmio->list->resp_opcode = afu_resp_opcode;  //save this to send back to libocxl/client
	      if (resp_data_is_valid) {
#ifdef DEBUG
    	            printf( "rdata_bus = 0x" );
		    for (i = 0; i < 64; i++) {
		      printf( "%02x", rdata_bus[i] );
		    }
		    printf( "\n" );
#endif	  
		    if (mmio->list->cfg) {
		          //TODO data is only 4B, for now don't put into uint64_t, put in uint32_t 
		          //we will fix this lateri and use cfg_resp_data_byte cnt!
		          length = 4;
			  memcpy( &cfg_read_data, &rdata_bus[0], length );
			  debug_msg("%s:%s CFG CMD RESP  length=%d data=0x%08x code=0x%02x", mmio->afu_name, type, length, cfg_read_data, resp_code ); // ???
		    } else {
		          // if this is an lpc response, the data could be a number of sizes at varying offsets in rdata
		          // extract data from address aligned offset in vector - this might not work if size > 64...
		          offset = mmio->list->cmd_PA & 0x000000000000003F ;

			  // calculate length.  
			  //    for lpc, we can just use mmio->list->size if we want.  Or we can decode dl/dp
			  //    for mmio, we use pL - maybe we could set up mmio->list->size even for the old mmio path - then this is always use the size...
			  if ( mmio->list->size == 0 ) {
			    if (mmio->list->cmd_pL == 0x02) {
			      length = 4;
			    } else {
			      length = 8;
			    }
			    memcpy( &read_data, &rdata_bus[offset], length );
			    debug_msg("%s:%s CMD RESP offset=%d length=%d data=0x%016x code=0x%x", mmio->afu_name, type, offset, length, read_data, resp_code );
			  } else {
			    length = mmio->list->size;
			    memcpy( mem_data, &rdata_bus[offset], length );
			    debug_msg("%s:%s CMD RESP offset=%d length=%d code=0x%x", mmio->afu_name, type, offset, length, resp_code );
#ifdef DEBUG
    	                    printf( "mem_data = 0x" );
			    for (i = 0; i < 64; i++) {
			      printf( "%02x", mem_data[i] );
			    }
			    printf( "\n" );
#endif	  
			  }
		    }
	      } else {
		    if ((afu_resp_opcode == 2) && ((resp_capptag == 0xdead) || 
			(resp_capptag == 0xcafe) || (resp_capptag == 0xefac))) {
		          printf("CFG/MMIO/MEM RD FAILED! afu_resp_opcode = 0x%x and resp_code = 0x%x \n",
				 afu_resp_opcode, resp_code);
		    	debug_msg("%s:%s CMD RESP code=0x%x", mmio->afu_name, type, resp_code);
		    }
		// do we get an ack back for write?
		    if ((afu_resp_opcode == 2) && ((resp_capptag == 0xbeef) || 
			(resp_capptag == 0xbead) || (resp_capptag == 0xdaeb))) {
		          printf("CFG/MMIO/MEM WR FAILED! afu_resp_opcode = 0x%x and resp_code = 0x%x \n",
				 afu_resp_opcode, resp_code);
		    	debug_msg("%s:%s CMD RESP code=0x%x", mmio->afu_name, type, resp_code);
		    }
	      }

	      // Keep data for MMIO reads
	      if (mmio->list->rnw) {
		if (mmio->list->cfg) {
		      mmio->list->cmd_data = (uint64_t) (cfg_read_data);
		} else if ( mmio->list->size == 0 ) {
                      mmio->list->cmd_data = read_data;
		} else {
		      memcpy( mmio->list->data, mem_data, length );
#ifdef DEBUG
		      printf( "mmio->list->data = 0x" );
		      for (i = 0; i < 64; i++) {
			printf( "%02x", mmio->list->data[i] );
		      }
		      printf( "\n" );
#endif	  
		}
	      }
	      mmio->list->state = OCSE_DONE;
	      mmio->list = mmio->list->_next;
	}

}

// Handle MMIO map request from client
void handle_mmio_map(struct mmio *mmio, struct client *client)
{
	uint32_t flags;
	uint8_t *buffer;
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
	   buffer = (uint8_t *) malloc(2);
	   buffer[0] = ack;
	   buffer[1] = 0;
	      if (put_bytes(fd, 2, buffer, mmio->dbg_fp, mmio->dbg_id,
			      client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}

	//if (put_bytes(fd, 1, &ack, mmio->dbg_fp, mmio->dbg_id, client->context)
	//    < 0) {
	//	client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	//}
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



// Handle MMIO request from client
struct mmio_event *handle_mmio(struct mmio *mmio, struct client *client,
			       int rnw, int dw, int global)
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

	// if AFU sent a mem_rd_fail or mem_wr_fail response, send them on to libocxl so it can interpret the resp_code
	// and retry if needed, or fail simulation 
	if (((event->resp_opcode == 0x02) || (event->resp_opcode == 0x04)) && (event->resp_code != 0))  {
	      debug_msg("handle mmio_done: sending OCSE_ACK for failed READ or WRITE to client");
	      buffer = (uint8_t *) malloc(2);
	      buffer[0] = event->ack;
	      buffer[1] = event->resp_code;
	      if (put_bytes(fd, 2, buffer, mmio->dbg_fp, mmio->dbg_id,
			      client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}
	debug_mmio_return(mmio->dbg_fp, mmio->dbg_id, client->context);
	free(event);
	free(buffer);
	return NULL;
	}

	if (event->rnw) {
	      // Return acknowledge with read data
	      if ( event->size !=0 ) {
   		    // this is an lpc mem request coming back
		    debug_msg("handle_mmio_done:sending OCSE_LPC_ACK for a READ to client!!!!");
		    buffer = (uint8_t *) malloc(event->size + 2);
		    buffer[0] = event->ack;
		    buffer[1] = event->resp_code;
		    memcpy( &(buffer[2]), event->data, event->size );
		    if (put_bytes(fd, event->size + 2, buffer, mmio->dbg_fp, mmio->dbg_id, client->context) < 0) {
		          client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		    }
		    free( event->data );
	      } else if ( event->dw ) {
		    debug_msg("handle_mmio_done:sending OCSE_MMIO_ACK for a dw READ to client!!!!");
		    buffer = (uint8_t *) malloc(10);
		    buffer[0] = event->ack;
		    buffer[1] = event->resp_code;
		    data64 = htonll(event->cmd_data);
		    memcpy(&(buffer[2]), &data64, 8);
		    if (put_bytes(fd, 10, buffer, mmio->dbg_fp, mmio->dbg_id, client->context) < 0) {
		          client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		    }
	      } else {
		    debug_msg("handle_mmio_done:sending OCSE_MMIO_ACK for a READ to client!!!!");
	    	    buffer = (uint8_t *) malloc(6);
		    buffer[0] = event->ack;
		    buffer[1] = event->resp_code;
		    data32 = htonl(event->cmd_data);
		    memcpy(&(buffer[2]), &data32, 4);
		    if (put_bytes(fd, 6, buffer, mmio->dbg_fp, mmio->dbg_id, client->context) < 0) {
		          client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		    }
	      }
	} else {
		// Return acknowledge for write
		debug_msg("READY TO SEND OCSE_*_ACK for a WRITE to client!!!!");
		buffer = (uint8_t *) malloc(2);
		buffer[0] = event->ack;
		buffer[1] = event->resp_code;
		if (put_bytes(fd, 2, buffer, mmio->dbg_fp, mmio->dbg_id,
			      client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}
		debug_msg("SENT OCSE_*_ACK for a WRITE to client!!!!");
	}
	debug_mmio_return(mmio->dbg_fp, mmio->dbg_id, client->context);
	free(event);
	free(buffer);

	return NULL;
}

// Add mem write event to offset in memory space
static struct mmio_event *_handle_mem_write(struct mmio *mmio, struct client *client, int region, int be_valid)
{
	struct mmio_event *event;
	uint32_t offset;
	uint32_t size;
	uint64_t be;
	uint8_t *data;
	int fd = client->fd;

	// get offset from socket
	if (get_bytes_silent(fd, 4, (uint8_t *)&offset, mmio->timeout,
			     &(client->abort)) < 0) {
		goto write_fail;
	}
	offset = ntohl(offset);

	if (be_valid == 0) {
	  // get size from socket
	  if (get_bytes_silent(fd, 4, (uint8_t *)&size, mmio->timeout,
			       &(client->abort)) < 0) {
	    goto write_fail;
	  }
	  size = ntohl(size);
	  be = 0;
	} else {
	  // get byte_enable from socket (size is always 64)
	  if (get_bytes_silent(fd, 8, (uint8_t *)&be, mmio->timeout,
			       &(client->abort)) < 0) {
	    goto write_fail;
	  }
	  be = ntohl(be);
	  size = 64;
	}	  

	// allocate a buffer for the data
	data = (uint8_t *)malloc( size );

	// get size bytes of data from socket
	if ( get_bytes_silent( fd, size, data, mmio->timeout, &(client->abort) ) < 0 ) {
	  goto write_fail;
	}

	event = _add_mem( mmio, client, 0, size, region, offset, data, be_valid, be );

	return event;

 write_fail:
	// Socket connection is dead
	debug_msg("%s:_handle_mmio_write failed context=%d",
		  mmio->afu_name, client->context);
	client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	return NULL;
}

// Add mmio read event of register at offset to list
static struct mmio_event *_handle_mem_read(struct mmio *mmio, struct client *client, int region)
{
	struct mmio_event *event;
	uint32_t offset;
	uint32_t size;
	uint8_t *data;
	int fd = client->fd;

	if (get_bytes_silent(fd, 4, (uint8_t *) &offset, mmio->timeout, &(client->abort)) < 0) {
		goto read_fail;
	}
	offset = ntohl(offset);

	if (get_bytes_silent(fd, 4, (uint8_t *) &size, mmio->timeout, &(client->abort)) < 0) {
		goto read_fail;
	}
	size = ntohl(size);

	// allocate a buffer for the data coming back
	data = (uint8_t *)malloc( size );

	event = _add_mem( mmio, client, 1, size, region, offset, data, 0, 0 );

	return event;

 read_fail:
	// Socket connection is dead
	debug_msg("%s:_handle_mmio_read failed context=%d",
		  mmio->afu_name, client->context);
	client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	return NULL;
}

// Handle mem request from client
struct mmio_event *handle_mem(struct mmio *mmio, struct client *client,
			      int rnw, int region, int be_valid)
{
	uint8_t ack;

	debug_msg( "_handle_mem: rnw=%d", rnw );

	// Only allow mem access when client is valid
	if (client->state != CLIENT_VALID) {
	        debug_msg( "_handle_mem: invalid client" );
		ack = OCSE_LPC_FAIL;
		if (put_bytes(client->fd, 1, &ack, mmio->dbg_fp, mmio->dbg_id,
			      client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		}
		return NULL;
	}

	if (rnw)
		return _handle_mem_read(mmio, client, region);
	else
	        return _handle_mem_write(mmio, client, region, be_valid);
}

