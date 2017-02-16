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

#ifndef __tlx_interface_h__
#define __tlx_interface_h__ 1

#include "tlx_interface_t.h"

/* Call this at startup to reset all the event indicators */

void tlx_event_reset(struct AFU_EVENT *event);

/* Call this once after creation to initialize the AFU_EVENT structure and open
 * a socket conection to an AFU server.  This function initializes the TLX side
 * of the interface which is the client in the socket connection server_host
 * should be the name of the server hosting the simulation of the AFU and port
 * is the active port on that server */

int tlx_init_afu_event(struct AFU_EVENT *event, char *server_host, int port);

/* Call this to close the socket connection from either side */

int tlx_close_afu_event(struct AFU_EVENT *event);

/* Call this once after creation to initialize the AFU_EVENT structure.  This
 * function initializes the AFU side of the interface which is the server in
 * the socket connection */

int tlx_serv_afu_event(struct AFU_EVENT *event, int port);



/* Call this from ocse to send a  response  to tlx/afu*/

int tlx_afu_send_resp(struct AFU_EVENT *event,
		 uint8_t tlx_resp_opcode,
		 uint16_t resp_afutag, uint8_t resp_code, 
		 uint8_t resp_pg_size, uint8_t resp_dl,
#ifdef TLX4
		 uint32_t resp_host_tag, uint8_t resp_cache_state,
#endif
		 uint8_t resp_dp, uint32_t resp_addr_tag);


// TODO - DON"T CALL THIS YET - IT WON"T WORK
/* Call this from ocse to send response data to tlx/afu   assume can only send 64B 
 * @ time to FIFO ?*/

int tlx_afu_send_resp_data(struct AFU_EVENT *event,
		 uint8_t DATA_RESP_CONTINUATION,
		 uint8_t resp_data_bdi,uint8_t * resp_data);



/* Call this from ocse to send both response & response data to tlx/afu  */

int tlx_afu_send_resp_and_data(struct AFU_EVENT *event,
		 uint8_t tlx_resp_opcode,
		 uint16_t resp_afutag, uint8_t resp_code, 
		 uint8_t resp_pg_size, uint8_t resp_resp_dl,
#ifdef TLX4
		 uint32_t resp_host_tag, uint8_t resp_cache_state,
#endif
		 uint8_t resp_dp, uint32_t resp_addr_tag,
		 uint8_t resp_data_bdi,uint8_t * resp_data);


/* Call this from ocse to send a command to tlx/afu */

int tlx_afu_send_cmd(struct AFU_EVENT *event,
		 uint8_t tlx_cmd_opcode,
		 uint16_t cmd_capptag, uint8_t cmd_dl, 
		 uint8_t cmd_pl, uint64_t cmd_be,
		 uint8_t cmd_end, uint8_t cmd_t,
#ifdef TLX4
		 uint8_t cmd_os, uint8_t cmd_flag,
#endif
		 uint64_t cmd_pa);


// TODO - DON"T CALL THIS YET - IT WON"T WORK
/* Call this from ocse to send command data to tlx/afu   assume can only send 64B 
 * @ time to FIFO ?*/

int tlx_afu_send_cmd_data(struct AFU_EVENT *event,
		 uint8_t DATA_CMD_CONTINUATION,
		 uint8_t cmd_data_bdi,uint8_t * cmd_data);


/* Call this from ocse to send both command & command data to tlx/afu */

int tlx_afu_send_cmd_and_data(struct AFU_EVENT *event,
		 uint8_t tlx_cmd_opcode,
		 uint16_t cmd_capptag, uint8_t cmd_dl, 
		 uint8_t cmd_pl, uint64_t cmd_be,
		 uint8_t cmd_end, uint8_t cmd_t,
		 uint64_t cmd_pa,  
#ifdef TLX4
		 uint8_t cmd_os, uint8_t cmd_flag,
#endif
		 uint8_t cmd_data_bdi, uint8_t * cmd_data);


/* Call this from ocse to read AFU response. This reads both afu_tlx resp AND resp data interfaces */

int afu_tlx_read_resp_and_data(struct AFU_EVENT *event,
		    uint8_t * afu_resp_opcode, uint8_t * resp_dl,
		    uint16_t * resp_capptag, uint8_t * resp_dp,
		    uint8_t * resp_data_is_valid, uint8_t * resp_code, uint8_t * rdata_bus, uint8_t * rdata_bad);


/* Call this from ocse to read AFU command. This reads both afu_tlx cmd AND cmd data interfaces */

int afu_tlx_read_cmd_and_data(struct AFU_EVENT *event,
  		    uint8_t * afu_cmd_opcode, uint16_t * cmd_actag,             
  		    uint8_t * cmd_stream_id, uint8_t * cmd_ea_or_obj,  
 		    uint16_t * cmd_afutag, uint8_t * cmd_dl,                 
  		    uint8_t * cmd_pl, 
#ifdef TLX4
		    uint8_t * cmd_os,       
#endif          
		    uint64_t * cmd_be, uint8_t * cmd_flag,               
 		    uint8_t * cmd_endian, uint16_t * cmd_bdf,               
  	  	    uint32_t * cmd_pasid, uint8_t * cmd_pg_size, uint8_t * cmd_data_is_valid,             
 		    uint8_t * cdata_bus, uint8_t * cdata_bad);              


/* Call this periodically to send events and clocking synchronization to AFU */
/* The comparable function, tlx_signal_tlx_model, is not defined here bc it 
 * is called internally by tlx_get_tlx_events   */

int tlx_signal_afu_model(struct AFU_EVENT *event);


/* This function checks the socket connection for data from the external AFU
 * simulator. It needs to be called periodically to poll the socket connection.
 * It will update the AFU_EVENT structure.  It returns a 1 if there are new
 * events to process, 0 if not, -1 on error or close.
 * On a 1 return, the following functions should be called to retrieve the
 * individual events.
 * afu_tlx_read_cmd
 * afu_tlx_read_resp */

int tlx_get_afu_events(struct AFU_EVENT *event);


/* This function checks the socket connection for data from the external OCL
 * simulator. It  needs to be called periodically to poll the socket connection.
 * (every clock cycle)  It will update the AFU_EVENT structure and returns a 1
 * if there are new events to process */

int tlx_get_tlx_events(struct AFU_EVENT *event);


/* Call this on the AFU side to send a response to ocse.  */

int afu_tlx_send_resp(struct AFU_EVENT *event,
 		 uint8_t afu_resp_opcode,            
 		 uint8_t resp_dl, uint16_t resp_capptag,          
 		 uint8_t resp_dp, uint8_t resp_code);              


// TODO - DON"T CALL THIS YET - IT WON"T WORK
/* Call this from afu to send response data to ocse   assume can only send 64B 
 * @ time to FIFO ?*/

int afu_tlx_send_resp_data(struct AFU_EVENT *event,
		 uint8_t DATA_RESP_CONTINUATION,
		 uint8_t rdata_bad,uint8_t resp_dp,
		 uint8_t resp_dl,uint8_t * rdata_bus);


/* Call this on the AFU side to send a response and response data to ocse.  */

int afu_tlx_send_resp_and_data(struct AFU_EVENT *event,
 		 uint8_t afu_resp_opcode,            
 		 uint8_t resp_dl, uint16_t resp_capptag,          
 		 uint8_t resp_dp, uint8_t resp_code,              
  		 uint8_t rdata_valid, uint8_t * rdata_bus,    
 		 uint8_t rdata_bad);              


/* Call this on the AFU side to send a command to ocse */

int afu_tlx_send_cmd(struct AFU_EVENT *event,
		 uint8_t afu_cmd_opcode, uint16_t cmd_actag,             
  	 	 uint8_t cmd_stream_id, uint8_t * cmd_ea_or_obj, 
  		 uint16_t cmd_afutag, uint8_t cmd_dl,  
  		 uint8_t cmd_pl,                 
#ifdef TLX4
  		 uint8_t cmd_os,     /* 1 bit ordered segment CAPI 4 */
#endif
  	 	 uint64_t cmd_be,uint8_t cmd_flag,               
		 uint8_t cmd_endian, uint16_t cmd_bdf,               
 		 uint32_t cmd_pasid, uint8_t cmd_pg_size);            


// TODO - DON"T CALL THIS YET - IT WON"T WORK
/* Call this from afu to send command data to ocse   assume can only send 64B 
 * @ time to FIFO ?*/

int afu_tlx_send_cmd_data(struct AFU_EVENT *event,
		 uint8_t DATA_CMD_CONTINUATION,
		 uint8_t cdata_bad, uint8_t cmd_pl,
		 uint8_t cmd_dl, uint8_t * cdata_bus);


/* Call this on the AFU side to send a command and cmd data to ocse */

int afu_tlx_send_cmd_and_data(struct AFU_EVENT *event,
		 uint8_t afu_cmd_opcode, uint16_t cmd_actag,             
  	 	 uint8_t cmd_stream_id, uint8_t * cmd_ea_or_obj, 
  		 uint16_t cmd_afutag, uint8_t cmd_dl,  /* combine dl and pl ??? */
  		 uint8_t cmd_pl,                 
#ifdef TLX4
  		 uint8_t cmd_os,     /* 1 bit ordered segment CAPI 4 */
#endif
  	 	 uint64_t cmd_be, uint8_t cmd_flag,               
		 uint8_t cmd_endian, uint16_t cmd_bdf,               
 		 uint32_t cmd_pasid, uint8_t cmd_pg_size,            
  		 uint8_t * cdata_bus, uint8_t cdata_bad);              

			     

/* Call this from AFU to read ocse (CAPP/TL) response. This reads both tlx_afu resp AND resp data interfaces */

int tlx_afu_read_resp_and_data(struct AFU_EVENT *event,
		 uint8_t tlx_resp_opcode,
		 uint16_t resp_afutag, uint8_t resp_code, 
		 uint8_t resp_pg_size, uint8_t resp_resp_dl,
#ifdef TLX4
		 uint32_t resp_host_tag, uint8_t resp_cache_state,
#endif
		 uint8_t resp_dp, uint32_t resp_addr_tag,
		 uint8_t resp_data_is_valid, uint8_t resp_data_bdi, uint8_t * resp_data);


/* Call this from AFU to read ocse (CAPP/TL) command. This reads both tlx_afu cmd AND cmd data interfaces */

int tlx_afu_read_cmd_and_data(struct AFU_EVENT *event,
		 uint8_t tlx_cmd_opcode,
		 uint16_t cmd_capptag, uint8_t cmd_dl, 
		 uint8_t cmd_pl, uint64_t cmd_be,
		 uint8_t cmd_end, uint8_t cmd_t,
		 uint64_t cmd_pa, 
#ifdef TLX4
		 uint8_t cmd_flag,  /* used for atomics from host CAPI 4 */
  		 uint8_t cmd_os,     /* 1 bit ordered segment CAPI 4 */
#endif
		 uint8_t cmd_data_is_valid, uint8_t cmd_data_bdi,uint8_t * cmd_data);

// TODO Still to come - add credits to interfaces.....
  		                 

#endif
