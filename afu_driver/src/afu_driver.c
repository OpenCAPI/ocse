/*
 * Copyright 2014 International Business Machines
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

#include <malloc.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tlx_interface.h"
#include "vpi_user.h"
#include "svdpi.h"

// Global Variables
static struct AFU_EVENT event;
//
//
// Local Variables
#define CLOCK_EDGE_DELAY 2
#define CACHELINE_BYTES 64
#define EA_OBJ_HANDLE 10
uint64_t c_sim_time ;
int      c_sim_error ;
static int clk_afu_resp_val;
static int clk_afu_cmd_val;
static int clk_afu_resp_dat_val;
static int clk_afu_cmd_dat_val;

// inputs from AFX
uint8_t		c_reset = 1;
uint8_t		c_reset_d1 = 1;
uint8_t		c_reset_d2 = 1;
uint8_t		c_afu_tlx_cmd_credit;
uint8_t		c_afu_tlx_cmd_initial_credit;
uint8_t		c_afu_tlx_resp_credit;
uint8_t		c_afu_tlx_resp_initial_credit;

uint8_t		c_afu_tlx_cmd_valid;
uint8_t		c_afu_tlx_cmd_opcode;
uint16_t	c_afu_tlx_cmd_actag;
uint8_t		c_afu_tlx_cmd_stream_id;
uint8_t		c_afu_tlx_cmd_ea_or_obj[EA_OBJ_HANDLE];
uint16_t	c_afu_tlx_cmd_afutag;
uint8_t		c_afu_tlx_cmd_dl;
uint8_t		c_afu_tlx_cmd_pl;
uint8_t		c_afu_tlx_cmd_os;
uint64_t	c_afu_tlx_cmd_be;
uint8_t		c_afu_tlx_cmd_flag;
uint8_t		c_afu_tlx_cmd_endian;
uint16_t	c_afu_tlx_cmd_bdf;
uint32_t	c_afu_tlx_cmd_pasid;
uint8_t		c_afu_tlx_cmd_pg_size;
uint8_t		c_afu_tlx_cdata_valid;
uint8_t		c_afu_tlx_cdata_bdi;
uint8_t  	c_afu_tlx_cdata_bus[CACHELINE_BYTES];

uint8_t		c_afu_tlx_resp_valid;
uint8_t		c_afu_tlx_resp_opcode;
uint8_t		c_afu_tlx_resp_dl;
uint16_t	c_afu_tlx_resp_capptag;
uint8_t		c_afu_tlx_resp_dp;
uint8_t		c_afu_tlx_resp_code;
uint8_t		c_afu_tlx_rdata_valid;
uint8_t		c_afu_tlx_rdata_bus[CACHELINE_BYTES];
uint8_t		c_afu_tlx_rdata_bdi;

uint8_t		c_afu_tlx_cmd_rd_req_top;
uint8_t		c_afu_tlx_cmd_rd_cnt_top;

uint8_t		c_afu_tlx_resp_rd_req_top;
uint8_t		c_afu_tlx_resp_rd_cnt_top;
//
//
// Local Methods
static int getMy64Bit(const svLogicVecVal *my64bSignal, uint64_t *conv64bit);
int getMyCacheLine(const svLogicVecVal *myLongSignal, uint8_t myCacheData[]);
int getMyByteArray(const svLogicVecVal *myLongSignal, uint32_t arrayLength, uint8_t myCacheData[arrayLength]);
void setMyCacheLine(svLogicVecVal *myLongSignal, uint8_t myCacheData[]);
void setDpiSignal32(svLogicVecVal *my32bSignal, uint32_t inData, int size);
static void setDpiSignal64(svLogicVecVal *my64bSignal, uint64_t data);
static void error_message(const char *str);
static void tlx_control(void);
//
void tlx_bfm(
	            const svLogic       tlx_clock,
		    const svLogic       afu_clock,
		    const svLogic       reset,
				// Table 1: TLX to AFU Response Interface
			svLogic		*tlx_afu_resp_valid_top,
			svLogicVecVal	*tlx_afu_resp_opcode_top,
			svLogicVecVal	*tlx_afu_resp_afutag_top,
			svLogicVecVal	*tlx_afu_resp_code_top,
			svLogicVecVal	*tlx_afu_resp_pg_size_top,
			svLogicVecVal	*tlx_afu_resp_dl_top,
			svLogicVecVal	*tlx_afu_resp_dp_top,
			svLogicVecVal	*tlx_afu_resp_host_tag_top,
			svLogicVecVal	*tlx_afu_resp_addr_tag_top,
			svLogicVecVal	*tlx_afu_resp_cache_state_top,

				//	Table 2: TLX Response Credit Interface	// TODO: Process Credit interface
			const svLogic	afu_tlx_resp_credit_top,
		const svLogicVecVal	*afu_tlx_resp_initial_credit_top,

				//	Table 3: TLX to AFU Command Interface
			svLogic		*tlx_afu_cmd_valid_top,
			svLogicVecVal	*tlx_afu_cmd_opcode_top,
			svLogicVecVal	*tlx_afu_cmd_capptag_top,
			svLogicVecVal	*tlx_afu_cmd_dl_top,
			svLogicVecVal	*tlx_afu_cmd_pl_top,
			svLogicVecVal	*tlx_afu_cmd_be_top,
			svLogic		*tlx_afu_cmd_end_top,
			svLogic		*tlx_afu_cmd_t_top,
			svLogicVecVal	*tlx_afu_cmd_pa_top,
			svLogicVecVal	*tlx_afu_cmd_flag_top,
			svLogic		*tlx_afu_cmd_os_top,

				//	Table 4: TLX Command Credit Interface	// TODO: Process Credit interface
			const svLogic	afu_tlx_cmd_credit_top,
		const svLogicVecVal	*afu_tlx_cmd_initial_credit_top,

				//	Table 5: TLX to AFU Response Data Interface
			svLogic		*tlx_afu_resp_data_valid_top,
			svLogicVecVal	*tlx_afu_resp_data_bus_top,
			svLogic		*tlx_afu_resp_data_bdi_top,
			const svLogic	afu_tlx_resp_rd_req_top,
		const svLogicVecVal	*afu_tlx_resp_rd_cnt_top,

				//	Table 6: TLX to AFU Command Data Interface
			svLogic		*tlx_afu_cmd_data_valid_top,
			svLogicVecVal	*tlx_afu_cmd_data_bus_top,
			svLogic		*tlx_afu_cmd_data_bdi_top,
			const svLogic	afu_tlx_cmd_rd_req_top,
		const svLogicVecVal	*afu_tlx_cmd_rd_cnt_top,

				//	Table 7: TLX Framer credit interface	// TODO: Process Credit interface
			svLogic		*tlx_afu_resp_credit_top,
			svLogic		*tlx_afu_resp_data_credit_top,
			svLogic		*tlx_afu_cmd_credit_top,
			svLogic		*tlx_afu_cmd_data_credit_top,
			svLogicVecVal	*tlx_afu_cmd_resp_initial_credit_top,
			svLogicVecVal	*tlx_afu_data_initial_credit_top,

				//	Table 8: TLX Framer Command Interface
			const svLogic	afu_tlx_cmd_valid_top,
		const svLogicVecVal	*afu_tlx_cmd_opcode_top,
		const svLogicVecVal	*afu_tlx_cmd_actag_top,
		const svLogicVecVal	*afu_tlx_cmd_stream_id_top,
		const svLogicVecVal	*afu_tlx_cmd_ea_or_obj_top,
		const svLogicVecVal	*afu_tlx_cmd_afutag_top,
		const svLogicVecVal	*afu_tlx_cmd_dl_top,
		const svLogicVecVal	*afu_tlx_cmd_pl_top,
			const svLogic	afu_tlx_cmd_os_top,
		const svLogicVecVal	*afu_tlx_cmd_be_top,
		const svLogicVecVal	*afu_tlx_cmd_flag_top,
			const svLogic	afu_tlx_cmd_endian_top,
		const svLogicVecVal	*afu_tlx_cmd_bdf_top,
		const svLogicVecVal	*afu_tlx_cmd_pasid_top,
		const svLogicVecVal	*afu_tlx_cmd_pg_size_top,
		const svLogicVecVal	*afu_tlx_cdata_bus_top,
			const svLogic	afu_tlx_cdata_bdi_top,// TODO: TLX Ref Design doc lists this as afu_tlx_cdata_bad
			const svLogic	afu_tlx_cdata_valid_top,

				//	Table 9: TLX Framer Response Interface
			const svLogic	afu_tlx_resp_valid_top,
		const svLogicVecVal	*afu_tlx_resp_opcode_top,
		const svLogicVecVal	*afu_tlx_resp_dl_top,
		const svLogicVecVal	*afu_tlx_resp_capptag_top,
		const svLogicVecVal	*afu_tlx_resp_dp_top,
		const svLogicVecVal	*afu_tlx_resp_code_top,
			const svLogic	afu_tlx_rdata_valid_top,
		const svLogicVecVal	*afu_tlx_rdata_bus_top,
			const svLogic	afu_tlx_rdata_bdi_top,

// These signals do not appear on the RefDesign Doc. However it is present on the TLX spec
			svLogic		*afu_cfg_in_rcv_tmpl_capability_0_top,
			svLogic		*afu_cfg_in_rcv_tmpl_capability_1_top,
			svLogic		*afu_cfg_in_rcv_tmpl_capability_2_top,
			svLogic		*afu_cfg_in_rcv_tmpl_capability_3_top,
			svLogicVecVal	*afu_cfg_in_rcv_rate_capability_0_top,
			svLogicVecVal	*afu_cfg_in_rcv_rate_capability_1_top,
			svLogicVecVal	*afu_cfg_in_rcv_rate_capability_2_top,
			svLogicVecVal	*afu_cfg_in_rcv_rate_capability_3_top,
			svLogic		*tlx_afu_ready_top
            )
{
//  int change = 0;
  int invalidVal = 0;
  c_reset			= reset & 0x1;
  if(!c_reset_d2)
  {
    if ( tlx_clock == sv_0 ) {
	//	Accessing inputs from the AFX
      c_afu_tlx_cmd_initial_credit  	= (afu_tlx_cmd_initial_credit_top->aval) & 0x1F;
      invalidVal			+= (afu_tlx_cmd_initial_credit_top->bval) & 0x1F;
      c_afu_tlx_resp_initial_credit  	= (afu_tlx_resp_initial_credit_top->aval) & 0x1F;
      invalidVal			+= (afu_tlx_resp_initial_credit_top->bval) & 0x1F;
      if(!c_reset)
      {
        afu_tlx_send_initial_credits (&event, c_afu_tlx_cmd_initial_credit, c_afu_tlx_resp_initial_credit);
        tlx_afu_read_initial_credits (&event, &c_afu_tlx_cmd_initial_credit, &c_afu_tlx_resp_initial_credit);
      }
#ifdef DEBUG1
      if(invalidVal != 0)
      {
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Cmd Credit Interface has either X or Z value \n" );
      }
#endif
/*
    invalidVal = 0;
    c_afu_tlx_resp_credit  	= (afu_tlx_resp_credit_top & 0x2) ? 0 : (afu_tlx_resp_credit_top & 0x1);
    invalidVal			+= afu_tlx_resp_credit_top & 0x2;
    c_afu_tlx_cmd_credit  	= (afu_tlx_cmd_credit_top & 0x2) ? 0 : (afu_tlx_cmd_credit_top & 0x1);
    invalidVal			+= afu_tlx_cmd_credit_top & 0x2;
    afu_tlx_read_initial_credits (&event, &c_afu_tlx_resp_credit, &c_afu_tlx_resp_initial_credit);
#ifdef DEBUG1
    if(invalidVal != 0)
    {
      printf("%08lld: ", (long long) c_sim_time);
      printf(" The AFU-TLX Resp Credit Interface has either X or Z value \n" );
    }
#endif
*/
      invalidVal = 0;
	//	Code to access the AFU->TLX command interface
      c_afu_tlx_cmd_valid  	= (afu_tlx_cmd_valid_top & 0x2) ? 0 : (afu_tlx_cmd_valid_top & 0x1);
      invalidVal			+= afu_tlx_cmd_valid_top & 0x2;
      c_afu_tlx_cdata_valid  	= (afu_tlx_cdata_valid_top & 0x2) ? 0 : (afu_tlx_cdata_valid_top & 0x1);
      invalidVal			+= afu_tlx_cdata_valid_top & 0x2;
      if(c_afu_tlx_cmd_valid)
      {
        c_afu_tlx_cmd_opcode	= (afu_tlx_cmd_opcode_top->aval) & 0xFF;
        invalidVal		= (afu_tlx_cmd_opcode_top->bval) & 0xFF;
        c_afu_tlx_cmd_actag	= (afu_tlx_cmd_actag_top->aval) & 0xFFF;
        invalidVal		+= (afu_tlx_cmd_actag_top->bval) & 0xFFF;
        c_afu_tlx_cmd_stream_id	= (afu_tlx_cmd_stream_id_top->aval) & 0xF;
        invalidVal		+= (afu_tlx_cmd_stream_id_top->bval) & 0xF;
        invalidVal		+= getMyByteArray(afu_tlx_cmd_ea_or_obj_top, 9, c_afu_tlx_cmd_ea_or_obj);
        c_afu_tlx_cmd_afutag	= (afu_tlx_cmd_afutag_top->aval) & 0xFFFF;
        invalidVal		+= (afu_tlx_cmd_afutag_top->bval) & 0xFFFF;
        c_afu_tlx_cmd_dl		= (afu_tlx_cmd_dl_top->aval) & 0x3;
        invalidVal		+= (afu_tlx_cmd_dl_top->bval) & 0x3;
        c_afu_tlx_cmd_pl		= (afu_tlx_cmd_pl_top->aval) & 0x7;
        invalidVal		+= (afu_tlx_cmd_pl_top->bval) & 0x7;
        c_afu_tlx_cmd_os		= (afu_tlx_cmd_os_top & 0x2) ? 0 : (afu_tlx_cmd_os_top & 0x1);
        invalidVal		+= afu_tlx_cmd_os_top & 0x2;
        invalidVal		+= getMy64Bit(afu_tlx_cmd_be_top, &c_afu_tlx_cmd_be);
        c_afu_tlx_cmd_flag	= (afu_tlx_cmd_flag_top->aval) & 0xF;
        invalidVal		+= (afu_tlx_cmd_flag_top->bval) & 0xF;
        c_afu_tlx_cmd_endian	= (afu_tlx_cmd_endian_top & 0x2) ? 0 : (afu_tlx_cmd_endian_top & 0x1);
        invalidVal		+= afu_tlx_cmd_endian_top & 0x2;
        c_afu_tlx_cmd_bdf		= (afu_tlx_cmd_bdf_top->aval) & 0xFFFF;
        invalidVal		+= (afu_tlx_cmd_bdf_top->bval) & 0xFFFF;
        c_afu_tlx_cmd_pasid	= (afu_tlx_cmd_pasid_top->aval) & 0xFFFFF;
        invalidVal		+= (afu_tlx_cmd_pasid_top->bval) & 0xFFFFF;
        c_afu_tlx_cmd_pg_size	= (afu_tlx_cmd_pg_size_top->aval) & 0x3F;
        invalidVal		+= (afu_tlx_cmd_pg_size_top->bval) & 0x3F;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Command Valid, with opcode: 0x%x \n",  c_afu_tlx_cmd_opcode);
      }
      if(c_afu_tlx_cdata_valid)
      {
        c_afu_tlx_cdata_bdi  	= (afu_tlx_cdata_bdi_top & 0x2) ? 0 : (afu_tlx_cdata_bdi_top & 0x1);
        invalidVal		+= afu_tlx_cdata_bdi_top & 0x2;
        invalidVal		+= getMyCacheLine(afu_tlx_cdata_bus_top, c_afu_tlx_cdata_bus);
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Command Data Valid, with opcode: 0x%x \n",  c_afu_tlx_cmd_opcode);
      }
#ifdef DEBUG1
      if(invalidVal != 0)
      {
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Command Interface has either X or Z value \n" );
      }
#endif
      if(c_afu_tlx_cmd_valid & (!c_afu_tlx_cdata_valid))
      {
        afu_tlx_send_cmd(&event,
        		c_afu_tlx_cmd_opcode, c_afu_tlx_cmd_actag, c_afu_tlx_cmd_stream_id,
  		c_afu_tlx_cmd_ea_or_obj, c_afu_tlx_cmd_afutag,
  		c_afu_tlx_cmd_dl, c_afu_tlx_cmd_pl,
#ifdef TLX4
		c_afu_tlx_cmd_os,
#endif
		c_afu_tlx_cmd_be, c_afu_tlx_cmd_flag, c_afu_tlx_cmd_endian,
		c_afu_tlx_cmd_bdf, c_afu_tlx_cmd_pasid, c_afu_tlx_cmd_pg_size
        );
      }
      else if(c_afu_tlx_cdata_valid)
      {
        afu_tlx_send_cmd_and_data(&event,
        		c_afu_tlx_cmd_opcode, c_afu_tlx_cmd_actag, c_afu_tlx_cmd_stream_id,
  		c_afu_tlx_cmd_ea_or_obj, c_afu_tlx_cmd_afutag,
		c_afu_tlx_cmd_dl, c_afu_tlx_cmd_pl,
#ifdef TLX4
		c_afu_tlx_cmd_os,
#endif
		c_afu_tlx_cmd_be, c_afu_tlx_cmd_flag, c_afu_tlx_cmd_endian,
		c_afu_tlx_cmd_bdf, c_afu_tlx_cmd_pasid, c_afu_tlx_cmd_pg_size,
		c_afu_tlx_cdata_bus, c_afu_tlx_cdata_bdi
        );
      }
      invalidVal = 0;
      c_afu_tlx_resp_valid  	= (afu_tlx_resp_valid_top & 0x2) ? 0 : (afu_tlx_resp_valid_top & 0x1);
      invalidVal			= afu_tlx_resp_valid_top & 0x2;
      c_afu_tlx_rdata_valid  	= (afu_tlx_rdata_valid_top & 0x2) ? 0 : (afu_tlx_rdata_valid_top & 0x1);
      invalidVal			+= afu_tlx_rdata_valid_top & 0x2;
      if(c_afu_tlx_resp_valid)
      {
        c_afu_tlx_resp_opcode	= (afu_tlx_resp_opcode_top->aval) & 0xFF;
        invalidVal		+= (afu_tlx_resp_opcode_top->bval) & 0xFF;
        c_afu_tlx_resp_dl		= (afu_tlx_resp_dl_top->aval) & 0x3;
        invalidVal		+= (afu_tlx_resp_dl_top->bval) & 0x3;
        c_afu_tlx_resp_capptag	= (afu_tlx_resp_capptag_top->aval) & 0xFFFF;
        invalidVal		+= (afu_tlx_resp_capptag_top->bval) & 0xFFFF;
        c_afu_tlx_resp_dp		= (afu_tlx_resp_dp_top->aval) & 0x3;
        invalidVal		+= (afu_tlx_resp_dp_top->bval) & 0x3;
        c_afu_tlx_resp_code	= (afu_tlx_resp_code_top->aval) & 0xF;
        invalidVal		+= (afu_tlx_resp_code_top->bval) & 0xF;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Response Valid, with opcode: 0x%x \n",  c_afu_tlx_resp_opcode);
      }
      if(c_afu_tlx_rdata_valid)
      {
        c_afu_tlx_rdata_bdi  	= (afu_tlx_rdata_bdi_top & 0x2) ? 0 : (afu_tlx_rdata_bdi_top & 0x1);
        invalidVal		+= afu_tlx_rdata_bdi_top & 0x2;
        invalidVal		+= getMyCacheLine(afu_tlx_rdata_bus_top, c_afu_tlx_rdata_bus);
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Response Data Valid, with opcode: 0x%x \n",  c_afu_tlx_resp_opcode);
      }
#ifdef DEBUG1
      if(invalidVal != 0)
      {
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Response Interface has either X or Z value \n" );
      }
#endif
      if(c_afu_tlx_resp_valid && !c_afu_tlx_rdata_valid)
      {
        afu_tlx_send_resp(&event,
        		c_afu_tlx_resp_opcode, c_afu_tlx_resp_dl, c_afu_tlx_resp_capptag,
        		c_afu_tlx_resp_dp, c_afu_tlx_resp_code
        );
      }
      else if(c_afu_tlx_rdata_valid)
      {
        int resp_code = afu_tlx_send_resp_and_data(&event,
        		c_afu_tlx_resp_opcode, c_afu_tlx_resp_dl, c_afu_tlx_resp_capptag,
        		c_afu_tlx_resp_dp, c_afu_tlx_resp_code, c_afu_tlx_rdata_valid,
        		c_afu_tlx_rdata_bus, c_afu_tlx_rdata_bdi
        );
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Response Data transferred thru method and the resp code is %d \n",  resp_code);
      }
      invalidVal = 0;
      c_afu_tlx_cmd_rd_req_top  	= (afu_tlx_cmd_rd_req_top & 0x2) ? 0 : (afu_tlx_cmd_rd_req_top & 0x1);
      invalidVal			= afu_tlx_cmd_rd_req_top & 0x2;
      if(c_afu_tlx_cmd_rd_req_top)
      {
        c_afu_tlx_cmd_rd_cnt_top 	 = (afu_tlx_cmd_rd_cnt_top->aval) & 0x7;
        invalidVal		+= (afu_tlx_cmd_rd_cnt_top->bval) & 0x7;
        afu_tlx_cmd_data_read_req(&event,
        		c_afu_tlx_cmd_rd_req_top, c_afu_tlx_cmd_rd_cnt_top
        );
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Cmd Read Request for Cnt: %d \n", c_afu_tlx_cmd_rd_cnt_top );
      }
#ifdef DEBUG1
      if(invalidVal != 0)
      {
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Response Cmd Data Request Interface has either X or Z value \n" );
      }
#endif
      invalidVal = 0;
      c_afu_tlx_resp_rd_req_top  	= (afu_tlx_resp_rd_req_top & 0x2) ? 0 : (afu_tlx_resp_rd_req_top & 0x1);
      invalidVal			= afu_tlx_resp_rd_req_top & 0x2;
      if(c_afu_tlx_resp_rd_req_top)
      {
        c_afu_tlx_resp_rd_cnt_top 	 = (afu_tlx_resp_rd_cnt_top->aval) & 0x7;
        invalidVal		+= (afu_tlx_resp_rd_cnt_top->bval) & 0x7;
        afu_tlx_resp_data_read_req(&event,
        		c_afu_tlx_resp_rd_req_top, c_afu_tlx_resp_rd_cnt_top
        );
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Response Read Request for Cnt: %d \n", c_afu_tlx_resp_rd_cnt_top );
      }
#ifdef DEBUG1
      if(invalidVal != 0)
      {
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Response Data Interface has either X or Z value \n" );
      }
#endif
    } else {
      c_sim_error = 0;
      tlx_control();
      if(event.tlx_afu_resp_valid)
      {
        setDpiSignal32(tlx_afu_resp_opcode_top, event.tlx_afu_resp_opcode, 8);
        setDpiSignal32(tlx_afu_resp_afutag_top, event.tlx_afu_resp_afutag, 16);
        setDpiSignal32(tlx_afu_resp_code_top, event.tlx_afu_resp_code, 4);
        setDpiSignal32(tlx_afu_resp_pg_size_top, event.tlx_afu_resp_pg_size, 6);
        setDpiSignal32(tlx_afu_resp_dl_top, event.tlx_afu_resp_dl, 2);
        setDpiSignal32(tlx_afu_resp_dp_top, event.tlx_afu_resp_dp, 2);
        setDpiSignal32(tlx_afu_resp_addr_tag_top, event.tlx_afu_resp_addr_tag, 18);
#ifdef TLX4
        setDpiSignal32(tlx_afu_resp_host_tag_top, event.tlx_afu_resp_host_tag, 24);
        setDpiSignal32(tlx_afu_resp_cache_state_top, event.tlx_afu_resp_cache_state, 4);
#endif
        *tlx_afu_resp_valid_top = 1;
        clk_afu_resp_val = CLOCK_EDGE_DELAY;
        event.tlx_afu_resp_valid = 0;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-AFU Response with OPCODE=0x%x \n",  event.tlx_afu_resp_opcode);
      }
      if (clk_afu_resp_val) {
      	--clk_afu_resp_val;
      	if (!clk_afu_resp_val)
    		*tlx_afu_resp_valid_top = 0;
      }
      if(event.tlx_afu_cmd_valid)
      {
        setDpiSignal32(tlx_afu_cmd_opcode_top, event.tlx_afu_cmd_opcode, 8);
        setDpiSignal32(tlx_afu_cmd_capptag_top, event.tlx_afu_cmd_capptag, 16);
        setDpiSignal32(tlx_afu_cmd_dl_top, event.tlx_afu_cmd_dl, 2);
        setDpiSignal32(tlx_afu_cmd_pl_top, event.tlx_afu_cmd_pl, 3);
        setDpiSignal64(tlx_afu_cmd_be_top, event.tlx_afu_cmd_be);
        *tlx_afu_cmd_end_top = (event.tlx_afu_cmd_end) & 0x1;
        *tlx_afu_cmd_t_top = (event.tlx_afu_cmd_t) & 0x1;
        setDpiSignal64(tlx_afu_cmd_pa_top, event.tlx_afu_cmd_pa);
#ifdef TLX4
        setDpiSignal32(tlx_afu_cmd_flag_top, event.tlx_afu_cmd_flag, 4);
        *tlx_afu_cmd_os_top = (event.tlx_afu_cmd_os) & 0x1;
#endif
        *tlx_afu_cmd_valid_top = 1;
        clk_afu_cmd_val = CLOCK_EDGE_DELAY;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-AFU Cmd with OPCODE=0x%x \n",  event.tlx_afu_cmd_opcode);
        event.tlx_afu_cmd_valid = 0;
      }
      if (clk_afu_cmd_val) {
    	--clk_afu_cmd_val;
    	if (!clk_afu_cmd_val)
    		*tlx_afu_cmd_valid_top = 0;
      }
      if(event.tlx_afu_resp_data_valid)
      {
        *tlx_afu_resp_data_bdi_top = (event.tlx_afu_resp_data_bdi) & 0x1;
        setMyCacheLine(tlx_afu_resp_data_bus_top, event.tlx_afu_resp_data);
        *tlx_afu_resp_data_valid_top = 1;
        clk_afu_resp_dat_val = CLOCK_EDGE_DELAY;
        event.tlx_afu_resp_data_valid = 0;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-AFU Response with Data Available \n");
      }
      if (clk_afu_resp_dat_val) {
    	--clk_afu_resp_dat_val;
    	if (!clk_afu_resp_dat_val)
    		*tlx_afu_resp_data_valid_top = 0;
      }
      if(event.tlx_afu_cmd_data_valid)
      {
        *tlx_afu_cmd_data_bdi_top = (event.tlx_afu_cmd_data_bdi) & 0x1;
        setMyCacheLine(tlx_afu_cmd_data_bus_top, event.tlx_afu_cmd_data_bus);
        *tlx_afu_cmd_data_valid_top = 1;
        clk_afu_cmd_dat_val = CLOCK_EDGE_DELAY;
        event.tlx_afu_cmd_data_valid = 0;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-AFU Command with Data Available \n");
      }
      if (clk_afu_cmd_dat_val) {
    	--clk_afu_cmd_dat_val;
    	if (!clk_afu_cmd_dat_val)
    		*tlx_afu_cmd_data_valid_top = 0;
      }
      *tlx_afu_resp_credit_top 		= (event.tlx_afu_resp_credit) & 0x1;
      *tlx_afu_resp_data_credit_top 	= (event.tlx_afu_resp_data_credit) & 0x1;
      *tlx_afu_cmd_credit_top	 	= (event.tlx_afu_cmd_credit) & 0x1;
      *tlx_afu_cmd_data_credit_top	= (event.tlx_afu_cmd_data_credit) & 0x1;
      setDpiSignal32(tlx_afu_cmd_resp_initial_credit_top, event.tlx_afu_cmd_resp_initial_credit, 3);
      setDpiSignal32(tlx_afu_data_initial_credit_top, event.tlx_afu_data_initial_credit, 4);
      *tlx_afu_ready_top			= 1;	// TODO: need to check this
    }
  }
  c_reset_d2 = c_reset_d1;
  c_reset_d1 = c_reset;
}

void tlx_bfm_init()
{
  int port = 32768;
  while (tlx_serv_afu_event(&event, port) != TLX_SUCCESS) {
    if (tlx_serv_afu_event(&event, port) == TLX_VERSION_ERROR) {
      printf("%08lld: ", (long long) c_sim_time);
      printf("Socket closed: Ending Simulation.");
      c_sim_error = 1;
    }
    if (port == 65535) {
      error_message("Unable to find open port!");
    }
    ++port;
  }
//  tlx_close_afu_event(&event);
  return;
}

void set_simulation_time(const svLogicVecVal *simulationTime)
{
   getMy64Bit(simulationTime, &c_sim_time);
//  printf("inside C: time value  = %08lld\n", (long long) c_sim_time);
}

void get_simuation_error(svLogic *simulationError)
{
  *simulationError  = c_sim_error & 0x1;
//  printf("inside C: error value  = %08d\n",  c_sim_error);
}

// Setup & facility functions
static int getMy64Bit(const svLogicVecVal *my64bSignal, uint64_t *conv64bit)
{
    //gets the two 32bit values from the 4-state svLogicVec array
    //and packs it into a 64bit in *conv64bit
    //Also returns 1 if bval is non-zero (i.e. value contains Z, X or both)

  uint32_t lsb32_aval, msb32_aval, lsb32_bval, msb32_bval;
  lsb32_bval =  my64bSignal->bval;
  msb32_bval = (my64bSignal+1)->bval;
  lsb32_aval =  my64bSignal->aval;
  msb32_aval = (my64bSignal+1)->aval;
//    printf("msb32_aval=%08x, lsb32_aval=%08x\n", msb32_aval, lsb32_aval);
//    printf("msb32_bval=%08x, lsb32_bval=%08x\n", msb32_bval, lsb32_bval);

  *conv64bit = ((uint64_t) msb32_aval <<32) | (uint64_t) lsb32_aval;
//    printf("conv64bit = %llx\n", (long long) *conv64bit);
  if((lsb32_bval | msb32_bval) == 0){ return 0;}
  return 1;
}

// The getMyCacheLine is a more specific version of the PLI function
// get_signal_long. In here, we are specifically doing the conversion of 1024
// bit long vector to 128 byte cacheline buffer. On VPI as well as DPI, the
// 1024 bit vector is returned as array of 32bit entries. ie, array[0] will
// contain the aval for bits [992:1023]. The OCSE demands that the first
// entry of the array has bits [0:31], hence we do a reversal of that array
// the htonl std lib function will ensure that the byte ordering is maintained
// based on the endianness of the processor
int getMyCacheLine(const svLogicVecVal *myLongSignal, uint8_t myCacheData[CACHELINE_BYTES])
{
   int i, j;
  uint8_t errorVal = 0;
  uint32_t *p32BitCacheWords = (uint32_t*)myCacheData;
  for(i=0; i <(CACHELINE_BYTES/4 ); i++)
  {
    j = (CACHELINE_BYTES/4 ) - (i + 1);
    if(myLongSignal[i].bval !=0){ errorVal=1; }
    p32BitCacheWords[j] = myLongSignal[i].aval;
    p32BitCacheWords[j] = htonl(p32BitCacheWords[j]);
  }
  if(errorVal!=0){return 1;}
  return 0;
}

int getMyByteArray(const svLogicVecVal *myLongSignal, uint32_t arrayLength, uint8_t myCacheData[arrayLength])
{
   int i, j;
  uint8_t errorVal = 0;
  uint32_t *p32BitCacheWords = (uint32_t*)myCacheData;
  for(i=0; i <(arrayLength/4 ); i++)
  {
    j = (arrayLength/4 ) - (i + 1);
    if(myLongSignal[i].bval !=0){ errorVal=1; }
    p32BitCacheWords[j] = myLongSignal[i].aval;
    p32BitCacheWords[j] = htonl(p32BitCacheWords[j]);
  }
  if(errorVal!=0){return 1;}
  return 0;
}

void setMyCacheLine(svLogicVecVal *myLongSignal, uint8_t myCacheData[CACHELINE_BYTES])
{
   int i, j;
  //uint32_t get32aval, get32bval;
  uint32_t *p32BitCacheWords = (uint32_t*)myCacheData;
  for(i=0; i <(CACHELINE_BYTES/4 ); i++)
  {
    j = (CACHELINE_BYTES/4 ) - (i + 1);
    myLongSignal[j].aval = htonl(p32BitCacheWords[i]);
    myLongSignal[j].bval = 0;
  }
}

void setDpiSignal32(svLogicVecVal *my32bSignal, uint32_t inData, int size)
{
  uint32_t myMask = ~(0xFFFFFFFF << size);
  my32bSignal->aval = inData & myMask;
  my32bSignal->bval = 0x0;
}

static void setDpiSignal64(svLogicVecVal *my64bSignal, uint64_t data)
{
	(my64bSignal+1)->aval = (uint32_t)(data >> 32);
	(my64bSignal+1)->bval = 0x0;
	(my64bSignal)->aval = (uint32_t)(data & 0xffffffff);
	(my64bSignal)->bval = 0x0;
}

static void tlx_control(void)
{
	// Wait for clock edge from OCSE
	fd_set watchset;
	FD_ZERO(&watchset);
	FD_SET(event.sockfd, &watchset);
	select(event.sockfd + 1, &watchset, NULL, NULL, NULL);
	int rc = tlx_get_tlx_events(&event);
	// No clock edge
	while (!rc) {
	  select(event.sockfd + 1, &watchset, NULL, NULL, NULL);
	  rc = tlx_get_tlx_events(&event);
	}
	// Error case
	if (rc < 0) {
	  printf("%08lld: ", (long long) c_sim_time);
	  printf("Socket closed: Ending Simulation.");
	  c_sim_error = 1;
	}
}

static void error_message(const char *str)
{
	fflush(stdout);
//	fprintf(stderr, "%08lld: ERROR: %s\n", get_time(), str);
//	Removing the get_time() from the function, since this is a VPI function unsupported on DPI
	fprintf(stderr, "%08lld: ERROR: %s\n", (long long) c_sim_time, str);
	fflush(stderr);
}

