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

#include <malloc.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../common/utils.h"
#include "../../common/debug.h"
#include "tlx_interface.h"
#include "vpi_user.h"
#include "svdpi.h"

// ==================================================================
// Constant/Variable declarations
static struct DATA_PKT *new_vc0data_pkt;
static struct DATA_PKT *old_vc0data_pkt;
static struct DATA_PKT *new_vc1data_pkt;
static struct DATA_PKT *old_vc1data_pkt;
static struct AFU_EVENT event;

#define CLOCK_EDGE_DELAY 2
#define CACHELINE_BYTES 64
#define EA_OBJ_HANDLE 10
uint64_t c_sim_time ;
int      c_sim_error ;
static int tick = 0;
static int clk_afu_vc0_val = 0;
static int clk_afu_vc1_val = 0;
static int clk_afu_vc2_val = 0;
static int clk_tlx_cfg_val = 0;
static int clk_tlx_dcp0_data_val = 0;
static int clk_tlx_dcp1_data_val = 0;
static int afu_tlx_credits_initialized = 0;
static int tlx_afu_credits_initialized = 0;

// inputs from AFX
uint8_t		c_reset = 1;
uint8_t		c_reset_d1 = 1;
uint8_t		c_reset_d2 = 1;
uint8_t		c_reset_d3 = 1;
uint8_t		c_reset_d4 = 1;

// variables to capture inputs
uint8_t         c_afu_tlx_vc0_initial_credit;
uint8_t         c_afu_tlx_vc1_initial_credit;
uint8_t         c_afu_tlx_vc2_initial_credit;
uint8_t         c_cfg_tlx_initial_credit;
uint8_t         c_tlx_afu_vc0_initial_credit = 7;
uint8_t         c_tlx_afu_vc1_initial_credit = 4;
uint8_t         c_tlx_afu_vc2_initial_credit = 4;
uint8_t         c_tlx_afu_vc3_initial_credit = 4;
uint8_t         c_tlx_afu_dcp0_initial_credit = 16;
uint8_t         c_tlx_afu_dcp2_initial_credit = 16;
uint8_t         c_tlx_afu_dcp3_initial_credit = 16;

uint8_t         c_cfg_tlx_credit_return;
uint8_t         c_afu_tlx_vc0_credit;
uint8_t         c_afu_tlx_vc1_credit;
uint8_t         c_afu_tlx_vc2_credit;
uint8_t         c_cfg_tlx_resync_credits;

uint8_t		c_cfg_resp_ack_pending = 0;
uint8_t         c_afu_tlx_dcp0_rd_req;
uint8_t         c_afu_tlx_dcp0_rd_cnt;
uint8_t         c_tlx_dcp0_data_pending = 0;
uint8_t         c_tlx_dcp0_data_pending_d1 = 0;
uint8_t         c_tlx_dcp0_data_pending_d2 = 0;

uint8_t         c_afu_tlx_dcp1_rd_req;
uint8_t         c_afu_tlx_dcp1_rd_cnt;
uint8_t         c_tlx_dcp1_data_pending = 0;
uint8_t         c_tlx_dcp1_data_pending_d1 = 0;
uint8_t         c_tlx_dcp1_data_pending_d2 = 0;

uint8_t         c_cfg_tlx_resp_valid;
uint8_t         c_cfg_tlx_resp_opcode;
uint16_t        c_cfg_tlx_resp_capptag;
uint8_t         c_cfg_tlx_resp_code;
uint8_t         c_cfg_tlx_rdata_offset;
uint8_t  	c_cfg_tlx_rdata_bus[CACHELINE_BYTES];
uint8_t         c_afu_tlx_cdata_bdi;

uint8_t         c_afu_tlx_vc0_valid;
uint8_t         c_afu_tlx_dcp0_data_valid;
uint8_t         c_afu_tlx_vc0_opcode;
uint16_t        c_afu_tlx_vc0_capptag;
uint8_t         c_afu_tlx_vc0_dl;
uint8_t         c_afu_tlx_vc0_dp;
uint8_t         c_afu_tlx_vc0_resp_code;
uint8_t  	c_afu_tlx_dcp0_data_bus[CACHELINE_BYTES];
uint8_t         c_afu_tlx_dcp0_data_bdi;

uint8_t         c_afu_tlx_vc1_valid;
uint8_t         c_afu_tlx_vc1_opcode;
uint8_t         c_afu_tlx_vc1_stream_id;
uint16_t        c_afu_tlx_vc1_afutag;
uint64_t        c_afu_tlx_vc1_pa;
uint8_t         c_afu_tlx_vc1_dl;

uint8_t         c_afu_tlx_vc2_valid;
uint8_t         c_afu_tlx_dcp2_data_valid;
uint8_t         c_afu_tlx_vc2_opcode;
uint8_t         c_afu_tlx_vc2_dl;
uint32_t        c_afu_tlx_vc2_host_tag;
uint8_t         c_afu_tlx_vc2_cache_state;
uint8_t         c_afu_tlx_vc2_cmdflag;
uint8_t  	c_afu_tlx_dcp2_data_bus[CACHELINE_BYTES];
uint8_t         c_afu_tlx_dcp2_data_bdi;

uint8_t         c_afu_tlx_vc3_valid;
uint8_t         c_afu_tlx_vc3_opcode;
uint8_t         c_afu_tlx_vc3_stream_id;
uint16_t        c_afu_tlx_vc3_afutag;
uint16_t        c_afu_tlx_vc3_actag;
uint8_t		c_afu_tlx_vc3_ea_ta_or_obj[EA_OBJ_HANDLE];
uint8_t         c_afu_tlx_vc3_dl;
uint64_t        c_afu_tlx_vc3_be;
uint8_t         c_afu_tlx_vc3_pl;
uint8_t         c_afu_tlx_vc3_os;
uint8_t         c_afu_tlx_vc3_endian;
uint8_t         c_afu_tlx_vc3_pg_size;
uint8_t         c_afu_tlx_vc3_cmdflag;
uint32_t        c_afu_tlx_vc3_pasid;
uint16_t        c_afu_tlx_vc3_bdf;
uint8_t         c_afu_tlx_vc3_mad;
uint16_t         c_afu_tlx_vc3_capptag;
uint8_t         c_afu_tlx_vc3_resp_code;
uint8_t         c_afu_tlx_dcp3_data_valid;
uint8_t         c_afu_tlx_dcp3_data_bdi;
uint8_t  	c_afu_tlx_dcp3_data_bus[CACHELINE_BYTES];

uint32_t	c_tlx_cfg_data_del;
uint8_t		c_tlx_cfg_data_bdi_del;
uint8_t  	c_clearedCacheline[CACHELINE_BYTES];
uint8_t  	cacheLineCleared = 0;
// ==================================================================

// Local Methods
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

  *conv64bit = ((uint64_t) msb32_aval <<32) | (uint64_t) lsb32_aval;
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
    j = i;
    if(myLongSignal[i].bval !=0){ errorVal=1; }
    p32BitCacheWords[j] = myLongSignal[i].aval;
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
    j = i;
    if(myLongSignal[i].bval !=0){ errorVal=1; }
    p32BitCacheWords[j] = myLongSignal[i].aval;
    p32BitCacheWords[j] = (p32BitCacheWords[j]);
  }
  if(errorVal!=0){return 1;}
  return 0;
}

void setMyCacheLine(svLogicVecVal *myLongSignal, uint8_t myCacheData[CACHELINE_BYTES])
{
  int i, j;
  uint32_t *p32BitCacheWords = (uint32_t*)myCacheData;
  for(i=0; i <(CACHELINE_BYTES/4 ); i++)
  {
    j = i;
    myLongSignal[j].aval = (p32BitCacheWords[i]);
    myLongSignal[j].bval = 0;
  }
}

void setDpiSignal32(svLogicVecVal *my32bSignal, uint32_t inData, int size)
{
  uint32_t myMask = ~(0xFFFFFFFF << size);
  if(size == 32) myMask = 0xFFFFFFFF;
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

static void error_message(const char *str)
{
  fflush(stdout);
//	fprintf(stderr, "%08lld: ERROR: %s\n", get_time(), str);
//	Removing the get_time() from the function, since this is a VPI function unsupported on DPI
  fprintf(stderr, "%08lld: ERROR: %s\n", (long long) c_sim_time, str);
  fflush(stderr);
}

void tlx_bfm_init()
{
  int port = 32768;

  // print some values
  debug_msg("tlx_bfm_init: tick = %d, c_reset = %d, c_reset_d1 = %d, c_reset_d2 = %d, c_reset_d3 = %d, c_reset_d4 = %d", tick, c_reset, c_reset_d1, c_reset_d2, c_reset_d3, c_reset_d4 );

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
// ==================================================================
// Space for the definition of method tlx_control()
// ==================================================================
static void tlx_control(void)
{
	// Wait for clock edge from OCSE
	fd_set watchset;
	FD_ZERO(&watchset);
	FD_SET(event.sockfd, &watchset);
	select(event.sockfd + 1, &watchset, NULL, NULL, NULL);
	
	debug_msg("tlx_control: %08lld: calling tlx_get_tlx_events...", (long long) c_sim_time);
	int rc = tlx_get_tlx_events(&event);
	
	// No clock edge
	while (!rc) {
	  select(event.sockfd + 1, &watchset, NULL, NULL, NULL);
	  debug_msg("tlx_control: no clock edge: %08lld: calling get tlx events again...", (long long) c_sim_time);
	  rc = tlx_get_tlx_events(&event);
	}
	// Error case
	if (rc < 0) {
	  printf("%08lld: Socket closed: Ending Simulation.\n", (long long) c_sim_time);
	  c_sim_error = 1;
	}
}

// ==================================================================
// the main bfm definition for the DPI
// ==================================================================
void tlx_bfm(
  const svLogic            tlx_clock,
  const svLogic            afu_clock,
  const svLogic            reset,
    // Table 1: DLX to TLX Flit Interface - not defined
    // Table 2: TLX to AFU VCO Interface
  const svLogicVecVal	  *afu_tlx_vc0_initial_credit_top,
  const svLogic	           afu_tlx_vc0_credit_top,
        svLogic	          *tlx_afu_vc0_valid_top,
        svLogicVecVal     *tlx_afu_vc0_opcode_top,
        svLogicVecVal     *tlx_afu_vc0_afutag_top,
        svLogicVecVal     *tlx_afu_vc0_capptag_top,
        svLogicVecVal     *tlx_afu_vc0_pa_or_ta_top,
        svLogicVecVal     *tlx_afu_vc0_dl_top,
        svLogicVecVal     *tlx_afu_vc0_dp_top,
        svLogic	          *tlx_afu_vc0_ef_top,
        svLogic	          *tlx_afu_vc0_w_top,
        svLogic	          *tlx_afu_vc0_mh_top,
        svLogicVecVal     *tlx_afu_vc0_pg_size_top,
        svLogicVecVal     *tlx_afu_vc0_host_tag_top,		// for OCSE5
        svLogicVecVal     *tlx_afu_vc0_resp_code_top,
        svLogicVecVal     *tlx_afu_vc0_cache_state_top,		// for OCSE5
    // Table 3: TLX to AFU DCP0 Data Interface
  const svLogic	           afu_tlx_dcp0_rd_req_top,
  const svLogicVecVal	  *afu_tlx_dcp0_rd_cnt_top,
        svLogic	          *tlx_afu_dcp0_data_valid_top,
        svLogicVecVal     *tlx_afu_dcp0_data_bus_top,
        svLogic	          *tlx_afu_dcp0_data_bdi_top,
    // Table 4: TLX to AFU VC1 Interface
  const svLogicVecVal	  *afu_tlx_vc1_initial_credit_top,
  const svLogic	           afu_tlx_vc1_credit_top,
        svLogic	          *tlx_afu_vc1_valid_top,
        svLogicVecVal     *tlx_afu_vc1_opcode_top,
        svLogicVecVal     *tlx_afu_vc1_afutag_top,
        svLogicVecVal     *tlx_afu_vc1_capptag_top,
        svLogicVecVal     *tlx_afu_vc1_pa_top,
        svLogicVecVal     *tlx_afu_vc1_dl_top,
        svLogicVecVal     *tlx_afu_vc1_dp_top,
        svLogicVecVal     *tlx_afu_vc1_be_top,
        svLogicVecVal     *tlx_afu_vc1_pl_top,
        svLogic	          *tlx_afu_vc1_endian_top,
        svLogic	          *tlx_afu_vc1_co_top,
        svLogic	          *tlx_afu_vc1_os_top,
        svLogicVecVal     *tlx_afu_vc1_cmdflag_top,
        svLogicVecVal     *tlx_afu_vc1_mad_top,
    // Table 5: TLX to AFU DCP1 Data Interface
  const svLogic	           afu_tlx_dcp1_rd_req_top,
  const svLogicVecVal	  *afu_tlx_dcp1_rd_cnt_top,
        svLogic	          *tlx_afu_dcp1_data_valid_top,
        svLogicVecVal     *tlx_afu_dcp1_data_bus_top,
        svLogic	          *tlx_afu_dcp1_data_bdi_top,
    // Table 6: TLX to AFU VC2 Interface
  const svLogicVecVal	  *afu_tlx_vc2_initial_credit_top,
  const svLogic	           afu_tlx_vc2_credit_top,
        svLogic	          *tlx_afu_vc2_valid_top,
        svLogicVecVal     *tlx_afu_vc2_opcode_top,
        svLogicVecVal     *tlx_afu_vc2_capptag_top,
        svLogicVecVal     *tlx_afu_vc2_ea_top,
        svLogicVecVal     *tlx_afu_vc2_pg_size_top,
        svLogicVecVal     *tlx_afu_vc2_cmdflag_top,
        svLogicVecVal     *tlx_afu_vc2_pasid_top,
        svLogicVecVal     *tlx_afu_vc2_bdf_top,
    // Table 7: TLX to CFG Interface for Configuration Commands
  const svLogicVecVal     *cfg_tlx_initial_credit_top,
  const svLogic	           cfg_tlx_credit_return_top,
        svLogic	          *tlx_cfg_valid_top,
        svLogicVecVal     *tlx_cfg_opcode_top,
        svLogicVecVal     *tlx_cfg_capptag_top,
        svLogicVecVal     *tlx_cfg_pa_top,
        svLogicVecVal     *tlx_cfg_pl_top,
        svLogic	          *tlx_cfg_t_top,
        svLogicVecVal     *tlx_cfg_data_bus_top,
        svLogic	          *tlx_cfg_data_bdi_top,
    // Table 8: TLX Receiver - Template Configuration Ports
        svLogic		*tlx_cfg_rcv_tmpl_capability_0_top,
        svLogic		*tlx_cfg_rcv_tmpl_capability_1_top,
        svLogic		*tlx_cfg_rcv_tmpl_capability_2_top,
        svLogic		*tlx_cfg_rcv_tmpl_capability_3_top,
        svLogicVecVal	*tlx_cfg_rcv_rate_capability_0_top,
        svLogicVecVal	*tlx_cfg_rcv_rate_capability_1_top,
        svLogicVecVal	*tlx_cfg_rcv_rate_capability_2_top,
        svLogicVecVal	*tlx_cfg_rcv_rate_capability_3_top,
  const svLogic	         cfg_tlx_resync_credits_top,
    // Table 9: TLX Credit Interface
    // Table 10: TL Credit Interface
    // Table 11: TLX Receiver - Miscellaneous Ports
        svLogic		*tlx_afu_ready_top,
    // Table 12: TLX Framer - Miscellaneous Ports
    // Table 13: TLX Framer - AFU to TLX  AP  Configuration Response Interface (VCO, DCP0)
  const svLogic	         cfg_tlx_resp_valid_top,
  const svLogicVecVal   *cfg_tlx_resp_opcode_top,
  const svLogicVecVal   *cfg_tlx_resp_capptag_top,
  const svLogicVecVal   *cfg_tlx_resp_code_top,
  const svLogicVecVal   *cfg_tlx_rdata_offset_top,
  const svLogicVecVal   *cfg_tlx_rdata_bus_top,
  const svLogic	         cfg_tlx_rdata_bdi_top,
        svLogic	        *tlx_cfg_resp_ack_top,
    // Table 14: TLX Framer - AFU to TLX  VC0/DCP0 Interface
        svLogicVecVal	*tlx_afu_vc0_initial_credit_top,
        svLogicVecVal	*tlx_afu_dcp0_initial_credit_top,
        svLogic		*tlx_afu_vc0_credit_top,
        svLogic		*tlx_afu_dcp0_credit_top,
  const svLogic		 afu_tlx_vc0_valid_top,
  const svLogicVecVal   *afu_tlx_vc0_opcode_top,
  const svLogicVecVal   *afu_tlx_vc0_capptag_top,
  const svLogicVecVal   *afu_tlx_vc0_dl_top,
  const svLogicVecVal   *afu_tlx_vc0_dp_top,
  const svLogicVecVal   *afu_tlx_vc0_resp_code_top,
  const svLogic		 afu_tlx_dcp0_data_valid_top,
  const svLogicVecVal   *afu_tlx_dcp0_data_bus_top,
  const svLogic		 afu_tlx_dcp0_data_bdi_top,
    // Table 15: TLX Framer - AFU to TLX  VC1 Interface
        svLogicVecVal	*tlx_afu_vc1_initial_credit_top,
        svLogic		*tlx_afu_vc1_credit_top,
  const svLogic		 afu_tlx_vc1_valid_top,
  const svLogicVecVal   *afu_tlx_vc1_opcode_top,
  const svLogicVecVal   *afu_tlx_vc1_stream_id_top,
  const svLogicVecVal   *afu_tlx_vc1_afutag_top,
  const svLogicVecVal   *afu_tlx_vc1_pa_top,
  const svLogicVecVal   *afu_tlx_vc1_dl_top,
    // Table 16: AFU to TLX  VC2/DCP2 Interface
        svLogicVecVal	*tlx_afu_vc2_initial_credit_top,
        svLogicVecVal	*tlx_afu_dcp2_initial_credit_top,
        svLogic		*tlx_afu_vc2_credit_top,
        svLogic		*tlx_afu_dcp2_credit_top,
  const svLogic		 afu_tlx_vc2_valid_top,
  const svLogicVecVal   *afu_tlx_vc2_opcode_top,
  const svLogicVecVal   *afu_tlx_vc2_dl_top,
  const svLogicVecVal   *afu_tlx_vc2_host_tag_top,
  const svLogicVecVal   *afu_tlx_vc2_cache_state_top,
  const svLogicVecVal   *afu_tlx_vc2_cmdflag_top,
  const svLogic		 afu_tlx_dcp2_data_valid_top,
  const svLogicVecVal   *afu_tlx_dcp2_data_bus_top,
  const svLogic		 afu_tlx_dcp2_data_bdi_top,
    // Table 17: TLX Framer - AFU to TLX  VC3/DCP3 Interface
        svLogicVecVal	*tlx_afu_vc3_initial_credit_top,
        svLogicVecVal	*tlx_afu_dcp3_initial_credit_top,
        svLogic		*tlx_afu_vc3_credit_top,
        svLogic		*tlx_afu_dcp3_credit_top,
  const svLogic		 afu_tlx_vc3_valid_top,
  const svLogicVecVal   *afu_tlx_vc3_opcode_top,
  const svLogicVecVal   *afu_tlx_vc3_stream_id_top,
  const svLogicVecVal   *afu_tlx_vc3_afutag_top,
  const svLogicVecVal   *afu_tlx_vc3_actag_top,
  const svLogicVecVal   *afu_tlx_vc3_ea_ta_or_obj_top,
  const svLogicVecVal   *afu_tlx_vc3_dl_top,
  const svLogicVecVal   *afu_tlx_vc3_be_top,
  const svLogicVecVal   *afu_tlx_vc3_pl_top,
  const svLogic		 afu_tlx_vc3_os_top,
  const svLogic		 afu_tlx_vc3_endian_top,
  const svLogicVecVal   *afu_tlx_vc3_pg_size_top,
  const svLogicVecVal   *afu_tlx_vc3_cmdflag_top,
  const svLogicVecVal   *afu_tlx_vc3_pasid_top,
  const svLogicVecVal   *afu_tlx_vc3_bdf_top,
  const svLogicVecVal   *afu_tlx_vc3_mad_top,
  const svLogicVecVal   *afu_tlx_vc3_capptag_top,
  const svLogicVecVal   *afu_tlx_vc3_resp_code_top,
  const svLogic		 afu_tlx_dcp3_data_valid_top,
  const svLogicVecVal   *afu_tlx_dcp3_data_bus_top,
  const svLogic		 afu_tlx_dcp3_data_bdi_top
)
{
  int invalidVal = 0;
  int i = 0;
  int j = 0;
  int rc= 0;
  int new_line_cnt;
  
  c_reset			= reset & 0x1;
  // print some values
  debug_msg("tlx_bfm: tick = %d, reset = %d, c_reset = %d, c_reset_d1 = %d, c_reset_d2 = %d, c_reset_d3 = %d, c_reset_d4 = %d", tick, (uint8_t)reset, c_reset, c_reset_d1, c_reset_d2, c_reset_d3, c_reset_d4 );
  // increment tick
  tick = tick + 1;

  if(!c_reset_d4)
  {
    if ( tlx_clock == sv_0 ) {	// On OCSE, we are doing the signal sensing and driving on the active low mode of clock
      debug_msg("tlx_bfm: clock = 0, reading inputs from AFU" );
      c_afu_tlx_vc0_initial_credit          =  (afu_tlx_vc0_initial_credit_top->aval) & 0x7F;
      invalidVal                            += (afu_tlx_vc0_initial_credit_top->bval) & 0x7F;
      c_afu_tlx_vc1_initial_credit          =  (afu_tlx_vc1_initial_credit_top->aval) & 0x7F;
      invalidVal                            += (afu_tlx_vc1_initial_credit_top->bval) & 0x7F;
      c_afu_tlx_vc2_initial_credit          =  (afu_tlx_vc2_initial_credit_top->aval) & 0x7F;
      invalidVal                            += (afu_tlx_vc2_initial_credit_top->bval) & 0x7F;
      c_cfg_tlx_initial_credit              =  (cfg_tlx_initial_credit_top->aval) & 0x7F;
      invalidVal                            += (cfg_tlx_initial_credit_top->bval) & 0x7F;
      if(!c_reset)
      {
	if (afu_tlx_credits_initialized == 0 ) {
	  debug_msg("tlx_bfm: setting initial credits to tlx vc0 = %d, vc1 = %d, vc2 = %d, cfg = %d", c_afu_tlx_vc0_initial_credit, c_afu_tlx_vc1_initial_credit, c_afu_tlx_vc2_initial_credit, c_cfg_tlx_initial_credit);
	  afu_tlx_send_initial_credits (&event, c_afu_tlx_vc0_initial_credit, c_afu_tlx_vc1_initial_credit, c_afu_tlx_vc2_initial_credit, c_cfg_tlx_initial_credit);
	  debug_msg("tlx_bfm: set" );
	  afu_tlx_credits_initialized = 1;
	}
	if (tlx_afu_credits_initialized == 0 ) {
	  debug_msg("tlx_bfm: reading initial credits from tlx" );
	  rc = tlx_afu_read_initial_credits (&event, &c_tlx_afu_vc0_initial_credit, &c_tlx_afu_vc1_initial_credit, &c_tlx_afu_vc2_initial_credit, &c_tlx_afu_vc3_initial_credit, &c_tlx_afu_dcp0_initial_credit, &c_tlx_afu_dcp2_initial_credit, &c_tlx_afu_dcp3_initial_credit);
          if(rc == 0)
          {
	    debug_msg("tlx_bfm: read initial credits to afu vc0 = %d, vc1 = %d, vc2 = %d, vc3 = %d, dcp0 = %d,  dcp2 = %d, dcp3 = %d", c_tlx_afu_vc0_initial_credit, c_tlx_afu_vc1_initial_credit, c_tlx_afu_vc2_initial_credit, c_tlx_afu_vc3_initial_credit, c_tlx_afu_dcp0_initial_credit, c_tlx_afu_dcp2_initial_credit, c_tlx_afu_dcp3_initial_credit);
	    tlx_afu_credits_initialized = 1;
	  } else {
	    debug_msg("tlx_bfm: initial credits not ready" );
	  }
	}
      }
      if(invalidVal != 0)
      {
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU-TLX Cmd Credit Interface has either X or Z value \n" );
      }
      // credit managment - return credits, if any, to tlx
      // cfg interface credit
      // printf( "credit management\n" );
      invalidVal = 0;
      c_cfg_tlx_credit_return  	        = (cfg_tlx_credit_return_top & 0x2) ? 0 : (cfg_tlx_credit_return_top & 0x1);
      invalidVal  			= (cfg_tlx_credit_return_top & 0x2);
      if(invalidVal != 0) {
	debug_msg("%08lld: ", (long long) c_sim_time);
	debug_msg("tlx_bfm: The CFG-TLX Credit return value has either X or Z value \n" );
      } else {
	if (c_cfg_tlx_credit_return == 1 ) {
	  // printf( "returning cfg credit\n" );
	  event.cfg_tlx_credit_return = 1;
	  event.afu_tlx_credit_req_valid = 1;
	} else {
	  // printf( "no cfg credit to return\n" );
	  event.cfg_tlx_credit_return = 0;
	}
      }

      invalidVal = 0;
      c_afu_tlx_vc0_credit  	        = (afu_tlx_vc0_credit_top & 0x2) ? 0 : (afu_tlx_vc0_credit_top & 0x1);
      invalidVal  			= (afu_tlx_vc0_credit_top & 0x2);
      if(invalidVal != 0) {
	debug_msg("%08lld: ", (long long) c_sim_time);
	debug_msg("tlx_bfm: The AFU-TLX VC0 Credit return value has either X or Z value \n" );
      } else {
	if (c_afu_tlx_vc0_credit == 1 ) {
	  // printf( "returning cfg credit\n" );
	  event.afu_tlx_vc0_credit = 1;
	  event.afu_tlx_credit_req_valid = 1;
	} else {
	  // printf( "no cfg credit to return\n" );
	  event.afu_tlx_vc0_credit = 0;
	}
      }

      invalidVal = 0;
      c_afu_tlx_vc1_credit  	        = (afu_tlx_vc1_credit_top & 0x2) ? 0 : (afu_tlx_vc1_credit_top & 0x1);
      invalidVal  			= (afu_tlx_vc1_credit_top & 0x2);
      if(invalidVal != 0) {
	debug_msg("%08lld: ", (long long) c_sim_time);
	debug_msg("tlx_bfm: The AFU-TLX VC1 Credit return value has either X or Z value \n" );
      } else {
	if (c_afu_tlx_vc1_credit == 1 ) {
	  // printf( "returning cfg credit\n" );
	  event.afu_tlx_vc1_credit = 1;
	  event.afu_tlx_credit_req_valid = 1;
	} else {
	  // printf( "no cfg credit to return\n" );
	  event.afu_tlx_vc1_credit = 0;
	}
      }

      invalidVal = 0;
      c_afu_tlx_vc2_credit  	        = (afu_tlx_vc2_credit_top & 0x2) ? 0 : (afu_tlx_vc2_credit_top & 0x1);
      invalidVal  			= (afu_tlx_vc2_credit_top & 0x2);
      if(invalidVal != 0) {
	debug_msg("%08lld: ", (long long) c_sim_time);
	debug_msg("tlx_bfm: The AFU-TLX VC2 Credit return value has either X or Z value \n" );
      } else {
	if (c_afu_tlx_vc2_credit == 1 ) {
	  // printf( "returning cfg credit\n" );
	  event.afu_tlx_vc2_credit = 1;
	  event.afu_tlx_credit_req_valid = 1;
	} else {
	  // printf( "no cfg credit to return\n" );
	  event.afu_tlx_vc2_credit = 0;
	}
      }
      if(event.tlx_afu_credit_valid)
      {
	// only drive initial credits if the credit event is valid.
	// should we only do this once some how?
	setDpiSignal32(tlx_afu_vc0_initial_credit_top, event.tlx_afu_vc0_initial_credit, 4);
	setDpiSignal32(tlx_afu_dcp0_initial_credit_top, event.tlx_afu_dcp0_initial_credit, 6);
	setDpiSignal32(tlx_afu_vc1_initial_credit_top, event.tlx_afu_vc1_initial_credit, 4);
	setDpiSignal32(tlx_afu_vc2_initial_credit_top, event.tlx_afu_vc2_initial_credit, 4);
	setDpiSignal32(tlx_afu_dcp2_initial_credit_top, event.tlx_afu_dcp2_initial_credit, 6);
	setDpiSignal32(tlx_afu_vc3_initial_credit_top, event.tlx_afu_vc3_initial_credit, 4);
	setDpiSignal32(tlx_afu_dcp3_initial_credit_top, event.tlx_afu_dcp3_initial_credit, 6);
      }
      // printf("lgt: tlx_bfm: driving tlx to afu credits\n");
      // should this be gated by credit_valid as well?
      *tlx_afu_vc0_credit_top 	        = (event.tlx_afu_vc0_credit) & 0x1;
      *tlx_afu_dcp0_credit_top 	        = (event.tlx_afu_dcp0_credit) & 0x1;
      *tlx_afu_vc1_credit_top 	        = (event.tlx_afu_vc1_credit) & 0x1;
      *tlx_afu_vc2_credit_top 	        = (event.tlx_afu_vc2_credit) & 0x1;
      *tlx_afu_dcp2_credit_top 	        = (event.tlx_afu_dcp2_credit) & 0x1;
      *tlx_afu_vc3_credit_top 	        = (event.tlx_afu_vc3_credit) & 0x1;
      *tlx_afu_dcp3_credit_top 	        = (event.tlx_afu_dcp3_credit) & 0x1;
      // TODO: what is to be done with this signal
      invalidVal = 0;
      c_cfg_tlx_resync_credits  	= (cfg_tlx_resync_credits_top & 0x2) ? 0 : (cfg_tlx_resync_credits_top & 0x1);
      invalidVal  			= (cfg_tlx_resync_credits_top & 0x2);
      // lgt: added resets to tlx_afu_*_credit fields because these are not reset on clock only events
      event.tlx_afu_vc3_credit = 0;
      event.tlx_afu_vc2_credit = 0;
      event.tlx_afu_vc1_credit = 0;
      event.tlx_afu_vc0_credit = 0;
      event.tlx_afu_dcp3_credit = 0;
      event.tlx_afu_dcp2_credit = 0;
      event.tlx_afu_dcp0_credit = 0;
      // credit managment - completed

      *tlx_afu_ready_top			= 1;	// TODO: need to check this

      // Signals driven by the AFU are sensed here and transferred over to tlx_interface through methods
      // TODO: revisit the data transfer based on the signals
      // Table 3: TLX to AFU DCP0 Data Interface
      invalidVal = 0;
      c_afu_tlx_dcp0_rd_req  	= (afu_tlx_dcp0_rd_req_top & 0x2) ? 0 : (afu_tlx_dcp0_rd_req_top & 0x1);
      invalidVal		+= afu_tlx_dcp0_rd_req_top & 0x2;
      c_tlx_dcp0_data_pending_d2 = c_tlx_dcp0_data_pending_d2 + c_tlx_dcp0_data_pending_d1;
      c_tlx_dcp0_data_pending_d1 = c_tlx_dcp0_data_pending;
      if(c_afu_tlx_dcp0_rd_req)
      {
        c_afu_tlx_dcp0_rd_cnt	= (afu_tlx_dcp0_rd_cnt_top->aval) & 0x7;
        invalidVal		+= (afu_tlx_dcp0_rd_cnt_top->bval) & 0x7;
        c_tlx_dcp0_data_pending	= decode_rd_cnt( c_afu_tlx_dcp0_rd_cnt );
        printf("%08lld: ", (long long) c_sim_time);
        int resp_code = afu_tlx_dcp0_data_read_req(&event, 
                            c_afu_tlx_dcp0_rd_req, c_afu_tlx_dcp0_rd_cnt);
        printf(" The AFU to DCP0 Data Request -- with the method resp code as 0x%02x \n", resp_code);
      } else {
        c_tlx_dcp0_data_pending	= 0;
      }

      // Table 5: TLX Receiver ¿ TLX to AFU DCP1 Data Interface
      invalidVal = 0;
      c_afu_tlx_dcp1_rd_req  	= (afu_tlx_dcp1_rd_req_top & 0x2) ? 0 : (afu_tlx_dcp1_rd_req_top & 0x1);
      invalidVal		+= afu_tlx_dcp1_rd_req_top & 0x2;
      c_tlx_dcp1_data_pending_d2 = c_tlx_dcp1_data_pending_d2 + c_tlx_dcp1_data_pending_d1;
      c_tlx_dcp1_data_pending_d1 = c_tlx_dcp1_data_pending;
      if(c_afu_tlx_dcp1_rd_req)
      {
        c_afu_tlx_dcp1_rd_cnt	= (afu_tlx_dcp1_rd_cnt_top->aval) & 0x7;
        invalidVal		+= (afu_tlx_dcp1_rd_cnt_top->bval) & 0x7;
        c_tlx_dcp1_data_pending	= decode_rd_cnt( c_afu_tlx_dcp1_rd_cnt );
        printf("%08lld: ", (long long) c_sim_time);
        int resp_code = afu_tlx_dcp1_data_read_req(&event, 
                            c_afu_tlx_dcp1_rd_req, c_afu_tlx_dcp1_rd_cnt);
        printf(" The AFU to DCP1 Data Request -- with the method resp code as 0x%02x \n", resp_code);
      }else {
        c_tlx_dcp1_data_pending	= 0;
      }

      // Table 13: TLX Framer - AFU to TLX  AP  Configuration Response Interface (VCO, DCP0)
      invalidVal = 0;
      c_cfg_tlx_resp_valid  	= (cfg_tlx_resp_valid_top & 0x2) ? 0 : (cfg_tlx_resp_valid_top & 0x1);
      invalidVal		+= cfg_tlx_resp_valid_top & 0x2;
      if(c_cfg_tlx_resp_valid && (c_cfg_resp_ack_pending == 0))
      {
        c_cfg_tlx_resp_opcode	= (cfg_tlx_resp_opcode_top->aval) & 0xFF;
        invalidVal		+= (cfg_tlx_resp_opcode_top->bval) & 0xFF;
        c_cfg_tlx_resp_capptag	= (cfg_tlx_resp_capptag_top->aval) & 0xFFFF;
        invalidVal		+= (cfg_tlx_resp_capptag_top->bval) & 0xFFFF;
        c_cfg_tlx_resp_code	= (cfg_tlx_resp_code_top->aval) & 0xF;
        invalidVal		+= (cfg_tlx_resp_code_top->bval) & 0xF;
        c_cfg_tlx_rdata_offset	= (cfg_tlx_rdata_offset_top->aval) & 0xF;
        invalidVal		+= (cfg_tlx_rdata_offset_top->bval) & 0xF;
        invalidVal		+= getMyByteArray(cfg_tlx_rdata_bus_top, 4, &c_cfg_tlx_rdata_bus[0]);
        c_afu_tlx_cdata_bdi  	= (cfg_tlx_rdata_bdi_top & 0x2) ? 0 : (cfg_tlx_rdata_bdi_top & 0x1);
        invalidVal		+= cfg_tlx_rdata_bdi_top & 0x2;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The AFU to TLX  AP  Configuration Response Valid, with opcode: 0x%x \n",  c_cfg_tlx_resp_opcode);
        int resp_code = afu_cfg_send_resp_and_data(&event, 
                            c_cfg_tlx_resp_opcode, c_cfg_tlx_resp_capptag, 
                            c_cfg_tlx_resp_code, c_cfg_tlx_rdata_offset, 
                            c_cfg_tlx_resp_valid, c_cfg_tlx_rdata_bus, c_afu_tlx_cdata_bdi);
        printf(" The AFU-TLX Command Response Data transferred thru method - OPCODE = 0x%02x the method's resp code is 0x%02x \n",  c_cfg_tlx_resp_opcode, resp_code);
	c_cfg_resp_ack_pending = 1;
      }
      if(!c_cfg_tlx_resp_valid)
      {
	c_cfg_resp_ack_pending = 0;
      }
      *tlx_cfg_resp_ack_top		= (event.tlx_cfg_resp_ack) & 0x1;

      // remember to clear the ack in the event because a clock only cycle will not update the event structure
      if(event.tlx_cfg_resp_ack != 0)
	{
	  event.tlx_cfg_resp_ack = 0;
	}

      // Table 14: TLX Framer - AFU to TLX  VC0/DCP0 Interface
      invalidVal = 0;
      c_afu_tlx_vc0_valid  	         = (afu_tlx_vc0_valid_top & 0x2) ? 0 : (afu_tlx_vc0_valid_top & 0x1);
      invalidVal		        += afu_tlx_vc0_valid_top & 0x2;
      c_afu_tlx_dcp0_data_valid  	 = (afu_tlx_dcp0_data_valid_top & 0x2) ? 0 : (afu_tlx_dcp0_data_valid_top & 0x1);
      invalidVal		        += afu_tlx_dcp0_data_valid_top & 0x2;
      if(c_afu_tlx_vc0_valid)
      {
        c_afu_tlx_vc0_opcode	         = (afu_tlx_vc0_opcode_top->aval) & 0xFF;
        invalidVal		        += (afu_tlx_vc0_opcode_top->bval) & 0xFF;
        c_afu_tlx_vc0_capptag	         = (afu_tlx_vc0_capptag_top->aval) & 0xFFFF;
        invalidVal		        += (afu_tlx_vc0_capptag_top->bval) & 0xFFFF;
        c_afu_tlx_vc0_dl	         = (afu_tlx_vc0_dl_top->aval) & 0x3;
        invalidVal		        += (afu_tlx_vc0_dl_top->bval) & 0x3;
        c_afu_tlx_vc0_dp	         = (afu_tlx_vc0_dp_top->aval) & 0x3;
        invalidVal		        += (afu_tlx_vc0_dp_top->bval) & 0x3;
        c_afu_tlx_vc0_resp_code	         = (afu_tlx_vc0_resp_code_top->aval) & 0xF;
        invalidVal		        += (afu_tlx_vc0_resp_code_top->bval) & 0xF;
      }
      if(c_afu_tlx_dcp0_data_valid)
      {
        c_afu_tlx_dcp0_data_bdi  	 = (afu_tlx_dcp0_data_bdi_top & 0x2) ? 0 : (afu_tlx_dcp0_data_bdi_top & 0x1);
        invalidVal	         	+= afu_tlx_dcp0_data_bdi_top & 0x2;
        invalidVal		        += getMyCacheLine(afu_tlx_dcp0_data_bus_top, c_afu_tlx_dcp0_data_bus);
      }
      if(c_afu_tlx_vc0_valid & (c_afu_tlx_dcp0_data_valid == 0))
      {
        printf("%08lld: ", (long long) c_sim_time);
        int resp_code = afu_tlx_send_resp_vc0(&event, 
 		 c_afu_tlx_vc0_opcode, c_afu_tlx_vc0_dl, c_afu_tlx_vc0_capptag,
 		 c_afu_tlx_vc0_dp, c_afu_tlx_vc0_resp_code);
        printf(" The AFU to TLX  VC0 response, with opcode: 0x%x, (No Data) and the method resp code being 0x%02x\n",  c_afu_tlx_vc0_opcode, resp_code);
      }
      else if((c_afu_tlx_vc0_valid == 0) & c_afu_tlx_dcp0_data_valid)
      {
        printf("%08lld: ", (long long) c_sim_time);
	int resp_code = afu_tlx_send_dcp0_data(&event, c_afu_tlx_vc0_resp_code, c_afu_tlx_dcp0_data_bdi, 
 		 c_afu_tlx_vc0_dp, c_afu_tlx_vc0_dl,
  		 c_afu_tlx_dcp0_data_bus);
        printf(" The AFU to TLX  VC0 response, with opcode: 0x%x, (Data Only) and the method resp code being 0x%02x\n",  c_afu_tlx_vc0_opcode, resp_code);
      }
      else if(c_afu_tlx_vc0_valid & c_afu_tlx_dcp0_data_valid)
      {
        printf("%08lld: ", (long long) c_sim_time);
	int resp_code = afu_tlx_send_resp_vc0_and_dcp0(&event, 
 		 c_afu_tlx_vc0_opcode, c_afu_tlx_vc0_dl, c_afu_tlx_vc0_capptag,
 		 c_afu_tlx_vc0_dp, c_afu_tlx_vc0_resp_code, 
		 c_afu_tlx_dcp0_data_valid, c_afu_tlx_dcp0_data_bus, c_afu_tlx_dcp0_data_bdi);
        printf(" The AFU to TLX  VC0 response, with opcode: 0x%x, (OpCode & Data) and the method resp code being 0x%02x\n",  c_afu_tlx_vc0_opcode, resp_code);
      }

      // Table 15: TLX Framer - AFU to TLX  VC1 Interface
      invalidVal = 0;
      c_afu_tlx_vc1_valid      	         = (afu_tlx_vc1_valid_top & 0x2) ? 0 : (afu_tlx_vc1_valid_top & 0x1);
      invalidVal		        += afu_tlx_vc1_valid_top & 0x2;
      if(c_afu_tlx_vc1_valid)
      {
        c_afu_tlx_vc1_opcode	         = (afu_tlx_vc1_opcode_top->aval) & 0xFF;
        invalidVal		        += (afu_tlx_vc1_opcode_top->bval) & 0xFF;
        c_afu_tlx_vc1_stream_id	         = (afu_tlx_vc1_stream_id_top->aval) & 0xF;
        invalidVal		        += (afu_tlx_vc1_stream_id_top->bval) & 0xF;
        c_afu_tlx_vc1_afutag	         = (afu_tlx_vc1_afutag_top->aval) & 0xFFFF;
        invalidVal		        += (afu_tlx_vc1_afutag_top->bval) & 0xFFFF;
        invalidVal		        += getMy64Bit(afu_tlx_vc1_pa_top, &c_afu_tlx_vc1_pa);
        c_afu_tlx_vc1_dl	         = (afu_tlx_vc1_dl_top->aval) & 0x3;
        invalidVal		        += (afu_tlx_vc1_dl_top->bval) & 0x3;
        printf("%08lld: ", (long long) c_sim_time);
        int resp_code = afu_tlx_send_cmd_vc1(&event,
 		 c_afu_tlx_vc1_opcode, c_afu_tlx_vc1_stream_id, c_afu_tlx_vc1_afutag,
 		 c_afu_tlx_vc1_pa, c_afu_tlx_vc1_dl);
        printf(" The AFU to TLX  VC1 response, with opcode: 0x%x, and the method resp code being 0x%02x\n",  c_afu_tlx_vc1_opcode, resp_code);
      }

      // Table 16: AFU to TLX  VC2/DCP2 Interface
      invalidVal = 0;
      c_afu_tlx_vc2_valid  	         = (afu_tlx_vc2_valid_top & 0x2) ? 0 : (afu_tlx_vc2_valid_top & 0x1);
      invalidVal		        += afu_tlx_vc2_valid_top & 0x2;
      c_afu_tlx_dcp2_data_valid  	 = (afu_tlx_dcp2_data_valid_top & 0x2) ? 0 : (afu_tlx_dcp2_data_valid_top & 0x1);
      invalidVal		        += afu_tlx_dcp2_data_valid_top & 0x2;
      if(c_afu_tlx_vc2_valid)
      {
        c_afu_tlx_vc2_opcode	         = (afu_tlx_vc2_opcode_top->aval) & 0xFF;
        invalidVal		        += (afu_tlx_vc2_opcode_top->bval) & 0xFF;
        c_afu_tlx_vc2_dl	         = (afu_tlx_vc2_dl_top->aval) & 0x3;
        invalidVal		        += (afu_tlx_vc2_dl_top->bval) & 0x3;
        c_afu_tlx_vc2_host_tag	         = (afu_tlx_vc2_host_tag_top->aval) & 0xFFFFFF;
        invalidVal		        += (afu_tlx_vc2_host_tag_top->bval) & 0xFFFFFF;
        c_afu_tlx_vc2_cache_state        = (afu_tlx_vc2_cache_state_top->aval) & 0x7;
        invalidVal		        += (afu_tlx_vc2_cache_state_top->bval) & 0x7;
        c_afu_tlx_vc2_cmdflag            = (afu_tlx_vc2_cmdflag_top->aval) & 0x7;
        invalidVal		        += (afu_tlx_vc2_cmdflag_top->bval) & 0x7;
      }
      if(c_afu_tlx_dcp2_data_valid)
      {
        c_afu_tlx_dcp2_data_bdi  	 = (afu_tlx_dcp2_data_bdi_top & 0x2) ? 0 : (afu_tlx_dcp2_data_bdi_top & 0x1);
        invalidVal	         	+= afu_tlx_dcp2_data_bdi_top & 0x2;
        invalidVal		        += getMyCacheLine(afu_tlx_dcp2_data_bus_top, c_afu_tlx_dcp2_data_bus);
      }
      if(c_afu_tlx_vc2_valid & (c_afu_tlx_dcp2_data_valid == 0))
      {
        printf("%08lld: ", (long long) c_sim_time);
        int resp_code = afu_tlx_send_cmd_vc2(&event,
 		 c_afu_tlx_vc2_opcode, c_afu_tlx_vc2_dl, c_afu_tlx_vc2_host_tag,
 		 c_afu_tlx_vc2_cache_state, c_afu_tlx_vc2_cmdflag);
        printf(" The AFU to TLX  VC2 response, with opcode: 0x%x, (No Data) and the method resp code being 0x%02x\n",  c_afu_tlx_vc2_opcode, resp_code);
      }
      else if((c_afu_tlx_vc2_valid == 0) & c_afu_tlx_dcp2_data_valid )
      {
        printf("%08lld: ", (long long) c_sim_time);
        int resp_code = afu_tlx_send_dcp2_data(&event,
  		 c_afu_tlx_dcp2_data_bdi, c_afu_tlx_dcp2_data_bus);
        printf(" The AFU to TLX  VC2 response, with opcode: 0x%x, (Only Data) and the method resp code being 0x%02x\n",  c_afu_tlx_vc2_opcode, resp_code);
      }
      else if(c_afu_tlx_vc2_valid & c_afu_tlx_dcp2_data_valid )
      {
        printf("%08lld: ", (long long) c_sim_time);
	int resp_code = afu_tlx_send_cmd_vc2_and_dcp2_data(&event, 
 		 c_afu_tlx_vc2_opcode, c_afu_tlx_vc2_dl, c_afu_tlx_vc2_host_tag,
 		 c_afu_tlx_vc2_cache_state, c_afu_tlx_vc2_cmdflag,
  		 c_afu_tlx_dcp2_data_bdi, c_afu_tlx_dcp2_data_bus);
        printf(" The AFU to TLX  VC2 response, with opcode: 0x%x, (Opcode & Data) and the method resp code being 0x%02x\n",  c_afu_tlx_vc2_opcode, resp_code);
      }

      // Table 17: TLX Framer - AFU to TLX  VC3/DCP3 Interface
      invalidVal = 0;
      c_afu_tlx_vc3_valid  	         = (afu_tlx_vc3_valid_top & 0x2) ? 0 : (afu_tlx_vc3_valid_top & 0x1);
      invalidVal		        += afu_tlx_vc3_valid_top & 0x2;
      c_afu_tlx_dcp3_data_valid  	 = (afu_tlx_dcp3_data_valid_top & 0x2) ? 0 : (afu_tlx_dcp3_data_valid_top & 0x1);
      invalidVal		        += afu_tlx_dcp3_data_valid_top & 0x2;
      if(c_afu_tlx_vc3_valid)
      {
        c_afu_tlx_vc3_opcode	         = (afu_tlx_vc3_opcode_top->aval) & 0xFF;
        invalidVal		        += (afu_tlx_vc3_opcode_top->bval) & 0xFF;
        c_afu_tlx_vc3_stream_id	         = (afu_tlx_vc3_stream_id_top->aval) & 0xF;
        invalidVal		        += (afu_tlx_vc3_stream_id_top->bval) & 0xF;
        c_afu_tlx_vc3_afutag	         = (afu_tlx_vc3_afutag_top->aval) & 0xFFFF;
        invalidVal		        += (afu_tlx_vc3_afutag_top->bval) & 0xFFFF;
        c_afu_tlx_vc3_actag	         = (afu_tlx_vc3_actag_top->aval) & 0xFFF;
        invalidVal		        += (afu_tlx_vc3_actag_top->bval) & 0xFFF;
        invalidVal		        += getMyByteArray(afu_tlx_vc3_ea_ta_or_obj_top, 9, c_afu_tlx_vc3_ea_ta_or_obj);
        c_afu_tlx_vc3_dl	         = (afu_tlx_vc3_dl_top->aval) & 0x3;
        invalidVal		        += (afu_tlx_vc3_dl_top->bval) & 0x3;
        invalidVal		        += getMy64Bit(afu_tlx_vc3_be_top, &c_afu_tlx_vc3_be);
        c_afu_tlx_vc3_pl	         = (afu_tlx_vc3_pl_top->aval) & 0x7;
        invalidVal		        += (afu_tlx_vc3_pl_top->bval) & 0x7;
        c_afu_tlx_vc3_os  	         = (afu_tlx_vc3_os_top & 0x2) ? 0 : (afu_tlx_vc3_os_top & 0x1);
        invalidVal		        += afu_tlx_vc3_os_top & 0x2;
        c_afu_tlx_vc3_endian	         = (afu_tlx_vc3_endian_top & 0x2) ? 0 : (afu_tlx_vc3_endian_top & 0x1);
        invalidVal		        += (afu_tlx_vc3_endian_top & 0x2);
        c_afu_tlx_vc3_pg_size	         = (afu_tlx_vc3_pg_size_top->aval) & 0x3F;
        invalidVal		        += (afu_tlx_vc3_pg_size_top->bval) & 0x3F;
        c_afu_tlx_vc3_cmdflag	         = (afu_tlx_vc3_cmdflag_top->aval) & 0xF;
        invalidVal		        += (afu_tlx_vc3_cmdflag_top->bval) & 0xF;
        c_afu_tlx_vc3_pasid	         = (afu_tlx_vc3_pasid_top->aval) & 0xFFFFF;
        invalidVal		        += (afu_tlx_vc3_pasid_top->bval) & 0xFFFFF;
        c_afu_tlx_vc3_bdf	         = (afu_tlx_vc3_bdf_top->aval) & 0xFFFF;
        invalidVal		        += (afu_tlx_vc3_bdf_top->bval) & 0xFFFF;
        c_afu_tlx_vc3_mad	         = (afu_tlx_vc3_mad_top->aval) & 0xFF;
        invalidVal		        += (afu_tlx_vc3_mad_top->bval) & 0xFF;
        c_afu_tlx_vc3_capptag	         = (afu_tlx_vc3_capptag_top->aval) & 0xFFFF;
        invalidVal		        += (afu_tlx_vc3_capptag_top->bval) & 0xFFFF;
        c_afu_tlx_vc3_resp_code	         = (afu_tlx_vc3_resp_code_top->aval) & 0x0F;
        invalidVal		        += (afu_tlx_vc3_resp_code_top->bval) & 0x0F;
        printf("%08lld: ", (long long) c_sim_time);
        int resp_code = afu_tlx_send_cmd_vc3(&event, 
  		 c_afu_tlx_vc3_opcode, c_afu_tlx_vc3_actag,
  		 c_afu_tlx_vc3_stream_id, c_afu_tlx_vc3_ea_ta_or_obj,
  		 c_afu_tlx_vc3_afutag, c_afu_tlx_vc3_dl, c_afu_tlx_vc3_pl, c_afu_tlx_vc3_os, c_afu_tlx_vc3_be,
  		 c_afu_tlx_vc3_cmdflag, c_afu_tlx_vc3_endian, c_afu_tlx_vc3_bdf, c_afu_tlx_vc3_pasid, 
                 c_afu_tlx_vc3_pg_size, c_afu_tlx_vc3_mad,
                 c_afu_tlx_vc3_capptag, c_afu_tlx_vc3_resp_code);
        printf(" The AFU to TLX  VC3 response, with opcode: 0x%x, and the method resp code being 0x%02x\n",  c_afu_tlx_vc3_opcode, resp_code);
      }
      if(c_afu_tlx_dcp3_data_valid)
      {
        c_afu_tlx_dcp3_data_bdi  	 = (afu_tlx_dcp3_data_bdi_top & 0x2) ? 0 : (afu_tlx_dcp3_data_bdi_top & 0x1);
        invalidVal		        += afu_tlx_dcp3_data_bdi_top & 0x2;
        invalidVal		        += getMyCacheLine(afu_tlx_dcp3_data_bus_top, c_afu_tlx_dcp3_data_bus);
        printf("%08lld: ", (long long) c_sim_time);
        int resp_code = afu_tlx_send_dcp3_data(&event, 
  		 c_afu_tlx_dcp3_data_bdi, c_afu_tlx_dcp3_data_bus);
        printf(" The AFU to TLX  VC3 Data, with opcode: 0x%x, and the method resp code being 0x%02x\n",  c_afu_tlx_vc3_opcode, resp_code);
      }
      // Table 17: TLX Framer - AFU to TLX  VC3/DCP3 Interface


      // The code below is for driving the signals to the AFU, as they are provided from the tlx_interface
      // Table 2: TLX to AFU VCO Interface
      if(event.tlx_afu_vc0_valid)
      {
        setDpiSignal32(tlx_afu_vc0_opcode_top, event.tlx_afu_vc0_opcode, 8);
        setDpiSignal32(tlx_afu_vc0_afutag_top, event.tlx_afu_vc0_afutag, 16);
        setDpiSignal32(tlx_afu_vc0_capptag_top, event.tlx_afu_vc0_capptag, 16);
        setDpiSignal64(tlx_afu_vc0_pa_or_ta_top, event.tlx_afu_vc0_pa_or_ta >> 12 ); // use the high order bits
        setDpiSignal32(tlx_afu_vc0_dl_top, event.tlx_afu_vc0_dl, 2);
        setDpiSignal32(tlx_afu_vc0_dp_top, event.tlx_afu_vc0_dp, 2);
        *tlx_afu_vc0_ef_top     = (event.tlx_afu_vc0_ef) & 0x1;
        *tlx_afu_vc0_w_top      = (event.tlx_afu_vc0_w) & 0x1;
        *tlx_afu_vc0_mh_top     = (event.tlx_afu_vc0_mh) & 0x1;
        setDpiSignal32(tlx_afu_vc0_pg_size_top, event.tlx_afu_vc0_pg_size, 6);
        setDpiSignal32(tlx_afu_vc0_host_tag_top, event.tlx_afu_vc0_host_tag, 24);
        setDpiSignal32(tlx_afu_vc0_resp_code_top, event.tlx_afu_vc0_resp_code, 4);
        setDpiSignal32(tlx_afu_vc0_cache_state_top, event.tlx_afu_vc0_cache_state, 3);
        *tlx_afu_vc0_valid_top = 1;
        clk_afu_vc0_val = CLOCK_EDGE_DELAY;
        event.tlx_afu_vc0_valid = 0;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-AFU VC0 Response with OPCODE=0x%x \n",  event.tlx_afu_vc0_opcode);
        if(event.tlx_afu_dcp0_data_valid){
	  // split it into 64 B chucks an add it to the tail of a fifo
	  // the event struct can hold the head and tail pointers, and a rd_cnt that we get later
	  // the afu will issue afu_tlx_dcp0_rd_req later to tell us to start to pump the data out
	  // imbed the check for tlx_afu_dcp0_data_valid in here to grab the data, if any.
	  // event->tlx_afu_dcp0_data has all the data
	  // use dl to create dl 64 B enties in a fifo linked list dcp0_data_head, dcp0_data_tail
	  // cdata_pkt contain _next, and 64 B of cdata
          if(event.tlx_afu_vc0_dl == 0) {
            new_line_cnt = 1;
          } else{
            new_line_cnt = decode_dl(event.tlx_afu_vc0_dl);
          }
          for ( i = 0; i < new_line_cnt; i++ ) {
            new_vc0data_pkt = (struct DATA_PKT *)malloc( sizeof( struct DATA_PKT ) );
  	    new_vc0data_pkt->_next = NULL;
  	    for ( j=0; j<64; j++ ) {
	      new_vc0data_pkt->data[j] = event.tlx_afu_dcp0_data[(64*i)+j];
#ifdef DEBUG
	      printf( "%02x", event.tlx_afu_dcp0_data[(64*i)+j] );
#endif	      
	    }
#ifdef DEBUG
	    printf( "\n" );
#endif	      
	    // put the packet at the tail of the fifo
	    if ( event.dcp0_data_head == NULL ) {
	      event.dcp0_data_head = new_vc0data_pkt;
	    } else {
	      event.dcp0_data_tail->_next = new_vc0data_pkt;
	    }
	    event.dcp0_data_tail = new_vc0data_pkt;
          }
          event.tlx_afu_dcp0_data_valid = 0;
        }
      }
      if (clk_afu_vc0_val) {
      	--clk_afu_vc0_val;
      	if (!clk_afu_vc0_val)
    		*tlx_afu_vc0_valid_top = 0;
      }

      // Table 3: TLX to AFU DCP0 Data Interface
      if(c_tlx_dcp0_data_pending_d2 )
      {
        *tlx_afu_dcp0_data_bdi_top     = (event.tlx_afu_dcp0_data_bdi) & 0x1;
        setMyCacheLine( tlx_afu_dcp0_data_bus_top, event.dcp0_data_head->data );
        *tlx_afu_dcp0_data_valid_top = 1;
        clk_tlx_dcp0_data_val = CLOCK_EDGE_DELAY;
	--c_tlx_dcp0_data_pending_d2;
	old_vc0data_pkt = event.dcp0_data_head;
	event.dcp0_data_head = event.dcp0_data_head->_next;
	free( old_vc0data_pkt ); // DANGER - if this is the last one, tail will point to unallocated memory
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-AFU VC0 with Data Available \n");
      }
      if (clk_tlx_dcp0_data_val) {
      	--clk_tlx_dcp0_data_val;
      	if (!clk_tlx_dcp0_data_val)
    		*tlx_afu_dcp0_data_valid_top = 0;
      }

      // Table 4: TLX Receiver - TLX to AFU VC1 Interface
      if(event.tlx_afu_vc1_valid)
      {
        setDpiSignal32(tlx_afu_vc1_opcode_top, event.tlx_afu_vc1_opcode, 8);
        setDpiSignal32(tlx_afu_vc1_afutag_top, event.tlx_afu_vc1_afutag, 16);
        setDpiSignal32(tlx_afu_vc1_capptag_top, event.tlx_afu_vc1_capptag, 16);
        setDpiSignal64(tlx_afu_vc1_pa_top, event.tlx_afu_vc1_pa);
        setDpiSignal32(tlx_afu_vc1_dl_top, event.tlx_afu_vc1_dl, 2);
        setDpiSignal32(tlx_afu_vc1_dp_top, event.tlx_afu_vc1_dp, 2);
        setDpiSignal64(tlx_afu_vc1_be_top, event.tlx_afu_vc1_be);
        setDpiSignal32(tlx_afu_vc1_pl_top, event.tlx_afu_vc1_pl, 3);
        *tlx_afu_vc1_endian_top     = (event.tlx_afu_vc1_endian) & 0x1;
        *tlx_afu_vc1_co_top     = (event.tlx_afu_vc1_co) & 0x1;
        *tlx_afu_vc1_os_top     = (event.tlx_afu_vc1_os) & 0x1;
        setDpiSignal32(tlx_afu_vc1_cmdflag_top, event.tlx_afu_vc1_cmdflag, 4);
        setDpiSignal32(tlx_afu_vc1_mad_top, event.tlx_afu_vc1_mad, 8);
        *tlx_afu_vc1_valid_top = 1;
        clk_afu_vc1_val = CLOCK_EDGE_DELAY;
        event.tlx_afu_vc1_valid = 0;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-AFU VC1 Response with OPCODE=0x%x \n",  event.tlx_afu_vc1_opcode);
        if(event.tlx_afu_dcp1_data_valid){
	  // split it into 64 B chucks an add it to the tail of a fifo
	  // the event struct can hold the head and tail pointers, and a rd_cnt that we get later
	  // the afu will issue afu_tlx_dcp1_rd_req later to tell us to start to pump the data out
	  // imbed the check for tlx_afu_dcp1_data_valid in here to grab the data, if any.
	  // event->tlx_afu_dcp1_data has all the data
	  // use dl to create dl 64 B enties in a fifo linked list dcp1_data_head, dcp1_data_tail
	  // cdata_pkt contain _next, and 64 B of cdata
          if(event.tlx_afu_vc1_dl == 0) {
            new_line_cnt = 1;
          } else{
            new_line_cnt = decode_dl(event.tlx_afu_vc1_dl);
          }
          for ( i = 0; i < new_line_cnt; i++ ) {
            new_vc1data_pkt = (struct DATA_PKT *)malloc( sizeof( struct DATA_PKT ) );
  	    new_vc1data_pkt->_next = NULL;
  	    for ( j=0; j<64; j++ ) {
	      new_vc1data_pkt->data[j] = event.tlx_afu_dcp1_data[(64*i)+j];
#ifdef DEBUG
	      printf( "%02x", event.tlx_afu_dcp1_data[(64*i)+j] );
#endif	      
	    }
#ifdef DEBUG
	    printf( "\n" );
#endif	      
	    // put the packet at the tail of the fifo
	    if ( event.dcp1_data_head == NULL ) {
	      event.dcp1_data_head = new_vc1data_pkt;
	    } else {
	      event.dcp1_data_tail->_next = new_vc1data_pkt;
	    }
	    event.dcp1_data_tail = new_vc1data_pkt;
          }
          event.tlx_afu_dcp1_data_valid = 0;
        }
      }
      if (clk_afu_vc1_val) {
      	--clk_afu_vc1_val;
      	if (!clk_afu_vc1_val)
    		*tlx_afu_vc1_valid_top = 0;
      }

      // Table 5: TLX Receiver - TLX to AFU DCP1 Data Interface
      if ( c_tlx_dcp1_data_pending_d2 ) 
      {
        *tlx_afu_dcp1_data_bdi_top     = (event.tlx_afu_dcp1_data_bdi) & 0x1;
        setMyCacheLine( tlx_afu_dcp1_data_bus_top, event.dcp1_data_head->data );
        *tlx_afu_dcp1_data_valid_top = 1;
        clk_tlx_dcp1_data_val = CLOCK_EDGE_DELAY;
	--c_tlx_dcp1_data_pending_d2;
	old_vc1data_pkt = event.dcp1_data_head;
	event.dcp1_data_head = event.dcp1_data_head->_next;
	free( old_vc1data_pkt ); // DANGER - if this is the last one, tail will point to unallocated memory
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-AFU VC1 Data at Cnt =0x%x \n",  c_afu_tlx_dcp1_rd_cnt);
      }
      if (clk_tlx_dcp1_data_val) {
      	--clk_tlx_dcp1_data_val;
      	if (!clk_tlx_dcp1_data_val)
    		*tlx_afu_dcp1_data_valid_top = 0;
      }

      // Table 6: TLX Receiver - TLX to AFU VC2 Interface
      if(event.tlx_afu_vc2_valid)
      {
        setDpiSignal32(tlx_afu_vc2_opcode_top, event.tlx_afu_vc2_opcode, 8);
        setDpiSignal32(tlx_afu_vc2_capptag_top, event.tlx_afu_vc2_capptag, 16);
        setDpiSignal64(tlx_afu_vc2_ea_top, event.tlx_afu_vc2_ea >> 12 );  // use the high order bits
        setDpiSignal32(tlx_afu_vc2_pg_size_top, event.tlx_afu_vc2_pg_size, 6);
        setDpiSignal32(tlx_afu_vc2_cmdflag_top, event.tlx_afu_vc2_cmdflag, 4);
        setDpiSignal32(tlx_afu_vc2_pasid_top, event.tlx_afu_vc2_pasid, 20);
        setDpiSignal32(tlx_afu_vc2_bdf_top, event.tlx_afu_vc2_bdf, 16);
        *tlx_afu_vc2_valid_top = 1;
        clk_afu_vc2_val = CLOCK_EDGE_DELAY;
        event.tlx_afu_vc2_valid = 0;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-AFU VC2 Response with OPCODE=0x%x \n",  event.tlx_afu_vc2_opcode);
      }
      if (clk_afu_vc2_val) {
      	--clk_afu_vc2_val;
      	if (!clk_afu_vc2_val)
    		*tlx_afu_vc2_valid_top = 0;
      }

    // Table 7: TLX to CFG Interface for Configuration Commands
      if(event.tlx_cfg_valid)
      {
        setDpiSignal32(tlx_cfg_opcode_top, event.tlx_cfg_opcode, 8);
        setDpiSignal32(tlx_cfg_capptag_top, event.tlx_cfg_capptag, 16);
          setDpiSignal64(tlx_cfg_pa_top, event.tlx_cfg_pa);
        setDpiSignal32(tlx_cfg_pl_top, event.tlx_cfg_pl, 3);
        *tlx_cfg_t_top = (event.tlx_cfg_t) & 0x1;
        *tlx_cfg_valid_top = 1;
        clk_tlx_cfg_val = CLOCK_EDGE_DELAY;
        event.tlx_cfg_valid = 0;
        printf("%08lld: ", (long long) c_sim_time);
        printf(" The TLX-CFG Response with OPCODE=0x%x \n",  event.tlx_cfg_opcode);

	memcpy( &c_tlx_cfg_data_del, event.tlx_cfg_data_bus, 4 );
	c_tlx_cfg_data_bdi_del = (event.tlx_cfg_data_bdi) & 0x1;   
	printf( "lgt:tlx_afu_cfg_data_valid: received data from tlx.  raw data=0x" );
	for ( i=0; i<4; i++ ) {
	    printf( "%02x", event.tlx_cfg_data_bus[i] );
	 }
	printf( "\n" );
	printf( "lgt:tlx_afu_cfg_data_valid: received data from tlx.  copied data=0x%08x\n", c_tlx_cfg_data_del );

        setDpiSignal32(tlx_cfg_data_bus_top, c_tlx_cfg_data_del, 32); // lgt might need to delay these in top.v
 	*tlx_cfg_data_bdi_top = c_tlx_cfg_data_bdi_del;
      }
      if (clk_tlx_cfg_val) {
      	--clk_tlx_cfg_val;
      	if (!clk_tlx_cfg_val)
    		*tlx_cfg_valid_top = 0;
      }
    }
    else
    {
      // Stuff to be done on the active high period of the clock
      debug_msg("tlx_bfm: clock = 1" );
      c_sim_error = 0;
      tlx_control();
    }
  }
  else
  {
  // Stuff to be done while reset is high
  /*
    *tlx_afu_vc0_credit_top 	        = 0;
    *tlx_afu_dcp0_credit_top 	        = 0;
    *tlx_afu_vc1_credit_top 	        = 0;
    *tlx_afu_vc2_credit_top 	        = 0;
    *tlx_afu_dcp2_credit_top 	        = 0;
    *tlx_afu_vc3_credit_top 	        = 0;
    *tlx_afu_dcp3_credit_top 	        = 0;
*/
    if(cacheLineCleared == 0)
    {
      for(i=0; i < CACHELINE_BYTES; i++)
      {
        c_clearedCacheline[i] = 0;
      }
      cacheLineCleared = 1;
    }
    setDpiSignal32(tlx_afu_vc0_initial_credit_top, c_tlx_afu_vc0_initial_credit, 4);
    setDpiSignal32(tlx_afu_dcp0_initial_credit_top, c_tlx_afu_dcp0_initial_credit, 6);
    setDpiSignal32(tlx_afu_vc1_initial_credit_top, c_tlx_afu_vc1_initial_credit, 4);
    setDpiSignal32(tlx_afu_vc2_initial_credit_top, c_tlx_afu_vc2_initial_credit, 4);
    setDpiSignal32(tlx_afu_dcp2_initial_credit_top, c_tlx_afu_dcp2_initial_credit, 6);
    setDpiSignal32(tlx_afu_vc3_initial_credit_top, c_tlx_afu_vc3_initial_credit, 4);
    setDpiSignal32(tlx_afu_dcp3_initial_credit_top, c_tlx_afu_dcp3_initial_credit, 6);
// To ensure that we are driving a known value at reset
    setDpiSignal32(tlx_afu_vc0_opcode_top, 0x0, 8);
    setDpiSignal32(tlx_afu_vc0_afutag_top, 0x0, 16);
    setDpiSignal32(tlx_afu_vc0_capptag_top, 0x0, 16);
    setDpiSignal64(tlx_afu_vc0_pa_or_ta_top, 0x0);
    setDpiSignal32(tlx_afu_vc0_dl_top, 0x0, 2);
    setDpiSignal32(tlx_afu_vc0_dp_top, 0x0, 2);
    *tlx_afu_vc0_ef_top     = 0x0;
    *tlx_afu_vc0_w_top      = 0x0;
    *tlx_afu_vc0_mh_top     = 0x0;
    setDpiSignal32(tlx_afu_vc0_pg_size_top, 0x0, 6);
    setDpiSignal32(tlx_afu_vc0_host_tag_top, 0x0, 24);
    setDpiSignal32(tlx_afu_vc0_resp_code_top, 0x0, 4);
    setDpiSignal32(tlx_afu_vc0_cache_state_top, 0x0, 3);
    *tlx_afu_vc0_valid_top = 0;
    setDpiSignal32(tlx_afu_vc1_opcode_top, 0x0, 8);
    setDpiSignal32(tlx_afu_vc1_afutag_top, 0x0, 16);
    setDpiSignal32(tlx_afu_vc1_capptag_top, 0x0, 16);
    setDpiSignal64(tlx_afu_vc1_pa_top, 0x0);
    setDpiSignal32(tlx_afu_vc1_dl_top, 0x0, 2);
    setDpiSignal32(tlx_afu_vc1_dp_top, 0x0, 2);
    setDpiSignal64(tlx_afu_vc1_be_top, 0x0);
    setDpiSignal32(tlx_afu_vc1_pl_top, 0x0, 3);
    *tlx_afu_vc1_endian_top = 0;
    *tlx_afu_vc1_co_top     = 0;
    *tlx_afu_vc1_os_top     = 0;
    setDpiSignal32(tlx_afu_vc1_cmdflag_top, 0x0, 4);
    setDpiSignal32(tlx_afu_vc1_mad_top, 0x0, 8);
    *tlx_afu_vc1_valid_top = 0x0;
    setDpiSignal32(tlx_afu_vc2_opcode_top, 0x0, 8);
    setDpiSignal32(tlx_afu_vc2_capptag_top, 0x0, 16);
    setDpiSignal64(tlx_afu_vc2_ea_top, 0x0);
    setDpiSignal32(tlx_afu_vc2_pg_size_top, 0x0, 6);
    setDpiSignal32(tlx_afu_vc2_cmdflag_top, 0x0, 4);
    setDpiSignal32(tlx_afu_vc2_pasid_top, 0x0, 20);
    setDpiSignal32(tlx_afu_vc2_bdf_top, 0x0, 16);
    *tlx_afu_vc2_valid_top = 0;
    *tlx_afu_dcp0_data_valid_top = 0;
    *tlx_afu_dcp0_data_bdi_top = 0;
    *tlx_afu_dcp1_data_valid_top = 0;
    *tlx_afu_dcp1_data_bdi_top = 0;
    setMyCacheLine( tlx_afu_dcp0_data_bus_top, c_clearedCacheline );
    setMyCacheLine( tlx_afu_dcp1_data_bus_top, c_clearedCacheline );
  }
  c_reset_d4 = c_reset_d3;
  c_reset_d3 = c_reset_d2;
  c_reset_d2 = c_reset_d1;
  c_reset_d1 = c_reset;
}
