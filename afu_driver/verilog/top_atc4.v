//
// Copyright 2014,2017 International Business Machines
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

`timescale 1ns / 1ns

module top_atc4 (
  output          breakpoint
);

   import "DPI-C" function void tlx_bfm_init( );
   import "DPI-C" function void set_simulation_time(input [0:63] simulationTime);
   import "DPI-C" function void get_simuation_error(inout simulationError);
   import "DPI-C" function void tlx_bfm(
                                input             tlx_clock,
                                input             afu_clock,
                                input             reset,
                                // Table 2: TLX to AFU VCO Interface
				input   [6:0]	  afu_tlx_vc0_initial_credit_top,
				input		  afu_tlx_vc0_credit_top,
				inout             tlx_afu_vc0_valid_top,
				inout   [7:0]     tlx_afu_vc0_opcode_top,
				inout  [15:0]     tlx_afu_vc0_afutag_top,
				inout  [15:0]     tlx_afu_vc0_capptag_top,
				inout  [51:0]     tlx_afu_vc0_pa_or_ta_top,	// Address 63:12
				inout   [1:0]     tlx_afu_vc0_dl_top,
				inout   [1:0]     tlx_afu_vc0_dp_top,
				inout             tlx_afu_vc0_ef_top,
				inout             tlx_afu_vc0_w_top,
				inout             tlx_afu_vc0_mh_top,
				inout   [5:0]     tlx_afu_vc0_pg_size_top,
				inout  [23:0]     tlx_afu_vc0_host_tag_top,
				inout   [3:0]     tlx_afu_vc0_resp_code_top,
				inout   [2:0]     tlx_afu_vc0_cache_state_top,
				//	Table 3: TLX to AFU DCP0 Data Interface
				input		  afu_tlx_dcp0_rd_req_top,
				input   [2:0]	  afu_tlx_dcp0_rd_cnt_top,
				inout             tlx_afu_dcp0_data_valid_top,
				inout [511:0]     tlx_afu_dcp0_data_bus_top,
				inout             tlx_afu_dcp0_data_bdi_top,
				//	Table 4: TLX to AFU VC1 Interface
				input   [6:0]	  afu_tlx_vc1_initial_credit_top,
				input		  afu_tlx_vc1_credit_top,
				inout             tlx_afu_vc1_valid_top,
				inout   [7:0]     tlx_afu_vc1_opcode_top,
				inout  [15:0]     tlx_afu_vc1_afutag_top,
				inout  [15:0]     tlx_afu_vc1_capptag_top,
				inout  [63:0]     tlx_afu_vc1_pa_top,
				inout   [1:0]     tlx_afu_vc1_dl_top,
				inout   [1:0]     tlx_afu_vc1_dp_top,
				inout  [63:0]     tlx_afu_vc1_be_top,
				inout   [2:0]     tlx_afu_vc1_pl_top,
				inout             tlx_afu_vc1_endian_top,
				inout             tlx_afu_vc1_co_top,
				inout             tlx_afu_vc1_os_top,
				inout   [3:0]     tlx_afu_vc1_cmdflag_top,
				inout   [7:0]     tlx_afu_vc1_mad_top,
				//	Table 5: TLX to AFU DCP1 Data Interface
				input		  afu_tlx_dcp1_rd_req_top,
				input   [2:0]	  afu_tlx_dcp1_rd_cnt_top,
				inout             tlx_afu_dcp1_data_valid_top,
				inout [511:0]     tlx_afu_dcp1_data_bus_top,
				inout             tlx_afu_dcp1_data_bdi_top,
				//	Table 6: TLX to AFU VC2 Interface
				input   [6:0]	  afu_tlx_vc2_initial_credit_top,
				input		  afu_tlx_vc2_credit_top,
				inout             tlx_afu_vc2_valid_top,
				inout   [7:0]     tlx_afu_vc2_opcode_top,
				inout  [15:0]     tlx_afu_vc2_capptag_top,
				inout  [51:0]     tlx_afu_vc2_ea_top,	// Address 63:12
				inout   [5:0]     tlx_afu_vc2_pg_size_top,
				inout   [3:0]     tlx_afu_vc2_cmdflag_top,
				inout  [19:0]     tlx_afu_vc2_pasid_top,
				inout  [15:0]     tlx_afu_vc2_bdf_top,
				//	Table 7: TLX to CFG Interface for Configuration Commands
				input   [3:0]	  cfg_tlx_initial_credit_top,
				input		  cfg_tlx_credit_return_top,
				inout             tlx_cfg_valid_top,
				inout   [7:0]     tlx_cfg_opcode_top,
				inout  [15:0]     tlx_cfg_capptag_top,
				inout  [63:0]     tlx_cfg_pa_top,
				inout   [2:0]     tlx_cfg_pl_top,
				inout             tlx_cfg_t_top,
				inout  [31:0]     tlx_cfg_data_bus_top,
				inout             tlx_cfg_data_bdi_top,
				//	Table 8: TLX Receiver - Template Configuration Ports
    				inout	     	  tlx_cfg_rcv_tmpl_capability_0_top,
    				inout	     	  tlx_cfg_rcv_tmpl_capability_1_top,
    				inout	     	  tlx_cfg_rcv_tmpl_capability_2_top,
    				inout	     	  tlx_cfg_rcv_tmpl_capability_3_top,
    				inout   [3:0]  	  tlx_cfg_rcv_rate_capability_0_top,
    				inout   [3:0] 	  tlx_cfg_rcv_rate_capability_1_top,
    				inout   [3:0]  	  tlx_cfg_rcv_rate_capability_2_top,
    				inout   [3:0]  	  tlx_cfg_rcv_rate_capability_3_top,
				input		  cfg_tlx_resync_credits_top,
				//	Table 9: TLX Credit Interfac
				//	Table 10: TL Credit Interface
				//	Table 11: TLX Receiver - Miscellaneous Ports
    				inout	     	  tlx_afu_ready_top,
				//	Table 12: TLX Framer - Miscellaneous Ports
				//	Table 13: TLX Framer - AFU to TLX  AP  Configuration Response Interface (VCO, DCP0)
				input		  cfg_tlx_resp_valid_top,
				input   [7:0]	  cfg_tlx_resp_opcode_top,
				input  [15:0]	  cfg_tlx_resp_capptag_top,
				input   [3:0]	  cfg_tlx_resp_code_top,
				input   [3:0]	  cfg_tlx_rdata_offset_top,
				input  [31:0]	  cfg_tlx_rdata_bus_top,
				input		  cfg_tlx_rdata_bdi_top,
    				inout	     	  tlx_cfg_resp_ack_top,
				//	Table 14: TLX Framer - AFU to TLX  VC0/DCP0 Interface
    				inout   [3:0]  	  tlx_afu_vc0_initial_credit_top,
    				inout   [5:0]  	  tlx_afu_dcp0_initial_credit_top,
    				inout	     	  tlx_afu_vc0_credit_top,
    				inout	     	  tlx_afu_dcp0_credit_top,
				input		  afu_tlx_vc0_valid_top,
				input   [7:0]	  afu_tlx_vc0_opcode_top,
				input  [15:0]	  afu_tlx_vc0_capptag_top,
				input   [1:0]	  afu_tlx_vc0_dl_top,
				input   [1:0]	  afu_tlx_vc0_dp_top,
				input   [3:0]	  afu_tlx_vc0_resp_code_top,
				input             afu_tlx_dcp0_data_valid_top,
				input [511:0]     afu_tlx_dcp0_data_bus_top,
				input             afu_tlx_dcp0_data_bdi_top,

				//	Table 15: TLX Framer - AFU to TLX  VC1 Interface
    				inout   [3:0]  	  tlx_afu_vc1_initial_credit_top,
    				inout	     	  tlx_afu_vc1_credit_top,
				input		  afu_tlx_vc1_valid_top,
				input   [7:0]	  afu_tlx_vc1_opcode_top,
				input   [3:0]	  afu_tlx_vc1_stream_id_top,
				input  [15:0]	  afu_tlx_vc1_afutag_top,
				input  [57:0]	  afu_tlx_vc1_pa_top,	// afu_tlx_vc1_pa[63:6]
				input   [1:0]	  afu_tlx_vc1_dl_top,

				//	Table 16: AFU to TLX  VC2/DCP2 Interface
    				inout   [3:0]  	  tlx_afu_vc2_initial_credit_top,
    				inout   [5:0]  	  tlx_afu_dcp2_initial_credit_top,
    				inout	     	  tlx_afu_vc2_credit_top,
    				inout	     	  tlx_afu_dcp2_credit_top,
				input		  afu_tlx_vc2_valid_top,
				input   [7:0]	  afu_tlx_vc2_opcode_top,
				input   [1:0]	  afu_tlx_vc2_dl_top,
				input  [23:0]	  afu_tlx_vc2_host_tag_top,
				input   [2:0]	  afu_tlx_vc2_cache_state_top,
				input   [3:0]	  afu_tlx_vc2_cmdflag_top,
				input             afu_tlx_dcp2_data_valid_top,
				input [511:0]     afu_tlx_dcp2_data_bus_top,
				input             afu_tlx_dcp2_data_bdi_top,

				//	Table 17: TLX Framer - AFU to TLX  VC3/DCP3 Interface
    				inout   [3:0]  	  tlx_afu_vc3_initial_credit_top,
    				inout   [5:0]  	  tlx_afu_dcp3_initial_credit_top,
    				inout	     	  tlx_afu_vc3_credit_top,
    				inout	     	  tlx_afu_dcp3_credit_top,
				input		  afu_tlx_vc3_valid_top,
				input   [7:0]	  afu_tlx_vc3_opcode_top,
				input   [3:0]	  afu_tlx_vc3_stream_id_top,
				input  [15:0]	  afu_tlx_vc3_afutag_top,
				input  [11:0]	  afu_tlx_vc3_actag_top,
				input  [67:0]	  afu_tlx_vc3_ea_ta_or_obj_top,
				input   [1:0]	  afu_tlx_vc3_dl_top,
				input  [63:0]	  afu_tlx_vc3_be_top,
				input   [2:0]	  afu_tlx_vc3_pl_top,
				input		  afu_tlx_vc3_os_top,
				input		  afu_tlx_vc3_endian_top,
				input   [5:0]	  afu_tlx_vc3_pg_size_top,
				input   [3:0]	  afu_tlx_vc3_cmdflag_top,
				input  [19:0]	  afu_tlx_vc3_pasid_top,
				input  [15:0]	  afu_tlx_vc3_bdf_top,
				input   [7:0]	  afu_tlx_vc3_mad_top,
				input             afu_tlx_dcp3_data_valid_top,
				input [511:0]     afu_tlx_dcp3_data_bus_top,
				input             afu_tlx_dcp3_data_bdi_top
                                       );

   parameter RESET_CYCLES = 9;
   reg             tlx_clock;
   reg             afu_clock;
   reg             reset;
   // Table 2: TLX to AFU VCO Interface
   reg   [6:0]	  afu_tlx_vc0_initial_credit_top;
   reg		  afu_tlx_vc0_credit_top;
   reg             tlx_afu_vc0_valid_top;
   reg   [7:0]     tlx_afu_vc0_opcode_top;
   reg  [15:0]     tlx_afu_vc0_afutag_top;
   reg  [15:0]     tlx_afu_vc0_capptag_top;
   reg  [51:0]     tlx_afu_vc0_pa_or_ta_top;	// Address 63:12
   reg   [1:0]     tlx_afu_vc0_dl_top;
   reg   [1:0]     tlx_afu_vc0_dp_top;
   reg             tlx_afu_vc0_ef_top;
   reg             tlx_afu_vc0_w_top;
   reg             tlx_afu_vc0_mh_top;
   reg   [5:0]     tlx_afu_vc0_pg_size_top;
   reg  [23:0]     tlx_afu_vc0_host_tag_top;
   reg   [3:0]     tlx_afu_vc0_resp_code_top;
   reg   [2:0]     tlx_afu_vc0_cache_state_top;

   //	Table 3: TLX to AFU DCP0 Data Interface
   reg		  afu_tlx_dcp0_rd_req_top;
   reg   [2:0]	  afu_tlx_dcp0_rd_cnt_top;
   reg            tlx_afu_dcp0_data_valid_top;
   reg [511:0]    tlx_afu_dcp0_data_bus_top;
   reg            tlx_afu_dcp0_data_bdi_top;

   //	Table 4: TLX to AFU VC1 Interface
   reg   [6:0]	  afu_tlx_vc1_initial_credit_top;
   reg		  afu_tlx_vc1_credit_top;
   reg             tlx_afu_vc1_valid_top;
   reg   [7:0]     tlx_afu_vc1_opcode_top;
   reg  [15:0]     tlx_afu_vc1_afutag_top;
   reg  [15:0]     tlx_afu_vc1_capptag_top;
   reg  [63:0]     tlx_afu_vc1_pa_top;
   reg   [1:0]     tlx_afu_vc1_dl_top;
   reg   [1:0]     tlx_afu_vc1_dp_top;
   reg  [63:0]     tlx_afu_vc1_be_top;
   reg   [2:0]     tlx_afu_vc1_pl_top;
   reg             tlx_afu_vc1_endian_top;
   reg             tlx_afu_vc1_co_top;
   reg             tlx_afu_vc1_os_top;
   reg   [3:0]     tlx_afu_vc1_cmdflag_top;
   reg   [7:0]     tlx_afu_vc1_mad_top;

//	Table 5: TLX to AFU Response Data Interface
   wire             tlx_afu_resp_data_valid_top;
   wire [511:0]     tlx_afu_resp_data_bus_top;
   wire             tlx_afu_resp_data_bdi_top;

//	Table 5: TLX to AFU Response Data Interface delays
   reg             tlx_afu_resp_data_valid_dly1;
   reg [511:0]     tlx_afu_resp_data_bus_dly1;
   reg             tlx_afu_resp_data_bdi_dly1;

//	Table 5: TLX to AFU Response Data Interface delays
   reg             tlx_afu_resp_data_valid_dly2;
   reg [511:0]     tlx_afu_resp_data_bus_dly2;
   reg             tlx_afu_resp_data_bdi_dly2;

   //	Table 5: TLX to AFU DCP1 Data Interface
   reg		  afu_tlx_dcp1_rd_req_top;
   reg   [2:0]	  afu_tlx_dcp1_rd_cnt_top;
   reg            tlx_afu_dcp1_data_valid_top;
   reg [511:0]    tlx_afu_dcp1_data_bus_top;
   reg            tlx_afu_dcp1_data_bdi_top;

//	Table 6: TLX to AFU Command Data Interface
   wire             tlx_afu_cmd_data_valid_top;
   wire [511:0]     tlx_afu_cmd_data_bus_top;
   wire             tlx_afu_cmd_data_bdi_top;

   //	Table 6: TLX to AFU VC2 Interface
   reg   [6:0]	  afu_tlx_vc2_initial_credit_top;
   reg		  afu_tlx_vc2_credit_top;
   reg            tlx_afu_vc2_valid_top;
   reg   [7:0]    tlx_afu_vc2_opcode_top;
   reg  [15:0]    tlx_afu_vc2_capptag_top;
   reg  [51:0]    tlx_afu_vc2_ea_top;	// Address 63:12
   reg   [5:0]    tlx_afu_vc2_pg_size_top;
   reg   [3:0]    tlx_afu_vc2_cmdflag_top;
   reg  [19:0]    tlx_afu_vc2_pasid_top;
   reg  [15:0]    tlx_afu_vc2_bdf_top;

//	Table 7: TLX Framer credit interface
   wire             tlx_afu_resp_credit_top;
   wire             tlx_afu_resp_data_credit_top;
   wire             tlx_afu_cmd_credit_top;
   wire             tlx_afu_cmd_data_credit_top;
   wire [3:0]       tlx_afu_cmd_resp_initial_credit_top;
   wire [3:0]       tlx_afu_data_initial_credit_top;
   wire [5:0]       tlx_afu_cmd_data_initial_credit_top;
   wire [5:0]       tlx_afu_resp_data_initial_credit_top;

   //	Table 7: TLX to CFG Interface for Configuration Commands
   reg   [3:0]	  cfg_tlx_initial_credit_top;
   reg		  cfg_tlx_credit_return_top;
   reg            tlx_cfg_valid_top;
   reg   [7:0]    tlx_cfg_opcode_top;
   reg  [15:0]    tlx_cfg_capptag_top;
   reg  [63:0]    tlx_cfg_pa_top;
   reg   [2:0]    tlx_cfg_pl_top;
   reg            tlx_cfg_t_top;
   reg  [31:0]    tlx_cfg_data_bus_top;
   reg            tlx_cfg_data_bdi_top;

   reg       [4:0] ro_device_top;

   //	Table 8: TLX Receiver - Template Configuration Ports
   reg	     	  tlx_cfg_rcv_tmpl_capability_0_top;
   reg	     	  tlx_cfg_rcv_tmpl_capability_1_top;
   reg	     	  tlx_cfg_rcv_tmpl_capability_2_top;
   reg	     	  tlx_cfg_rcv_tmpl_capability_3_top;
   reg   [3:0]    tlx_cfg_rcv_rate_capability_0_top;
   reg   [3:0] 	  tlx_cfg_rcv_rate_capability_1_top;
   reg   [3:0]    tlx_cfg_rcv_rate_capability_2_top;
   reg   [3:0]    tlx_cfg_rcv_rate_capability_3_top;
   reg		  cfg_tlx_resync_credits_top;

   //	Table 9: TLX Credit Interfac
   //	Table 10: TL Credit Interface
   //	Table 11: TLX Receiver - Miscellaneous Ports
   reg             tlx_afu_ready_top;
   //	Table 12: TLX Framer - Miscellaneous Ports
   //	Table 13: TLX Framer - AFU to TLX  AP  Configuration Response Interface (VCO, DCP0)
   reg		  cfg_tlx_resp_valid_top;
   reg   [7:0]	  cfg_tlx_resp_opcode_top;
   reg  [15:0]	  cfg_tlx_resp_capptag_top;
   reg   [3:0]	  cfg_tlx_resp_code_top;
   reg   [3:0]	  cfg_tlx_rdata_offset_top;
   reg  [31:0]	  cfg_tlx_rdata_bus_top;
   reg		  cfg_tlx_rdata_bdi_top;
   reg	     	  tlx_cfg_resp_ack_top;


   //	Table 14: TLX Framer - AFU to TLX  VC0/DCP0 Interface
   reg   [3:0]    tlx_afu_vc0_initial_credit_top;
   reg   [5:0]    tlx_afu_dcp0_initial_credit_top;
   reg	     	  tlx_afu_vc0_credit_top;
   reg	     	  tlx_afu_dcp0_credit_top;
   reg		  afu_tlx_vc0_valid_top;
   reg   [7:0]	  afu_tlx_vc0_opcode_top;
   reg  [15:0]	  afu_tlx_vc0_capptag_top;
   reg   [1:0]	  afu_tlx_vc0_dl_top;
   reg   [1:0]	  afu_tlx_vc0_dp_top;
   reg   [3:0]	  afu_tlx_vc0_resp_code_top;
   reg            afu_tlx_dcp0_data_valid_top;
   reg [511:0]    afu_tlx_dcp0_data_bus_top;
   reg            afu_tlx_dcp0_data_bdi_top;
   
   //	Table 15: TLX Framer - AFU to TLX  VC1 Interface
   reg   [3:0]    tlx_afu_vc1_initial_credit_top;
   reg	     	  tlx_afu_vc1_credit_top;
   reg		  afu_tlx_vc1_valid_top = 1'b0;
   reg   [7:0]	  afu_tlx_vc1_opcode_top = 8'b0;
   reg   [3:0]	  afu_tlx_vc1_stream_id_top = 4'b0;
   reg  [15:0]	  afu_tlx_vc1_afutag_top = 16'b0;
   reg  [57:0]	  afu_tlx_vc1_pa_top = 58'b0;	// afu_tlx_vc1_pa[63:6]
   reg   [1:0]	  afu_tlx_vc1_dl_top = 2'b0;
   
   //	Table 16: AFU to TLX  VC2/DCP2 Interface
   reg   [3:0]    tlx_afu_vc2_initial_credit_top;
   reg   [5:0]    tlx_afu_dcp2_initial_credit_top;
   reg	     	  tlx_afu_vc2_credit_top;
   reg	     	  tlx_afu_dcp2_credit_top;
   reg		  afu_tlx_vc2_valid_top = 1'b0;	// to ensure non-X
   reg   [7:0]	  afu_tlx_vc2_opcode_top = 8'b0;
   reg   [1:0]	  afu_tlx_vc2_dl_top = 2'b0;
   reg  [23:0]	  afu_tlx_vc2_host_tag_top = 24'b0;
   reg   [2:0]	  afu_tlx_vc2_cache_state_top = 3'b0;
   reg   [3:0]	  afu_tlx_vc2_cmdflag_top = 4'b0;
   reg            afu_tlx_dcp2_data_valid_top = 1'b0;
   reg [511:0]    afu_tlx_dcp2_data_bus_top = 512'b0;
   reg            afu_tlx_dcp2_data_bdi_top = 1'b0;
   
   //	Table 17: TLX Framer - AFU to TLX  VC3/DCP3 Interface
   reg   [3:0]    tlx_afu_vc3_initial_credit_top;
   reg   [5:0]    tlx_afu_dcp3_initial_credit_top;
   reg	     	  tlx_afu_vc3_credit_top;
   reg	     	  tlx_afu_dcp3_credit_top;
   reg		  afu_tlx_vc3_valid_top;
   reg   [7:0]	  afu_tlx_vc3_opcode_top;
   reg   [3:0]	  afu_tlx_vc3_stream_id_top;
   reg  [15:0]	  afu_tlx_vc3_afutag_top;
   reg  [11:0]	  afu_tlx_vc3_actag_top;
   reg  [67:0]	  afu_tlx_vc3_ea_ta_or_obj_top;
   reg   [1:0]	  afu_tlx_vc3_dl_top;
   reg  [63:0]	  afu_tlx_vc3_be_top;
   reg   [2:0]	  afu_tlx_vc3_pl_top;
   reg		  afu_tlx_vc3_os_top;
   reg		  afu_tlx_vc3_endian_top;
   reg   [5:0]	  afu_tlx_vc3_pg_size_top;
   reg   [3:0]	  afu_tlx_vc3_cmdflag_top;
   reg  [19:0]	  afu_tlx_vc3_pasid_top;
   reg  [15:0]	  afu_tlx_vc3_bdf_top;
   reg   [7:0]	  afu_tlx_vc3_mad_top;
   reg            afu_tlx_dcp3_data_valid_top;
   reg [511:0]    afu_tlx_dcp3_data_bus_top;
   reg            afu_tlx_dcp3_data_bdi_top;

 // Wires for AFU o/p
//	Table 2: TLX Response Credit Interface
   wire	[6:0]		afu_tlx_resp_initial_credit               ;

// Other wires
   wire            reset_n;

//	Table 5: TLX to AFU Response Data Interface
   reg             tlx_afu_resp_data_valid;
   reg [511:0]     tlx_afu_resp_data_bus;
   reg             tlx_afu_resp_data_bdi;

//	Table 6: TLX to AFU Command Data Interface
   wire             tlx_afu_cmd_data_valid;
   wire [511:0]     tlx_afu_cmd_data_bus;
   wire             tlx_afu_cmd_data_bdi;

//	Table 7: TLX Framer credit interface
   wire             tlx_afu_resp_credit;
   wire             tlx_afu_resp_data_credit;
   wire             tlx_afu_cmd_credit;
   wire             tlx_afu_cmd_data_credit;
   wire [3:0]       tlx_afu_cmd_initial_credit;
   wire [3:0]       tlx_afu_resp_initial_credit;
   wire [5:0]       tlx_afu_cmd_data_initial_credit;
   wire [5:0]       tlx_afu_resp_data_initial_credit;

   wire             tlx_cfg0_in_rcv_tmpl_capability_0;
   wire             tlx_cfg0_in_rcv_tmpl_capability_1;
   wire             tlx_cfg0_in_rcv_tmpl_capability_2;
   wire             tlx_cfg0_in_rcv_tmpl_capability_3;
   wire       [3:0] tlx_cfg0_in_rcv_rate_capability_0;
   wire       [3:0] tlx_cfg0_in_rcv_rate_capability_1;
   wire       [3:0] tlx_cfg0_in_rcv_rate_capability_2;
   wire       [3:0] tlx_cfg0_in_rcv_rate_capability_3;

   wire      [4:0]  ro_device;
   wire     [31:0] ro_dlx0_version ;                     // -- Connect to DLX output at next level, or tie off to all 0s
   wire     [31:0] tlx0_cfg_oc4_tlx_version ;                     // -- (was ro_tlx0_version[31:0])
   wire             tlx_afu_ready;
    // VC0 interface to AFU [Responses from Host to AFU, for AFU to Host commands]
   wire   [6:0] afu_tlx_vc0_initial_credit       ;
   wire         afu_tlx_vc0_credit               ;
   wire         tlx_afu_vc0_valid                ; 
   wire   [7:0] tlx_afu_vc0_opcode               ;
   wire  [15:0] tlx_afu_vc0_afutag               ;
   wire  [15:0] tlx_afu_vc0_capptag              ;
   wire [63:12] tlx_afu_vc0_pa_or_ta             ;
   wire   [1:0] tlx_afu_vc0_dl                   ;
   wire   [1:0] tlx_afu_vc0_dp                   ;
   wire         tlx_afu_vc0_ef                   ;
   wire         tlx_afu_vc0_w                    ;
   wire         tlx_afu_vc0_mh                   ;
   wire   [5:0] tlx_afu_vc0_pg_size              ;
   wire  [23:0] tlx_afu_vc0_host_tag             ;
   wire   [3:0] tlx_afu_vc0_resp_code            ;
   wire   [2:0] tlx_afu_vc0_cache_state          ;
        // DCP0 data interface to AFU [Response data from Host to AFU, for AFU to Host commands]
   wire             afu_tlx_dcp0_rd_req              ;
   wire  [  2:0]    afu_tlx_dcp0_rd_cnt              ;
   wire             tlx_afu_dcp0_data_valid          ;
   wire             tlx_afu_dcp0_data_bdi            ;
   wire  [511:0]    tlx_afu_dcp0_data_bus            ;
        // VC1 interface to AFU [CAPP Commands from Host to AFU]
   wire  [  6:0]    afu_tlx_vc1_initial_credit      ;	// (static) Number of cmd credits available for TLX to use in the AFU
   wire             afu_tlx_vc1_credit              ;	// Returns a cmd credit to the TLX
   wire             tlx_afu_vc1_valid               ;	// Indicates TLX has a valid cmd for AFU to process
   wire  [  7:0]    tlx_afu_vc1_opcode              ;	// (w/cmd_valid) Cmd Opcode
   wire  [ 15:0]    tlx_afu_vc1_afutag              ;	// 
   wire  [ 15:0]    tlx_afu_vc1_capptag             ;	// (w/cmd_valid) Unique operation tag from CAPP unit
   wire  [ 63:0]    tlx_afu_vc1_pa                  ;	// (w/cmd_valid) Physical Address
   wire  [  1:0]    tlx_afu_vc1_dl                  ;	// (w/cmd_valid) Cmd Data Length (00=rsvd, 01=64B, 10=128B, 11=256B)
   wire  [  1:0]    tlx_afu_vc1_dp                  ;	// 
   wire  [ 63:0]    tlx_afu_vc1_be                  ;	// (w/cmd_valid) Byte Enable
   wire  [  2:0]    tlx_afu_vc1_pl                  ;	// (w/cmd_valid) Partial Length (000=1B,001=2B,010=4B,011=8B,100=16B,101=32B,110/111=rsvd)
   wire             tlx_afu_vc1_endian              ;	// (w/cmd_valid) Operand Endian-ess
   wire             tlx_afu_vc1_co                  ;	// 
   wire             tlx_afu_vc1_os                  ;	// (w/cmd_valid) Ordered Segment - 1 means ordering is guaranteed (unsupported)
   wire  [  3:0]    tlx_afu_vc1_cmdflag             ;	// (w/cmd_valid) Specifies atomic memory operation (unsupported)
   wire  [  7:0]    tlx_afu_vc1_mad                 ;
        // DCP1 data interface to AFU [CAPP Command data from Host to AFU]
   wire             afu_tlx_dcp1_rd_req              ;
   wire  [  2:0]    afu_tlx_dcp1_rd_cnt              ;
   wire             tlx_afu_dcp1_data_valid          ;
   wire             tlx_afu_dcp1_data_bdi            ;
   wire  [511:0]    tlx_afu_dcp1_data_bus            ;
        // VC2 interface to AFU [TL 4.0 CAPP commands - kill_xlate, disable_cache, enable_cache, disable_atc, enable_atc]
   wire  [  6:0]    afu_tlx_vc2_initial_credit       ;
   wire             afu_tlx_vc2_credit               ;
   wire             tlx_afu_vc2_valid                ;
   wire   [  7:0]    tlx_afu_vc2_opcode               ;
   wire   [ 15:0]    tlx_afu_vc2_capptag              ;
   wire   [ 63:12]   tlx_afu_vc2_ea                   ;
   wire   [  5:0]    tlx_afu_vc2_pg_size              ;
   wire   [ 19:0]    tlx_afu_vc2_pasid                ;
   wire   [ 15:0]    tlx_afu_vc2_bdf                  ;
   wire   [  3:0]    tlx_afu_vc2_cmdflag              ;
        // -----------------------------------
        // AFU to TLX Framer Transmit Interface
        // -----------------------------------
        // --- VC0 interface from AFU [Responses from AFU to Host, for Host to AFU commands]
   wire [  3:0]    tlx_afu_vc0_initial_credit       ;
   wire            tlx_afu_vc0_credit               ;
   wire            afu_tlx_vc0_valid                ;
   wire [  7:0]    afu_tlx_vc0_opcode               ;
   wire [ 15:0]    afu_tlx_vc0_capptag              ;
   wire [  1:0]    afu_tlx_vc0_dl                   ;
   wire [  1:0]    afu_tlx_vc0_dp                   ;
   wire [  3:0]    afu_tlx_vc0_resp_code            ;
        // --- DCP0 interface from AFU [Response data from AFU to Host, for Host to AFU commands]
   wire  [  5:0]    tlx_afu_dcp0_initial_credit      ;
   wire             tlx_afu_dcp0_credit              ;
   wire             afu_tlx_dcp0_data_valid          ;
   wire  [511:0]    afu_tlx_dcp0_data_bus            ;
   wire             afu_tlx_dcp0_data_bdi            ;
        // --- VC1 interface from AFU [AP 4.0 Commands from AFU to Host - mem_pa_flush]
   wire  [  3:0]    tlx_afu_vc1_initial_credit       ;
   wire             tlx_afu_vc1_credit               ;
   wire             afu_tlx_vc1_valid                ;
   wire  [  7:0]    afu_tlx_vc1_opcode               ;
   wire  [  3:0]    afu_tlx_vc1_stream_id            ;
   wire  [ 15:0]    afu_tlx_vc1_afutag               ;
   wire  [ 63:6]    afu_tlx_vc1_pa                   ;
   wire  [  1:0]    afu_tlx_vc1_dl                   ;
        // --- VC2 interface from AFU [AP 4.0 Commands from AFU to Host - synonym_done, castout, castout.push]
   wire [  3:0]    tlx_afu_vc2_initial_credit       ;
   wire            tlx_afu_vc2_credit               ;
   wire            afu_tlx_vc2_valid                ;
   wire [  7:0]    afu_tlx_vc2_opcode               ;
   wire [  1:0]    afu_tlx_vc2_dl                   ;
   wire [ 23:0]    afu_tlx_vc2_host_tag             ;
   wire [  2:0]    afu_tlx_vc2_cache_state          ;
   wire [  3:0]    afu_tlx_vc2_cmdflag              ;
        // --- DCP2 interface from AFU [AP Command data from AFU to Host - castout.push]
   wire  [  5:0]    tlx_afu_dcp2_initial_credit      ;
   wire             tlx_afu_dcp2_credit              ;
   wire             afu_tlx_dcp2_data_valid          ;
   wire [511:0]     afu_tlx_dcp2_data_bus            ;
   wire             afu_tlx_dcp2_data_bdi            ;
        // --- VC3 interface from AFU [AP Commands from AFU to Host - original cmds]
   wire [  3:0]    tlx_afu_vc3_initial_credit       ;
   wire            tlx_afu_vc3_credit               ;
   wire            afu_tlx_vc3_valid                ;
   wire [  7:0]    afu_tlx_vc3_opcode               ;
   wire [  3:0]    afu_tlx_vc3_stream_id            ;
   wire [ 15:0]    afu_tlx_vc3_afutag               ;
   wire [ 11:0]    afu_tlx_vc3_actag                ;
   wire [ 67:0]    afu_tlx_vc3_ea_ta_or_obj         ;
   wire [  1:0]    afu_tlx_vc3_dl                   ;
   wire [ 63:0]    afu_tlx_vc3_be                   ;
   wire [  2:0]    afu_tlx_vc3_pl                   ;
   wire            afu_tlx_vc3_os                   ;
   wire            afu_tlx_vc3_endian               ;
   wire [  5:0]    afu_tlx_vc3_pg_size              ;
   wire [  3:0]    afu_tlx_vc3_cmdflag              ;
   wire [ 19:0]    afu_tlx_vc3_pasid                ;
   wire [ 15:0]    afu_tlx_vc3_bdf                  ;
   wire [  7:0]    afu_tlx_vc3_mad                  ;
        // --- DCP3 interface from AFU [AP Command Data from AFU to Host - original cmds]
   wire [  5:0]    tlx_afu_dcp3_initial_credit      ;
   wire            tlx_afu_dcp3_credit              ;
   wire            afu_tlx_dcp3_data_valid          ;
   wire [511:0]    afu_tlx_dcp3_data_bus            ;
   wire            afu_tlx_dcp3_data_bdi            ;
        // -----------------------------------
        // Configuration Ports
        // -----------------------------------
    // Configuration Ports: Drive Configuration (determined by software)
   wire             cfg0_tlx_xmit_tmpl_config_0      ; // When 1, TLX should support transmitting template 0
   wire             cfg0_tlx_xmit_tmpl_config_1      ; // When 1, TLX should support transmitting template 1
   wire             cfg0_tlx_xmit_tmpl_config_2      ; // When 1, TLX should support transmitting template 2
   wire             cfg0_tlx_xmit_tmpl_config_3      ; // When 1, TLX should support transmitting template 3
   wire     [  3:0] cfg0_tlx_xmit_rate_config_0      ; // Value corresponds to the rate TLX can transmit template 0
   wire     [  3:0] cfg0_tlx_xmit_rate_config_1      ; // Value corresponds to the rate TLX can transmit template 1
   wire     [  3:0] cfg0_tlx_xmit_rate_config_2      ; // Value corresponds to the rate TLX can transmit template 2
   wire     [  3:0] cfg0_tlx_xmit_rate_config_3      ; // Value corresponds to the rate TLX can transmit template 3

   wire             tlx_cfg0_rcv_tmpl_capability_0   ; // When 1, TLX supports receiving template 0
   wire             tlx_cfg0_rcv_tmpl_capability_1   ; // When 1, TLX supports receiving template 1
   wire             tlx_cfg0_rcv_tmpl_capability_2   ; // When 1, TLX supports receiving template 2
   wire             tlx_cfg0_rcv_tmpl_capability_3   ; // When 1, TLX supports receiving template 3
   wire  [  3:0]    tlx_cfg0_rcv_rate_capability_0   ; // Value corresponds to the rate TLX can receive template 0
   wire  [  3:0]    tlx_cfg0_rcv_rate_capability_1   ; // Value corresponds to the rate TLX can receive template 1
   wire  [  3:0]    tlx_cfg0_rcv_rate_capability_2   ; // Value corresponds to the rate TLX can receive template 2
   wire  [  3:0]    tlx_cfg0_rcv_rate_capability_3   ; // Value corresponds to the rate TLX can receive template 3

   wire             cfg0_tlx_resync_credits      ; 
    // ---------------------------
    // Config_* command interfaces
    // ---------------------------
    // Port 0: config_write/read commands from host    
   wire         tlx_cfg0_valid;
   wire   [7:0] tlx_cfg0_opcode;
   wire  [63:0] tlx_cfg0_pa;
   wire         tlx_cfg0_t;
   wire   [2:0] tlx_cfg0_pl;
   wire  [15:0] tlx_cfg0_capptag;
   wire  [31:0] tlx_cfg0_data_bus;
   wire         tlx_cfg0_data_bdi;
   wire   [3:0] cfg0_tlx_initial_credit;
   wire         cfg0_tlx_credit_return;

    // Port 0: config_* responses back to host
   wire         cfg0_tlx_resp_valid;
   wire   [7:0] cfg0_tlx_resp_opcode;
   wire  [15:0] cfg0_tlx_resp_capptag;
   wire   [3:0] cfg0_tlx_resp_code;
   wire   [3:0] cfg0_tlx_data_offset;    // TLX 4.0 name          
   wire  [31:0] cfg0_tlx_data_bus ;      // TLX 4.0 name              
   wire         cfg0_tlx_data_bdi ;      // TLX 4.0 name              
   wire         tlx_cfg0_resp_ack;
    // ------------------------------------
    // Configuration Space to TLX and AFU 
    // ------------------------------------
   wire         cfg_f1_octrl00_resync_credits;   // Make available to TLX
    // ------------------------------------
    // Configuration Space to VPD Interface
    // ------------------------------------
    // Interface to VPD 
   wire [14:0] cfg_vpd_addr         ; // VPD address for write or read
   wire        cfg_vpd_wren         ; // Set to 1 to write a location, hold at 1 until see vpd_done = 1 then clear to 0
   wire [31:0] cfg_vpd_wdata        ; // Contains data to write to VPD register (valid while wren=1)
   wire        cfg_vpd_rden         ; // Set to 1 to read  a location, hold at 1 until see vpd_done = 1 then clear to 0
   wire [31:0] vpd_cfg_rdata        ; // Contains data read back from VPD register (valid when rden=1 and vpd_done=1)
   wire        vpd_cfg_done         ; // VPD pulses to 1 for 1 cycle when write is complete, or when rdata contains valid results
   wire         vpd_err_unimplemented_addr;  // When 1, VPD detected an invalid address
    // ------------------------------------
    // Configuration Space to FLASH Interface
    // ------------------------------------
   // Interface to FLASH control logic
   wire  [1:0] cfg_flsh_devsel       ;// Select AXI4-Lite device to target
   wire [13:0] cfg_flsh_addr         ;// Read or write address to selected target
   wire        cfg_flsh_wren         ;// Set to 1 to write a location, hold at 1 until see 'flsh_done' = 1 then clear to 0
   wire [31:0] cfg_flsh_wdata        ;// Contains data to write to FLASH register (valid while wren=1)
   wire        cfg_flsh_rden         ;// Set to 1 to read  a location, hold at 1 until see 'flsh_done' = 1 the clear to 0
   wire [31:0] flsh_cfg_rdata        ;// Contains data read back from FLASH register (valid when rden=1 and 'flsh_done'=1)
   wire        flsh_cfg_done         ;// FLASH logic pulses to 1 for 1 cycle when write is complete, or when rdata contains valid results
   wire  [7:0] flsh_cfg_status       ;// Device Specific status information
   wire  [1:0] flsh_cfg_bresp        ;// Write response from selected AXI4-Lite device
   wire  [1:0] flsh_cfg_rresp        ;// Read  response from selected AXI4-Lite device
   wire        cfg_flsh_expand_enable;// When 1, expand/collapse 4 bytes of data into four, 1 byte AXI operations
   wire        cfg_flsh_expand_dir   ;// When 0, expand bytes [3:0] in order 0,1,2,3 . When 1, expand in order 3,2,1,0 .

 // Integers
  integer         i;
  integer         resetCnt;
 // Sim related variables
  reg [0:63]      simulationTime ;
  reg             simulationError;

initial begin
    resetCnt = 0;
    i = 0;
    tlx_clock				<= 0;
    afu_clock				<= 0;
    reset   				<= 1;

  // Table 2: TLX to AFU VCO Interface
     tlx_afu_vc0_valid_top			<= 0;
     tlx_afu_vc0_opcode_top			<= 8'b0;
     tlx_afu_vc0_afutag_top			<= 16'b0;
     tlx_afu_vc0_capptag_top			<= 16'b0;
     tlx_afu_vc0_pa_or_ta_top			<= 52'b0;
     tlx_afu_vc0_dl_top			<= 2'b0;
     tlx_afu_vc0_dp_top			<= 2'b0;
     tlx_afu_vc0_ef_top			<= 0;
     tlx_afu_vc0_w_top			<= 0;
     tlx_afu_vc0_mh_top			<= 0;
     tlx_afu_vc0_pg_size_top		<= 6'b0;
     tlx_afu_vc0_host_tag_top		<= 24'b0;
     tlx_afu_vc0_resp_code_top		<= 4'b0;
     tlx_afu_vc0_cache_state_top		<= 3'b0;

//	Table 3: TLX to AFU DCP0 Data Interface
     tlx_afu_dcp0_data_valid_top		<= 0;
     tlx_afu_dcp0_data_bus_top		<= 512'b0;
     tlx_afu_dcp0_data_bdi_top		<= 0;

//	Table 4: TLX to AFU VC1 Interface
     tlx_afu_vc1_valid_top		<= 1'b0;
     tlx_afu_vc1_opcode_top		<= 8'b0;
     tlx_afu_vc1_afutag_top		<= 16'b0;
     tlx_afu_vc1_capptag_top		<= 16'b0;
     tlx_afu_vc1_pa_top		<= 64'b0;
     tlx_afu_vc1_dl_top		<= 2'b0;
     tlx_afu_vc1_dp_top		<= 2'b0;
     tlx_afu_vc1_be_top		<= 64'b0;
     tlx_afu_vc1_pl_top		<= 3'b0;
     tlx_afu_vc1_endian_top		<= 1'b0;
     tlx_afu_vc1_co_top		<= 1'b0;
     tlx_afu_vc1_os_top		<= 1'b0;
     tlx_afu_vc1_cmdflag_top		<= 4'b0;
     tlx_afu_vc1_mad_top		<= 8'b0;

//	Table 5: TLX to AFU DCP1 Data Interface
     tlx_afu_dcp1_data_valid_top	<= 1'b0;
     tlx_afu_dcp1_data_bus_top		<= 512'b0;
     tlx_afu_dcp1_data_bdi_top		<= 1'b0;
//	Table 6: TLX to AFU VC2 Interface
     tlx_afu_vc2_valid_top		<= 1'b0;
     tlx_afu_vc2_opcode_top		<= 8'b0;
     tlx_afu_vc2_capptag_top		<= 16'b0;
     tlx_afu_vc2_ea_top			<= 52'b0;
     tlx_afu_vc2_pg_size_top		<= 6'b0;
     tlx_afu_vc2_cmdflag_top		<= 4'b0;
     tlx_afu_vc2_pasid_top		<= 20'b0;
     tlx_afu_vc2_bdf_top		<= 16'b0;

//	Table 8: TLX Receiver - Template Configuration Ports
    tlx_cfg_rcv_tmpl_capability_0_top	<= 0;
    tlx_cfg_rcv_tmpl_capability_1_top	<= 0;
    tlx_cfg_rcv_tmpl_capability_2_top	<= 0;
    tlx_cfg_rcv_tmpl_capability_3_top	<= 0;
    tlx_cfg_rcv_rate_capability_0_top	<= 4'b0;
    tlx_cfg_rcv_rate_capability_1_top	<= 4'b0;
    tlx_cfg_rcv_rate_capability_2_top	<= 4'b0;
    tlx_cfg_rcv_rate_capability_3_top	<= 4'b0;
    cfg_tlx_resync_credits_top		<= 1;
//	Table 11: TLX Receiver - Miscellaneous Ports
    tlx_afu_ready_top			<= 1;
//	Table 13: TLX Framer - AFU to TLX  AP  Configuration Response Interface (VCO, DCP0)
    tlx_cfg_resp_ack_top			<= 0;
//	Table 14: TLX Framer - AFU to TLX  VC0/DCP0 Interface
    tlx_afu_vc0_initial_credit_top	<= 4'b0111;
    tlx_afu_dcp0_initial_credit_top	<= 6'b010000;
    tlx_afu_vc0_credit_top		<= 1'b0;
    tlx_afu_dcp0_credit_top		<= 1'b0;
//	Table 15: TLX Framer - AFU to TLX  VC1 Interface
    tlx_afu_vc1_initial_credit_top	<= 4'b0100;
    tlx_afu_vc1_credit_top		<= 1'b0;
//	Table 16: AFU to TLX  VC2/DCP2 Interface
    tlx_afu_vc2_initial_credit_top	<= 4'b0100;
    tlx_afu_dcp2_initial_credit_top	<= 6'b010000;
    tlx_afu_vc2_credit_top	<= 1'b0;
    tlx_afu_dcp2_credit_top	<= 1'b0;
//	Table 17: TLX Framer - AFU to TLX  VC3/DCP3 Interface
    tlx_afu_vc3_initial_credit_top	<= 4'b0100;
    tlx_afu_dcp3_initial_credit_top	<= 6'b010000;
    tlx_afu_vc3_credit_top	<= 1'b0;
    tlx_afu_dcp3_credit_top	<= 1'b0;
    ro_device_top				<= 5'b0;			//Updated per Jeff R's note of 23/Jun/2017
    tlx_cfg_valid_top		<= 1'b0;
    tlx_cfg_opcode_top		<= 8'b0;
    tlx_cfg_capptag_top		<= 16'b0;
    tlx_cfg_pa_top		<= 64'b0;
    tlx_cfg_pl_top		<= 3'b0;
    tlx_cfg_t_top		<= 1'b0;
    tlx_cfg_data_bus_top	<= 32'b0;
    tlx_cfg_data_bdi_top		<= 1'b0;
end

  // Clock generation

  always begin
    #2 tlx_clock = !tlx_clock;
  end

  always @ (posedge tlx_clock) begin
    afu_clock = !afu_clock;
  end

  always @ ( tlx_clock ) begin
    if(resetCnt < 30)
      resetCnt = resetCnt + 1;
    else
      i = 1;
  end

  always @ ( tlx_clock ) begin
    if(resetCnt == RESET_CYCLES + 2)
      #0 tlx_bfm_init();
  end

  always @ ( tlx_clock ) begin
    if(resetCnt < RESET_CYCLES)
      reset = 1'b1;
    else
      reset = 1'b0;
  end

  always @ (posedge tlx_clock) begin
   cfg_tlx_initial_credit_top		<= cfg0_tlx_initial_credit; // new
   cfg_tlx_credit_return_top		<= cfg0_tlx_credit_return;  // new lgt
   cfg_tlx_resp_valid_top               <= cfg0_tlx_resp_valid;
   cfg_tlx_resp_opcode_top              <= cfg0_tlx_resp_opcode;
   cfg_tlx_resp_capptag_top             <= cfg0_tlx_resp_capptag;
   cfg_tlx_resp_code_top                <= cfg0_tlx_resp_code;
   cfg_tlx_rdata_offset_top             <= cfg0_tlx_data_offset;
   cfg_tlx_rdata_bus_top                <= cfg0_tlx_data_bus;
   cfg_tlx_rdata_bdi_top                <= cfg0_tlx_data_bdi;

   afu_tlx_vc0_initial_credit_top 	<= afu_tlx_vc0_initial_credit;
   afu_tlx_vc0_credit_top		<= afu_tlx_vc0_credit;

   afu_tlx_dcp0_rd_req_top		<= afu_tlx_dcp0_rd_req;
   afu_tlx_dcp0_rd_cnt_top		<= afu_tlx_dcp0_rd_cnt;

   afu_tlx_vc1_initial_credit_top 	<= afu_tlx_vc1_initial_credit;
   afu_tlx_vc1_credit_top		<= afu_tlx_vc1_credit;

   afu_tlx_dcp1_rd_req_top		<= afu_tlx_dcp1_rd_req;
   afu_tlx_dcp1_rd_cnt_top		<= afu_tlx_dcp1_rd_cnt;

   afu_tlx_vc2_initial_credit_top 	<= afu_tlx_vc2_initial_credit;
   afu_tlx_vc2_credit_top		<= afu_tlx_vc2_credit;

   afu_tlx_vc0_valid_top		<= afu_tlx_vc0_valid;
   afu_tlx_vc0_opcode_top		<= afu_tlx_vc0_opcode;
   afu_tlx_vc0_capptag_top		<= afu_tlx_vc0_capptag;
   afu_tlx_vc0_dl_top			<= afu_tlx_vc0_dl;
   afu_tlx_vc0_dp_top			<= afu_tlx_vc0_dp;
   afu_tlx_vc0_resp_code_top		<= afu_tlx_vc0_resp_code;
   afu_tlx_dcp0_data_valid_top		<= afu_tlx_dcp0_data_valid;
   afu_tlx_dcp0_data_bus_top		<= afu_tlx_dcp0_data_bus;
   afu_tlx_dcp0_data_bdi_top		<= afu_tlx_dcp0_data_bdi;

   afu_tlx_vc1_valid_top		<= afu_tlx_vc1_valid;
   afu_tlx_vc1_opcode_top		<= afu_tlx_vc1_opcode;
   afu_tlx_vc1_stream_id_top		<= afu_tlx_vc1_stream_id;
   afu_tlx_vc1_afutag_top		<= afu_tlx_vc1_afutag;
   afu_tlx_vc1_pa_top			<= afu_tlx_vc1_pa;
   afu_tlx_vc1_dl_top			<= afu_tlx_vc1_dl;

   afu_tlx_vc2_valid_top		<= afu_tlx_vc2_valid;
   afu_tlx_vc2_opcode_top		<= afu_tlx_vc2_opcode;
   afu_tlx_vc2_dl_top			<= afu_tlx_vc2_dl;
   afu_tlx_vc2_host_tag_top		<= afu_tlx_vc2_host_tag;
   afu_tlx_vc2_cache_state_top		<= afu_tlx_vc2_cache_state;
   afu_tlx_vc2_cmdflag_top		<= afu_tlx_vc2_cmdflag;
   afu_tlx_dcp2_data_valid_top		<= afu_tlx_dcp2_data_valid;
   afu_tlx_dcp2_data_bus_top		<= afu_tlx_dcp2_data_bus;
   afu_tlx_dcp2_data_bdi_top		<= afu_tlx_dcp2_data_bdi;

   afu_tlx_vc3_valid_top		<= afu_tlx_vc3_valid;
   afu_tlx_vc3_opcode_top		<= afu_tlx_vc3_opcode;
   afu_tlx_vc3_stream_id_top		<= afu_tlx_vc3_stream_id;
   afu_tlx_vc3_afutag_top		<= afu_tlx_vc3_afutag;
   afu_tlx_vc3_actag_top		<= afu_tlx_vc3_actag;
   afu_tlx_vc3_ea_ta_or_obj_top		<= afu_tlx_vc3_ea_ta_or_obj;
   afu_tlx_vc3_dl_top			<= afu_tlx_vc3_dl;
   afu_tlx_vc3_be_top			<= afu_tlx_vc3_be;
   afu_tlx_vc3_pl_top			<= afu_tlx_vc3_pl;
   afu_tlx_vc3_os_top			<= afu_tlx_vc3_os;
   afu_tlx_vc3_endian_top		<= afu_tlx_vc3_endian;
   afu_tlx_vc3_pg_size_top		<= afu_tlx_vc3_pg_size;
   afu_tlx_vc3_cmdflag_top		<= afu_tlx_vc3_cmdflag;
   afu_tlx_vc3_pasid_top		<= afu_tlx_vc3_pasid;
   afu_tlx_vc3_bdf_top			<= afu_tlx_vc3_bdf;
   afu_tlx_vc3_mad_top			<= afu_tlx_vc3_mad;
   afu_tlx_dcp3_data_valid_top		<= afu_tlx_dcp3_data_valid;
   afu_tlx_dcp3_data_bus_top		<= afu_tlx_dcp3_data_bus;
   afu_tlx_dcp3_data_bdi_top		<= afu_tlx_dcp3_data_bdi;
  end

    assign 	reset_n			= !reset;
   
// Pass Through Signals
   assign tlx_afu_vc0_valid            	= tlx_afu_vc0_valid_top;
   assign tlx_afu_vc0_opcode           	= tlx_afu_vc0_opcode_top;
   assign tlx_afu_vc0_afutag           	= tlx_afu_vc0_afutag_top;
   assign tlx_afu_vc0_capptag          	= tlx_afu_vc0_capptag_top;
   assign tlx_afu_vc0_pa_or_ta         	= tlx_afu_vc0_pa_or_ta_top;
   assign tlx_afu_vc0_dl               	= tlx_afu_vc0_dl_top;
   assign tlx_afu_vc0_dp               	= tlx_afu_vc0_dp_top;
   assign tlx_afu_vc0_ef               	= tlx_afu_vc0_ef_top;
   assign tlx_afu_vc0_w                	= tlx_afu_vc0_w_top;
   assign tlx_afu_vc0_mh               	= tlx_afu_vc0_mh_top;
   assign tlx_afu_vc0_pg_size          	= tlx_afu_vc0_pg_size_top;
   assign tlx_afu_vc0_host_tag         	= tlx_afu_vc0_host_tag_top;
   assign tlx_afu_vc0_resp_code        	= tlx_afu_vc0_resp_code_top;
   assign tlx_afu_vc0_cache_state      	= tlx_afu_vc0_cache_state_top;

   assign tlx_afu_dcp0_data_valid      	= tlx_afu_dcp0_data_valid_top;
   assign tlx_afu_dcp0_data_bus      	= tlx_afu_dcp0_data_bus_top;
   assign tlx_afu_dcp0_data_bdi      	= tlx_afu_dcp0_data_bdi_top;

   assign tlx_afu_vc1_valid            	= tlx_afu_vc1_valid_top;
   assign tlx_afu_vc1_opcode           	= tlx_afu_vc1_opcode_top;
   assign tlx_afu_vc1_afutag           	= tlx_afu_vc1_afutag_top;
   assign tlx_afu_vc1_capptag          	= tlx_afu_vc1_capptag_top;
   assign tlx_afu_vc1_pa               	= tlx_afu_vc1_pa_top;
   assign tlx_afu_vc1_dl               	= tlx_afu_vc1_dl_top;
   assign tlx_afu_vc1_dp               	= tlx_afu_vc1_dp_top;
   assign tlx_afu_vc1_be               	= tlx_afu_vc1_be_top;
   assign tlx_afu_vc1_pl               	= tlx_afu_vc1_pl_top;
   assign tlx_afu_vc1_endian            = tlx_afu_vc1_endian_top;
   assign tlx_afu_vc1_co               	= tlx_afu_vc1_co_top;
   assign tlx_afu_vc1_os               	= tlx_afu_vc1_os_top;
   assign tlx_afu_vc1_cmdflag           = tlx_afu_vc1_cmdflag_top;
   assign tlx_afu_vc1_mad               = tlx_afu_vc1_mad_top;

   assign tlx_afu_dcp1_data_valid      	= tlx_afu_dcp1_data_valid_top;
   assign tlx_afu_dcp1_data_bus      	= tlx_afu_dcp1_data_bus_top;
   assign tlx_afu_dcp1_data_bdi      	= tlx_afu_dcp1_data_bdi_top;

   assign tlx_afu_vc2_valid            	= tlx_afu_vc2_valid_top;
   assign tlx_afu_vc2_opcode           	= tlx_afu_vc2_opcode_top;
   assign tlx_afu_vc2_capptag           = tlx_afu_vc2_capptag_top;
   assign tlx_afu_vc2_ea           	= tlx_afu_vc2_ea_top;
   assign tlx_afu_vc2_pg_size           = tlx_afu_vc2_pg_size_top;
   assign tlx_afu_vc2_cmdflag           = tlx_afu_vc2_cmdflag_top;
   assign tlx_afu_vc2_pasid           	= tlx_afu_vc2_pasid_top;
   assign tlx_afu_vc2_bdf           	= tlx_afu_vc2_bdf_top;

   assign tlx_afu_vc0_initial_credit    = tlx_afu_vc0_initial_credit_top;
   assign tlx_afu_dcp0_initial_credit   = tlx_afu_dcp0_initial_credit_top;
   assign tlx_afu_vc0_credit            = tlx_afu_vc0_credit_top;
   assign tlx_afu_dcp0_credit           = tlx_afu_dcp0_credit_top;

   assign tlx_afu_vc1_initial_credit    = tlx_afu_vc1_initial_credit_top;
   assign tlx_afu_vc1_credit            = tlx_afu_vc1_credit_top;

   assign tlx_afu_vc2_initial_credit    = tlx_afu_vc2_initial_credit_top;
   assign tlx_afu_dcp2_initial_credit   = tlx_afu_dcp2_initial_credit_top;
   assign tlx_afu_vc2_credit            = tlx_afu_vc2_credit_top;
   assign tlx_afu_dcp2_credit           = tlx_afu_dcp2_credit_top;

   assign tlx_afu_vc3_initial_credit    = tlx_afu_vc3_initial_credit_top;
   assign tlx_afu_dcp3_initial_credit   = tlx_afu_dcp3_initial_credit_top;
   assign tlx_afu_vc3_credit            = tlx_afu_vc3_credit_top;
   assign tlx_afu_dcp3_credit           = tlx_afu_dcp3_credit_top;

   always @( negedge tlx_clock ) begin
      tlx_afu_resp_data_valid		<= tlx_afu_resp_data_valid_dly1;
      tlx_afu_resp_data_bus		<= tlx_afu_resp_data_bus_dly1;
      tlx_afu_resp_data_bdi		<= tlx_afu_resp_data_bdi_dly1;
   end

//	Table 6: TLX to AFU Command Data Interface
    assign 	tlx_afu_cmd_data_valid		= tlx_afu_cmd_data_valid_top;
    assign 	tlx_afu_cmd_data_bus		= tlx_afu_cmd_data_bus_top;
    assign 	tlx_afu_cmd_data_bdi		= tlx_afu_cmd_data_bdi_top;

//	Table 7: TLX Framer credit interface
    assign 	tlx_afu_resp_credit			= tlx_afu_resp_credit_top;
    assign 	tlx_afu_resp_data_credit		= tlx_afu_resp_data_credit_top;
    assign 	tlx_afu_cmd_credit			= tlx_afu_cmd_credit_top;
    assign 	tlx_afu_cmd_data_credit			= tlx_afu_cmd_data_credit_top;
    assign 	tlx_afu_cmd_initial_credit		= tlx_afu_cmd_resp_initial_credit_top;
    assign 	tlx_afu_resp_initial_credit		= tlx_afu_data_initial_credit_top;
    assign 	tlx_afu_cmd_data_initial_credit		= tlx_afu_cmd_data_initial_credit_top;
    assign 	tlx_afu_resp_data_initial_credit	= tlx_afu_resp_data_initial_credit_top;

    assign 	tlx_afu_ready				= tlx_afu_ready_top;
    assign 	ro_device				= ro_device_top;
    assign 	tlx_cfg0_in_rcv_tmpl_capability_0	= tlx_cfg_rcv_tmpl_capability_0_top;
    assign 	tlx_cfg0_in_rcv_tmpl_capability_1	= tlx_cfg_rcv_tmpl_capability_1_top;
    assign 	tlx_cfg0_in_rcv_tmpl_capability_2	= tlx_cfg_rcv_tmpl_capability_2_top;
    assign 	tlx_cfg0_in_rcv_tmpl_capability_3	= tlx_cfg_rcv_tmpl_capability_3_top;
    assign 	tlx_cfg0_in_rcv_rate_capability_0	= tlx_cfg_rcv_rate_capability_0_top;
    assign 	tlx_cfg0_in_rcv_rate_capability_1	= tlx_cfg_rcv_rate_capability_1_top;
    assign 	tlx_cfg0_in_rcv_rate_capability_2	= tlx_cfg_rcv_rate_capability_2_top;
    assign 	tlx_cfg0_in_rcv_rate_capability_3	= tlx_cfg_rcv_rate_capability_3_top;
    assign	tlx_cfg0_valid				= tlx_cfg_valid_top;
    assign 	tlx_cfg0_opcode				= tlx_cfg_opcode_top;
    assign 	tlx_cfg0_pa				= tlx_cfg_pa_top;
    assign 	tlx_cfg0_t				= tlx_cfg_t_top;
    assign 	tlx_cfg0_pl				= tlx_cfg_pl_top;
    assign 	tlx_cfg0_capptag			= tlx_cfg_capptag_top;
    assign 	tlx_cfg0_data_bus			= tlx_cfg_data_bus_top;
    assign 	tlx_cfg0_data_bdi			= tlx_cfg_data_bdi_top;
    assign 	tlx_cfg0_resp_ack			= tlx_cfg_resp_ack_top;
    assign 	ro_dlx0_version				= 32'b0;
    assign 	tlx0_cfg_oc4_tlx_version		= 32'b0;
    assign 	flsh_cfg_rdata				= 32'b0;
    assign 	flsh_cfg_done				= 1'b0;
    assign 	flsh_cfg_status				= 8'b0;
    assign 	flsh_cfg_bresp				= 2'b0;
    assign 	flsh_cfg_rresp				= 2'b0;

   // a block to delay the resp_data path 1 cycle
   // todo: variable number of cycles from 1 to n
   always @ ( negedge tlx_clock ) begin
      tlx_afu_resp_data_valid_dly1 <= tlx_afu_dcp0_data_valid_top;	// DCP0 is the old Resp Data
      tlx_afu_resp_data_bus_dly1 <= tlx_afu_resp_data_bus_top;
      tlx_afu_resp_data_bdi_dly1 <= tlx_afu_resp_data_bdi_top;
   end

   always @ ( negedge tlx_clock ) begin
      tlx_afu_resp_data_valid_dly2 <= tlx_afu_resp_data_valid_dly1;
      tlx_afu_resp_data_bus_dly2 <= tlx_afu_resp_data_bus_dly1;
      tlx_afu_resp_data_bdi_dly2 <= tlx_afu_resp_data_bdi_dly1;
   end

  always @ ( tlx_clock ) begin
    simulationTime = $time;
    #0 set_simulation_time(simulationTime);
    #0 tlx_bfm( tlx_clock,
             afu_clock,
             reset,
        // Table 2: TLX to AFU VCO Interface
	afu_tlx_vc0_initial_credit_top,
	afu_tlx_vc0_credit_top,
	tlx_afu_vc0_valid_top,
	tlx_afu_vc0_opcode_top,
	tlx_afu_vc0_afutag_top,
	tlx_afu_vc0_capptag_top,
	tlx_afu_vc0_pa_or_ta_top,	// Address 63:12
	tlx_afu_vc0_dl_top,
	tlx_afu_vc0_dp_top,
	tlx_afu_vc0_ef_top,
	tlx_afu_vc0_w_top,
	tlx_afu_vc0_mh_top,
	tlx_afu_vc0_pg_size_top,
	tlx_afu_vc0_host_tag_top,
	tlx_afu_vc0_resp_code_top,
	tlx_afu_vc0_cache_state_top,
        //	Table 3: TLX to AFU DCP0 Data Interface
        afu_tlx_dcp0_rd_req_top,
        afu_tlx_dcp0_rd_cnt_top,
        tlx_afu_dcp0_data_valid_top,
        tlx_afu_dcp0_data_bus_top,
        tlx_afu_dcp0_data_bdi_top,
	//	Table 4: TLX to AFU VC1 Interface
	afu_tlx_vc1_initial_credit_top,
	afu_tlx_vc1_credit_top,
	tlx_afu_vc1_valid_top,
	tlx_afu_vc1_opcode_top,
	tlx_afu_vc1_afutag_top,
	tlx_afu_vc1_capptag_top,
	tlx_afu_vc1_pa_top,
	tlx_afu_vc1_dl_top,
	tlx_afu_vc1_dp_top,
	tlx_afu_vc1_be_top,
	tlx_afu_vc1_pl_top,
	tlx_afu_vc1_endian_top,
	tlx_afu_vc1_co_top,
	tlx_afu_vc1_os_top,
	tlx_afu_vc1_cmdflag_top,
	tlx_afu_vc1_mad_top,
	//	Table 5: TLX to AFU DCP1 Data Interface
	afu_tlx_dcp1_rd_req_top,
	afu_tlx_dcp1_rd_cnt_top,
	tlx_afu_dcp1_data_valid_top,
	tlx_afu_dcp1_data_bus_top,
	tlx_afu_dcp1_data_bdi_top,
	//	Table 6: TLX to AFU VC2 Interface
	afu_tlx_vc2_initial_credit_top,
	afu_tlx_vc2_credit_top,
	tlx_afu_vc2_valid_top,
	tlx_afu_vc2_opcode_top,
	tlx_afu_vc2_capptag_top,
	tlx_afu_vc2_ea_top,	// Address 63:12
	tlx_afu_vc2_pg_size_top,
	tlx_afu_vc2_cmdflag_top,
	tlx_afu_vc2_pasid_top,
	tlx_afu_vc2_bdf_top,
	//	Table 7: TLX to CFG Interface for Configuration Commands
	cfg_tlx_initial_credit_top,
	cfg_tlx_credit_return_top,
	tlx_cfg_valid_top,
	tlx_cfg_opcode_top,
	tlx_cfg_capptag_top,
	tlx_cfg_pa_top,
	tlx_cfg_pl_top,
	tlx_cfg_t_top,
	tlx_cfg_data_bus_top,
	tlx_cfg_data_bdi_top,
	//	Table 8: TLX Receiver - Template Configuration Ports
    	tlx_cfg_rcv_tmpl_capability_0_top,
    	tlx_cfg_rcv_tmpl_capability_1_top,
    	tlx_cfg_rcv_tmpl_capability_2_top,
    	tlx_cfg_rcv_tmpl_capability_3_top,
    	tlx_cfg_rcv_rate_capability_0_top,
    	tlx_cfg_rcv_rate_capability_1_top,
    	tlx_cfg_rcv_rate_capability_2_top,
    	tlx_cfg_rcv_rate_capability_3_top,
	cfg_tlx_resync_credits_top,
	//	Table 9: TLX Credit Interfac
	//	Table 10: TL Credit Interface
	//	Table 11: TLX Receiver - Miscellaneous Ports
    	tlx_afu_ready_top,
	//	Table 12: TLX Framer - Miscellaneous Ports
	//	Table 13: TLX Framer - AFU to TLX  AP  Configuration Response Interface (VCO, DCP0)
	cfg_tlx_resp_valid_top,
	cfg_tlx_resp_opcode_top,
	cfg_tlx_resp_capptag_top,
	cfg_tlx_resp_code_top,
	cfg_tlx_rdata_offset_top,
	cfg_tlx_rdata_bus_top,
	cfg_tlx_rdata_bdi_top,
    	tlx_cfg_resp_ack_top,
	//	Table 14: TLX Framer - AFU to TLX  VC0/DCP0 Interface
    	tlx_afu_vc0_initial_credit_top,
    	tlx_afu_dcp0_initial_credit_top,
    	tlx_afu_vc0_credit_top,
    	tlx_afu_dcp0_credit_top,
	afu_tlx_vc0_valid_top,
	afu_tlx_vc0_opcode_top,
	afu_tlx_vc0_capptag_top,
	afu_tlx_vc0_dl_top,
	afu_tlx_vc0_dp_top,
	afu_tlx_vc0_resp_code_top,
	afu_tlx_dcp0_data_valid_top,
	afu_tlx_dcp0_data_bus_top,
	afu_tlx_dcp0_data_bdi_top,

	//	Table 15: TLX Framer - AFU to TLX  VC1 Interface
    	tlx_afu_vc1_initial_credit_top,
    	tlx_afu_vc1_credit_top,
	afu_tlx_vc1_valid_top,
	afu_tlx_vc1_opcode_top,
	afu_tlx_vc1_stream_id_top,
	afu_tlx_vc1_afutag_top,
	afu_tlx_vc1_pa_top,	// afu_tlx_vc1_pa[63:6]
	afu_tlx_vc1_dl_top,

	//	Table 16: AFU to TLX  VC2/DCP2 Interface
    	tlx_afu_vc2_initial_credit_top,
    	tlx_afu_dcp2_initial_credit_top,
    	tlx_afu_vc2_credit_top,
    	tlx_afu_dcp2_credit_top,
	afu_tlx_vc2_valid_top,
	afu_tlx_vc2_opcode_top,
	afu_tlx_vc2_dl_top,
	afu_tlx_vc2_host_tag_top,
	afu_tlx_vc2_cache_state_top,
	afu_tlx_vc2_cmdflag_top,
	afu_tlx_dcp2_data_valid_top,
	afu_tlx_dcp2_data_bus_top,
	afu_tlx_dcp2_data_bdi_top,

	//	Table 17: TLX Framer - AFU to TLX  VC3/DCP3 Interface
    	tlx_afu_vc3_initial_credit_top,
    	tlx_afu_dcp3_initial_credit_top,
    	tlx_afu_vc3_credit_top,
    	tlx_afu_dcp3_credit_top,
	afu_tlx_vc3_valid_top,
	afu_tlx_vc3_opcode_top,
	afu_tlx_vc3_stream_id_top,
	afu_tlx_vc3_afutag_top,
	afu_tlx_vc3_actag_top,
	afu_tlx_vc3_ea_ta_or_obj_top,
	afu_tlx_vc3_dl_top,
	afu_tlx_vc3_be_top,
	afu_tlx_vc3_pl_top,
	afu_tlx_vc3_os_top,
	afu_tlx_vc3_endian_top,
	afu_tlx_vc3_pg_size_top,
	afu_tlx_vc3_cmdflag_top,
	afu_tlx_vc3_pasid_top,
	afu_tlx_vc3_bdf_top,
	afu_tlx_vc3_mad_top,
	afu_tlx_dcp3_data_valid_top,
	afu_tlx_dcp3_data_bus_top,
	afu_tlx_dcp3_data_bdi_top
    );
  end

  always @ (negedge tlx_clock) begin
    #0 get_simuation_error(simulationError);
  end

  always @ (posedge tlx_clock) begin
    if(simulationError)
      $finish;
  end

  atc4_device a0 (
  // -- Clocks
    .clock_tlx				(tlx_clock),
    .clock_afu				(afu_clock),
  // -- Reset
    .reset_n				(reset_n),
  // -- Freeze
    .xxx_atc_freeze			(1'b0),
    .atc_xxx_freeze			(),
  // -- Simulation Idle
    .sim_idle_device			(),
  // -- Device/Function/Port
    .ro_device				(ro_device),
    .ro_dlx0_version                    (ro_dlx0_version),	// Connect to DLX output at next level, or tie off to all 0s
    .tlx0_cfg_oc4_tlx_version           (tlx0_cfg_oc4_tlx_version),	// (was ro_tlx0_version[31:0])
    // =====================================================================
    // TLX 4.0 Interface
    // Connect these ports to the AFU interface ports of an OpenCAPI 4.0 TLX
    // =====================================================================
    .tlx_afu_ready                    	(tlx_afu_ready),	// When 1, TLX is ready to receive both commands and responses from the AFU
    // VC0 interface to AFU [Responses from Host to AFU, for AFU to Host commands]
    .afu_tlx_vc0_initial_credit         (afu_tlx_vc0_initial_credit),
    .afu_tlx_vc0_credit               	(afu_tlx_vc0_credit),
    .tlx_afu_vc0_valid               	(tlx_afu_vc0_valid),
    .tlx_afu_vc0_opcode               	(tlx_afu_vc0_opcode),
    .tlx_afu_vc0_afutag               	(tlx_afu_vc0_afutag),
    .tlx_afu_vc0_capptag               	(tlx_afu_vc0_capptag),
    .tlx_afu_vc0_pa_or_ta               (tlx_afu_vc0_pa_or_ta),
    .tlx_afu_vc0_dl               	(tlx_afu_vc0_dl),
    .tlx_afu_vc0_dp               	(tlx_afu_vc0_dp),
    .tlx_afu_vc0_ef               	(tlx_afu_vc0_ef),
    .tlx_afu_vc0_w               	(tlx_afu_vc0_w),
    .tlx_afu_vc0_mh               	(tlx_afu_vc0_mh),
    .tlx_afu_vc0_pg_size               	(tlx_afu_vc0_pg_size),
    .tlx_afu_vc0_host_tag               (tlx_afu_vc0_host_tag),
    .tlx_afu_vc0_resp_code              (tlx_afu_vc0_resp_code),
    .tlx_afu_vc0_cache_state            (tlx_afu_vc0_cache_state),
        // DCP0 data interface to AFU [Response data from Host to AFU, for AFU to Host commands]
    .afu_tlx_dcp0_rd_req               	(afu_tlx_dcp0_rd_req),
    .afu_tlx_dcp0_rd_cnt               	(afu_tlx_dcp0_rd_cnt),
    .tlx_afu_dcp0_data_valid            (tlx_afu_dcp0_data_valid),
    .tlx_afu_dcp0_data_bdi              (tlx_afu_dcp0_data_bdi),
    .tlx_afu_dcp0_data_bus              (tlx_afu_dcp0_data_bus),
        // VC1 interface to AFU [CAPP Commands from Host to AFU]
    .afu_tlx_vc1_initial_credit         (afu_tlx_vc1_initial_credit),
    .afu_tlx_vc1_credit               	(afu_tlx_vc1_credit),
    .tlx_afu_vc1_valid               	(tlx_afu_vc1_valid),
    .tlx_afu_vc1_opcode               	(tlx_afu_vc1_opcode),
    .tlx_afu_vc1_afutag               	(tlx_afu_vc1_afutag),
    .tlx_afu_vc1_capptag               	(tlx_afu_vc1_capptag),
    .tlx_afu_vc1_pa               	(tlx_afu_vc1_pa),
    .tlx_afu_vc1_dl               	(tlx_afu_vc1_dl),
    .tlx_afu_vc1_dp               	(tlx_afu_vc1_dp),
    .tlx_afu_vc1_be               	(tlx_afu_vc1_be),
    .tlx_afu_vc1_pl               	(tlx_afu_vc1_pl),
    .tlx_afu_vc1_endian               	(tlx_afu_vc1_endian),
    .tlx_afu_vc1_co               	(tlx_afu_vc1_co),
    .tlx_afu_vc1_os               	(tlx_afu_vc1_os),
    .tlx_afu_vc1_cmdflag               	(tlx_afu_vc1_cmdflag),
    .tlx_afu_vc1_mad               	(tlx_afu_vc1_mad),
        // DCP1 data interface to AFU [CAPP Command data from Host to AFU]
    .afu_tlx_dcp1_rd_req               	(afu_tlx_dcp1_rd_req),
    .afu_tlx_dcp1_rd_cnt               	(afu_tlx_dcp1_rd_cnt),
    .tlx_afu_dcp1_data_valid            (tlx_afu_dcp1_data_valid),
    .tlx_afu_dcp1_data_bdi              (tlx_afu_dcp1_data_bdi),
    .tlx_afu_dcp1_data_bus              (tlx_afu_dcp1_data_bus),
        // VC2 interface to AFU [TL 4.0 CAPP commands - kill_xlate, disable_cache, enable_cache, disable_atc, enable_atc]
    .afu_tlx_vc2_initial_credit         (afu_tlx_vc2_initial_credit),
    .afu_tlx_vc2_credit               	(afu_tlx_vc2_credit),
    .tlx_afu_vc2_valid               	(tlx_afu_vc2_valid),
    .tlx_afu_vc2_opcode               	(tlx_afu_vc2_opcode),
    .tlx_afu_vc2_capptag               	(tlx_afu_vc2_capptag),
    .tlx_afu_vc2_ea               	(tlx_afu_vc2_ea),
    .tlx_afu_vc2_pg_size               	(tlx_afu_vc2_pg_size),
    .tlx_afu_vc2_pasid               	(tlx_afu_vc2_pasid),
    .tlx_afu_vc2_bdf               	(tlx_afu_vc2_bdf),
    .tlx_afu_vc2_cmdflag               	(tlx_afu_vc2_cmdflag),
        // -----------------------------------
        // AFU to TLX Framer Transmit Interface
        // -----------------------------------
        // --- VC0 interface from AFU [Responses from AFU to Host, for Host to AFU commands]
    .tlx_afu_vc0_initial_credit         (tlx_afu_vc0_initial_credit),
    .tlx_afu_vc0_credit               	(tlx_afu_vc0_credit),
    .afu_tlx_vc0_valid               	(afu_tlx_vc0_valid),
    .afu_tlx_vc0_opcode               	(afu_tlx_vc0_opcode),
    .afu_tlx_vc0_capptag               	(afu_tlx_vc0_capptag),
    .afu_tlx_vc0_dl               	(afu_tlx_vc0_dl),
    .afu_tlx_vc0_dp               	(afu_tlx_vc0_dp),
    .afu_tlx_vc0_resp_code              (afu_tlx_vc0_resp_code),
        // --- DCP0 interface from AFU [Response data from AFU to Host, for Host to AFU commands]
    .tlx_afu_dcp0_initial_credit        (tlx_afu_dcp0_initial_credit),
    .tlx_afu_dcp0_credit               	(tlx_afu_dcp0_credit),
    .afu_tlx_dcp0_data_valid            (afu_tlx_dcp0_data_valid),
    .afu_tlx_dcp0_data_bus              (afu_tlx_dcp0_data_bus),
    .afu_tlx_dcp0_data_bdi              (afu_tlx_dcp0_data_bdi),
        // --- VC1 interface from AFU [AP 4.0 Commands from AFU to Host - mem_pa_flush]
    .tlx_afu_vc1_initial_credit         (tlx_afu_vc1_initial_credit),
    .tlx_afu_vc1_credit               	(tlx_afu_vc1_credit),
    .afu_tlx_vc1_valid               	(afu_tlx_vc1_valid),
    .afu_tlx_vc1_opcode               	(afu_tlx_vc1_opcode),
    .afu_tlx_vc1_stream_id              (afu_tlx_vc1_stream_id),
    .afu_tlx_vc1_afutag               	(afu_tlx_vc1_afutag),
    .afu_tlx_vc1_pa               	(afu_tlx_vc1_pa),
    .afu_tlx_vc1_dl               	(afu_tlx_vc1_dl),
        // --- VC2 interface from AFU [AP 4.0 Commands from AFU to Host - synonym_done, castout, castout.push]
    .tlx_afu_vc2_initial_credit         (tlx_afu_vc2_initial_credit),
    .tlx_afu_vc2_credit               	(tlx_afu_vc2_credit),
    .afu_tlx_vc2_valid               	(afu_tlx_vc2_valid),
    .afu_tlx_vc2_opcode               	(afu_tlx_vc2_opcode),
    .afu_tlx_vc2_dl               	(afu_tlx_vc2_dl),
    .afu_tlx_vc2_host_tag               (afu_tlx_vc2_host_tag),
    .afu_tlx_vc2_cache_state            (afu_tlx_vc2_cache_state),
    .afu_tlx_vc2_cmdflag               	(afu_tlx_vc2_cmdflag),
        // --- DCP2 interface from AFU [AP Command data from AFU to Host - castout.push]
    .tlx_afu_dcp2_initial_credit        (tlx_afu_dcp2_initial_credit),
    .tlx_afu_dcp2_credit               	(tlx_afu_dcp2_credit),
    .afu_tlx_dcp2_data_valid            (afu_tlx_dcp2_data_valid),
    .afu_tlx_dcp2_data_bus              (afu_tlx_dcp2_data_bus),
    .afu_tlx_dcp2_data_bdi              (afu_tlx_dcp2_data_bdi),
        // --- VC3 interface from AFU [AP Commands from AFU to Host - original cmds]
    .tlx_afu_vc3_initial_credit         (tlx_afu_vc3_initial_credit),
    .tlx_afu_vc3_credit               	(tlx_afu_vc3_credit),
    .afu_tlx_vc3_valid               	(afu_tlx_vc3_valid),
    .afu_tlx_vc3_opcode               	(afu_tlx_vc3_opcode),
    .afu_tlx_vc3_stream_id              (afu_tlx_vc3_stream_id),
    .afu_tlx_vc3_afutag               	(afu_tlx_vc3_afutag),
    .afu_tlx_vc3_actag               	(afu_tlx_vc3_actag),
    .afu_tlx_vc3_ea_ta_or_obj           (afu_tlx_vc3_ea_ta_or_obj),
    .afu_tlx_vc3_dl               	(afu_tlx_vc3_dl),
    .afu_tlx_vc3_be               	(afu_tlx_vc3_be),
    .afu_tlx_vc3_pl               	(afu_tlx_vc3_pl),
    .afu_tlx_vc3_os               	(afu_tlx_vc3_os),
    .afu_tlx_vc3_endian               	(afu_tlx_vc3_endian),
    .afu_tlx_vc3_pg_size               	(afu_tlx_vc3_pg_size),
    .afu_tlx_vc3_cmdflag               	(afu_tlx_vc3_cmdflag),
    .afu_tlx_vc3_pasid               	(afu_tlx_vc3_pasid),
    .afu_tlx_vc3_bdf               	(afu_tlx_vc3_bdf),
    .afu_tlx_vc3_mad               	(afu_tlx_vc3_mad),
    .afu_tlx_vc3_capptag               	(),	// o/p left open since afu_driver is not looking for this yet
    .afu_tlx_vc3_resp_code              (),	// o/p left open since afu_driver is not looking for this yet
        // --- DCP3 interface from AFU [AP Command Data from AFU to Host - original cmds]
    .tlx_afu_dcp3_initial_credit        (tlx_afu_dcp3_initial_credit),
    .tlx_afu_dcp3_credit               	(tlx_afu_dcp3_credit),
    .afu_tlx_dcp3_data_valid            (afu_tlx_dcp3_data_valid),
    .afu_tlx_dcp3_data_bus              (afu_tlx_dcp3_data_bus),
    .afu_tlx_dcp3_data_bdi              (afu_tlx_dcp3_data_bdi),
        // -----------------------------------
        // Configuration Ports
        // -----------------------------------
    // Configuration Ports: Drive Configuration (determined by software)
    .cfg0_tlx_xmit_tmpl_config_0        (cfg0_tlx_xmit_tmpl_config_0),
    .cfg0_tlx_xmit_tmpl_config_1        (cfg0_tlx_xmit_tmpl_config_1),
    .cfg0_tlx_xmit_tmpl_config_2        (cfg0_tlx_xmit_tmpl_config_2),
    .cfg0_tlx_xmit_tmpl_config_3        (cfg0_tlx_xmit_tmpl_config_3),
    .cfg0_tlx_xmit_rate_config_0        (cfg0_tlx_xmit_rate_config_0),
    .cfg0_tlx_xmit_rate_config_1        (cfg0_tlx_xmit_rate_config_1),
    .cfg0_tlx_xmit_rate_config_2        (cfg0_tlx_xmit_rate_config_2),
    .cfg0_tlx_xmit_rate_config_3        (cfg0_tlx_xmit_rate_config_3),
    .tlx_cfg0_rcv_tmpl_capability_0     (tlx_cfg0_rcv_tmpl_capability_0),
    .tlx_cfg0_rcv_tmpl_capability_1     (tlx_cfg0_rcv_tmpl_capability_1),
    .tlx_cfg0_rcv_tmpl_capability_2     (tlx_cfg0_rcv_tmpl_capability_2),
    .tlx_cfg0_rcv_tmpl_capability_3     (tlx_cfg0_rcv_tmpl_capability_3),
    .tlx_cfg0_rcv_rate_capability_0     (tlx_cfg0_rcv_rate_capability_0),
    .tlx_cfg0_rcv_rate_capability_1     (tlx_cfg0_rcv_rate_capability_1),
    .tlx_cfg0_rcv_rate_capability_2     (tlx_cfg0_rcv_rate_capability_2),
    .tlx_cfg0_rcv_rate_capability_3     (tlx_cfg0_rcv_rate_capability_3),
    .cfg0_tlx_resync_credits            (cfg0_tlx_resync_credits),
    // ---------------------------
    // Config_* command interfaces
    // ---------------------------
    // Port 0: config_write/read commands from host    
    .tlx_cfg0_valid               	(tlx_cfg0_valid),
    .tlx_cfg0_opcode               	(tlx_cfg0_opcode),
    .tlx_cfg0_pa               		(tlx_cfg0_pa),
    .tlx_cfg0_t               		(tlx_cfg0_t),
    .tlx_cfg0_pl               		(tlx_cfg0_pl),
    .tlx_cfg0_capptag               	(tlx_cfg0_capptag),
    .tlx_cfg0_data_bus               	(tlx_cfg0_data_bus),
    .tlx_cfg0_data_bdi               	(tlx_cfg0_data_bdi),
    .cfg0_tlx_initial_credit            (cfg0_tlx_initial_credit),
    .cfg0_tlx_credit_return             (cfg0_tlx_credit_return),
    // Port 0: config_* responses back to host
    .cfg0_tlx_resp_valid               	(cfg0_tlx_resp_valid),
    .cfg0_tlx_resp_opcode               (cfg0_tlx_resp_opcode),
    .cfg0_tlx_resp_capptag              (cfg0_tlx_resp_capptag),
    .cfg0_tlx_resp_code               	(cfg0_tlx_resp_code),
    .cfg0_tlx_data_offset               (cfg0_tlx_data_offset),
    .cfg0_tlx_data_bus               	(cfg0_tlx_data_bus),
    .cfg0_tlx_data_bdi               	(cfg0_tlx_data_bdi),
    .tlx_cfg0_resp_ack               	(tlx_cfg0_resp_ack),
    // ------------------------------------
    // Configuration Space to TLX and AFU 
    // ------------------------------------
    
    // ------------------------------------
    // Configuration Space to VPD Interface
    // ------------------------------------
    .cfg_vpd_addr               	(cfg_vpd_addr),
    .cfg_vpd_wren               	(cfg_vpd_wren),
    .cfg_vpd_wdata               	(cfg_vpd_wdata),
    .cfg_vpd_rden               	(cfg_vpd_rden),
    .vpd_cfg_rdata               	(vpd_cfg_rdata),
    .vpd_cfg_done               	(vpd_cfg_done),
    .vpd_err_unimplemented_addr         (vpd_err_unimplemented_addr),
    // ------------------------------------
    // Configuration Space to FLASH Interface
    // ------------------------------------
    .cfg_flsh_devsel               	(cfg_flsh_devsel),
    .cfg_flsh_addr               	(cfg_flsh_addr),
    .cfg_flsh_wren               	(cfg_flsh_wren),
    .cfg_flsh_wdata               	(cfg_flsh_wdata),
    .cfg_flsh_rden               	(cfg_flsh_rden),
    .flsh_cfg_rdata               	(flsh_cfg_rdata),
    .flsh_cfg_done               	(flsh_cfg_done),
    .flsh_cfg_status               	(flsh_cfg_status),
    .flsh_cfg_bresp               	(flsh_cfg_bresp),
    .flsh_cfg_rresp               	(flsh_cfg_rresp),
    .cfg_flsh_expand_enable             (cfg_flsh_expand_enable),
    .cfg_flsh_expand_dir               	(cfg_flsh_expand_dir)
  );
/*
  oc4_bb bb0 (
   .afu_tlx_vc0_initial_credit_top       (afu_tlx_vc0_initial_credit_top),
   .afu_tlx_vc0_credit_top               (afu_tlx_vc0_credit_top),
   .tlx_afu_vc0_valid_top                (tlx_afu_vc0_valid_top),
   .tlx_afu_vc0_opcode_top               (tlx_afu_vc0_opcode_top),
   .tlx_afu_vc0_afutag_top               (tlx_afu_vc0_afutag_top),
   .tlx_afu_vc0_capptag_top              (tlx_afu_vc0_capptag_top),
   .tlx_afu_vc0_pa_or_ta_top             (tlx_afu_vc0_pa_or_ta_top),
   .tlx_afu_vc0_dl_top                   (tlx_afu_vc0_dl_top),
   .tlx_afu_vc0_dp_top                   (tlx_afu_vc0_dp_top),
   .tlx_afu_vc0_ef_top                   (tlx_afu_vc0_ef_top),
   .tlx_afu_vc0_w_top                    (tlx_afu_vc0_w_top),
   .tlx_afu_vc0_mh_top                   (tlx_afu_vc0_mh_top),
   .tlx_afu_vc0_pg_size_top              (tlx_afu_vc0_pg_size_top),
   .tlx_afu_vc0_host_tag_top             (tlx_afu_vc0_host_tag_top),
   .tlx_afu_vc0_resp_code_top            (tlx_afu_vc0_resp_code_top),
   .tlx_afu_vc0_cache_state_top          (tlx_afu_vc0_cache_state_top),
   .afu_tlx_dcp0_rd_req_top              (afu_tlx_dcp0_rd_req_top),
   .afu_tlx_dcp0_rd_cnt_top              (afu_tlx_dcp0_rd_cnt_top),
   .tlx_afu_dcp0_data_valid_top          (tlx_afu_dcp0_data_valid_top),
   .tlx_afu_dcp0_data_bus_top            (tlx_afu_dcp0_data_bus_top),
   .tlx_afu_dcp0_data_bdi_top            (tlx_afu_dcp0_data_bdi_top),
   .tlx_afu_vc0_initial_credit_top       (tlx_afu_vc0_initial_credit_top),
   .tlx_afu_dcp0_initial_credit_top      (tlx_afu_dcp0_initial_credit_top),
   .tlx_afu_vc0_credit_top               (tlx_afu_vc0_credit_top),
   .tlx_afu_dcp0_credit_top              (tlx_afu_dcp0_credit_top),
   .afu_tlx_vc0_valid_top                (afu_tlx_vc0_valid_top),
   .afu_tlx_vc0_opcode_top               (afu_tlx_vc0_opcode_top),
   .afu_tlx_vc0_capptag_top              (afu_tlx_vc0_capptag_top),
   .afu_tlx_vc0_dl_top                   (afu_tlx_vc0_dl_top),
   .afu_tlx_vc0_dp_top                   (afu_tlx_vc0_dp_top),
   .afu_tlx_vc0_resp_code_top            (afu_tlx_vc0_resp_code_top),
   .afu_tlx_dcp0_data_valid_top          (afu_tlx_dcp0_data_valid_top),
   .afu_tlx_dcp0_data_bus_top            (afu_tlx_dcp0_data_bus_top),
   .afu_tlx_dcp0_data_bdi_top            (afu_tlx_dcp0_data_bdi_top),

   .afu_tlx_vc1_initial_credit_top       (afu_tlx_vc1_initial_credit_top),
   .afu_tlx_vc1_credit_top               (afu_tlx_vc1_credit_top),
   .tlx_afu_vc1_valid_top                (tlx_afu_vc1_valid_top),
   .tlx_afu_vc1_opcode_top               (tlx_afu_vc1_opcode_top),
   .tlx_afu_vc1_afutag_top               (tlx_afu_vc1_afutag_top),
   .tlx_afu_vc1_capptag_top              (tlx_afu_vc1_capptag_top),
   .tlx_afu_vc1_pa_top                   (tlx_afu_vc1_pa_top),
   .tlx_afu_vc1_dl_top                   (tlx_afu_vc1_dl_top),
   .tlx_afu_vc1_dp_top                   (tlx_afu_vc1_dp_top),
   .tlx_afu_vc1_be_top                   (tlx_afu_vc1_be_top),
   .tlx_afu_vc1_pl_top                   (tlx_afu_vc1_pl_top),
   .tlx_afu_vc1_endian_top               (tlx_afu_vc1_endian_top),
   .tlx_afu_vc1_co_top                   (tlx_afu_vc1_co_top),
   .tlx_afu_vc1_os_top                   (tlx_afu_vc1_os_top),
   .tlx_afu_vc1_cmdflag_top              (tlx_afu_vc1_cmdflag_top),
   .tlx_afu_vc1_mad_top                  (tlx_afu_vc1_mad_top),
   .afu_tlx_dcp1_rd_req_top              (afu_tlx_dcp1_rd_req_top),
   .afu_tlx_dcp1_rd_cnt_top              (afu_tlx_dcp1_rd_cnt_top),
   .tlx_afu_dcp1_data_valid_top          (tlx_afu_dcp1_data_valid_top),
   .tlx_afu_dcp1_data_bus_top            (tlx_afu_dcp1_data_bus_top),
   .tlx_afu_dcp1_data_bdi_top            (tlx_afu_dcp1_data_bdi_top),
   .tlx_afu_vc1_initial_credit_top       (tlx_afu_vc1_initial_credit_top),
   .afu_tlx_vc2_initial_credit_top       (afu_tlx_vc2_initial_credit_top),
   .afu_tlx_vc2_credit_top               (afu_tlx_vc2_credit_top),
   .tlx_afu_vc3_initial_credit_top       (tlx_afu_vc3_initial_credit_top),
   .tlx_afu_dcp3_initial_credit_top      (tlx_afu_dcp3_initial_credit_top),
   .tlx_afu_vc3_credit_top               (tlx_afu_vc3_credit_top),
   .tlx_afu_dcp3_credit_top              (tlx_afu_dcp3_credit_top),
   .afu_tlx_vc3_valid_top                (afu_tlx_vc3_valid_top),
   .afu_tlx_vc3_opcode_top               (afu_tlx_vc3_opcode_top),
   .afu_tlx_vc3_stream_id_top            (afu_tlx_vc3_stream_id_top),
   .afu_tlx_vc3_afutag_top               (afu_tlx_vc3_afutag_top),
   .afu_tlx_vc3_actag_top                (afu_tlx_vc3_actag_top),
   .afu_tlx_vc3_ea_ta_or_obj_top         (afu_tlx_vc3_ea_ta_or_obj_top),
   .afu_tlx_vc3_dl_top                   (afu_tlx_vc3_dl_top),
   .afu_tlx_vc3_be_top                   (afu_tlx_vc3_be_top),
   .afu_tlx_vc3_pl_top                   (afu_tlx_vc3_pl_top),
   .afu_tlx_vc3_os_top                   (afu_tlx_vc3_os_top),
   .afu_tlx_vc3_endian_top               (afu_tlx_vc3_endian_top),
   .afu_tlx_vc3_pg_size_top              (afu_tlx_vc3_pg_size_top),
   .afu_tlx_vc3_cmdflag_top              (afu_tlx_vc3_cmdflag_top),
   .afu_tlx_vc3_pasid_top                (afu_tlx_vc3_pasid_top),
   .afu_tlx_vc3_bdf_top                  (afu_tlx_vc3_bdf_top),
   .afu_tlx_vc3_mad_top                  (afu_tlx_vc3_mad_top),
   .afu_tlx_dcp3_data_valid_top          (afu_tlx_dcp3_data_valid_top),
   .afu_tlx_dcp3_data_bus_top            (afu_tlx_dcp3_data_bus_top),
   .afu_tlx_dcp3_data_bdi_top            (afu_tlx_dcp3_data_bdi_top),

   .afu_tlx_resp_initial_credit_top      (afu_tlx_resp_initial_credit_top),
   .afu_tlx_resp_credit_top              (afu_tlx_resp_credit_top),
   .tlx_afu_resp_valid_top               (tlx_afu_resp_valid_top),
   .tlx_afu_resp_opcode_top              (tlx_afu_resp_opcode_top),
   .tlx_afu_resp_afutag_top              (tlx_afu_resp_afutag_top),
   .tlx_afu_resp_code_top                (tlx_afu_resp_code_top),
   .tlx_afu_resp_pg_size_top             (tlx_afu_resp_pg_size_top),
   .tlx_afu_resp_dl_top                  (tlx_afu_resp_dl_top),
   .tlx_afu_resp_dp_top                  (tlx_afu_resp_dp_top),
   .tlx_afu_resp_host_tag_top            (tlx_afu_resp_host_tag_top),
   .tlx_afu_resp_addr_tag_top            (tlx_afu_resp_addr_tag_top),
   .tlx_afu_resp_cache_state_top         (tlx_afu_resp_cache_state_top),
   .afu_tlx_resp_rd_req_top              (afu_tlx_resp_rd_req_top),
   .afu_tlx_resp_rd_cnt_top              (afu_tlx_resp_rd_cnt_top),
   .tlx_afu_resp_data_valid_top          (tlx_afu_resp_data_valid_top),
   .tlx_afu_resp_data_bus_top            (tlx_afu_resp_data_bus_top),
   .tlx_afu_resp_data_bdi_top            (tlx_afu_resp_data_bdi_top),
   .tlx_afu_cmd_resp_initial_credit_top  (tlx_afu_cmd_resp_initial_credit_top),
   .tlx_afu_data_initial_credit_top      (tlx_afu_data_initial_credit_top),
   .tlx_afu_cmd_data_initial_credit_top  (tlx_afu_cmd_data_initial_credit_top),
   .tlx_afu_resp_data_initial_credit_top (tlx_afu_resp_data_initial_credit_top),
   .tlx_afu_resp_credit_top              (tlx_afu_resp_credit_top),
   .tlx_afu_resp_data_credit_top         (tlx_afu_resp_data_credit_top),
   .afu_tlx_resp_valid_top               (afu_tlx_resp_valid_top),
   .afu_tlx_resp_opcode_top              (afu_tlx_resp_opcode_top),
   .afu_tlx_resp_dl_top                  (afu_tlx_resp_dl_top),
   .afu_tlx_resp_capptag_top             (afu_tlx_resp_capptag_top),
   .afu_tlx_resp_dp_top                  (afu_tlx_resp_dp_top),
   .afu_tlx_resp_code_top                (afu_tlx_resp_code_top),
   .afu_tlx_rdata_valid_top              (afu_tlx_rdata_valid_top),
   .afu_tlx_rdata_bus_top                (afu_tlx_rdata_bus_top),
   .afu_tlx_rdata_bdi_top                (afu_tlx_rdata_bdi_top),
   .tlx_afu_cmd_valid_top                (tlx_afu_cmd_valid_top),
   .tlx_afu_cmd_opcode_top               (tlx_afu_cmd_opcode_top),
   .tlx_afu_cmd_capptag_top              (tlx_afu_cmd_capptag_top),
   .tlx_afu_cmd_dl_top                   (tlx_afu_cmd_dl_top),
   .tlx_afu_cmd_pl_top                   (tlx_afu_cmd_pl_top),
   .tlx_afu_cmd_be_top                   (tlx_afu_cmd_be_top),
   .tlx_afu_cmd_end_top                  (tlx_afu_cmd_end_top),
   .tlx_afu_cmd_pa_top                   (tlx_afu_cmd_pa_top),
   .tlx_afu_cmd_flag_top                 (tlx_afu_cmd_flag_top),
   .tlx_afu_cmd_os_top                   (tlx_afu_cmd_os_top),
   .afu_tlx_cmd_credit_top               (afu_tlx_cmd_credit_top),
   .afu_tlx_cmd_initial_credit_top       (afu_tlx_cmd_initial_credit_top),
   .afu_tlx_cmd_rd_req_top               (afu_tlx_cmd_rd_req_top),
   .afu_tlx_cmd_rd_cnt_top               (afu_tlx_cmd_rd_cnt_top),
   .tlx_afu_cmd_data_valid_top           (tlx_afu_cmd_data_valid_top),
   .tlx_afu_cmd_data_bus_top             (tlx_afu_cmd_data_bus_top),
   .tlx_afu_cmd_data_bdi_top             (tlx_afu_cmd_data_bdi_top),
   .tlx_afu_cmd_credit_top               (tlx_afu_cmd_credit_top),
   .tlx_afu_cmd_data_credit_top          (tlx_afu_cmd_data_credit_top),
   .afu_tlx_cmd_valid_top                (afu_tlx_cmd_valid_top),
   .afu_tlx_cmd_opcode_top               (afu_tlx_cmd_opcode_top),
   .afu_tlx_cmd_stream_id_top            (afu_tlx_cmd_stream_id_top),
   .afu_tlx_cmd_afutag_top               (afu_tlx_cmd_afutag_top),
   .afu_tlx_cmd_actag_top                (afu_tlx_cmd_actag_top),
   .afu_tlx_cmd_ea_or_obj_top            (afu_tlx_cmd_ea_or_obj_top),
   .afu_tlx_cmd_dl_top                   (afu_tlx_cmd_dl_top),
   .afu_tlx_cmd_be_top                   (afu_tlx_cmd_be_top),
   .afu_tlx_cmd_pl_top                   (afu_tlx_cmd_pl_top),
   .afu_tlx_cmd_os_top                   (afu_tlx_cmd_os_top),
   .afu_tlx_cmd_endian_top               (afu_tlx_cmd_endian_top),
   .afu_tlx_cmd_pg_size_top              (afu_tlx_cmd_pg_size_top),
   .afu_tlx_cmd_flag_top                 (afu_tlx_cmd_flag_top),
   .afu_tlx_cmd_pasid_top                (afu_tlx_cmd_pasid_top),
   .afu_tlx_cmd_bdf_top                  (afu_tlx_cmd_bdf_top),
   .afu_tlx_cdata_valid_top              (afu_tlx_cdata_valid_top),
   .afu_tlx_cdata_bus_top                (afu_tlx_cdata_bus_top),
   .afu_tlx_cdata_bdi_top                (afu_tlx_cdata_bdi_top)
  );
*/
endmodule
