//
// Copyright 2014 International Business Machines
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

module top (
  output          breakpoint
);

   import "DPI-C" function void tlx_bfm_init( );
   import "DPI-C" function void set_simulation_time(input [0:63] simulationTime);
   import "DPI-C" function void get_simuation_error(inout simulationError);
   import "DPI-C" function void tlx_bfm(
                                input ha_pclock,
				// Table 1: TLX to AFU Response Interface
				inout             tlx_afu_resp_valid,
				inout [7:0]       tlx_afu_resp_opcode,
				inout [15:0]      tlx_afu_resp_afutag,
				inout [3:0]       tlx_afu_resp_code,
				inout [5:0]       tlx_afu_resp_pg_size,
				inout [1:0]       tlx_afu_resp_dl,
				inout [1:0]       tlx_afu_resp_dp,
				inout [23:0]      tlx_afu_resp_host_tag,
				inout [17:0]      tlx_afu_resp_addr_tag,
				inout [3:0]       tlx_afu_resp_cache_state,

				//	Table 2: TLX Response Credit Interface
				input			afu_tlx_resp_credit,
				input	[6:0]		afu_tlx_resp_initial_credit,

				//	Table 3: TLX to AFU Command Interface
				inout             tlx_afu_cmd_valid,
				inout [7:0]       tlx_afu_cmd_opcode,
				inout [15:0]      tlx_afu_cmd_capptag,
				inout [1:0]       tlx_afu_cmd_dl,
				inout [2:0]       tlx_afu_cmd_pl,
				inout [63:0]      tlx_afu_cmd_be,
				inout             tlx_afu_cmd_end,
				inout             tlx_afu_cmd_t,
				inout [63:0]      tlx_afu_cmd_pa,
				inout [3:0]       tlx_afu_cmd_flag,
				inout             tlx_afu_cmd_os,

				//	Table 4: TLX Command Credit Interface
				input			afu_tlx_cmd_credit,
				input	[6:0]		afu_tlx_cmd_initial_credit,

				//	Table 5: TLX to AFU Response Data Interface
				inout             tlx_afu_resp_data_valid,
				inout [511:0]     tlx_afu_resp_data_bus,
				inout             tlx_afu_resp_data_bdi,
				input			afu_tlx_resp_rd_req,
				input	[2:0]		afu_tlx_resp_rd_cnt,

				//	Table 6: TLX to AFU Command Data Interface
				inout             tlx_afu_cmd_data_valid,
				inout [511:0]     tlx_afu_cmd_data_bus,
				inout             tlx_afu_cmd_data_bdi,
				input			afu_tlx_cmd_rd_req,
				input	[2:0]		afu_tlx_cmd_rd_cnt,

				//	Table 7: TLX Framer credit interface
				inout             tlx_afu_resp_credit,
				inout             tlx_afu_resp_data_credit,
				inout             tlx_afu_cmd_credit,
				inout             tlx_afu_cmd_data_credit,
				inout [2:0]       tlx_afu_cmd_resp_initial_credit,
				inout [4:0]       tlx_afu_data_initial_credit,

				//	Table 8: TLX Framer Command Interface
				input			afu_tlx_cmd_valid,
				input	[7:0]		afu_tlx_cmd_opcode,
				input	[11:0]		afu_tlx_cmd_actag,
				input	[3:0]		afu_tlx_cmd_stream_id,
				input	[67:0]		afu_tlx_cmd_ea_or_obj,
				input	[15:0]		afu_tlx_cmd_afutag,
				input	[1:0]		afu_tlx_cmd_dl,
				input	[2:0]		afu_tlx_cmd_pl,
				input			afu_tlx_cmd_os,
				input	[63:0]		afu_tlx_cmd_be,
				input	[3:0]		afu_tlx_cmd_flag,
				input			afu_tlx_cmd_endian,
				input	[15:0]		afu_tlx_cmd_bdf,
				input	[19:0]		afu_tlx_cmd_pasid,
				input	[5:0]		afu_tlx_cmd_pg_size,
				input	[511:0]		afu_tlx_cdata_bus,
				input			afu_tlx_cdata_bdi,// TODO: TLX Ref Design doc lists this as afu_tlx_cdata_bad
				input			afu_tlx_cdata_valid,

				//	Table 9: TLX Framer Response Interface
				input			afu_tlx_resp_valid,
				input  [7:0]		afu_tlx_resp_opcode,
				input  [1:0]		afu_tlx_resp_dl,
				input  [15:0]		afu_tlx_resp_capptag,
				input  [1:0]		afu_tlx_resp_dp,
				input  [3:0]		afu_tlx_resp_code,
				input			afu_tlx_rdata_valid,
				input  [511:0]		afu_tlx_rdata_bus,
				input			afu_tlx_rdata_bdi,

				// These signals do not appear on the RefDesign Doc. However it is present
				// on the TLX spec
				inout             afu_cfg_in_rcv_tmpl_capability_0,
				inout             afu_cfg_in_rcv_tmpl_capability_1,
				inout             afu_cfg_in_rcv_tmpl_capability_2,
				inout             afu_cfg_in_rcv_tmpl_capability_3,
				inout [3:0]       afu_cfg_in_rcv_rate_capability_0,
				inout [3:0]       afu_cfg_in_rcv_rate_capability_1,
				inout [3:0]       afu_cfg_in_rcv_rate_capability_2,
				inout [3:0]       afu_cfg_in_rcv_rate_capability_3,
				inout             tlx_afu_ready
                                       );
  
   reg             ha_pclock;
   reg             reset;
  // Table 1: TLX to AFU Response Interface
   reg             tlx_afu_resp_valid;
   reg [7:0]       tlx_afu_resp_opcode;
   reg [15:0]      tlx_afu_resp_afutag;
   reg [3:0]       tlx_afu_resp_code;
   reg [5:0]       tlx_afu_resp_pg_size;
   reg [1:0]       tlx_afu_resp_dl;
   reg [1:0]       tlx_afu_resp_dp;
   reg [23:0]      tlx_afu_resp_host_tag;
   reg [17:0]      tlx_afu_resp_addr_tag;
   reg [3:0]       tlx_afu_resp_cache_state;

//	Table 3: TLX to AFU Command Interface
   reg             tlx_afu_cmd_valid;
   reg [7:0]       tlx_afu_cmd_opcode;
   reg [15:0]      tlx_afu_cmd_capptag;
   reg [1:0]       tlx_afu_cmd_dl;
   reg [2:0]       tlx_afu_cmd_pl;
   reg [63:0]      tlx_afu_cmd_be;
   reg             tlx_afu_cmd_end;
   reg             tlx_afu_cmd_t;
   reg [63:0]      tlx_afu_cmd_pa;
   reg [3:0]       tlx_afu_cmd_flag;
   reg             tlx_afu_cmd_os;

//	Table 5: TLX to AFU Response Data Interface
   reg             tlx_afu_resp_data_valid;
   reg [511:0]     tlx_afu_resp_data_bus;
   reg             tlx_afu_resp_data_bdi;

//	Table 6: TLX to AFU Command Data Interface
   reg             tlx_afu_cmd_data_valid;
   reg [511:0]     tlx_afu_cmd_data_bus;
   reg             tlx_afu_cmd_data_bdi;

//	Table 7: TLX Framer credit interface
   reg             tlx_afu_resp_credit;
   reg             tlx_afu_resp_data_credit;
   reg             tlx_afu_cmd_credit;
   reg             tlx_afu_cmd_data_credit;
   reg [2:0]       tlx_afu_cmd_resp_initial_credit;
   reg [4:0]       tlx_afu_data_initial_credit;

  // These signals do not appear on the RefDesign Doc. However it is present
  // on the TLX spec
   reg             afu_cfg_in_rcv_tmpl_capability_0;
   reg             afu_cfg_in_rcv_tmpl_capability_1;
   reg             afu_cfg_in_rcv_tmpl_capability_2;
   reg             afu_cfg_in_rcv_tmpl_capability_3;
   reg [3:0]       afu_cfg_in_rcv_rate_capability_0;
   reg [3:0]       afu_cfg_in_rcv_rate_capability_1;
   reg [3:0]       afu_cfg_in_rcv_rate_capability_2;
   reg [3:0]       afu_cfg_in_rcv_rate_capability_3;
   reg             tlx_afu_ready;
 // Wires for AFU o/p
//	Table 2: TLX Response Credit Interface
   wire			afu_tlx_resp_credit               ;
   wire	[6:0]		afu_tlx_resp_initial_credit               ;	

//	Table 4: TLX Command Credit Interface
   wire			afu_tlx_cmd_credit               ;
   wire	[6:0]		afu_tlx_cmd_initial_credit               ;

//	Table 5: TLX to AFU Response Data Interface
   wire			afu_tlx_resp_rd_req               ;
   wire	[2:0]		afu_tlx_resp_rd_cnt               ;

//	Table 6: TLX to AFU Command Data Interface
   wire			afu_tlx_cmd_rd_req               ;
   wire	[2:0]		afu_tlx_cmd_rd_cnt               ;

//	Table 8: TLX Framer Command Interface
   wire			afu_tlx_cmd_valid                ;
   wire	[7:0]		afu_tlx_cmd_opcode               ;
   wire	[11:0]		afu_tlx_cmd_actag                ;
   wire	[3:0]		afu_tlx_cmd_stream_id            ;
   wire	[67:0]		afu_tlx_cmd_ea_or_obj            ;
   wire	[15:0]		afu_tlx_cmd_afutag               ;
   wire	[1:0]		afu_tlx_cmd_dl                   ;
   wire	[2:0]		afu_tlx_cmd_pl                   ;
   wire			afu_tlx_cmd_os                   ;
   wire	[63:0]		afu_tlx_cmd_be                   ;
   wire	[3:0]		afu_tlx_cmd_flag                 ;
   wire			afu_tlx_cmd_endian               ;
   wire	[15:0]		afu_tlx_cmd_bdf                  ;
   wire	[19:0]		afu_tlx_cmd_pasid                ;
   wire	[5:0]		afu_tlx_cmd_pg_size              ;
   wire	[511:0]		afu_tlx_cdata_bus                  ;
   wire			afu_tlx_cdata_bdi               ;	// TODO: TLX Ref Design doc lists this as afu_tlx_cdata_bad
   wire			afu_tlx_cdata_valid               ;

//	Table 9: TLX Framer Response Interface
   wire			afu_tlx_resp_valid               ;
   wire	[7:0]		afu_tlx_resp_opcode               ;
   wire	[1:0]		afu_tlx_resp_dl               ;
   wire	[15:0]		afu_tlx_resp_capptag               ;
   wire	[1:0]		afu_tlx_resp_dp               ;
   wire	[3:0]		afu_tlx_resp_code               ;
   wire			afu_tlx_rdata_valid               ;
   wire	[511:0]		afu_tlx_rdata_bus               ;
   wire			afu_tlx_rdata_bdi               ;

//	Table 10: TLX Framer Template Configuration
   wire			afu_cfg_xmit_tmpl_config_0               ;
   wire			afu_cfg_xmit_tmpl_config_1               ;
   wire			afu_cfg_xmit_tmpl_config_2               ;
   wire			afu_cfg_xmit_tmpl_config_3               ;
   wire	[3:0]		afu_cfg_xmit_rate_config_0               ;
   wire	[3:0]		afu_cfg_xmit_rate_config_1               ;
   wire	[3:0]		afu_cfg_xmit_rate_config_2               ;
   wire	[3:0]		afu_cfg_xmit_rate_config_3               ;
  
 // Integers
  integer         i;
 // Sim related variables
  reg [0:63]      simulationTime ;
  reg             simulationError;
  
initial begin
    ha_pclock				<= 0;
    reset   				<= 1;
  // Table 1: TLX to AFU Response Interface
    tlx_afu_resp_valid			<= 0;
    tlx_afu_resp_opcode			<= 8'b0;
    tlx_afu_resp_afutag			<= 16'b0;
    tlx_afu_resp_code			<= 4'b0;
    tlx_afu_resp_pg_size		<= 6'b0;
    tlx_afu_resp_dl			<= 2'b0;
    tlx_afu_resp_dp			<= 2'b0;
    tlx_afu_resp_host_tag		<= 24'b0;
    tlx_afu_resp_addr_tag		<= 18'b0;
    tlx_afu_resp_cache_state		<= 4'b0;

//	Table 3: TLX to AFU Command Interface
    tlx_afu_cmd_valid			<= 0;
    tlx_afu_cmd_opcode			<= 8'b0;
    tlx_afu_cmd_capptag			<= 16'b0;
    tlx_afu_cmd_dl			<= 2'b0;
    tlx_afu_cmd_pl			<= 3'b0;
    tlx_afu_cmd_be			<= 64'b0;
    tlx_afu_cmd_end			<= 0;
    tlx_afu_cmd_t			<= 0;
    tlx_afu_cmd_pa			<= 64'b0;
    tlx_afu_cmd_flag			<= 4'b0;
    tlx_afu_cmd_os			<= 0;

//	Table 5: TLX to AFU Response Data Interface
    tlx_afu_resp_data_valid		<= 0;
    tlx_afu_resp_data_bus		<= 512'b0;
    tlx_afu_resp_data_bdi		<= 0;

//	Table 6: TLX to AFU Command Data Interface
    tlx_afu_cmd_data_valid		<= 0;
    tlx_afu_cmd_data_bus		<= 512'b0;
    tlx_afu_cmd_data_bdi		<= 0;

//	Table 7: TLX Framer credit interface
    tlx_afu_resp_credit			<= 0;
    tlx_afu_resp_data_credit		<= 0;
    tlx_afu_cmd_credit			<= 0;
    tlx_afu_cmd_data_credit		<= 0;
    tlx_afu_cmd_resp_initial_credit	<= 3'b0;
    tlx_afu_data_initial_credit		<= 5'b0;

  // These signals do not appear on the RefDesign Doc. However it is present
  // on the TLX spec
    afu_cfg_in_rcv_tmpl_capability_0	<= 0;
    afu_cfg_in_rcv_tmpl_capability_1	<= 0;
    afu_cfg_in_rcv_tmpl_capability_2	<= 0;
    afu_cfg_in_rcv_tmpl_capability_3	<= 0;
    afu_cfg_in_rcv_rate_capability_0	<= 4'b0;
    afu_cfg_in_rcv_rate_capability_1	<= 4'b0;
    afu_cfg_in_rcv_rate_capability_2	<= 4'b0;
    afu_cfg_in_rcv_rate_capability_3	<= 4'b0;
    tlx_afu_ready			<= 0;

    tlx_bfm_init();
end

  // Clock generation

  always begin
    #2 ha_pclock = !ha_pclock;
  end

  always @ ( ha_pclock ) begin
    if(reset == 1'b1)
      reset = 1'b0;
  end

  always @ ( ha_pclock ) begin
    simulationTime = $time;
    set_simulation_time(simulationTime);
    tlx_bfm( ha_pclock,
				// Table 1: TLX to AFU Response Interface
	tlx_afu_resp_valid,
	tlx_afu_resp_opcode,
	tlx_afu_resp_afutag,
	tlx_afu_resp_code,
	tlx_afu_resp_pg_size,
	tlx_afu_resp_dl,
	tlx_afu_resp_dp,
	tlx_afu_resp_host_tag,
	tlx_afu_resp_addr_tag,
	tlx_afu_resp_cache_state,

				//	Table 2: TLX Response Credit Interface
	afu_tlx_resp_credit,
	afu_tlx_resp_initial_credit,

				//	Table 3: TLX to AFU Command Interface
	tlx_afu_cmd_valid,
	tlx_afu_cmd_opcode,
	tlx_afu_cmd_capptag,
	tlx_afu_cmd_dl,
	tlx_afu_cmd_pl,
	tlx_afu_cmd_be,
	tlx_afu_cmd_end,
	tlx_afu_cmd_t,
	tlx_afu_cmd_pa,
	tlx_afu_cmd_flag,
	tlx_afu_cmd_os,

				//	Table 4: TLX Command Credit Interface
	afu_tlx_cmd_credit,
	afu_tlx_cmd_initial_credit,

				//	Table 5: TLX to AFU Response Data Interface
	tlx_afu_resp_data_valid,
	tlx_afu_resp_data_bus,
	tlx_afu_resp_data_bdi,
	afu_tlx_resp_rd_req,
	afu_tlx_resp_rd_cnt,

				//	Table 6: TLX to AFU Command Data Interface
	tlx_afu_cmd_data_valid,
	tlx_afu_cmd_data_bus,
	tlx_afu_cmd_data_bdi,
	afu_tlx_cmd_rd_req,
	afu_tlx_cmd_rd_cnt,

				//	Table 7: TLX Framer credit interface
	tlx_afu_resp_credit,
	tlx_afu_resp_data_credit,
	tlx_afu_cmd_credit,
	tlx_afu_cmd_data_credit,
	tlx_afu_cmd_resp_initial_credit,
	tlx_afu_data_initial_credit,

				//	Table 8: TLX Framer Command Interface
	afu_tlx_cmd_valid,
	afu_tlx_cmd_opcode,
	afu_tlx_cmd_actag,
	afu_tlx_cmd_stream_id,
	afu_tlx_cmd_ea_or_obj,
	afu_tlx_cmd_afutag,
	afu_tlx_cmd_dl,
	afu_tlx_cmd_pl,
	afu_tlx_cmd_os,
	afu_tlx_cmd_be,
	afu_tlx_cmd_flag,
	afu_tlx_cmd_endian,
	afu_tlx_cmd_bdf,
	afu_tlx_cmd_pasid,
	afu_tlx_cmd_pg_size,
	afu_tlx_cdata_bus,
	afu_tlx_cdata_bdi,// TODO: TLX Ref Design doc lists this as afu_tlx_cdata_bad
	afu_tlx_cdata_valid,

				//	Table 9: TLX Framer Response Interface
	afu_tlx_resp_valid,
	afu_tlx_resp_opcode,
	afu_tlx_resp_dl,
	afu_tlx_resp_capptag,
	afu_tlx_resp_dp,
	afu_tlx_resp_code,
	afu_tlx_rdata_valid,
	afu_tlx_rdata_bus,
	afu_tlx_rdata_bdi,

// These signals do not appear on the RefDesign Doc. However it is present on the TLX spec
	afu_cfg_in_rcv_tmpl_capability_0,
	afu_cfg_in_rcv_tmpl_capability_1,
	afu_cfg_in_rcv_tmpl_capability_2,
	afu_cfg_in_rcv_tmpl_capability_3,
	afu_cfg_in_rcv_rate_capability_0,
	afu_cfg_in_rcv_rate_capability_1,
	afu_cfg_in_rcv_rate_capability_2,
	afu_cfg_in_rcv_rate_capability_3,
	tlx_afu_ready
    );
  end

  always @ (negedge ha_pclock) begin
    get_simuation_error(simulationError);
  end

  always @ (posedge ha_pclock) begin
    if(simulationError)
      $finish;
  end

  mcp3_top a0 (
    .clock_tlx(ha_pclock),
    .clock_afu(ha_pclock),
    .reset(reset),
  // Table 1: TLX to AFU Response Interface
    .tlx_afu_resp_valid               (tlx_afu_resp_valid),
    .tlx_afu_resp_opcode              (tlx_afu_resp_opcode),
    .tlx_afu_resp_afutag              (tlx_afu_resp_afutag),
    .tlx_afu_resp_code                (tlx_afu_resp_code),
    .tlx_afu_resp_pg_size             (tlx_afu_resp_pg_size),
    .tlx_afu_resp_dl                  (tlx_afu_resp_dl),
    .tlx_afu_resp_dp                  (tlx_afu_resp_dp),
//    .tlx_afu_resp_host_tag          (tlx_afu_resp_host_tag), //    Reserved for CAPI4.0
    .tlx_afu_resp_addr_tag            (tlx_afu_resp_addr_tag),
//    .tlx_afu_resp_cache_state       (tlx_afu_resp_cache_state), //    Reserved for CAPI4.0
                                   
//	Table 2: TLX Response Credit Interface
    .afu_tlx_resp_credit              (afu_tlx_resp_credit),
    .afu_tlx_resp_initial_credit      (afu_tlx_resp_initial_credit),

//	Table 3: TLX to AFU Command Interface
    .tlx_afu_cmd_valid                (tlx_afu_cmd_valid),
    .tlx_afu_cmd_opcode               (tlx_afu_cmd_opcode),
    .tlx_afu_cmd_capptag              (tlx_afu_cmd_capptag),
    .tlx_afu_cmd_dl                   (tlx_afu_cmd_dl),
    .tlx_afu_cmd_pl                   (tlx_afu_cmd_pl),
    .tlx_afu_cmd_be                   (tlx_afu_cmd_be),
    .tlx_afu_cmd_end                  (tlx_afu_cmd_end),
    .tlx_afu_cmd_t                    (tlx_afu_cmd_t),
    .tlx_afu_cmd_pa                   (tlx_afu_cmd_pa),
    .tlx_afu_cmd_flag                 (tlx_afu_cmd_flag),
    .tlx_afu_cmd_os                   (tlx_afu_cmd_os),

//	Table 4: TLX Command Credit Interface
    .afu_tlx_cmd_credit               (afu_tlx_cmd_credit),
    .afu_tlx_cmd_initial_credit       (afu_tlx_cmd_initial_credit),

//	Table 5: TLX to AFU Response Data Interface
    .tlx_afu_resp_data_valid          (tlx_afu_resp_data_valid),
    .tlx_afu_resp_data_bus            (tlx_afu_resp_data_bus),
    .tlx_afu_resp_data_bdi            (tlx_afu_resp_data_bdi),
    .afu_tlx_resp_rd_req              (afu_tlx_resp_rd_req),
    .afu_tlx_resp_rd_cnt              (afu_tlx_resp_rd_cnt),

//	Table 6: TLX to AFU Command Data Interface
    .tlx_afu_cmd_data_valid           (tlx_afu_cmd_data_valid),
    .tlx_afu_cmd_data_bus             (tlx_afu_cmd_data_bus),
    .tlx_afu_cmd_data_bdi             (tlx_afu_cmd_data_bdi),
    .afu_tlx_cmd_rd_req               (afu_tlx_cmd_rd_req),
    .afu_tlx_cmd_rd_cnt               (afu_tlx_cmd_rd_cnt),

//	Table 7: TLX Framer credit interface
    .tlx_afu_resp_credit              (tlx_afu_resp_credit),
    .tlx_afu_resp_data_credit         (tlx_afu_resp_data_credit),
    .tlx_afu_cmd_credit               (tlx_afu_cmd_credit),
    .tlx_afu_cmd_data_credit          (tlx_afu_cmd_data_credit),
    .tlx_afu_cmd_resp_initial_credit  (tlx_afu_cmd_resp_initial_credit),
    .tlx_afu_data_initial_credit      (tlx_afu_data_initial_credit),

//	Table 8: TLX Framer Command Interface
    .afu_tlx_cmd_valid                (afu_tlx_cmd_valid),
    .afu_tlx_cmd_opcode               (afu_tlx_cmd_opcode),
    .afu_tlx_cmd_actag                (afu_tlx_cmd_actag),
    .afu_tlx_cmd_stream_id            (afu_tlx_cmd_stream_id),
    .afu_tlx_cmd_ea_or_obj            (afu_tlx_cmd_ea_or_obj),
    .afu_tlx_cmd_afutag               (afu_tlx_cmd_afutag),
    .afu_tlx_cmd_dl                   (afu_tlx_cmd_dl),
    .afu_tlx_cmd_pl                   (afu_tlx_cmd_pl),
    .afu_tlx_cmd_os                   (afu_tlx_cmd_os),
    .afu_tlx_cmd_be                   (afu_tlx_cmd_be),
    .afu_tlx_cmd_flag                 (afu_tlx_cmd_flag),
    .afu_tlx_cmd_endian               (afu_tlx_cmd_endian),
    .afu_tlx_cmd_bdf                  (afu_tlx_cmd_bdf),
    .afu_tlx_cmd_pasid                (afu_tlx_cmd_pasid),
    .afu_tlx_cmd_pg_size              (afu_tlx_cmd_pg_size),
    .afu_tlx_cdata_bus                (afu_tlx_cdata_bus),
    .afu_tlx_cdata_bdi                (afu_tlx_cdata_bdi),	// TODO: TLX Ref Design doc lists this as afu_tlx_cdata_bad
    .afu_tlx_cdata_valid              (afu_tlx_cdata_valid),

//	Table 9: TLX Framer Response Interface
    .afu_tlx_resp_valid               (afu_tlx_resp_valid),
    .afu_tlx_resp_opcode              (afu_tlx_resp_opcode),
    .afu_tlx_resp_dl                  (afu_tlx_resp_dl),
    .afu_tlx_resp_capptag             (afu_tlx_resp_capptag),
    .afu_tlx_resp_dp                  (afu_tlx_resp_dp),
    .afu_tlx_resp_code                (afu_tlx_resp_code),
    .afu_tlx_rdata_valid              (afu_tlx_rdata_valid),
    .afu_tlx_rdata_bus                (afu_tlx_rdata_bus),
    .afu_tlx_rdata_bdi                (afu_tlx_rdata_bdi),	// TODO: the name given in the spec for this signal is afu_tlx_rdata_bad

//	Table 10: TLX Framer Template Configuration
    .afu_cfg_xmit_tmpl_config_0       (afu_cfg_xmit_tmpl_config_0),
    .afu_cfg_xmit_tmpl_config_1       (afu_cfg_xmit_tmpl_config_1),
    .afu_cfg_xmit_tmpl_config_2       (afu_cfg_xmit_tmpl_config_2),
    .afu_cfg_xmit_tmpl_config_3       (afu_cfg_xmit_tmpl_config_3),
    .afu_cfg_xmit_rate_config_0       (afu_cfg_xmit_rate_config_0),
    .afu_cfg_xmit_rate_config_1       (afu_cfg_xmit_rate_config_1),
    .afu_cfg_xmit_rate_config_2       (afu_cfg_xmit_rate_config_2),
    .afu_cfg_xmit_rate_config_3       (afu_cfg_xmit_rate_config_3),

  // These signals do not appear on the RefDesign Doc. However it is present
  // on the TLX spec
    .afu_cfg_in_rcv_tmpl_capability_0 (afu_cfg_in_rcv_tmpl_capability_0),
    .afu_cfg_in_rcv_tmpl_capability_1 (afu_cfg_in_rcv_tmpl_capability_1),
    .afu_cfg_in_rcv_tmpl_capability_2 (afu_cfg_in_rcv_tmpl_capability_2),
    .afu_cfg_in_rcv_tmpl_capability_3 (afu_cfg_in_rcv_tmpl_capability_3),
    .afu_cfg_in_rcv_rate_capability_0 (afu_cfg_in_rcv_rate_capability_0),
    .afu_cfg_in_rcv_rate_capability_1 (afu_cfg_in_rcv_rate_capability_1),
    .afu_cfg_in_rcv_rate_capability_2 (afu_cfg_in_rcv_rate_capability_2),
    .afu_cfg_in_rcv_rate_capability_3 (afu_cfg_in_rcv_rate_capability_3),
    .tlx_afu_ready                    (tlx_afu_ready)
                                       
  );

endmodule
