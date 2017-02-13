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
                                         input ha_pclock
                                       );
  
   reg             ha_pclock;
   reg             reset;
// AFU inputs
   reg             tlx_afu_cmd_credit;
   reg             tlx_afu_cmd_data_credit;
   reg [2:0]       tlx_afu_cmd_resp_initial_credit;
   reg [4:0]       tlx_afu_data_initial_credit;
   reg             tlx_afu_resp_valid;
   reg [7:0]       tlx_afu_resp_opcode;
   reg [15:0]      tlx_afu_resp_afutag;
   reg [3:0]       tlx_afu_resp_code;
   reg [1:0]       tlx_afu_resp_dl;
   reg [1:0]       tlx_afu_resp_dp;
   reg [5:0]       tlx_afu_resp_pg_size;
   reg [17:0]      tlx_afu_resp_addr_tag;
   reg             tlx_afu_resp_data_valid;
   reg             tlx_afu_resp_data_bdi;
   reg [511:0]     tlx_afu_resp_data_bus;
   reg             tlx_afu_ready;
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
   reg             tlx_afu_cmd_data_valid;
   reg             tlx_afu_cmd_data_bdi;
   reg [511:0]     tlx_afu_cmd_data_bus;
   reg             tlx_afu_resp_credit;
   reg             tlx_afu_resp_data_credit;
   reg             afu_cfg_in_rcv_tmpl_capability_0;
   reg             afu_cfg_in_rcv_tmpl_capability_1;
   reg             afu_cfg_in_rcv_tmpl_capability_2;
   reg             afu_cfg_in_rcv_tmpl_capability_3;
   reg [3:0]       afu_cfg_in_rcv_rate_capability_0;
   reg [3:0]       afu_cfg_in_rcv_rate_capability_1;
   reg [3:0]       afu_cfg_in_rcv_rate_capability_2;
   reg [3:0]       afu_cfg_in_rcv_rate_capability_3;
 // Wires for AFU o/p
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
   wire			afu_tlx_cdata_valid               ;
   wire			afu_tlx_cdata_bdi               ;
   wire	[511:0]		afu_tlx_cdata_bus                  ;
   wire			afu_tlx_resp_rd_req               ;
   wire	[2:0]		afu_tlx_resp_rd_cnt               ;
   wire			afu_tlx_resp_credit               ;
   wire	[6:0]		afu_tlx_resp_initial_credit               ;
   wire			afu_tlx_cmd_rd_req               ;
   wire	[2:0]		afu_tlx_cmd_rd_cnt               ;
   wire			afu_tlx_cmd_credit               ;
   wire	[6:0]		afu_tlx_cmd_initial_credit               ;
   wire			afu_tlx_resp_valid               ;
   wire	[7:0]		afu_tlx_resp_opcode               ;
   wire	[1:0]		afu_tlx_resp_dl               ;
   wire	[15:0]		afu_tlx_resp_capptag               ;
   wire	[1:0]		afu_tlx_resp_dp               ;
   wire	[3:0]		afu_tlx_resp_code               ;
   wire			afu_tlx_rdata_valid               ;
   wire			afu_tlx_rdata_bdi               ;
   wire	[511:0]		afu_tlx_rdata_bus               ;
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
    reset   				<= 0;
    tlx_afu_cmd_credit			<= 0;
    tlx_afu_cmd_data_credit		<= 0;
    tlx_afu_cmd_resp_initial_credit	<= 3'b0;
    tlx_afu_data_initial_credit		<= 5'b0;
    reset     		<= 0;
    tlx_bfm_init();
end

  // Clock generation

  always begin
    #2 ha_pclock = !ha_pclock;
  end

  always @ ( ha_pclock ) begin
    simulationTime = $time;
    set_simulation_time(simulationTime);
    tlx_bfm( ha_pclock);
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
  // AFU_TLX command transmit interface
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

    .afu_tlx_cdata_valid              (afu_tlx_cdata_valid),
    .afu_tlx_cdata_bdi                (afu_tlx_cdata_bdi),
    .afu_tlx_cdata_bus                (afu_tlx_cdata_bus),
                                  
    .tlx_afu_cmd_credit               (tlx_afu_cmd_credit),
    .tlx_afu_cmd_data_credit          (tlx_afu_cmd_data_credit),

    .tlx_afu_cmd_resp_initial_credit  (tlx_afu_cmd_resp_initial_credit),
    .tlx_afu_data_initial_credit      (tlx_afu_data_initial_credit),


  // TLX_AFU response receive interface
    .tlx_afu_resp_valid               (tlx_afu_resp_valid),
    .tlx_afu_resp_opcode              (tlx_afu_resp_opcode),
    .tlx_afu_resp_afutag              (tlx_afu_resp_afutag),
    .tlx_afu_resp_code                (tlx_afu_resp_code),
    .tlx_afu_resp_dl                  (tlx_afu_resp_dl),
    .tlx_afu_resp_dp                  (tlx_afu_resp_dp),
    .tlx_afu_resp_pg_size             (tlx_afu_resp_pg_size),
    .tlx_afu_resp_addr_tag            (tlx_afu_resp_addr_tag),
                                   
    .tlx_afu_resp_data_valid          (tlx_afu_resp_data_valid),
    .tlx_afu_resp_data_bdi            (tlx_afu_resp_data_bdi),
    .tlx_afu_resp_data_bus            (tlx_afu_resp_data_bus),
                                   
    .afu_tlx_resp_rd_req              (afu_tlx_resp_rd_req),
    .afu_tlx_resp_rd_cnt              (afu_tlx_resp_rd_cnt),

    .afu_tlx_resp_credit              (afu_tlx_resp_credit),
    .afu_tlx_resp_initial_credit      (afu_tlx_resp_initial_credit),


  // TLX_AFU command receive interface
    .tlx_afu_ready                    (tlx_afu_ready),
                                  
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

    .tlx_afu_cmd_data_valid           (tlx_afu_cmd_data_valid),
    .tlx_afu_cmd_data_bdi             (tlx_afu_cmd_data_bdi),
    .tlx_afu_cmd_data_bus             (tlx_afu_cmd_data_bus),
                                  
    .afu_tlx_cmd_rd_req               (afu_tlx_cmd_rd_req),
    .afu_tlx_cmd_rd_cnt               (afu_tlx_cmd_rd_cnt),

    .afu_tlx_cmd_credit               (afu_tlx_cmd_credit),
    .afu_tlx_cmd_initial_credit       (afu_tlx_cmd_initial_credit),


  // AFU_TLX response transmit interface
    .afu_tlx_resp_valid               (afu_tlx_resp_valid),
    .afu_tlx_resp_opcode              (afu_tlx_resp_opcode),
    .afu_tlx_resp_dl                  (afu_tlx_resp_dl),
    .afu_tlx_resp_capptag             (afu_tlx_resp_capptag),
    .afu_tlx_resp_dp                  (afu_tlx_resp_dp),
    .afu_tlx_resp_code                (afu_tlx_resp_code),

    .afu_tlx_rdata_valid              (afu_tlx_rdata_valid),
    .afu_tlx_rdata_bdi                (afu_tlx_rdata_bdi),
    .afu_tlx_rdata_bus                (afu_tlx_rdata_bus),
                                  
    .tlx_afu_resp_credit              (tlx_afu_resp_credit),
    .tlx_afu_resp_data_credit         (tlx_afu_resp_data_credit),

  // TLX-CNFG capability exchange
    .afu_cfg_in_rcv_tmpl_capability_0 (afu_cfg_in_rcv_tmpl_capability_0),
    .afu_cfg_in_rcv_tmpl_capability_1 (afu_cfg_in_rcv_tmpl_capability_1),
    .afu_cfg_in_rcv_tmpl_capability_2 (afu_cfg_in_rcv_tmpl_capability_2),
    .afu_cfg_in_rcv_tmpl_capability_3 (afu_cfg_in_rcv_tmpl_capability_3),
    .afu_cfg_in_rcv_rate_capability_0 (afu_cfg_in_rcv_rate_capability_0),
    .afu_cfg_in_rcv_rate_capability_1 (afu_cfg_in_rcv_rate_capability_1),
    .afu_cfg_in_rcv_rate_capability_2 (afu_cfg_in_rcv_rate_capability_2),
    .afu_cfg_in_rcv_rate_capability_3 (afu_cfg_in_rcv_rate_capability_3),
                                       
    .afu_cfg_xmit_tmpl_config_0       (afu_cfg_xmit_tmpl_config_0),
    .afu_cfg_xmit_tmpl_config_1       (afu_cfg_xmit_tmpl_config_1),
    .afu_cfg_xmit_tmpl_config_2       (afu_cfg_xmit_tmpl_config_2),
    .afu_cfg_xmit_tmpl_config_3       (afu_cfg_xmit_tmpl_config_3),
    .afu_cfg_xmit_rate_config_0       (afu_cfg_xmit_rate_config_0),
    .afu_cfg_xmit_rate_config_1       (afu_cfg_xmit_rate_config_1),
    .afu_cfg_xmit_rate_config_2       (afu_cfg_xmit_rate_config_2),
    .afu_cfg_xmit_rate_config_3       (afu_cfg_xmit_rate_config_3)
  );

endmodule
