// This block is to be used as a black box to connect the OCSE4's afu_driver
// to the OCSE3-based afu

`timescale 1ns / 1ps

module oc4_bb (
  // From the OCSE4 side
                                // Table 2: TLX to AFU VCO Interface
				output   [6:0]	  afu_tlx_vc0_initial_credit_top,
				output		  afu_tlx_vc0_credit_top,
				input             tlx_afu_vc0_valid_top,
				input   [7:0]     tlx_afu_vc0_opcode_top,
				input  [15:0]     tlx_afu_vc0_afutag_top,
				input  [15:0]     tlx_afu_vc0_capptag_top,
				input  [51:0]     tlx_afu_vc0_pa_or_ta_top,
				input   [1:0]     tlx_afu_vc0_dl_top,
				input   [1:0]     tlx_afu_vc0_dp_top,
				input             tlx_afu_vc0_ef_top,
				input             tlx_afu_vc0_w_top,
				input             tlx_afu_vc0_mh_top,
				input   [5:0]     tlx_afu_vc0_pg_size_top,
				input  [23:0]     tlx_afu_vc0_host_tag_top,
				input   [3:0]     tlx_afu_vc0_resp_code_top,
				input   [2:0]     tlx_afu_vc0_cache_state_top,
// need to find the eqt for addr_tag
				output		  afu_tlx_dcp0_rd_req_top,
				output   [2:0]	  afu_tlx_dcp0_rd_cnt_top,
				input             tlx_afu_dcp0_data_valid_top,
				input [511:0]     tlx_afu_dcp0_data_bus_top,
				input             tlx_afu_dcp0_data_bdi_top,

    				input   [3:0]  	  tlx_afu_vc0_initial_credit_top,
    				input   [5:0]  	  tlx_afu_dcp0_initial_credit_top,
    				input	     	  tlx_afu_vc0_credit_top,
    				input	     	  tlx_afu_dcp0_credit_top,
				output  	  afu_tlx_vc0_valid_top,
				output  [7:0]	  afu_tlx_vc0_opcode_top,
				output [15:0]	  afu_tlx_vc0_capptag_top,
				output  [1:0]	  afu_tlx_vc0_dl_top,
				output  [1:0]	  afu_tlx_vc0_dp_top,
				output  [3:0]	  afu_tlx_vc0_resp_code_top,
				output            afu_tlx_dcp0_data_valid_top,
				output [511:0]    afu_tlx_dcp0_data_bus_top,
				output            afu_tlx_dcp0_data_bdi_top,

				output   [6:0]	  afu_tlx_vc1_initial_credit_top,
				output            afu_tlx_vc1_credit_top,
				input             tlx_afu_vc1_valid_top,
				input   [7:0]     tlx_afu_vc1_opcode_top,
				input  [15:0]     tlx_afu_vc1_afutag_top,
				input  [15:0]     tlx_afu_vc1_capptag_top,
				input  [63:0]     tlx_afu_vc1_pa_top,
				input   [1:0]     tlx_afu_vc1_dl_top,
				input   [1:0]     tlx_afu_vc1_dp_top,
				input  [63:0]     tlx_afu_vc1_be_top,
				input   [2:0]     tlx_afu_vc1_pl_top,
				input             tlx_afu_vc1_endian_top,
				input             tlx_afu_vc1_co_top,
				input             tlx_afu_vc1_os_top,
				input   [3:0]     tlx_afu_vc1_cmdflag_top,
				input   [7:0]     tlx_afu_vc1_mad_top,

				output  	  afu_tlx_dcp1_rd_req_top,
				output  [2:0]	  afu_tlx_dcp1_rd_cnt_top,
				input             tlx_afu_dcp1_data_valid_top,
				input [511:0]     tlx_afu_dcp1_data_bus_top,
				input             tlx_afu_dcp1_data_bdi_top,
    				input   [3:0]  	  tlx_afu_vc1_initial_credit_top,
  // we will ignore the VC2/DCP2 interface for now, will drive some sane value
  // on the initial credits, just to ensure no hang
				output   [6:0]	  afu_tlx_vc2_initial_credit_top,
				output		  afu_tlx_vc2_credit_top,

    				input   [3:0]  	  tlx_afu_vc3_initial_credit_top,
    				input   [5:0]  	  tlx_afu_dcp3_initial_credit_top,
    				input	     	  tlx_afu_vc3_credit_top,
    				input	     	  tlx_afu_dcp3_credit_top,
				output  	  afu_tlx_vc3_valid_top,
				output  [7:0]	  afu_tlx_vc3_opcode_top,
				output  [3:0]	  afu_tlx_vc3_stream_id_top,
				output [15:0]	  afu_tlx_vc3_afutag_top,
				output [11:0]	  afu_tlx_vc3_actag_top,
				output [67:0]	  afu_tlx_vc3_ea_ta_or_obj_top,
				output  [1:0]	  afu_tlx_vc3_dl_top,
				output [63:0]	  afu_tlx_vc3_be_top,
				output  [2:0]	  afu_tlx_vc3_pl_top,
				output  	  afu_tlx_vc3_os_top,
				output  	  afu_tlx_vc3_endian_top,
				output  [5:0]	  afu_tlx_vc3_pg_size_top,
				output  [3:0]	  afu_tlx_vc3_cmdflag_top,
				output [19:0]	  afu_tlx_vc3_pasid_top,
				output [15:0]	  afu_tlx_vc3_bdf_top,
				output  [7:0]	  afu_tlx_vc3_mad_top,
				output            afu_tlx_dcp3_data_valid_top,
				output[511:0]     afu_tlx_dcp3_data_bus_top,
				output            afu_tlx_dcp3_data_bdi_top,
  // From the OCSE3 side
				input	[6:0]	  afu_tlx_resp_initial_credit_top,
				input		  afu_tlx_resp_credit_top,
				output            tlx_afu_resp_valid_top,
				output [7:0]      tlx_afu_resp_opcode_top,
				output [15:0]     tlx_afu_resp_afutag_top,
				output [3:0]      tlx_afu_resp_code_top,
				output [5:0]      tlx_afu_resp_pg_size_top,
				output [1:0]      tlx_afu_resp_dl_top,
				output [1:0]      tlx_afu_resp_dp_top,
				output [23:0]     tlx_afu_resp_host_tag_top,
				output [17:0]     tlx_afu_resp_addr_tag_top,
				output [3:0]      tlx_afu_resp_cache_state_top,

				input		  afu_tlx_resp_rd_req_top,
				input	[2:0]	  afu_tlx_resp_rd_cnt_top,
				output            tlx_afu_resp_data_valid_top,
				output [511:0]    tlx_afu_resp_data_bus_top,
				output            tlx_afu_resp_data_bdi_top,

				output  [3:0]     tlx_afu_cmd_resp_initial_credit_top,
				output  [3:0]     tlx_afu_data_initial_credit_top,
				output  [5:0]     tlx_afu_cmd_data_initial_credit_top,
				output  [5:0]     tlx_afu_resp_data_initial_credit_top,
				output            tlx_afu_resp_credit_top,
				output            tlx_afu_resp_data_credit_top,

				input  [7:0]	  afu_tlx_resp_opcode_top,
				input  [1:0]	  afu_tlx_resp_dl_top,
				input  [15:0]	  afu_tlx_resp_capptag_top,
				input  [1:0]	  afu_tlx_resp_dp_top,
				input  [3:0]	  afu_tlx_resp_code_top,
				input		  afu_tlx_resp_valid_top,
				input		  afu_tlx_rdata_valid_top,
				input  [511:0]	  afu_tlx_rdata_bus_top,
				input		  afu_tlx_rdata_bdi_top,

				output            tlx_afu_cmd_valid_top,
				output [7:0]      tlx_afu_cmd_opcode_top,
				output [15:0]     tlx_afu_cmd_capptag_top,
				output [1:0]      tlx_afu_cmd_dl_top,
				output [2:0]      tlx_afu_cmd_pl_top,
				output [63:0]     tlx_afu_cmd_be_top,
				output            tlx_afu_cmd_end_top,
				output [63:0]     tlx_afu_cmd_pa_top,
				output [3:0]      tlx_afu_cmd_flag_top,
				output            tlx_afu_cmd_os_top,

				input		  afu_tlx_cmd_credit_top,
				input	[6:0]	  afu_tlx_cmd_initial_credit_top,

				input		  afu_tlx_cmd_rd_req_top,
				input	[2:0]	  afu_tlx_cmd_rd_cnt_top,
				output            tlx_afu_cmd_data_valid_top,
				output [511:0]    tlx_afu_cmd_data_bus_top,
				output            tlx_afu_cmd_data_bdi_top,

				output            tlx_afu_cmd_credit_top,
				output            tlx_afu_cmd_data_credit_top,
				input		  afu_tlx_cmd_valid_top,
				input	[7:0]	  afu_tlx_cmd_opcode_top,
				input	[11:0]	  afu_tlx_cmd_actag_top,
				input	[3:0]	  afu_tlx_cmd_stream_id_top,
				input	[67:0]	  afu_tlx_cmd_ea_or_obj_top,
				input	[15:0]	  afu_tlx_cmd_afutag_top,
				input	[1:0]	  afu_tlx_cmd_dl_top,
				input	[2:0]	  afu_tlx_cmd_pl_top,
				input		  afu_tlx_cmd_os_top,
				input	[63:0]	  afu_tlx_cmd_be_top,
				input	[3:0]	  afu_tlx_cmd_flag_top,
				input		  afu_tlx_cmd_endian_top,
				input	[15:0]	  afu_tlx_cmd_bdf_top,
				input	[19:0]	  afu_tlx_cmd_pasid_top,
				input	[5:0]	  afu_tlx_cmd_pg_size_top,
				input	[511:0]	  afu_tlx_cdata_bus_top,
				input		  afu_tlx_cdata_bdi_top,
				input		  afu_tlx_cdata_valid_top,
				output		  cfg_tlx_resync_credits_top
);
// VC0/DCP0 is assumed to handle the OCSE'3 resp interface
    assign afu_tlx_vc0_initial_credit_top       = afu_tlx_resp_initial_credit_top;
    assign afu_tlx_vc0_credit_top               = afu_tlx_resp_credit_top;
    assign tlx_afu_resp_valid_top               = tlx_afu_vc0_valid_top;
    assign tlx_afu_resp_opcode_top              = tlx_afu_vc0_opcode_top;
    assign tlx_afu_resp_afutag_top              = tlx_afu_vc0_afutag_top;
    assign tlx_afu_resp_code_top                = tlx_afu_vc0_resp_code_top;
    assign tlx_afu_resp_pg_size_top             = tlx_afu_vc0_pg_size_top;
    assign tlx_afu_resp_dl_top                  = tlx_afu_vc0_dl_top;
    assign tlx_afu_resp_dp_top                  = tlx_afu_vc0_dp_top;
    assign tlx_afu_resp_host_tag_top            = tlx_afu_vc0_host_tag_top;
    assign tlx_afu_resp_addr_tag_top            = 18'b0;
    assign tlx_afu_resp_cache_state_top         = tlx_afu_vc0_cache_state_top;
    assign tlx_afu_data_initial_credit_top      = tlx_afu_vc0_initial_credit_top;
    assign tlx_afu_resp_credit_top              = tlx_afu_vc0_credit_top;
    assign afu_tlx_vc0_valid_top                = afu_tlx_resp_valid_top;
    assign afu_tlx_vc0_opcode_top               = afu_tlx_resp_opcode_top;
    assign afu_tlx_vc0_capptag_top              = afu_tlx_resp_capptag_top;
    assign afu_tlx_vc0_dl_top                   = afu_tlx_resp_dl_top;
    assign afu_tlx_vc0_dp_top                   = afu_tlx_resp_dp_top;
    assign afu_tlx_vc0_resp_code_top            = afu_tlx_resp_code_top;

    assign afu_tlx_dcp0_data_valid_top          = afu_tlx_rdata_valid_top;
    assign afu_tlx_dcp0_data_bus_top            = afu_tlx_rdata_bus_top;
    assign afu_tlx_dcp0_data_bdi_top            = afu_tlx_rdata_bdi_top;
    assign afu_tlx_dcp0_rd_req_top              = afu_tlx_resp_rd_req_top;
    assign afu_tlx_dcp0_rd_cnt_top              = afu_tlx_resp_rd_cnt_top;
    assign tlx_afu_resp_data_valid_top          = tlx_afu_dcp0_data_valid_top;
    assign tlx_afu_resp_data_bus_top            = tlx_afu_dcp0_data_bus_top;
    assign tlx_afu_resp_data_bdi_top            = tlx_afu_dcp0_data_bdi_top;
    assign tlx_afu_resp_data_initial_credit_top = tlx_afu_dcp0_initial_credit_top;
    assign tlx_afu_resp_data_credit_top         = tlx_afu_dcp0_credit_top;

// VC1/DCP1 is assumed to handle the OCSE'3 tlx_afu cmd interface
    assign afu_tlx_vc1_initial_credit_top       = afu_tlx_cmd_initial_credit_top;
    assign afu_tlx_vc1_credit_top               = afu_tlx_cmd_credit_top;
    assign tlx_afu_cmd_valid_top                = tlx_afu_vc1_valid_top;
    assign tlx_afu_cmd_opcode_top               = tlx_afu_vc1_opcode_top;
    assign tlx_afu_cmd_capptag_top              = tlx_afu_vc1_capptag_top;
    assign tlx_afu_cmd_dl_top                   = tlx_afu_vc1_dl_top;
    assign tlx_afu_cmd_pl_top                   = tlx_afu_vc1_pl_top;
    assign tlx_afu_cmd_be_top                   = tlx_afu_vc1_be_top;
    assign tlx_afu_cmd_end_top                  = tlx_afu_vc1_endian_top;
    assign tlx_afu_cmd_pa_top                   = tlx_afu_vc1_pa_top;
    assign tlx_afu_cmd_flag_top                 = tlx_afu_vc1_cmdflag_top;
    assign tlx_afu_cmd_os_top                   = tlx_afu_vc1_os_top;

    assign afu_tlx_dcp1_rd_req_top              = afu_tlx_cmd_rd_req_top;
    assign afu_tlx_dcp1_rd_cnt_top              = afu_tlx_cmd_rd_cnt_top;
    assign tlx_afu_cmd_data_valid_top           = tlx_afu_dcp1_data_valid_top;
    assign tlx_afu_cmd_data_bus_top             = tlx_afu_dcp1_data_bus_top;
    assign tlx_afu_cmd_data_bdi_top             = tlx_afu_dcp1_data_bdi_top;

    assign afu_tlx_vc2_initial_credit_top       = 7'b1;
    assign afu_tlx_vc2_credit_top               = 1'b0;

// VC3/DCP3 is assumed to handle the OCSE'3 afu_tlx cmd interface
    assign tlx_afu_cmd_resp_initial_credit_top  = tlx_afu_vc3_initial_credit_top;
    assign tlx_afu_cmd_data_initial_credit_top  = tlx_afu_dcp3_initial_credit_top;

    assign afu_tlx_vc3_valid_top                = afu_tlx_cmd_valid_top;
    assign afu_tlx_vc3_opcode_top               = afu_tlx_cmd_opcode_top;
    assign afu_tlx_vc3_stream_id_top            = afu_tlx_cmd_stream_id_top;
    assign afu_tlx_vc3_afutag_top               = afu_tlx_cmd_afutag_top;
    assign afu_tlx_vc3_actag_top                = afu_tlx_cmd_actag_top;
    assign afu_tlx_vc3_ea_ta_or_obj_top         = afu_tlx_cmd_ea_or_obj_top;
    assign afu_tlx_vc3_dl_top                   = afu_tlx_cmd_dl_top;
    assign afu_tlx_vc3_pl_top                   = afu_tlx_cmd_pl_top;
    assign afu_tlx_vc3_be_top                   = afu_tlx_cmd_be_top;
    assign afu_tlx_vc3_os_top                   = afu_tlx_cmd_os_top;
    assign afu_tlx_vc3_endian_top               = afu_tlx_cmd_endian_top;
    assign afu_tlx_vc3_pg_size_top              = afu_tlx_cmd_pg_size_top;
    assign afu_tlx_vc3_cmdflag_top              = afu_tlx_cmd_flag_top;
    assign afu_tlx_vc3_pasid_top                = afu_tlx_cmd_pasid_top;
    assign afu_tlx_vc3_bdf_top                  = afu_tlx_cmd_bdf_top;
    assign afu_tlx_vc3_mad_top                  = 8'b1;

    assign afu_tlx_dcp3_data_valid_top          = afu_tlx_cdata_valid_top;
    assign afu_tlx_dcp3_data_bus_top            = afu_tlx_cdata_bus_top;
    assign afu_tlx_dcp3_data_bdi_top            = afu_tlx_cdata_bdi_top;
    assign tlx_afu_cmd_credit_top               = tlx_afu_vc3_credit_top;
    assign tlx_afu_cmd_data_credit_top          = tlx_afu_dcp3_credit_top;

    assign cfg_tlx_resync_credits_top           = 1'b0;

/*
  always  begin
  end
*/
endmodule
