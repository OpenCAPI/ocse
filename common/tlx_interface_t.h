/*
 * Copyright 2014,2018 International Business Machines
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

#ifndef __tlx_interface_t_h__
#define __tlx_interface_t_h__ 1

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

// Choose ONE to define what TLX support level will be
//#define TLX3 1 
#define TLX4 1 

// this is the size of the transimit and receive buffers in the afu_event
// it needs to be large enough to transmit/receive the maximum size of legally concurrent events
// for example from tlx to afu this might be response, command, command data, resp data and credit xchange.
// we'll set it at 1070 for now and see if we can come up with the correct value later. (Do we have to read entire
// data buffer in one socket transaction? If not, this size can be reduced....
#define TLX_BUFFER_SIZE 1070

#ifdef TLX3
#define PROTOCOL_PRIMARY 3
#define PROTOCOL_SECONDARY 0000
#define PROTOCOL_TERTIARY 0
#endif /* TLX3 TODO we currently support TLX3 & TLX4 cmds....should we have to just support TlX3 ones? hope not... */

#ifdef TLX4
#define PROTOCOL_PRIMARY 4
#define PROTOCOL_SECONDARY 0001
#define PROTOCOL_TERTIARY 0
#endif /* TLX4 */



/* Select the initial value for credits??  */
/* TODO Test_afu still needs these MAX credits.. AFU is setting initial values; what are our "queue" sizes? */
#define MAX_AFU_TLX_CMD_CREDITS 5
#define MAX_AFU_TLX_RESP_CREDITS 10
#define MAX_TLX_AFU_CMD_CREDITS 8
#define MAX_TLX_AFU_CMD_DATA_CREDITS 32
#define MAX_TLX_AFU_RESP_CREDITS 7
#define MAX_TLX_AFU_RESP_DATA_CREDITS 32


/* Return codes for TLX interface functions */

#define TLX_SUCCESS 0
#define TLX_RESPONSE_DONE 0
#define TLX_AFU_DOUBLE_COMMAND 1
#define TLX_AFU_CMD_NOT_VALID 2
#define TLX_AFU_DOUBLE_CMD_AND_DATA 3
#define TLX_AFU_CMD_DATA_NOT_VALID 4
#define TLX_AFU_DOUBLE_RESP 5
#define TLX_AFU_RESP_NOT_VALID 6
#define TLX_AFU_DOUBLE_RESP_AND_DATA 7
#define TLX_AFU_RESP_DATA_NOT_VALID 8
#define TLX_AFU_NO_CREDITS 10
#define AFU_TLX_DOUBLE_DATA 20
#define AFU_TLX_DOUBLE_COMMAND 21
#define AFU_TLX_CMD_NOT_VALID 22
#define AFU_TLX_DOUBLE_CMD_AND_DATA 23
#define AFU_TLX_CMD_DATA_NOT_VALID 24
#define AFU_TLX_CMD_NO_DATA 25
#define AFU_TLX_DOUBLE_RESP 31
#define AFU_TLX_RESP_NOT_VALID 32
#define AFU_TLX_DOUBLE_RESP_AND_DATA 33
#define AFU_TLX_RESP_DATA_NOT_VALID 34
#define AFU_TLX_RESP_NO_DATA 35
#define AFU_TLX_DOUBLE_RESP_DATA 36
#define AFU_TLX_NO_CREDITS 40
#define AFU_TLX_RD_CNT_WRONG 41
#define CFG_TLX_NO_CREDITS 42
#define CFG_TLX_NOT_CFG_CMD 43
#define CFG_TLX_RESP_NOT_VALID 44
#define TLX_RESPONSE_FAILED 15
//#define TLX_RESPONSE_CONTEXT 17
#define TLX_BAD_SOCKET 16	/* The socket connection could not be established */
#define TLX_VERSION_ERROR 48	/* The TLX versions in use on local & remote do not match */
#define TLX_TRANSMISSION_ERROR 64	/* There was an error sending data across the socket
					   interface */
#define TLX_CLOSE_ERROR 128	/* There was an error closing the socket */

/* TL CAPP Command opcodes (from host to AFU) */

#define TLX_CMD_NOP 0
#define TLX_CMD_XLATE_DONE 	0x18 	// VC0
#define TLX_CMD_INTRP_RDY  	0x1a	// VC0
#define TLX_CMD_RD_MEM	  	0x20	// VC1
#define TLX_CMD_CO_MEM	  	0x21	// VC1      TLX5 only
#define TLX_CMD_RD_PF	  	0x22	// VC1      OMI only
#define TLX_CMD_PR_RD_MEM  	0x28	// VC1
#define TLX_CMD_AMO_RD     	0x30	// VC1      TLX4
#define TLX_CMD_AMO_RW     	0x31	// VC1 DCP1 TLX4
#define TLX_CMD_AMO_W      	0x40	// VC1 DCP1 TLX4
#define TLX_CMD_PAD_MEM  	0x80	// VC1      OMI only
#define TLX_CMD_WRITE_MEM  	0x81	// VC1 DCP1
#define TLX_CMD_WRITE_MEM_BE	0x82	// VC1 DCP1
#define TLX_CMD_WRITE_META	0x83	// VC1      TLX5 only
#define TLX_CMD_PR_WR_MEM	0x86	// VC1 DCP1
#define TLX_CMD_FORCE_EVICT	0xd0	// VC0      TLX4
#define TLX_CMD_KILL_XLATE	0xd2	// VC2      TLX4
#define TLX_CMD_DISABLE_CACHE	0xd4	// VC2      TLX4
#define TLX_CMD_ENABLE_CACHE	0xd5	// VC2      TLX4
#define TLX_CMD_DISABLE_ATC	0xd6	// VC2      TLX4
#define TLX_CMD_ENABLE_ATC	0xd7	// VC2      TLX4
#define TLX_CMD_CONFIG_READ	0xe0	// VC1
#define TLX_CMD_CONFIG_WRITE	0xe1	// VC1 DCP1
#define TLX_CMD_MEM_CNTL	0xef	// VC0      OMI only


/* TLX AP Command opcodes (from AFU to host) */

#define AFU_CMD_NOP 0
#define AFU_CMD_RD_WNITC 	0x10	// VC3
#define AFU_CMD_RD_WNITC_N 	0x14	// VC3
#define AFU_CMD_PR_RD_WNITC 	0x12	// VC3
#define AFU_CMD_PR_RD_WNITC_N 	0x16	// VC3
#define AFU_CMD_DMA_W  		0x20	// VC3 DCP3
#define AFU_CMD_DMA_W_N	  	0x24	// VC3 DCP3
#define AFU_CMD_DMA_W_BE  	0x28	// VC3 DCP3
#define AFU_CMD_DMA_W_BE_N  	0x2c	// VC3 DCP3
#define AFU_CMD_DMA_PR_W  	0x30	// VC3 DCP3
#define AFU_CMD_DMA_PR_W_N  	0x34	// VC3 DCP3
#define AFU_CMD_AMO_RD  	0x38	// VC3
#define AFU_CMD_AMO_RD_N  	0x3c	// VC3
#define AFU_CMD_AMO_RW  	0x40	// VC3 DCP3
#define AFU_CMD_AMO_RW_N  	0x44	// VC3 DCP3
#define AFU_CMD_AMO_W  		0x48	// VC3 DCP3
#define AFU_CMD_AMO_W_N  	0x4c	// VC3 DCP3
#define AFU_CMD_ASSIGN_ACTAG	0x50	// VC3
#define AFU_CMD_XLATE_RELEASE	0x51	// VC3      TLX4
#define AFU_CMD_MEM_PA_FLUSH	0x52	// VC1      TLX5 only
#define AFU_CMD_MEM_BACK_FLUSH	0x53	// VC1      TLX5 only
#define AFU_CMD_MEM_SYN_DONE	0x54	// VC2      TLX4
#define AFU_CMD_CASTOUT		0x55	// VC2      TLX4
#define AFU_CMD_CASTOUT_PUSH	0x56	// VC2 DCP2 TLX4
#define AFU_CMD_INTRP_REQ	0x58	// VC3
#define AFU_CMD_INTRP_REQ_S	0x59	// VC3      TLX4
#define AFU_CMD_INTRP_REQ_D	0x5a	// VC3 DCP3
#define AFU_CMD_INTRP_REQ_D_S	0x5b	// VC3 DCP3 TLX4
#define AFU_CMD_WAKE_HOST_THRD	0x5c	// VC3	
#define AFU_CMD_WAKE_HOST_THRD_S	0x5d    // VC3      TLX4
#define AFU_CMD_UPGRADE_STATE		0x60 	// VC3      TLX4
#define AFU_CMD_READ_ME			0x68 	// VC3      TLX4
#define AFU_CMD_READ_MES		0x69 	// VC3      TLX4
#define AFU_CMD_READ_S			0x6a 	// VC3      TLX4
#define AFU_CMD_XLATE_TOUCH		0x78	// VC3 
#define AFU_CMD_XLATE_TO_PA		0x79	// VC3      TLX5 only
#define AFU_CMD_XLATE_TOUCH_N		0x7c	// VC3
#define AFU_CMD_RD_WNITC_T		0x90 	// VC3      TLX4
#define AFU_CMD_RD_WNITC_T_S		0x91 	// VC3      TLX4
#define AFU_CMD_PR_RD_WNITC_T		0x92 	// VC3      TLX4
#define AFU_CMD_PR_RD_WNITC_T_S		0x93 	// VC3      TLX4
#define AFU_CMD_DMA_W_T_P	  	0xa2	// VC3 DCP3 TLX4
#define AFU_CMD_DMA_W_T_P_S		0xa3	// VC3 DCP3 TLX4
#define AFU_CMD_DMA_W_BE_T_P     	0xaa	// VC3 DCP3 TLX4
#define AFU_CMD_DMA_W_BE_T_P_S   	0xab	// VC3 DCP3 TLX4
#define AFU_CMD_DMA_PR_W_T_P  		0xb2	// VC3 DCP3 TLX4
#define AFU_CMD_DMA_PR_W_T_P_S		0xb3	// VC3 DCP3 TLX4
#define AFU_CMD_AMO_RD_T  		0xb8	// VC3      TLX4
#define AFU_CMD_AMO_RD_T_S  		0xb9	// VC3      TLX4
#define AFU_CMD_AMO_RW_T  		0xc0	// VC3 DCP3 TLX4
#define AFU_CMD_AMO_RW_T_S  		0xc1	// VC3 DCP3 TLX4
#define AFU_CMD_AMO_W_T_P  		0xca	// VC3 DCP3 TLX4
#define AFU_CMD_AMO_W_T_P_S		0xcb	// VC3 DCP3 TLX4
#define AFU_CMD_UPGRADE_STATE_T		0xe0 	// VC3      TLX4
#define AFU_CMD_READ_ME_T		0xe8 	// VC3      TLX4
#define AFU_CMD_READ_MES_T		0xe9 	// VC3      TLX4
#define AFU_CMD_READ_S_T		0xea	// VC3      TLX4
#define AFU_CMD_SYNC			0xef	// VC3      TLX4

/*  AMO_OPCODES per TL SPEC: used in LIBOCXL */
#define AMO_WRMWF_ADD	 0x00
#define AMO_WRMWF_XOR	 0x01
#define AMO_WRMWF_OR	 0x02
#define AMO_WRMWF_AND	 0x03
#define AMO_WRMWF_CAS_MAX_U	 0x04
#define AMO_WRMWF_CAS_MAX_S	 0x05
#define AMO_WRMWF_CAS_MIN_U	 0x06
#define AMO_WRMWF_CAS_MIN_S	 0x07
#define AMO_ARMWF_CAS_U	 0x08
#define AMO_ARMWF_CAS_E	 0x09
#define AMO_ARMWF_CAS_NE	 0x0a
#define AMO_ARMWF_INC_B	 0x0c
#define AMO_ARMWF_INC_E	 0x0d
#define AMO_ARMWF_DEC_B	 0x0e
#define AMO_W_CAS_T	 0x0c



/* TL CAPP responses (from host to AFU)  */
#define TLX_RSP_NOP 0
#define TLX_RSP_RET_TLX_CREDITS	0x01
#define TLX_RSP_TOUCH_RESP	0x02	// VC0
#define TLX_RSP_SYN_DETECTED	0x03	// VC0      TLX4
#define TLX_RSP_READ_RESP	0x04	// VC0 DCP0
#define TLX_RSP_READ_FAILED	0x05	// VC0
#define TLX_RSP_CL_RD_RESP	0x06 	// VC0 DCP0 TLX4
#define TLX_RSP_UGRADE_RESP	0x07 	// VC0      TLX4
#define TLX_RSP_WRITE_RESP	0x08	// VC0
#define TLX_RSP_WRITE_FAILED	0x09	// VC0
#define TLX_RSP_MEM_FLUSH_DONE	0x0a 	// VC1      TLX4
#define TLX_RSP_SYNC_DONE	0x0b 	// VC0      TLX4
#define TLX_RSP_INTRP_RESP	0x0c	// VC0
#define TLX_RSP_READ_RESP_OW	0x0d 	// VC0 DCP0 OMI only
#define TLX_RSP_READ_RESP_XW	0x0e 	// VC0 DCP0 OMI only
#define TLX_RSP_TOUCH_RESP_T	0x0f	// VC0      TLX4
#define TLX_RSP_WAKE_HOST_RESP	0x10	// VC0
#define TLX_RSP_BACK_FLUSH_DONE	0x11	// VC1      TLX5 only
#define TLX_RSP_PA_RESP		0x12	// VC0      TLX5 only
#define TLX_RSP_CL_RD_RESP_OW	0x16 	// VC0 DCP0 TLX4


/* TLX AP responses (from AFU to host) */
#define AFU_RSP_NOP  0
#define AFU_RSP_MEM_RD_RESP	0x01	// VC0 DCP0
#define AFU_RSP_MEM_RD_FAIL	0x02	// VC0
#define AFU_RSP_MEM_RD_RESP_OW	0x03 	// VC0 DCP0 OMI only
#define AFU_RSP_MEM_WR_RESP	0x04	// VC0
#define AFU_RSP_MEM_WR_FAIL	0x05	// VC0
#define AFU_RSP_MEM_RD_RESP_XW	0x07 	// VC0 DCP0 OMI only
#define AFU_RSP_RET_TL_CREDITS	0x08 	//          TLX4?
#define AFU_RSP_MEM_CO_RESP	0x09	// VC0      TLX4
#define AFU_RSP_MEM_CNTL_DONE	0x0b 	// VC0      OMI only
#define AFU_RSP_KILL_XLATE_DONE	0x0c 	// VC3      TLX4
#define AFU_RSP_CACHE_DISABLED	0x0d	// VC0      TLX4
#define AFU_RSP_CACHE_ENABLED	0x0e	// VC0      TLX4
#define AFU_RSP_ATC_DISABLED	0x80	// VC0      TLX4
#define AFU_RSP_ATC_ENABLED	0x81	// VC0      TLX4



/* Create one of these structures to interface to an AFU model and use the functions below to manipulate it */

/* *INDENT-OFF* */
struct DATA_PKT {
  uint8_t data[64];
  struct DATA_PKT *_next;
};

struct AFU_EVENT {
  int sockfd;                             /* socket file descriptor */
  uint32_t proto_primary;                 /* socket protocol version 1st number */
  uint32_t proto_secondary;               /* socket protocol version 2nd number */
  uint32_t proto_tertiary;                /* socket protocol version 3rd number */
  int clock;                              /* clock */
  unsigned char tbuf[TLX_BUFFER_SIZE];    /* transmit buffer for socket communications */
  unsigned char rbuf[TLX_BUFFER_SIZE];    /* receive buffer for socket communications */
  uint32_t rbp;                           /* receive buffer position */
  // Config and Credits
  uint8_t  afu_tlx_credit_req_valid;	  /* needed for xfer of credit & req changes TODO UPDATE THIS*/
  uint8_t  tlx_afu_credit_valid;	  /* needed for xfer of credits TODO UPDATE THIS */
  uint8_t  afu_tlx_vc0_credits_available; // init from afu_tlx_vc0_initial_credit, decrement on tlx_afu_vc0_valid, increment on afu_tlx_vc0_credit
  uint8_t  afu_tlx_vc1_credits_available; // init from afu_tlx_vc1_initial_credit, decrement on tlx_afu_vc1_valid, increment on afu_tlx_vc1_credit
  uint8_t  afu_tlx_vc2_credits_available; // init from afu_tlx_vc2_initial_credit, decrement on tlx_afu_vc2_valid, increment on afu_tlx_vc2_credit
  uint8_t  tlx_afu_cmd_credits_available; // init from tlx_afu_cmd_resp_initial_credit, decrement on afu_tlx_cmd_valid, increment on tlx_afu_cmd_credit
  uint8_t  tlx_afu_resp_credits_available; // init from tlx_afu_cmd_resp_initial_credit, decrement on afu_tlx_resp_valid, increment on tlx_afu_resp_credit
  uint8_t  tlx_afu_vc0_credits_available; // init from tlx_afu_vc0_initial_credit, decrement on afu_tlx_vc0_valid, increment on tlx_afu_vc0_credit
  uint8_t  tlx_afu_vc1_credits_available; // init from tlx_afu_vc1_initial_credit, decrement on afu_tlx_vc1_valid, increment on tlx_afu_vc1_credit
  uint8_t  tlx_afu_vc2_credits_available; // init from tlx_afu_vc2_initial_credit, decrement on afu_tlx_vc2_valid, increment on tlx_afu_vc2_credit
  uint8_t  tlx_afu_vc3_credits_available; // init from tlx_afu_vc3_initial_credit, decrement on afu_tlx_vc3_valid, increment on tlx_afu_vc3_credit
  uint8_t  tlx_afu_dcp0_credits_available; // init from tlx_afu_dcp0_initial_credit, decrement on afu_tlx_dcp0_data_valid, increment on tlx_afu_dcp0_credit
  uint8_t  tlx_afu_dcp2_credits_available; // init from tlx_afu_dcp1_initial_credit, decrement on afu_tlx_dcp1_data_valid, increment on tlx_afu_dcp1_credit
  uint8_t  tlx_afu_dcp3_credits_available; // init from tlx_afu_dcp3_initial_credit, decrement on afu_tlx_dcp3_data_valid, increment on tlx_afu_dcp3_credit
  uint8_t  cfg_tlx_credits_available;
  uint16_t  tlx_afu_dcp1_data_byte_cnt;	  /*  used for socket transfer only */
  uint16_t  tlx_afu_dcp0_data_byte_cnt;	  /*  used for socket transfer only */
  uint16_t  afu_cfg_resp_data_byte_cnt;	  /*  used for socket transfer only */


  // TLX Receiver Interface as shown in TLX4.0 Reference Design
  //
  // TLX to AFU VC0 Interface (table 2) TLX sends CAPP responses & posted cmds to AFU
  uint8_t afu_tlx_vc0_initial_credit;     /* 7 bit initial # of credits that the afu provides to tlx for sending CAPP responses to AFU  */
  uint8_t afu_tlx_vc0_credit;             /* 1 bit return a credit to tlx */
  uint8_t tlx_afu_vc0_valid;              /* 1 bit response/posted command valid from from host */
  uint8_t tlx_afu_vc0_opcode;             /* 8 bit response/posted command op code */
  uint16_t tlx_afu_vc0_afutag;            /* 16 bit response tag - match to afu_tlx_cmd_afutag */
  uint16_t tlx_afu_vc0_capptag;           /* 16 bit unique handle/command tag from host */
  uint64_t tlx_afu_vc0_pa_or_ta;          /* 52 bit response/command phyiscal or translated address  bits [63:12]*/
  uint8_t tlx_afu_vc0_dl;                 /* 2 bit response/command encoded data length */
  uint8_t tlx_afu_vc0_dp;                 /* 2 bit response/command data part - indicates data content of current resp packet */
  uint8_t tlx_afu_vc0_ef;                 /* 1 bit evict and fill directive  */
  uint8_t tlx_afu_vc0_w;                  /* 1 bit write permission flag  */
  uint8_t tlx_afu_vc0_mh;                 /* 1 bit memory hit flag  */
  uint8_t tlx_afu_vc0_pg_size;            /* 6 bit page size  */
  uint32_t tlx_afu_vc0_host_tag;          /* 24 bit tag associated w/data held in AFU L1  */
  uint8_t tlx_afu_vc0_resp_code;          /* 4 bit response code (see TL spec for specific cmd */
  uint8_t tlx_afu_vc0_cache_state;        /* 3 bit specifies cache state the cache line has obtained  */

  // TLX to AFU DCP0 DATA Interface (table 3) TLX sends CAPP response data to AFU
  uint8_t afu_tlx_dcp0_rd_req;             /* 1 bit DCP0 data read request */
  uint8_t afu_tlx_dcp0_rd_cnt;             /* 3 bit encoded DCP0 data read request size */
  uint8_t tlx_afu_dcp0_data_valid;         /* 1 bit response data valid */
  unsigned char tlx_afu_dcp0_data[256];    /* upto 256 B of data may come with a response - we should maybe make sure this is little endian order */
                                           /* we don't send this directly on tlx interface.  it is buffered for later distribution.   */
  uint8_t tlx_afu_dcp0_data_bdi;           /* 1 bit bad data indicator */

  // response data fifo to buffer responses for later resp_rd_req
  struct DATA_PKT *dcp0_data_head;
  struct DATA_PKT *dcp0_data_tail;
  uint32_t dcp0_data_rd_cnt;

  // TLX to AFU VC1 Interface (table 4)  TLX sends CAPP commands to AFU
  uint8_t afu_tlx_vc1_initial_credit;     /* 7 bit initial # of credits that the afu provides to tlx for sending CAPP cmds to AFU  */
  uint8_t afu_tlx_vc1_credit;             /* 1 bit return a credit to tlx */
  uint8_t tlx_afu_vc1_valid;              /* 1 bit command valid from from host */
  uint8_t tlx_afu_vc1_opcode;             /* 8 bit command op code */
  uint16_t tlx_afu_vc1_afutag;            /* 16 bit cmds tag - match to afu_tlx_cmd_afutag */
  uint16_t tlx_afu_vc1_capptag;           /* 16 bit command tag from host */
  uint64_t tlx_afu_vc1_pa;                /* 64 bit command phyiscal address */
  uint8_t tlx_afu_vc1_dl;                 /* 2 bit command encoded data length */
  uint8_t tlx_afu_vc1_dp;                 /* 2 bit command data part - indicates data content of current resp packet */
  uint64_t tlx_afu_vc1_be;                /* 64 bit byte enable  */
  uint8_t tlx_afu_vc1_pl;                 /* 3 bit encoded partial length  */
  uint8_t tlx_afu_vc1_endian;             /* 1 bit operand endianess 0 = LE, 1 = BE  */
  uint8_t tlx_afu_vc1_co;                 /* 1 bit chekout hint see spec  */
  uint8_t tlx_afu_vc1_os;                 /* 1 bit ordered segment 1= ordering guaranteed  */
  uint8_t tlx_afu_vc1_cmdflag;            /* 4 bit specifies execution behavior for cmds specified w/this field. see spec  */
  uint8_t tlx_afu_vc1_mad;                /* 8 bit memory access directive  */

  // TLX to AFU DCP1 DATA Interface (table 5) TLX sends CAPP command data to AFU upon request
  uint8_t afu_tlx_dcp1_rd_req;             /* 1 bit DCP0 data read request */
  uint8_t afu_tlx_dcp1_rd_cnt;             /* 3 bit encoded DCP0 data read request size */
  uint8_t tlx_afu_dcp1_data_valid;         /* 1 bit cmds data valid */
  unsigned char tlx_afu_dcp1_data[256];    /* upto 256 B of data may come back with a response - we should maybe make sure this is little endian order */
                                           /* we don't send this directly on tlx interface.  it is buffered for later distribution.   */
  uint8_t tlx_afu_dcp1_data_bdi;           /* 1 bit bad data indicator */

  // response data fifo to buffer responses for later cmd_rd_req
  struct DATA_PKT *dcp1_data_head;
  struct DATA_PKT *dcp1_data_tail;
  uint32_t dcp1_data_rd_cnt;

  // TLX to AFU VC2 Interface (table 6) TLX sends CAPP commands to AFU
  uint8_t afu_tlx_vc2_initial_credit;     /* 7 bit initial # of credits that the afu provides to tlx for sending CAPP responses to AFU  */
  uint8_t afu_tlx_vc2_credit;             /* 1 bit return a credit to tlx */
  uint8_t tlx_afu_vc2_valid;              /* 1 bit command valid from from host */
  uint8_t tlx_afu_vc2_opcode;             /* 8 bit command op code */
  uint16_t tlx_afu_vc2_capptag;           /* 16 bit command tag from host */
  uint64_t tlx_afu_vc2_ea;                /* 52 bit command effective address  bits [63:12] */
  uint8_t tlx_afu_vc2_pg_size;            /* 6 bit page size  */
  uint8_t tlx_afu_vc2_cmdflag;            /* 4 bit specifies execution behavior for cmds specified w/this field. see spec  */
  uint32_t tlx_afu_vc2_pasid;             /* 20 bit PASID for user process associated w/this cmd  */
  uint16_t tlx_afu_vc2_bdf;               /* 16 bit BDF Bus Device Function for AFU associated w/this cmd  */


  // TLX to AFU CFG Interface for configuration cmds (table 7) TLX sends cfg cmds to AFU
  uint8_t cfg_tlx_initial_credit;         /* 4 bit initial number of credits that the afu is providing to tlx for consumption */
  uint8_t cfg_tlx_credit_return;          /* 1 bit return a credit to tlx for config cmds */
  uint8_t tlx_cfg_valid;                  /* 1 bit cfg command valid from from host */
  uint8_t tlx_cfg_opcode;                 /* 8 bit cfg command op code */
  uint16_t tlx_cfg_capptag;               /* 16 bit cfg command tag from host */
  uint64_t tlx_cfg_pa;                    /* 64 bit cfg command phyiscal address */
  uint8_t tlx_cfg_pl;                     /* 3 bit cfg command encoded partial data length */
  uint8_t tlx_cfg_t;                      /* 1 bit command  0=type 0 configuration read/write; 1= type 1 configuration read/write */
  unsigned char tlx_cfg_data_bus[4];      /* 32 bit (4 byte) config cmd data  */
  uint8_t tlx_cfg_data_bdi;               /* 1 bit bad config data indicator */


  // TLX Receiver Configuration ports  (table 8)
  uint8_t tlx_cfg_rcv_tmpl_capability_0;  /* 1 bit xmit template enable - default */
  uint8_t tlx_cfg_rcv_tmpl_capability_1;  /* 1 bit xmit template enable */
  uint8_t tlx_cfg_rcv_tmpl_capability_2;  /* 1 bit xmit template enable */
  uint8_t tlx_cfg_rcv_tmpl_capability_3;  /* 1 bit xmit template enable */
  uint8_t tlx_cfg_rcv_rate_capability_0;  /* 4 bit xmit rate */
  uint8_t tlx_cfg_rcv_rate_capability_1;  /* 4 bit xmit rate */
  uint8_t tlx_cfg_rcv_rate_capability_2;  /* 4 bit xmit rate */
  uint8_t tlx_cfg_rcv_rate_capability_3;  /* 4 bit xmit rate */
  uint8_t cfg_tlx_resync_credits;         /* 1 bit 0 -> 1 transition means TLX will re-apply initial credits from AFU  */

  // TLX Receiver to TLX Framer Credit Interface (table 9 & table 10) Not modeled
  // TLX Receiver Misc Ports (table 11) Not modeled

  // TLX Framer Interfaces as shown in TLX 4.0 Reference Design
  
  // TLX Framer - AFU to TLX AP Configuration Response Interface (table 13) AFU sends cfg responses to TLX
  uint8_t cfg_tlx_resp_valid;             /* 1 bit afu cfg response is valid */
  uint8_t cfg_tlx_resp_opcode;            /* 8 bit cfg response op code */
  uint16_t cfg_tlx_resp_capptag;          /* 16 bit  cfg response capptag - should match a tlx_cfg_cmd capptag */
  uint8_t cfg_tlx_resp_code;              /* 4 bit cfg response reason code */
  uint8_t cfg_tlx_rdata_offset;           /* 4 bit offset into 32B buffer */
  unsigned char cfg_tlx_rdata_bus[4];  	  /* 32 bit (4 byte) config response data  */
  uint8_t cfg_tlx_rdata_valid;            /* 6 bit config response data is valid */
  uint8_t cfg_tlx_rdata_bdi;              /* 1 bit config response data is bad */
  uint8_t tlx_cfg_resp_ack;		  /* 1 bit signal to AFU after taking cfg resp from interface */

  // TLX Framer - AFU to TLX VC0/DCP0  Interface (table 14) AFU sends AP responses and response data to TLX
  uint8_t tlx_afu_vc0_initial_credit;     /* 4 bit initial number of response credits available to afu for AP responses -hardcoded to 7 in TLX 4 ref design */
  uint8_t tlx_afu_dcp0_initial_credit;    /* 6 bit initial number of response data credits available to afu ifor AP response data - hardcoded to 16 in TLX 4 ref design */
  uint8_t tlx_afu_vc0_credit;             /* 1 bit tlx returning a response credit to the afu */
  uint8_t tlx_afu_dcp0_credit;            /* 1 bit tlx returning a response data credit to the afu */
  uint8_t afu_tlx_vc0_valid;              /* 1 bit afu response is valid */
  uint8_t afu_tlx_vc0_opcode;             /* 8 bit response op code */
  uint16_t afu_tlx_vc0_capptag;           /* 16 bit response capptag - should match a tlx_afu_cmd_capptag */
  uint8_t afu_tlx_vc0_dl;                 /* 2 bit response data length */
  uint8_t afu_tlx_vc0_dp;                 /* 2 bit response data part */
  uint8_t afu_tlx_vc0_resp_code;          /* 4 bit response reason code */
  uint8_t afu_tlx_dcp0_data_valid;        /* 1 bit response data is valid */
  unsigned char afu_tlx_dcp0_data_bus[64]; /* 512 bit response data */
  uint8_t afu_tlx_dcp0_data_bdi;          /* 1 bit response data is bad */

  // TLX Framer - AFU to TLX VC1 Interface (table 15) AFU sends AP commands to TLX
  uint8_t tlx_afu_vc1_initial_credit;     /* 4 bit initial number of cmd credits available to the afu for AP cmds -hardcoded to 4 in TLX 4 ref design   */
  uint8_t tlx_afu_vc1_credit;             /* 1 bit tlx returning a command credit to the afu */
  uint8_t afu_tlx_vc1_valid;              /* 1 bit 0|1 indicates that a valid command is being presented by the afu to tlx */
  uint8_t afu_tlx_vc1_opcode;             /* 8 bit opcode */
  uint8_t afu_tlx_vc1_stream_id;          /* 4 bit stream identifier used by afu (AP)  */
  uint16_t afu_tlx_vc1_afutag;            /* 16 bit command tag */
  uint64_t afu_tlx_vc1_pa;                /* 58 bit physical address  bits [63:6]*/
  uint8_t afu_tlx_vc1_dl;                 /* 2 bits encoded data length */  

  // TLX Framer - AFU to TLX VC2/DCP2 Interface (table 16) AFU sends AP commands and data to TLX
  uint8_t tlx_afu_vc2_initial_credit;     /* 4 bit initial number of cmd credits available to afu for AP cmds -hardcoded to 4 in TLX 4 ref design */
  uint8_t tlx_afu_dcp2_initial_credit;    /* 6 bit initial number of cmd data credits available to afu for AP cmd data - hardcoded to 16 in TLX 4 ref design */
  uint8_t tlx_afu_vc2_credit;             /* 1 bit tlx returning a command credit to the afu */
  uint8_t tlx_afu_dcp2_credit;            /* 1 bit tlx returning a command data credit to the afu */
  uint8_t afu_tlx_vc2_valid;              /* 1 bit afu command is valid */
  uint8_t afu_tlx_vc2_opcode;             /* 8 bit command op code */
  uint8_t afu_tlx_vc2_dl;                 /* 2 bit command data length */
  uint32_t afu_tlx_vc2_host_tag;          /* 24 bit host tag */
  uint8_t afu_tlx_vc2_cache_state;        /* 3 bit cache state the line has obtained MESEI */
  uint8_t afu_tlx_vc2_cmdflg;             /* 4 bit cmdflg specifies exection behavior for cmds */
  uint8_t afu_tlx_dcp2_data_valid;        /* 1 bit cmd data is valid */
  unsigned char afu_tlx_dcp2_data_bus[64]; /* 512 bit cmd data */
  uint8_t afu_tlx_dcp2_data_bdi;          /* 1 bit cmd data is bad */

  // TLX Framer - AFU to TLX VC3/DCP3 Interface (table 17) AFU sends AP commands and data to TLX
  uint8_t tlx_afu_vc3_initial_credit;     /* 4 bit initial number of cmd credits available to afu for AP cmds -hardcoded to 4 in TLX 4 ref design */
  uint8_t tlx_afu_dcp3_initial_credit;    /* 6 bit initial number of cmd credits available to afu for AP cmds - hardcoded to 16 in TLX 4 ref design */
  uint8_t tlx_afu_vc3_credit;             /* 1 bit tlx returning a command credit to the afu */
  uint8_t tlx_afu_dcp3_credit;            /* 1 bit tlx returning a command data credit to the afu */
  uint8_t afu_tlx_vc3_valid;              /* 1 bit 0|1 indicates that a valid command is being presented by the afu to tlx */
  uint8_t afu_tlx_vc3_opcode;             /* 8 bit opcode */
  uint8_t afu_tlx_vc3_stream_id;          /* 4 bit stream identifier used by afu (AP) */
  uint16_t afu_tlx_vc3_afutag;            /* 16 bit command tag */
  uint16_t afu_tlx_vc3_actag;             /* 12 bit address context tag */
  unsigned char afu_tlx_vc3_ea_ta_or_obj[9]; /* 68 bit effective address, translated address or object handle */
  uint8_t afu_tlx_vc3_dl;                 /* 2 bits encoded data length */  /* combine dl and pl ??? */
  uint64_t afu_tlx_vc3_be;                /* 64 bit byte enable */
  uint8_t afu_tlx_vc3_pl;                 /* 3 bits encoded partial data length */
  uint8_t afu_tlx_vc3_os;                 /* 1 bit ordered segment CAPI 4 */
  uint8_t afu_tlx_vc3_endian;             /* 1 bit endianness 0=little endian; 1=big endian */
  uint8_t afu_tlx_vc3_pg_size;            /* 6 bit page size hint */
  uint8_t afu_tlx_vc3_cmdflag;            /* 4 bit command flag for atomic opcodes */
  uint32_t afu_tlx_vc3_pasid;             /* 20 bit PASID */
  uint16_t afu_tlx_vc3_bdf;               /* 16 bit bus device function - obtained during device config n*/
  uint8_t afu_tlx_vc3_mad;                /* 8 bit Memory Address Directive */
  uint8_t afu_tlx_dcp3_data_valid;        /* 1 bit command data valid */
  unsigned char afu_tlx_dcp3_data_bus[64]; /* 512 bit command data bus */
  uint8_t afu_tlx_dcp3_data_bdi;          /* 1 bit bad command data */

  
};
/* *INDENT-ON* */
#endif
