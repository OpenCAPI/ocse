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
#define TLX3 1

// this is the size of the transimit and receive buffers in the afu_event
// it needs to be large enough to transmit/receive the maximum size of legally concurrent events
// for example from tlx to afu this might be response, dma completion, and buffer write.
// we'll set it at 512 for now and see if we can come up with the correct value later
#define TLX_BUFFER_SIZE 512

#ifdef TLX3
#define PROTOCOL_PRIMARY 3
#define PROTOCOL_SECONDARY 0000
#define PROTOCOL_TERTIARY 0
#endif /* TLX3 */

/* Select # of DMA interfaces, per config options in CH 17 of workbook */
// TODO Remove these CAPI2 DMA port parms
#define TLX_DMA_A_SUPPORT 1
#define TLX_DMA_B_SUPPORT 0
#define MAX_DMA0_RD_CREDITS 8
#define MAX_DMA0_WR_CREDITS 8

/* Return codes for TLX interface functions */

#define TLX_SUCCESS 0
#define TLX_AFU_DOUBLE_COMMAND 1
#define TLX_AFU_CMD_NOT_VALID 2
#define TLX_AFU_DOUBLE_CMD_DATA 3
#define TLX_AFU_CMD_DATA_NOT_VALID 4
#define TLX_AFU_DOUBLE_RESP 5
#define TLX_AFU_RESP_NOT_VALID 6
#define TLX_AFU_DOUBLE_RESP_DATA 7
#define TLX_AFU_RESP_DATA_NOT_VALID 8
#define AFU_TLX_DOUBLE_COMMAND 21
#define AFU_TLX_CMD_NOT_VALID 22
#define AFU_TLX_DOUBLE_CMD_DATA 23
#define AFU_TLX_CMD_DATA_NOT_VALID 24
#define AFU_TLX_DOUBLE_RESP 25
#define AFU_TLX_RESP_NOT_VALID 26
#define AFU_TLX_DOUBLE_RESP_DATA 27
#define AFU_TLX_RESP_DATA_NOT_VALID 28
#define TLX_BAD_SOCKET 16	/* The socket connection could not be established */
#define TLX_VERSION_ERROR 48	/* The TLX versions in use on local & remote do not match */
#define TLX_TRANSMISSION_ERROR 64	/* There was an error sending data across the socket
					   interface */
#define TLX_CLOSE_ERROR 128	/* There was an error closing the socket */

/* TL CAPP Command opcodes (from host to AFU) */

#define TLX_CMD_NOP 0
#define TLX_CMD_XLATE_DONE 	0x18
#define TLX_CMD_RETURN_ADR_TAG  0x19	// TLX4 only
#define TLX_CMD_INTRP_RDY  	0x1a 
#define TLX_CMD_RD_MEM	  	 0x20
#define TLX_CMD_PR_RD_MEM  	0x28
#define TLX_CMD_AMO_RD     	0x30	// TLX4 only
#define TLX_CMD_AMO_RW     	0x31	// TLX4 only
#define TLX_CMD_AMO_W      	0x40	// TLX4 only
#define TLX_CMD_WRITE_MEM  	0x81
#define TLX_CMD_WRITE_MEM_BE	0x82
#define TLX_CMD_WRITE_META	0x83	// OMI ?
#define TLX_CMD_PR_WR_MEM	0x86
#define TLX_CMD_FORCE_EVICT	0xd0	// TLX4 only
#define TLX_CMD_FORCE_UR	0xd2	// TLX4 only
#define TLX_CMD_WAKE_AFU_THREAD	0xdf	// TLX4 only
#define TLX_CMD_CONFIG_READ	0xc0
#define TLX_CMD_CONFIG_WRITE	0xc1


/* TLX AP Command opcodes (from AFU to host) */

#define AFU_CMD_NOP 0
#define AFU_CMD_RD_WNITC 	0x10
#define AFU_CMD_RD_WNITC_S 	0x11 	//TLX4 only
#define AFU_CMD_RD_WNITC_N 	0x14 	
#define AFU_CMD_RD_WNITC_N_S 	0x15 	//TLX4 only
#define AFU_CMD_PR_RD_WNITC 	0x12
#define AFU_CMD_PR_RD_WNITC_S 	0x13 	//TLX4 only
#define AFU_CMD_PR_RD_WNITC_N 	0x16 	
#define AFU_CMD_PR_RD_WNITC_N_S	0x17 	//TLX4 only
#define AFU_CMD_DMA_W  		0x20	
#define AFU_CMD_DMA_W_S  	0x21	// TLX4 only 
#define AFU_CMD_DMA_W_P	  	0x22	// TLX4 only
#define AFU_CMD_DMA_W_P_S	0x23	// TLX4 only
#define AFU_CMD_DMA_W_N	  	0x24
#define AFU_CMD_DMA_W_N_S  	0x25	// TLX4 only
#define AFU_CMD_DMA_W_N_P 	0x26	// TLX4 only
#define AFU_CMD_DMA_W_N_P_S     0x27	// TLX4 only
#define AFU_CMD_DMA_W_BE  	0x28
#define AFU_CMD_DMA_W_BE_S     	0x29	// TLX4 only
#define AFU_CMD_DMA_W_BE_P     	0x2a	// TLX4 only
#define AFU_CMD_DMA_W_BE_P_S   	0x2b	// TLX4 only
#define AFU_CMD_DMA_W_BE_N  	0x2c
#define AFU_CMD_DMA_W_BE_N_S	0x2d	// TLX4 only
#define AFU_CMD_DMA_W_BE_N_P	0x2e	// TLX4 only
#define AFU_CMD_DMA_W_BE_N_P_S	0x2f	// TLX4 only
#define AFU_CMD_DMA_PR_W  	0x30	
#define AFU_CMD_DMA_PR_W_S  	0x31	// TLX4 only 
#define AFU_CMD_DMA_PR_W_P  	0x32	// TLX4 only
#define AFU_CMD_DMA_PR_W_P_S	0x33	// TLX4 only
#define AFU_CMD_DMA_PR_W_N  	0x34
#define AFU_CMD_DMA_PR_W_N_S  	0x35	// TLX4 only
#define AFU_CMD_DMA_PR_W_N_P 	0x36	// TLX4 only
#define AFU_CMD_DMA_PR_W_N_P_S  0x37	// TLX4 only
#define AFU_CMD_AMO_RD  	0x38	
#define AFU_CMD_AMO_RD_S  	0x39	// TLX4 only	
#define AFU_CMD_AMO_RD_N  	0x3c	
#define AFU_CMD_AMO_RD_N_S  	0x3d	// TLX4 only	
#define AFU_CMD_AMO_RW  	0x40	
#define AFU_CMD_AMO_RW_S  	0x41	// TLX4 only	
#define AFU_CMD_AMO_RW_N  	0x44	
#define AFU_CMD_AMO_RW_N_S  	0x45	// TLX4 only	
#define AFU_CMD_AMO_W  		0x48	
#define AFU_CMD_AMO_W_S  	0x49	// TLX4 only 
#define AFU_CMD_AMO_W_P  	0x4a	// TLX4 only
#define AFU_CMD_AMO_W_P_S	0x4b	// TLX4 only
#define AFU_CMD_AMO_W_N  	0x4c
#define AFU_CMD_AMO_W_N_S  	0x4d	// TLX4 only
#define AFU_CMD_AMO_W_N_P 	0x4e	// TLX4 only
#define AFU_CMD_AMO_W_N_P_S  	0x4f	// TLX4 only
#define AFU_CMD_ASSIGN_ACTAG	0x50	
#define AFU_CMD_ADR_TAG_RELEASE	0x51	// TLX4 only	
#define AFU_CMD_MEM_PA_FLUSH	0x52	// TLX4 only	
#define AFU_CMD_CASTOUT		0x55	// TLX4 only	
#define AFU_CMD_CASTOUT_PUSH	0x56	// TLX4 only	
#define AFU_CMD_INTRP_REQ	0x58	
#define AFU_CMD_INTRP_REQ_S	0x59	// TLX4 only	
#define AFU_CMD_INTRP_REQ_D	0x5a	
#define AFU_CMD_INTRP_REQ_D_S	0x5b	// TLX4 only	
#define AFU_CMD_WAKE_HOST_THRD	0x5c	
#define AFU_CMD_WAKE_HOST_THRD_S	0x5d // TLX4 only	
#define AFU_CMD_UPGRADE_STATE	0x60 	// TLX4 only	
#define AFU_CMD_READ_EXCLUSIVE	0x68 	// TLX4 only	
#define AFU_CMD_READ_SHARED	0x69 	// TLX4 only	
#define AFU_CMD_XLATE_TOUCH	0x78 	
#define AFU_CMD_XLATE_TOUCH_N	0x7c	
#define AFU_CMD_RD_WNITC_T	0x90 	// TLX4 only	
#define AFU_CMD_RD_WNITC_T_S	0x91 	// TLX4 only	
#define AFU_CMD_RD_WNITC_T_N	0x94 	// TLX4 only	
#define AFU_CMD_RD_WNITC_T_N_S	0x95 	// TLX4 only	
// there are 20+ more TLX4 only commands; add them later


/* TL CAPP responses (from host to AFU)  */
#define TLX_RSP_NOP 0
#define TLX_RSP_RET_TLX_CREDITS	0x01
#define TLX_RSP_TOUCH_RESP	0x02
#define TLX_RSP_READ_RESP	0x04
#define TLX_RSP_UGRADE_RESP	0x07 	// TLX4 only
#define TLX_RSP_READ_FAILED	0x05
#define TLX_RSP_CL_RD_RESP	0x06 	// TLX4 only
#define TLX_RSP_WRITE_RESP	0x08
#define TLX_RSP_WRITE_FAILED	0x09
#define TLX_RSP_MEM_FLUSH_DONE	0x0a 	// TLX4 only
#define TLX_RSP_INTRP_RESP	0x0c
#define TLX_RSP_READ_RESP_OW	0x0d 	// OMI ?
#define TLX_RSP_READ_RESP_XW	0x0e 	// OMI ?
#define TLX_RSP_WAKE_HOST_RESP	0x10
#define TLX_RSP_CL_RD_RESP_OW	0x16 	// TLX4 only


/* TLX AP responses (from AFU to host) */
#define AFU_RSP_NOP  0
#define AFU_RSP_MEM_RD_RESP	0x01
#define AFU_RSP_MEM_RD_FAIL	0x02
#define AFU_RSP_MEM_RD_RESP_OW	0x03 	// OMI ?
#define AFU_RSP_MEM_WR_RESP	0x04
#define AFU_RSP_MEM_WR_FAIL	0x05
#define AFU_RSP_MEM_RD_RESP_XW	0x07 	// OMI ?
#define AFU_RSP_RET_TL_CREDITS	0x08 	// OMI ?
#define AFU_RSP_WAKE_AFU_RESP	0x0a 	// TLX4 only
#define AFU_RSP_FORCE_UR_DONE	0x0c 	// TLX4 only


// TODO Delete these RCs for PSL interface
#define TLX_DOUBLE_COMMAND 1	/* A command has been issuedbefore the preceeding
				   command of the same type has been acknowledged */
#define TLX_DOUBLE_DMA0_REQ 2
#define TLX_NO_DMA_PORT_CREDITS 3
#define TLX_MMIO_ACK_NOT_VALID 4	/* Read data from previos MMIO read is not available */
#define TLX_BUFFER_READ_DATA_NOT_VALID 8	/* Read data from previous buffer read is notavailable */
#define TLX_COMMAND_NOT_VALID 32	/* There is no TLX command available */
#define TLX_AUX2_NOT_VALID 256	/* There auxilliary signalshave not changed */

/* TODO Remove these CAPI2 Job Control Codes */
#define TLX_JOB_START 0x90
#define TLX_JOB_RESET 0x80
#define TLX_JOB_LLCMD 0x45
#define TLX_JOB_TIMEBASE 0x42

/* TODO Remove these CAPI2 LLCMD decode */
#define TLX_LLCMD_MASK 0xFFFF000000000000LL
#define TLX_LLCMD_TERMINATE 0x0001000000000000LL
#define TLX_LLCMD_REMOVE 0x0002000000000000LL
#define TLX_LLCMD_ADD 0x0005000000000000LL
#define TLX_LLCMD_CONTEXT_MASK 0x000000000000FFFFLL

/* TODO Remove these CAPI2 Response codes for PSL responses */
#define TLX_RESPONSE_DONE 0
#define TLX_RESPONSE_AERROR 1
#define TLX_RESPONSE_DERROR 3
#define TLX_RESPONSE_NLOCK 4
#define TLX_RESPONSE_NRES 5
#define TLX_RESPONSE_FLUSHED 6
#define TLX_RESPONSE_FAULT 7
#define TLX_RESPONSE_FAILED 8
#define TLX_RESPONSE_PAGED 10
#define TLX_RESPONSE_CONTEXT 11
#define TLX_RESPONSE_COMP_EQ 12
#define TLX_RESPONSE_COMP_NEQ 13
#define TLX_RESPONSE_CAS_INV 14

/* TODO remove these CAPI2 Command codes for AFU commands */
#define TLX_COMMAND_READ_CL_NA   0x0A00
#define TLX_COMMAND_READ_CL_S    0x0A50
#define TLX_COMMAND_READ_CL_M    0x0A60
#define TLX_COMMAND_READ_CL_LCK  0x0A6B
#define TLX_COMMAND_READ_CL_RES  0x0A67
#define TLX_COMMAND_READ_PE      0x0A52
#define TLX_COMMAND_READ_PNA     0x0E00
#define TLX_COMMAND_TOUCH_I      0x0240
#define TLX_COMMAND_TOUCH_S      0x0250
#define TLX_COMMAND_TOUCH_M      0x0260
#define TLX_COMMAND_WRITE_MI     0x0D60
#define TLX_COMMAND_WRITE_MS     0x0D70
#define TLX_COMMAND_WRITE_UNLOCK 0x0D6B
#define TLX_COMMAND_WRITE_C      0x0D67
#define TLX_COMMAND_WRITE_NA     0x0D00
#define TLX_COMMAND_WRITE_INJ    0x0D10
#define TLX_COMMAND_PUSH_I       0x0140
#define TLX_COMMAND_PUSH_S       0x0150
#define TLX_COMMAND_EVICT_I      0x1140
#define TLX_COMMAND_FLUSH        0x0100
#define TLX_COMMAND_INTREQ       0x0000
#define TLX_COMMAND_LOCK         0x016B
#define TLX_COMMAND_UNLOCK       0x017B
#define TLX_COMMAND_RESTART      0x0001
#define TLX_COMMAND_ZERO_M	 0x1260
#define TLX_COMMAND_CAS_E_4B	 0x0180
#define TLX_COMMAND_CAS_NE_4B	 0x0181
#define TLX_COMMAND_CAS_U_4B	 0x0182
#define TLX_COMMAND_CAS_E_8B	 0x0183
#define TLX_COMMAND_CAS_NE_8B	 0x0184
#define TLX_COMMAND_CAS_U_8B	 0x0185
#define TLX_COMMAND_ASBNOT	 0x0103
#define TLX_COMMAND_XLAT_RD_P0	 0x1F00
#define TLX_COMMAND_XLAT_RD_P0_00	 0x1F20
#define TLX_COMMAND_XLAT_RD_P0_01	 0x1F21
#define TLX_COMMAND_XLAT_RD_P0_02	0x1F22
#define TLX_COMMAND_XLAT_RD_P0_03	0x1F23
#define TLX_COMMAND_XLAT_RD_P0_04	0x1F24
#define TLX_COMMAND_XLAT_RD_P0_05	0x1F25
#define TLX_COMMAND_XLAT_RD_P0_06	0x1F26
#define TLX_COMMAND_XLAT_RD_P0_07	0x1F27
#define TLX_COMMAND_XLAT_RD_P0_08	0x1F28
#define TLX_COMMAND_XLAT_RD_P0_10	0x1F30
#define TLX_COMMAND_XLAT_RD_P0_11	0x1F31
#define TLX_COMMAND_XLAT_RD_P0_18	0x1F38
#define TLX_COMMAND_XLAT_RD_P0_19	0x1F39
#define TLX_COMMAND_XLAT_RD_P0_1C	0x1F3C
#define TLX_COMMAND_XLAT_WR_P0	 0x1F01
#define TLX_COMMAND_XLAT_WR_P0_20	0x1F40
#define TLX_COMMAND_XLAT_WR_P0_21	0x1F41
#define TLX_COMMAND_XLAT_WR_P0_22	0x1F42
#define TLX_COMMAND_XLAT_WR_P0_23	0x1F43
#define TLX_COMMAND_XLAT_WR_P0_24	0x1F44
#define TLX_COMMAND_XLAT_WR_P0_25	0x1F45
#define TLX_COMMAND_XLAT_WR_P0_26	0x1F46
#define TLX_COMMAND_XLAT_WR_P0_27	0x1F47
#define TLX_COMMAND_XLAT_WR_P0_38	0x1F58
#define TLX_COMMAND_XLAT_RD_P1	 0x1F08
#define TLX_COMMAND_XLAT_WR_P1	 0x1F09
#define TLX_COMMAND_ITAG_ABRT_RD 0x1F02
#define TLX_COMMAND_ITAG_ABRT_WR 0x1F03
#define TLX_COMMAND_XLAT_RD_TOUCH 0x1F10
#define TLX_COMMAND_XLAT_WR_TOUCH 0x1F11
#define AMO_ARMWF_ADD	 0x00
#define AMO_ARMWF_XOR	 0x01
#define AMO_ARMWF_OR	 0x02
#define AMO_ARMWF_AND	 0x03
#define AMO_ARMWF_CAS_MAX_U	 0x04
#define AMO_ARMWF_CAS_MAX_S	 0x05
#define AMO_ARMWF_CAS_MIN_U	 0x06
#define AMO_ARMWF_CAS_MIN_S	 0x07
#define AMO_ARMWF_CAS_U	 0x08
#define AMO_ARMWF_CAS_E	 0x11
#define AMO_ARMWF_CAS_NE	 0x10
#define AMO_ARMWF_INC_B	 0x18
#define AMO_ARMWF_INC_E	 0x19
#define AMO_ARMWF_DEC_B	 0x1c
#define AMO_ARMW_ADD	 0x20
#define AMO_ARMW_XOR	 0x21
#define AMO_ARMW_OR	 0x22
#define AMO_ARMW_AND	 0x23
#define AMO_ARMW_CAS_MAX_U	 0x24
#define AMO_ARMW_CAS_MAX_S	 0x25
#define AMO_ARMW_CAS_MIN_U	 0x26
#define AMO_ARMW_CAS_MIN_S	 0x27
#define AMO_ARMW_CAS_T	 0x38
#define DMA_DTYPE_RD_REQ	0x0
#define DMA_DTYPE_WR_REQ_128	0x1
#define DMA_DTYPE_WR_REQ_MORE	0x2
#define DMA_DTYPE_ATOMIC	0x3
#define DMA_SENT_UTAG_STS_RD	0x0
#define DMA_SENT_UTAG_STS_WR	0x1
#define DMA_SENT_UTAG_STS_FAIL	0x2
#define DMA_SENT_UTAG_STS_FLUSH	0x3
#define DMA_CPL_TYPE_RD_128	0x0
#define DMA_CPL_TYPE_RD_PLUS	0x1
#define DMA_CPL_TYPE_ERR	0x2
#define DMA_CPL_TYPE_POISON_B	0x3
#define DMA_CPL_TYPE_ATOMIC_RSP	0x4


/* Create one of these structures to interface to an AFU model and use the functions below to manipulate it */

/* *INDENT-OFF* */
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

  // TLX to AFU Repsonse Interface (table 1)
  // CAPP to AP (host to afu) responses (generally to ap/capp commands and data)
  uint8_t tlx_afu_resp_valid;             /* 1 bit valid respoonse from tlx */
  uint8_t tlx_afu_resp_opcode;            /* 8 bit response op code */
  uint16_t tlx_afu_resp_afutag;           /* 16 bit response tag - match to afu_tlx_cmd_afutag */
  uint8_t tlx_afu_resp_code;              /* 4 bit response reason code */
  uint8_t tlx_afu_resp_pg_size;           /* 6 bit page size */
  uint8_t tlx_afu_resp_dl;                /* 2 bit encoded data length */
  uint8_t tlx_afu_resp_dp;                /* 2 bit data part - which part of the data is in resp data */
  // uint32_t tlx_afu_resp_host_tag;            /* TLX4 */
  uint32_t tlx_afu_resp_addr_tag;          /* 18 bit bad address tag from a translate request */
  // uint8_t tlx_afu_resp_cache_state;          /* TLX4 */
  
  // AFU to TLX Response Credit Interface (table 2)
  uint8_t afu_tlx_resp_credit;              /* 1 bit return a credit to tlx */
  uint8_t afu_tlx_resp_initial_credit;      /* 7 bit initial number of credits that the afu is providing to tlx for consumption - when is this valid? */
  
  // TLX to AFU Command Interface (table 3)
  // CAPP to AP (host to afu) commands and data 
  uint8_t tlx_afu_cmd_valid;              /* 1 bit command valid from from host */
  uint8_t tlx_afu_cmd_opcode;             /* 8 bit command op code */
  uint16_t tlx_afu_cmd_capptag;           /* 16 bit command tag from host */
  uint8_t tlx_afu_cmd_dl;                 /* 2 bit command encoded data length */
  uint8_t tlx_afu_cmd_pl;                 /* 3 bit command encoded partial data length */
  uint64_t tlx_afu_cmd_be;                /* 64 bit command byte enable */
  uint8_t tlx_afu_cmd_end;                /* 1 bit command endianness 0=little */
  uint8_t tlx_afu_cmd_t;                  /* 1 bit command type 0=configuration read/write; 1=configuration read/write */
  uint64_t tlx_afu_cmd_pa;                /* 64 bit command phyiscal address */
  uint8_t tlx_afu_cmd_flag;               /* 4 bit command flag for atomic memory ops - OCAPI 4 */
  uint8_t tlx_afu_cmd_os;                 /* 1 bit command ordered segment - OCAPI 4 */

  // TLX Command Credit Interface (table 4)
  uint8_t afu_tlx_cmd_credit;              /* 1 bit return a credit to tlx */
  uint8_t afu_tlx_cmd_initial_credit;      /* 7 bit initial number of credits that the afu is providing to tlx for consumption - when is this valid? */
  
  // TLX to AFU Repsonse DATA Interface (table 5)
  // CAPP to AP (host to afu) data responses (generally to ap/capp read commands)
  uint8_t tlx_afu_resp_data_valid;         /* 1 bit response data valid */
  unsigned char tlx_afu_resp_data[64];     /* 512 bit (64 byte) response data */
  uint8_t tlx_afu_resp_data_bdi;           /* 1 bit bad data indicator */
  uint8_t afu_tlx_resp_rd_req;             /* 1 bit response to a read request */
  uint8_t afu_tlx_resp_rd_cnt;             /* 3 bit encoded read count */
  
  // TLX to AFU command DATA Interface (table 6)
  // CAPP to AP (host to afu) data (generally to capp/ap write commands)
  uint8_t tlx_afu_cmd_data_valid;          /* 1 bit command from host valid */
  unsigned char tlx_afu_cmd_data_bus[64];  /* 512 bit (64 byte) command data */
  uint8_t tlx_afu_cmd_data_bdi;            /* 1 bit bad data indicator */
  uint8_t afu_tlx_cmd_rd_req;              /* 1 bit read request */
  uint8_t afu_tlx_cmd_rd_cnt;              /* 3 bit encoded read count */
 
  // TLX Framer Command Interface (table 7)
  uint8_t tlx_afu_resp_credit;             /* 1 bit tlx returning a response credit to the afu */
  uint8_t tlx_afu_resp_data_credit;        /* 1 bit tlx returning a response data credit to the afu */
  uint8_t tlx_afu_cmd_credit;              /* 1 bit tlx returning a command credit to the afu */
  uint8_t tlx_afu_cmd_data_credit;         /* 1 bit tlx returning a command data credit to the afu */
  uint8_t tlx_afu_cmd_resp_initial_credit; /* 3 bit initial number of response credits available to the afu - when is this valid? */
  uint8_t tlx_afu_data_initial_credit;     /* 5 bit initial number of data credits available to the afu - when is this valid? */

  // TLX Framer Command Interface (table 8)
  // AP to CAPP (afu to host) commands and data
  uint8_t afu_tlx_cmd_valid;              /* 1 bit 0|1 indicates that a valid command is being presented by the afu to tlx */
  uint8_t afu_tlx_cmd_opcode;             /* 8 bit opcode */
  uint16_t afu_tlx_cmd_actag;             /* 12 bit address context tag */
  uint8_t afu_tlx_cmd_stream_id;          /* 4 bit address context tag */
  unsigned char afu_tlx_cmd_ea_or_obj[9]; /* 68 bit effective address or object handle */
  uint16_t afu_tlx_cmd_afutag;            /* 16 bit command tag */
  uint8_t afu_tlx_cmd_dl;                 /* 2 bits encoded data length */  /* combine dl and pl ??? */
  uint8_t afu_tlx_cmd_pl;                 /* 3 bits encoded partial data length */
  uint8_t afu_tlx_cmd_os;                 /* 1 bit ordered segment CAPI 4 */
  uint64_t afu_tlx_cmd_be;                /* 64 bit byte enable */
  uint8_t afu_tlx_cmd_flag;               /* 4 bit command flag for atomic opcodes */
  uint8_t afu_tlx_cmd_endian;             /* 1 bit endianness 0=little endian; 1=big endian */
  uint16_t afu_tlx_cmd_bdf;               /* 16 bit bus device function - obtained during device config n*/
  uint32_t afu_tlx_cmd_pasid;             /* 20 bit PASID */
  uint8_t afu_tlx_cmd_pg_size;            /* 6 bit page size hint */
  uint8_t afu_tlx_cdata_valid;            /* 1 bit command data valid */
  unsigned char afu_tlx_cdata_bus[64];    /* 512 bit command data bus */
  uint8_t afu_tlx_cdata_bad;              /* 1 bit bad command data */

  // TLX Framer Response Interface (table 9)
  uint8_t afu_tlx_resp_valid;             /* 1 bit afu response is valid */
  uint8_t afu_tlx_resp_opcode;            /* 8 bit response op code */
  uint8_t afu_tlx_resp_dl;                /* 2 bit response data length */
  uint16_t afu_tlx_resp_capptag;          /* 16 bit response capptag - should match a tlx_afu_cmd_capptag */
  uint8_t afu_tlx_resp_dp;                /* 2 bit response data part */
  uint8_t afu_tlx_resp_code;              /* 4 bit response reason code */
  uint8_t afu_tlx_rdata_valid;            /* 6 bit response data is valid */
  unsigned char afu_tlx_rdata_bus[64];    /* 512 bit response data */
  uint8_t afu_tlx_rdata_bad;              /* 1 bit response data is bad */
  				       
  // TLX Framer Template Configuration (table 10)
  uint8_t afu_cfg_xmit_tmpl_config_0;     /* 1 bit xmit template enable - default */
  uint8_t afu_cfg_xmit_tmpl_config_1;     /* 1 bit xmit template enable */
  uint8_t afu_cfg_xmit_tmpl_config_2;     /* 1 bit xmit template enable - not in TLX3 */
  uint8_t afu_cfg_xmit_tmpl_config_3;     /* 1 bit xmit template enable */
  uint8_t afu_cfg_xmit_rate_config_0;     /* 4 bit xmit rate */
  uint8_t afu_cfg_xmit_rate_config_1;     /* 4 bit xmit rate */
  uint8_t afu_cfg_xmit_rate_config_2;     /* 4 bit xmit rate - not in TLX3 */
  uint8_t afu_cfg_xmit_rate_config_3;     /* 4 bit xmit rate */
  				       
  // CREDITS!!!

  // job is no longer a tlx interface TODO This goes away eventually
  uint64_t job_address;               /* effective address of the work element descriptor */
  uint64_t job_error;                 /* error code for completed job */
  uint32_t job_valid;                 /* AFU event contains a valid job control command */
  uint32_t job_code;                  /* job control command code as documented in the TLX workbook */
  uint32_t job_running;               /* a job is running in the accelerator */
  uint32_t job_done;                  /* a job has completed in the accelerator */
  uint32_t job_cack_llcmd;            /* LLCMD command has been processed by AFU */
  uint32_t job_code_parity;           /* Odd parity for ha_jcom (job_code) valid with ha_jval (job_valid) */
  uint32_t job_address_parity;        /* Odd parity for ha_jea (job_address) valid with ha_jval (job_valid) */
  uint32_t job_yield;                 /* Used to save context in Shared mode. */
  uint32_t timebase_request;          /* Requests TLX to send a timebase control command with current timebase value. */
  uint32_t parity_enable;             /* If asserted, AFU supports parity generation on various interface buses. */
  // port mmio to some sort of partial read/write TODO This goes away/mmio & 
  // config rd/wr go thru TLX->AFU cmd interface
  uint32_t mmio_address;              /* word address of the MMIO data to read/write */
  uint32_t mmio_address_parity;       /* Odd parity for MMIO address */
  uint64_t mmio_wdata;                /* write data for MMIO writes, unused if mmio_read is true */
  uint64_t mmio_wdata_parity;         /* Odd parity for MMIO write data */
  uint64_t mmio_rdata;                /* read data for MMIO reads */
  uint64_t mmio_rdata_parity;         /* Odd parity for MMIO read data */
  uint32_t mmio_valid;                /* AFU event contains a valid MMIO command */
  uint32_t mmio_read;                 /* MMIO command is a read type (otherwise it is a write type) */
  uint32_t mmio_double;               /* MMIO command is a 64-bit operation (otherwise read and write data should be limited to 32 bits) */
  uint32_t mmio_ack;                  /* MMIO command has been acknowledged */
  uint32_t mmio_afudescaccess;        /* MMIO command is access to AFU descriptor space */
  // port response to tlx_afu response stuff
  uint32_t response_valid;            /* AFU event contains a valid TLX response */
  uint32_t response_tag;              /* tag value from the command in the TLX_EVENT that is being responded to */
  uint32_t response_code;             /* response code for the command with tag value above as documented in the TLX workbook */
  int32_t credits;                    /* number of credits (positive or negative) to return to the AFU */
  // defer cache support to TLX4
  uint32_t cache_state;               /* cache state granted to the AFU as documented in the TLX workbook */
  uint32_t cache_position;            /* The cache position assigned by TLX */
  uint32_t response_tag_parity;       /* Odd parity for ha_rtag valid with ha_rvalid */
  uint32_t response_dma0_itag;        /* DMA translation tag for xlat_ *requests */
  uint32_t response_dma0_itag_parity; /* DMA translation tag parity   */
  uint32_t response_extra;            /* extra response information received from xlate logic */
  uint32_t response_r_pgsize;         /* command translated page size. values defined in CAIA2 workbook */
  // buffer reads are no longer driven from tlx.  rather they are driven complete from the afu as a write form of command
  uint32_t buffer_read;               /* AFU event contains a valid buffer read request */
  uint32_t buffer_read_tag;           /* tag from command in TLX_EVENT which requested the buffer read */
  uint32_t buffer_read_tag_parity;    /* Odd parity for buffer read tag */
  uint32_t buffer_read_address;       /* address within the transfer of the 64 byte chunk of data to read */
  uint32_t buffer_read_length;        /* length of transfer, must be either 64 or 128 bytes */
  uint32_t buffer_read_latency;       /* Read buffer latency in clocks */
  // buffer writes are sourced from the tlx
  uint32_t buffer_write;              /* AFU event contains a valid buffer write request */
  uint32_t buffer_write_tag;          /* tag from command in TLX_EVENT which requested the buffer write */
  uint32_t buffer_write_tag_parity;   /* Odd parity for buffer write tag */
  uint32_t buffer_write_address;      /* address within the transfer of the 64 byte chunk of data to write */
  uint32_t buffer_write_length;       /* length of transfer, must be either 64 or 128 bytes */
  unsigned char buffer_wdata[128];    /* 128B data to write to the AFUs buffer (only first half used for 64B calls) */
  unsigned char buffer_wparity[2];    /* 128b parity for the write data (only first half used for 64B calls) */
  uint32_t buffer_rdata_valid;        /* buffer read data is valid */
  unsigned char buffer_rdata[128];    /* 128B data to read from the AFUs buffer (only first half used for 64B calls) */
  unsigned char buffer_rparity[2];    /* 128b parity for the read data (only first half used for 64B calls) */
  uint32_t aux1_change;               /* The value of one of the auxilliary signals has changed (room) */
  uint32_t room;                      /* the number of commands TLX has room to accept */
  uint64_t command_address;           /* effective address for commands requiring an address */
  uint64_t command_address_parity;    /* Odd parity for effective address for command */
  uint32_t command_valid;             /* AFU event contains a valid command */
  uint32_t command_tag;               /* tag associated with the command. used for buffer allocation and response matching */
  uint32_t command_tag_parity;        /* Odd parity for command tag */
  uint32_t command_code;              /* command code as documented in the TLX workbook */
  uint32_t command_code_parity;       /* Odd parity for command code */
  uint32_t command_size;              /* number of bytes for commands requiring transfer size */
  uint32_t command_abort;             /* indicates that the command may be aborted */
  uint32_t command_handle;            /* Context handle (Process Element ID) */
  uint32_t aux2_change;               /* The value of one of the auxilliary signals has changed (running, job done or error, read latency) */
  uint32_t command_cpagesize;	      /*  Page size hint used by TLX for predicting page size during ERAT lookup & paged xlation ordering..codes documented in TLX workbook tbl 1-1 */
  // dma's are no longer a separate path.
  uint32_t dma0_dvalid;     	      /* DMA request from AFU is valid */
  uint32_t dma0_req_utag;	      /* DMA transaction request user transaction tag */
  uint32_t dma0_req_itag;     	      /* DMA transaction request user translation identifier */
  uint32_t dma0_req_type;	      /* DMA transaction request transaction type.  */
  uint32_t dma0_req_size;	      /* DMA transaction request transaction size in bytes */
  uint32_t dma0_atomic_op;	      /* Transaction request attribute - Atomic opcode */
  uint32_t dma0_atomic_le;	      /* Transaction request attribute - Little Endian used */
  uint32_t dma0_sent_utag_valid;      /* DMA request sent by TLX */
  uint32_t dma0_sent_utag;    	      /* DMA sent request indicates the UTAG of the request sent by TLX */
  uint32_t dma0_sent_utag_status;     /* DMA sent request indicates the status of the command that was sent by TLX. */
  uint32_t dma0_completion_valid;     /* DMA completion received  */
  uint32_t dma0_completion_utag;      /* DMA completion indicates the UTAG associated with the received completion data */
  uint32_t dma0_completion_type;      /* DMA completion indicates the type of response received with the current completion */
  uint32_t dma0_completion_size;      /* DMA completion indicates size of completion received */
  uint32_t dma0_completion_laddr;     /* DMA completion Atomic attribute - lower addr bits of rx cmpl */
  uint32_t dma0_completion_byte_count; /* DMA completion remaining amount of bytes required to complete originating read request
						including bytes being transferred in the current transaction   */
  unsigned char dma0_req_data[128];	      /* DMA data alignment is First byte first */
  unsigned char dma0_completion_data[128];  /* DMA completion data alignment is First Byte first */
  signed char dma0_wr_credits;	/* Used to limit # of outstanding DMA wr ops to MAX_DMA0_WR_CREDITS  */
  signed char dma0_rd_credits;	/* Used to limit # of outstanding DMA rd ops to MAX_DMA0_RD_CREDITS  */
  unsigned char dma0_rd_partial;;	/* Used to determine bc for DMA xfers > 128B  */
  unsigned char dma0_wr_partial;;	/* Used to determine bc for DMA xfers > 128B  */
};
/* *INDENT-ON* */

#endif
