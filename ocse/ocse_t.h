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
 * Description: ocse_t.h
 *
 *  This file contains the major type declarations used throughout ocse code.
 *  simulator(s) and allows client applications to connect for accessing the
 *  AFU(s).  When OCSE is executed parse_host_data() is called to find and
 *  connect to any AFU simulators specified in the shim_host.dat file. Each
 *  successful simulator connection will cause a seperate thread to be launched.
 *  The code for those threads is in ocl.c.  As long as at least one simulator
 *  connection is valid then OCSE will remain active and awaiting client
 *  connections.  Each time a valid client connection is made it will be
 *  assigned to the appropriate ocl thread for whichever AFU it is accessing.
 *  If it is the first client to connect then the AFU is reset and the AFU
 *  descriptor is read.
 */

#ifndef _OCSE_T_H_
#define _OCSE_T_H_


#include "../common/utils.h"
#include "../common/tlx_interface_t.h"

// formerly client.h
enum client_state {
	CLIENT_NONE,
	CLIENT_INIT,
	CLIENT_VALID
};

enum flush_state {
	FLUSH_NONE,
	FLUSH_PAGED,
	FLUSH_FLUSHING
};

struct client {
	int pending;
	int idle_cycles;
	int fd;
	int context;
	int abort;
	int timeout;
	enum flush_state flushing;
	enum client_state state;
	char type;
	uint64_t AMR;
	uint32_t pasid;
	uint16_t bdf;
  uint8_t bus;
  uint8_t dev;
  uint8_t fcn;
  uint8_t afuid;
  // uint16_t actag;
	uint32_t mmio_offset;
	uint32_t mmio_size;
	void *mem_access;
	void *mmio_access;
	char *ip;
	pthread_t thread;
	struct client *_prev;
	struct client *_next;
};

// formerly parms.h
struct parms {
	uint32_t timeout;
	uint32_t seed;
	uint32_t pagesize;
	uint32_t host_CL_size;
	uint32_t resp_percent;
	uint32_t paged_percent;
	uint32_t retry_percent;
	uint32_t lw_retry_percent;
	uint32_t failed_percent;
	uint32_t pending_percent;
	uint32_t pending_kill_xlate_percent;
	uint32_t derror_percent;
	uint32_t int_retry_percent;
	uint32_t int_failed_percent;
	uint32_t int_pending_percent;
	uint32_t int_derror_percent;
	uint32_t bdi_resp_err_percent;
	uint32_t bdi_cmd_err_percent;
	uint32_t reorder_percent;
	uint32_t buffer_percent;
};

// formerly mmio.h
// need to abstract dw - add a size element
// need to allow for dl and dp - add dl and dp elements
struct mmio_event {
	uint32_t rnw;
	uint32_t dw;    // TODO remove this ?  Maybe, we need to know 4/8 byte mmio  cmd_pL is an encoded length
	uint32_t cfg;
	uint64_t cmd_data;
	uint64_t cmd_PA;
	uint64_t cmd_ea;
	uint32_t cmd_host_tag;
	uint16_t cmd_pasid;
	uint16_t cmd_CAPPtag;
	uint8_t cmd_opcode;
	uint8_t cmd_flg;
	uint8_t cmd_pL;
        uint8_t cmd_dL;     // dL, dP, and pL are encoded from either size or dw in send_mmio
        uint8_t cmd_dP;
        uint8_t cmd_pg_size;
        uint16_t cmd_bdf;
	uint8_t cmd_endian;
  // parallel records for general capp commands
        uint16_t partial_index;  // this keeps track of where we are if multiple beats of data are coming with this response
        uint8_t ack;    // use this to hold the ack value for the message back to libocxl
        uint8_t resp_dL;     // the encoded length of the data in this part of the response 
        uint8_t resp_dP;     // the encoded offset of the location of this portion of the response
        uint8_t resp_code;    // use this to hold the resp value for the message back to libocxl
        uint8_t resp_opcode;    // use this to hold the resp opcode for the message back to libocxl
        uint8_t be_valid;  // use this to let us know whether or not to use the byte enable
        uint32_t size;  // if size = 0, we use dw to imply size
        uint32_t size_received;  // keep track of the total amount of data we have received from the afu response
        uint8_t *data;  // if size = 0, we use cmd_data as the data field
        uint8_t *dataw;  // used for capp amo_rw commands only
        uint64_t be;  // if be_valid, use this as the byte enable in the command
	enum ocse_state state;
        struct client *client;
	struct mmio_event *_next;
};

// per afu structure
// this is where we save the per afu config space data during discovery
// query/open will look for this based on the afu index parsed from the given device name
struct afu_cfg {
      // from AFU Control DVSEC
      uint8_t pasid_base;
      uint8_t pasid_len_enabled;
      uint8_t pasid_len_supported;
      uint16_t actag_base;
      uint16_t actag_length_enabled;
      uint16_t actag_length_supported;
      
      // from AFU Descriptor Template 0 via AFU Information DVSEC
      char namespace[25];  // (24 characters +1 to capture \0)
      uint8_t afu_version_major;
      uint8_t afu_version_minor;
      uint8_t  global_mmio_bar;
      uint64_t global_mmio_offset;
      uint32_t global_mmio_size;
      uint8_t  pp_mmio_bar;
      uint64_t pp_mmio_offset;
      uint32_t pp_mmio_stride;
      uint64_t mem_base_address;
      uint8_t  mem_size;
};

// per function structure
// this is where we save the interesting per function config space data during discovery and configuration
// query/open will look for this based on function number parsed from the given device name
struct fcn_cfg {
      // from config space header
      uint16_t device_id;
      uint16_t vendor_id;
      uint64_t bar0; // TODO: discover - write all 1's, read back size, configure - write configured base address
      uint64_t bar1; // "
      uint64_t bar2; // "

      // from process address space id extended capability
      uint8_t max_pasid_width; // per process dvsec.max pasid width

      // from OpenCAPI Transport Layer DVSEC (designated vendor specific extended capability)
      uint8_t tl_major_version_capability; // 0x0c
      uint8_t tl_minor_version_capability; // 0x0c
      uint32_t tl_xmit_template_cfg; // 0x24 - we only look at the cfg for templates 31 downto 0
      uint32_t tl_xmit_rate_per_template_cfg; // 0x6c - we only look at the cfg for templates 7 to 0

      // from Function DVSEC
      uint64_t function_dvsec_pa;
      uint8_t afu_present;
      uint8_t max_afu_index;
      uint16_t function_actag_base;
      uint16_t function_actag_length_enabled;

      // pointer to an array of pointers to per afu structures null if no afus (afu_function_dvsec.afu_present=0), 
      // length of array is function_dvsec.max_afu_index+1
      // this array will be indexed by the afu index part of the device name
      uint64_t afu_information_dvsec_pa;
      struct afu_cfg **afu_cfg_array;
};


struct mmio {
	struct AFU_EVENT *afu_event;
        struct fcn_cfg **fcn_cfg_array;  // this array will be indexed by the function part of the device name
	struct mmio_event *list;
	char *afu_name;
	FILE *dbg_fp;
	uint8_t dbg_id;
	uint32_t flags;
        uint16_t CAPPtag_next;
	int timeout;
};

// formerly cmd.h
enum cmd_type {
	CMD_READ,
	CMD_WRITE,
	CMD_TOUCH, 
	CMD_XL_TO_PA,  
	CMD_INTERRUPT,
	CMD_WAKE_HOST_THRD,
	CMD_WR_BE,
	CMD_AMO_RD,
	CMD_AMO_RW,
	CMD_AMO_WR,
	CMD_XLATE_REL, // release TA from CMD_XL_TOUCH
	CMD_KILL_DONE, 
	CMD_FAILED,
	CMD_SYNC,
	CMD_CACHE,
	CMD_CACHE_RD,
	CMD_OTHER
};

enum mem_state {
	MEM_IDLE,
	MEM_XLATE_PENDING,
	MEM_INT_PENDING,
	MEM_PENDING_SENT,
	MEM_TOUCH,
	MEM_TOUCHED,
	MEM_BUFFER,
	MEM_REQUEST,
	MEM_CAS_RD,
	//MEM_CAS_WR,
	MEM_RECEIVED,
	AMO_MEM_RESP,
	DMA_MEM_RESP,
	MEM_KILL_XLATE_SENT,
	MEM_SYNC,
	MEM_DONE
};


// struct pages {
//	uint64_t entry[PAGE_ENTRIES][PAGE_WAYS];
//	uint64_t entry_filter;
//	uint64_t page_filter;
//	int age[PAGE_ENTRIES][PAGE_WAYS];
//	uint8_t valid[PAGE_ENTRIES][PAGE_WAYS];
// };

struct cmd_event {
	uint64_t addr;
	int32_t context;
	uint32_t command;
	uint32_t afutag;
	uint32_t size;
	uint32_t resp;  // this is used as resp_code TODO change this to  resp_code
	uint32_t port;
	uint32_t resp_dl;
	uint32_t resp_dp;
	uint32_t resp_opcode;
        uint64_t resp_ta;
        uint32_t host_tag;
        uint8_t cache_state;
        uint8_t resp_ef;
        uint8_t resp_w;
        uint8_t resp_mh;
        uint8_t  resp_pg_size;
        uint16_t resp_capptag;  //???
	uint32_t dpartial;
	uint64_t wr_be;
	uint16_t resp_bytes_sent;
	uint16_t service_q_slot;
	uint8_t sync_b4me;
	uint8_t cmd_flag;
	uint8_t cmd_endian;
	uint8_t cmd_pg_size;
	uint8_t form_flag; // 0x1 = .S, 0x2= .P, 0x4 = .N , 0x80= .T form of AP instruction
	uint8_t stream_id;
	uint8_t unlock;
	uint8_t buffer_activity;
	uint8_t *data;
	//uint8_t *parity;
	int *abort;
	enum cmd_type type;
	enum mem_state state;
	enum client_state client_state;
	uint16_t presyncq[24];
	struct cmd_event *_next;
	struct cmd_event *_prev;
};

struct actag {
        uint8_t valid;
        uint32_t pasid;
        struct client *client;
};

struct cmd {
	struct AFU_EVENT *afu_event;
	struct cmd_event *list;
	struct cmd_event *buffer_read;
	struct mmio *mmio;
	struct parms *parms;
	struct client **client;
	struct actag *actag_array;
        // struct pages page_entries;
	volatile enum ocse_state *ocl_state;
	char *afu_name;
	FILE *dbg_fp;
	uint8_t dbg_id;
	uint64_t lock_addr;
	//uint64_t res_addr;
	int max_clients;
        int max_actags;
	uint32_t pagesize;
	uint32_t HOST_CL_SIZE;
	uint16_t irq;
	//int locked;
};

// formerly ocl.h
struct host_tag {
  uint32_t ca_host_tag;
  uint32_t context;
  uint8_t ca_state;
  uint8_t ef_expected;
  struct host_tag *_next;
};

struct ocl {
	struct AFU_EVENT *afu_event;
	pthread_t thread;
	pthread_mutex_t *lock;
	FILE *dbg_fp;
	struct client **client;
        struct actag *actag_array;
	struct cmd *cmd;
	struct mmio *mmio;
	struct host_tag *host_tag;
	struct ocl **head;
	struct ocl *_prev;
	struct ocl *_next;
	volatile enum ocse_state state;
	uint32_t latency;
	char *name;
	char *host;
        uint8_t bus;
	uint8_t dbg_id;
	int port;
	int idle_cycles;
        int max_clients;                 // this is the sum of the max_pasids in each functions pasid dvsec
        int max_actags;
	int attached_clients;
	int timeout;
	int has_been_reset;
        int next_host_tag;
};

#endif				/* _OCSE_T_H_ */
