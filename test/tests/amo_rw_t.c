/*
 * Copyright 2015,2017 International Business Machines
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

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <inttypes.h>
#include "TestAFU_config.h"
#include "tlx_interface_t.h"
//#include "../../libocxl/libocxl.h"
#include <time.h>

#define ProcessControl_REGISTER 0x0018
#define PROCESS_CONTROL_RESTART 0x0000000000000001
#define ProcessInterruptControl_REGISTER 0x0020
#define ProcessInterruptObject_REGISTER 0x0028
#define ProcessInterruptData_REGISTER 0x0030

#define CACHELINE 128
#define MDEVICE "/dev/cxl/tlx0.0000:00:00.1.0"
#define SDEVICE "/dev/cxl/tlx0,000:00:00.2.0"
#define NAME    "IBM,MAFU"
#define PHYSICAL_FUNCTION   "1234:00:00.1"
#define WED_REGISTER 0x0000 
#define AFU_MMIO_REG_SIZE   0x4000000
#define AFU_CONFIGURATION_USE_PE_WED    0x8000000000000000

static int verbose;
static unsigned int buffer_cl = 64;
static unsigned int timeout   = 1;

union amo_data_s {
    unsigned char byte[8];
    uint64_t lword;
} amo_data;

struct AMO_S {
    char name[20];
    int  cmd_flag;
};

enum AMO_RW_FLAGS {
    ADD=0x0, XOR, OR, AND, MAX_UNSIGNED, MAX_SIGNED,
    MIN_UNSIGNED, MIN_SIGNED, SWAP, SWAP_EQUAL, SWAP_NEQUAL 
} amo_rw_cmdflag;

struct work_element {
  uint8_t  command_byte; // left to right - 7:2 cmd, 1 wrap, 0 valid
  uint8_t  status;
  uint16_t length;
  uint8_t  command_extra;
  uint8_t  UNUSED_5;
  uint16_t UNUSED_6to7;
  uint64_t atomic_op1;
  uint64_t source_ea; // or atomic_op2
  uint64_t dest_ea;
};

static void print_help(char *name)
{
    printf("\nUsage:  %s [OPTIONS]\n", name);
    printf("\t--cachelines\tCachelines to copy.  Default=%d\n", buffer_cl);
    printf("\t--timeout   \tDefault=%d seconds\n", timeout);
    printf("\t--verbose   \tVerbose output\n");
    printf("\t--help      \tPrint Usage\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    struct timespec t;
    int opt, option_index, i, j;
    int rc;
    //char adata[16];
    char *rcacheline, *wcacheline;
    char *status;
    ocxl_afu_h mafu_h, safu_h;
    ocxl_irq_h irq_h;
    //ocxl_irq_h err_irq_h;
    ocxl_event event;
    MachineConfig machine_config;
    MachineConfigParam config_param;
    uint64_t irq_id;
    uint64_t result, t_address, ta_offset;
    uint8_t t_page_size;
    uint64_t unused_flags, amo_result;
    ocxl_mmio_h pp_mmio_h, pocxl_mmio_h;
    struct work_element *work_element_descriptor = 0;

    struct AMO_S amo_rw[] = {{"ADD",0x0}, {"XOR", 0x1}, {"OR", 0x2},
        {"AND",0x3},{"MAX_UNSIGNED", 0x4},{"MAX_SIGNED",0x5},
        {"MIN_UNSIGNED",0x6},{"MIN_SIGNED",0x7},{"SWAP", 0x8},
        {"SWAP_EQUAL",0x9},{"SWAP_NEQUAL",0xA}};

    static struct option long_options[] = {
	{"cachelines", required_argument, 0	  , 'c'},
	{"timeout",    required_argument, 0	  , 't'},
	{"verbose",    no_argument      , &verbose,   1},
	{"help",       no_argument      , 0	  , 'h'},
	{NULL, 0, 0, 0}
    };

    while((opt = getopt_long(argc, argv, "vhc:t:", long_options, &option_index)) >= 0 )
    {
	switch(opt)
	{
	    case 'v':
	  	break;
	    case 'c':
		buffer_cl = strtoul(optarg, NULL, 0);
		break;
	    case 't':
		timeout = strtoul(optarg, NULL, 0);
		break;
	    case 'h':
		print_help(argv[0]);
		return 0;
	    default:
		print_help(argv[0]);
		return 0;
	}
    }

    t.tv_sec = 0;
    t.tv_nsec = 100000;
    // initialize machine
    init_machine(&machine_config);

    // align and randomize cacheline
    if (posix_memalign((void**)&rcacheline, CACHELINE, CACHELINE) != 0) {
	perror("FAILED: posix_memalign for rcacheline");
	goto done;
    }
    if (posix_memalign((void**)&wcacheline, CACHELINE, CACHELINE) != 0) {
	perror("FAILED: posix_memalign for wcacheline");
	goto done;
    }
    if(posix_memalign((void**)&status, 128, 128) != 0) {
	perror("FAILED: posix_memalign for status");
	goto done;
    }

    //printf("rcacheline = 0x");
    //for(i=0; i<CACHELINE; i++) {
	//rcacheline[i] = rand();
	//wcacheline[i] = 0x0;
	//status[0] = 0x0;
	//printf("%02x", (uint8_t)rcacheline[i]);
    //}
    printf("\n");
    printf("Prep data for Fetch and incremented bounded test\n");
    //memcpy(adata,"a0a1b0b1c0c1", 12);
    amo_data.lword = 0x0102030411121314;
    memcpy(rcacheline, amo_data.byte, 8);
    //rcacheline = adata + 4;
    printf("rcacheline = 0x");
    for(i=0; i<8; i++){
        printf("%02x", rcacheline[i]);
    }
    printf("\n");
    // open master device
    printf("Attempt open device for mafu\n");
    
    //rc = ocxl_afu_open_from_dev(MDEVICE, &mafu_h);
    rc = ocxl_afu_open_specific(NAME, PHYSICAL_FUNCTION, 0, &mafu_h);
    if(rc != 0) {
	perror("cxl_afu_open_dev: for mafu"MDEVICE);
	return -1;
    }
     
    // attach device
    printf("Attaching mafu device ...\n");
    rc = ocxl_afu_attach(mafu_h, 0);
    if(rc != 0) {
	perror("cxl_afu_attach:"MDEVICE);
	return rc;
    }

    printf("Attempt mmio mapping afu registers\n");
    if (ocxl_mmio_map(mafu_h, OCXL_PER_PASID_MMIO, &pp_mmio_h) != 0) {
	printf("FAILED: ocxl_mmio_map mafu\n");
	goto done;
    }

    printf("Attempt xlate touch cmd.\n");
    config_param.context = 0;
    config_param.enable_always = 1;
    config_param.mem_size = 64;
    config_param.command = AFU_CMD_XLATE_TOUCH;
    config_param.mem_base_address = (uint64_t)rcacheline;
    config_param.machine_number = 0;
    config_param.status_address = (uint32_t)status;
    config_param.cmdflag = 0xe;
    printf("status address = 0x%p\n", status);
    printf("rcacheline = %p\n", rcacheline);
    printf("command = 0x%x\n", config_param.command);
    printf("mem base address = 0x%"PRIx64"\n", config_param.mem_base_address);
    rc = config_enable_and_run_machine(mafu_h, pp_mmio_h, &machine_config, config_param, DIRECTED);
    status[0] = 0xff;
    if( rc != -1) {
       printf("Response = 0x%x\n", rc);
       printf("config_enable_and_run_machine PASS\n");
    }
    else {
       printf("FAILED: config_enable_and_run_machine\n");
       goto done;
    }
    timeout = 0;
    printf("Polling xlate touch cmd completion status\n");
    while(status[0] != 0x0) {
       nanosleep(&t, &t);
       //printf("Polling read completion status = 0x%x\n", *status);
    }
    // clear machine config
    printf("clear_machine_config\n");
    rc = clear_machine_config(pp_mmio_h, &machine_config, config_param, DIRECTED, &result);
    if(rc != 0) {
       printf("Failed to clear machine config for read command\n");
       goto done;
    }
    t_address = result;
    t_page_size = t_address & 0x003F;
    t_address = t_address & 0xFFFFFFFFFFFFFF00;
    ta_offset = (uint64_t)rcacheline & 0x0000FFFF;
    printf("Result = 0x%"PRIx64"\n", result);

    //printf("Attempt AMO RW commands\n");
    for(j=0; j<1; j++) {
        printf("Attempt AMO RW and %s\n", amo_rw[j].name);
        config_param.context = 0;
        config_param.enable_always = 1;
        config_param.mem_size = CACHELINE;
        config_param.command = AFU_CMD_AMO_RW_T;
        config_param.mem_base_address = t_address + ta_offset;
        config_param.machine_number = 0;
        config_param.status_address = (uint32_t)status;
        config_param.cmdflag = amo_rw[j].cmd_flag;
        config_param.oplength = 0x02;
        printf("status address = %p\n", status);
        printf("rcacheline address = %p\n", rcacheline);
        printf("command = 0x%x\n", config_param.command);
        printf("mem base address = 0x%"PRIx64"\n", config_param.mem_base_address);
        rc = config_enable_and_run_machine(mafu_h, pp_mmio_h, &machine_config, 
            config_param, DIRECTED);
        printf("set status data = 0xff\n");
        status[0] = 0xff;
        if( rc != -1) {
	       printf("Response = 0x%x\n", rc);
	       printf("config_enable_and_run_machine PASS\n");
        }  
        else {
	       printf("FAILED: config_enable_and_run_machine\n");
	       goto done;
        }
        timeout = 0;
        printf("Waiting for read command completion status\n");
        while(status[0] != 0x0) {
	       nanosleep(&t, &t);
	   //printf("Polling read completion status = 0x%x\n", *status);
        }
        printf("AMO RW and %s command is completed\n", amo_rw[j].name);
        printf("Get amo result\n");
    //get_machine_memory_dest_address(&machine_config, &amo_result);
    
    // clear machine config
        rc = clear_machine_config(pp_mmio_h, &machine_config, config_param, 
            DIRECTED, &amo_result);
        if(rc != 0) {
	   printf("Failed to clear machine config\n");
	   goto done;
        }
        printf("Verify AMO RW command\n");
        printf("rcacheline = 0x");
        for(i=0; i<8; i++) {
            printf("%02x", rcacheline[i]);
        }
        printf("\n");
    }
/*
    printf("Attempt xlate release cmd 0x51\n");
    config_param.command = AFU_CMD_XLATE_RELEASE;
    config_param.mem_size = 64;
    config_param.machine_number = 0;
    config_param.mem_base_address = t_address | t_page_size;
    //config_param.mem_base_address = (uint64_t)rcacheline;
    config_param.status_address = (uint32_t)status;
    printf("rcacheline = 0x%"PRIx64"\n", rcacheline);
    printf("command = 0x%x\n",config_param.command);
    
    rc = config_enable_and_run_machine(mafu_h, pp_mmio_h, &machine_config, config_param, DIRECTED);
    //status[0] = 0xff;
    if(rc != -1) {
      printf("Response = 0x%x\n", rc);
      printf("config_enable_and_run_machine PASS\n");
    }
    else {
      printf("FAILED: config_enable_and_run_machine\n");
      goto done;
    }
*/ 
    status[0] = 0x55;   // send test complete status
    printf("Polling test completion status\n");
    while(status[0] != 0x00) {
       nanosleep(&t, &t);
       //printf("Polling test completion status\n");
    } 
    printf("Test is completed\n");
    
done:
    // free device
    printf("Freeing mafu device ...\n");
    ocxl_afu_close(mafu_h);

    return 0;
}
