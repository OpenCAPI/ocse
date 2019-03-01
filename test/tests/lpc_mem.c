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
#include "test.h"
#include "TestAFU_config.h"
#include "tlx_interface_t.h"
//#include "../../libocxl/libocxl.h"
//#include "../../libocxl/libocxl_lpc.h"

#define CACHELINE 128
#define MDEVICE "/dev/cxl/tlx0.0000:00:00.1.0"
#define NAME "IBM,MAFU"
#define PHYSICAL_FUNCTION "1234:00:00.1"

static int verbose;
static unsigned int buffer_cl = 64;
static unsigned int timeout   = 1;

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
    //int cr_device, cr_vendor;
    struct timespec t;
    uint64_t result;
    int opt, option_index, i;
    int rc;
    uint8_t *rcacheline, *wcacheline;
    char amo_r[8], amo_w[8];
    char *status;
    ocxl_afu_h mafu_h;
    MachineConfig machine_config;
    MachineConfigParam config_param;
    ocxl_mmio_h pp_mmio_h, mmio_h;

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

    printf("wcacheline = 0x");
    for(i=0; i<CACHELINE; i++) {
	wcacheline[i] = rand();
	rcacheline[i] = 0x0;
	status[i] = 0x0;
	printf("%02x", (uint8_t)wcacheline[i]);
    }
    printf("\n");
    
    //status[0]=0xff;
    // open master device
    printf("Attempt open device for mafu\n");
    
    //rc = ocxl_afu_open_from_dev(MDEVICE, &mafu_h);
    rc = ocxl_afu_open_specific(NAME, PHYSICAL_FUNCTION, 0, &mafu_h);
    if(rc != 0) {
	   perror("cxl_afu_open_dev: "MDEVICE);
	   return -1;
    }
    
    // attach device
    printf("Attaching device ...\n");
    rc = ocxl_afu_attach(mafu_h, 0);
    if(rc != 0) {
	   perror("cxl_afu_attach:"MDEVICE);
	   return rc;
    }

    // mapping device
    printf("Attempt mmio mapping afu registers\n");
    if (ocxl_mmio_map(mafu_h, OCXL_PER_PASID_MMIO, &pp_mmio_h) != 0) {
	   printf("FAILED: ocxl_mmio_map\n");
	   goto done;
    }
    if(ocxl_mmio_map(mafu_h, OCXL_GLOBAL_MMIO, &mmio_h) != 0) {
	   printf("FAILED: ocxl_global_mmio_map\n");
	   goto done;
    }

    printf("Attempt Read command\n");
    config_param.context = 0;
    config_param.enable_always = 1;
    config_param.mem_size = CACHELINE;
    config_param.command = AFU_CMD_RD_WNITC;
    config_param.mem_base_address = (uint64_t)rcacheline;
    config_param.machine_number = 0;
    config_param.status_address = (uint32_t)status;
    printf("status address = 0x%p\n", status);
    printf("rcacheline = 0x%p\n", rcacheline);
    printf("command = 0x%x\n", config_param.command);
    printf("mem base address = 0x%"PRIx64"\n", config_param.mem_base_address);
    rc = config_enable_and_run_machine(mafu_h, pp_mmio_h, &machine_config, config_param, DIRECTED);
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
    printf("Polling read completion status\n");
    while(status[0] != 0x0) {
        nanosleep(&t, &t);
    }
    // clear machine config
    printf("Clearing machine config\n");
    rc = clear_machine_config(pp_mmio_h, &machine_config, config_param, DIRECTED, &result);
    if(rc != 0) {
        printf("Failed to clear machine config\n");
        goto done;
    }
    printf("Attempt lpc memory mapping\n");
    if(ocxl_lpc_map(mafu_h, OCXL_MMIO_LITTLE_ENDIAN) != 0) {
	   printf("FAILED: ocxl_lpc_map\n");
	   goto done;
    }

    // lpc write
    printf("Attempting lpc write\n");
    ocxl_lpc_write(mafu_h, (uint64_t)rcacheline, wcacheline, 64);

    // lpc read
    printf("Attempting lpc read\n");
    ocxl_lpc_read(mafu_h, (uint64_t)rcacheline, rcacheline, 64);
    printf("rcacheline = 0x");
    for(i=0; i<CACHELINE; i++)
	   printf("%02x", (uint8_t)rcacheline[i]);
    printf("\n");
    // lpc amo write
    printf("Attempting lpc amo write\n");
    for(i=0; i< 8; i++) {
        amo_w[i] = i;
    }
    ocxl_lpc_amo_write(mafu_h, 0, 0x00f8b080, amo_w, 4 );
    printf("Attempting lpc amo read\n");
    printf("amo_r address = 0x%p\n", amo_r);
    ocxl_lpc_amo_read(mafu_h, 0xc, 0x00f8b080, amo_r, 4);
    printf("amo_r = 0x");
    for(i=0; i<4; i++) {
        printf("%02x", amo_r[i]);
    }    
    printf("\n");
done:
    // free device
    printf("Freeing device ... \n");
    ocxl_afu_close(mafu_h);

    return 0;
}
