#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <inttypes.h>
#include "TestAFU_config.h"
#include "tlx_interface_t.h"
#include "../../libocxl/libocxl.h"

#define CACHELINE 128
#define MDEVICE "/dev/cxl/afu0.0s"

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
    int opt, option_index, i;
    int rc, timeout;
    char *rcacheline, *wcacheline;
    char *status;
    struct ocxl_afu_h *mafu_h;
    MachineConfig machine_config;
    MachineConfigParam config_param;

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

    printf("rcacheline = 0x");
    for(i=0; i<CACHELINE; i++) {
	rcacheline[i] = rand();
	wcacheline[i] = 0x0;
	status[i] = 0x0;
	printf("%02x", (uint8_t)rcacheline[i]);
    }
    printf("\n");
    
    //status[0]=0xff;
    // open master device
    printf("Calling ocxl_afu_open_dev\n");
    
    mafu_h = ocxl_afu_open_dev(MDEVICE);
    if(!mafu_h) {
	perror("cxl_afu_open_dev: "MDEVICE);
	return -1;
    }
    
    // attach device
    printf("Attaching device ...\n");
    rc = ocxl_afu_attach(mafu_h);
    if(rc != 0) {
	perror("cxl_afu_attach:"MDEVICE);
	return rc;
    }

    printf("Attempt mmio mapping afu registers\n");
    if (ocxl_mmio_map(mafu_h, OCXL_MMIO_BIG_ENDIAN) != 0) {
	printf("FAILED: ocxl_mmio_map\n");
	goto done;
    }
    printf("Attempt Read command\n");
    status[0] = 0xff;
    config_param.context = 0;
    config_param.enable_always = 1;
    config_param.mem_size = CACHELINE;
    config_param.command = AFU_CMD_PR_RD_WNITC;
    config_param.mem_base_address = (uint64_t)rcacheline;
    config_param.machine_number = 0;
    config_param.status_address = (uint32_t)status;
    printf("status address = 0x%p\n", status);
    printf("rcacheline = 0x%p\n", rcacheline);
    printf("command = 0x%x\n", config_param.command);
    printf("mem base address = 0x%"PRIx64"\n", config_param.mem_base_address);
    rc = config_enable_and_run_machine(mafu_h, &machine_config, config_param, DIRECTED);
    //status[0] = 0xff;
    if( rc != -1) {
	printf("Response = 0x%x\n", rc);
	printf("config_enable_and_run_machine PASS\n");
    }
    else {
	printf("FAILED: config_enable_and_run_machine\n");
	goto done;
    }
    timeout = 0;
    while(status[0] != 0x0) {
	printf("Polling read completion status = 0x%x\n", *status);
    }

    // Attemp write command
    printf("Attempt Write command\n");
    status[0] = 0xff;
    config_param.command = AFU_CMD_DMA_W;
    config_param.mem_base_address = (uint64_t)wcacheline;
    printf("wcacheline = 0x%p\n", wcacheline);
    printf("command = 0x%x\n",config_param.command);
    printf("wcache address = 0x%"PRIx64"\n", config_param.mem_base_address);
    rc = config_enable_and_run_machine(mafu_h, &machine_config, config_param, DIRECTED);
    //status[0] = 0xff;
    if(rc != -1) {
	printf("Response = 0x%x\n", rc);
 	printf("config_enable_and_run_machine PASS\n");
    }
    else {
	printf("FAILED: config_enable_and_run_machine\n");
	goto done;
    }
    while(status[0] != 0x00) {
	printf("Polling write completion status = 0x%x\n", *status);
    }
    
    printf("wcacheline = 0x");
    for(i=0; i<CACHELINE; i++) {
	printf("%02x", (uint8_t)wcacheline[i]);
    }
    printf("\n");

done:
    // free device
    printf("Freeing device ... \n");
    ocxl_afu_free(mafu_h);

    return 0;
}
