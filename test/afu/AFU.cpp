#include "AFU.h"

#include <string>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <time.h>

using std::string;
using std::cout;
using std::endl;
using std::vector;

#define GLOBAL_CONFIG_OFFSET 0x400
#define CONTEXT_SIZE 0x400
#define CONTEXT_MASK (CONTEXT_SIZE - 1)


AFU::AFU (int port, string filename, bool parity, bool jerror):
    descriptor (filename),
    context_to_mc ()
{

    // initializes AFU socket connection as server
    if (tlx_serv_afu_event (&afu_event, port) == TLX_BAD_SOCKET)
        error_msg ("AFU: unable to create socket");

    if (jerror)
	set_jerror_not_run = true;
    else
	set_jerror_not_run = false;
    set_seed ();

    state = IDLE;
    debug_msg("AFU: state = IDLE");
    reset ();
}

void
AFU::start ()
{
    uint32_t cycle = 0;

    while (1) {
        fd_set watchset;

        FD_ZERO (&watchset);
        FD_SET (afu_event.sockfd, &watchset);
        select (afu_event.sockfd + 1, &watchset, NULL, NULL, NULL);

	// check socket if there are new events from ocse to process
        int rc = tlx_get_tlx_events (&afu_event);

        //info_msg("Cycle: %d", cycle);
        ++cycle;

	// connection dropped
        if (rc < 0) {
            info_msg ("AFU: connection lost");
            break;
        }

	// no new events to be processed
        if (rc <= 0)		
            continue;

        // job done should only be asserted for one cycle
        //if (afu_event.job_done)
        //    afu_event.job_done = 0;

	// process tlx commands
	if (afu_event.tlx_afu_cmd_valid) {
	    debug_msg("AFU: Process TLX commands 0x%x", afu_event.tlx_afu_cmd_opcode);
	    resolve_tlx_afu_cmd();
	}
	// process tlx response
	if (afu_event.tlx_afu_resp_valid) {
	    debug_msg("AFU: Process TLX response 0x%x", afu_event.tlx_afu_resp_opcode);
	    resolve_tlx_afu_resp();
	}

        // generate commands
        if (state == RUNNING) {
            if (context_to_mc.size () != 0) {
                std::map < uint16_t, MachineController * >::iterator prev =
                    highest_priority_mc;
                do {
                    if (highest_priority_mc == context_to_mc.end ())
                        highest_priority_mc = context_to_mc.begin ();
		    //debug_msg("AFU: call MachineController->send_command");
                    if (highest_priority_mc->
                            second->send_command (&afu_event, cycle)) {
                        debug_msg ("AFU: RUNNING complete send_command with context %d",
                                   highest_priority_mc->first);
                        ++highest_priority_mc;
                        break;
                    }
                    //++highest_priority_mc;
                } while (++highest_priority_mc != prev);
            }
        }
        else if (state == RESET) {
            if (reset_delay == 0) {
                state = READY;
		debug_msg("AFU: state = READY");
                reset ();
                debug_msg ("AFU: sending job_done after reset");

        	}
	}
        else if (state == WAITING_FOR_LAST_RESPONSES) {
            //debug_msg("AFU: waiting for last responses");
            bool all_machines_completed = true;

            for (std::map < uint16_t, MachineController * >::iterator it =
                        context_to_mc.begin (); it != context_to_mc.end (); ++it)
            {
                if (!(it->second)->all_machines_completed ())
                    all_machines_completed = false;
            }

            if (all_machines_completed) {
                debug_msg ("AFU: machine completed");

                reset_machine_controllers ();
              
                state = IDLE;
		debug_msg("AFU: state = IDLE");
            }
        }
    }
}

AFU::~AFU ()
{
    // close socket connection
    tlx_close_afu_event (&afu_event);

    for (std::map < uint16_t, MachineController * >::iterator it =
                context_to_mc.begin (); it != context_to_mc.end (); ++it)
        delete it->second;

    context_to_mc.clear ();
}


void
AFU::reset ()
{
    for (uint32_t i = 0; i < 3; ++i)
        global_configs[i] = 0;

    reset_delay = 0;

    reset_machine_controllers ();
}

void
AFU::reset_machine_controllers ()
{
    TagManager::reset ();

    for (std::map < uint16_t, MachineController * >::iterator it =
                context_to_mc.begin (); it != context_to_mc.end (); ++it)
        delete it->second;

    context_to_mc.clear ();

    if (descriptor.is_dedicated ()) {
        context_to_mc[0] = new MachineController (0);
        machine_controller = context_to_mc[0];
        highest_priority_mc = context_to_mc.end ();
    }
}

// process commands from ocse to AFU
void 
AFU::resolve_tlx_afu_cmd()
{
    uint8_t cmd_data;
    
    tlx_afu_read_cmd(&afu_event, afu_event.tlx_afu_cmd_opcode, 
		afu_event.tlx_afu_cmd_capptag, afu_event.tlx_afu_cmd_dl,
		afu_event.tlx_afu_cmd_pl, afu_event.tlx_afu_cmd_be, 
		afu_event.tlx_afu_cmd_end, afu_event.tlx_afu_cmd_t, 
#ifdef	TLX4
	afu_event.tlx_afu_cmd_os, afu_event.tlx_afu_cmd_flag,
#endif
		afu_event.tlx_afu_cmd_pa);
    switch (afu_event.tlx_afu_cmd_opcode) {
	case TLX_CMD_NOP:
	case TLX_CMD_XLATE_DONE:
	case TLX_CMD_RETURN_ADR_TAG:
	case TLX_CMD_INTRP_RDY:
	case TLX_CMD_RD_MEM:
	case TLX_CMD_PR_RD_MEM:
	case TLX_CMD_AMO_RD:
	case TLX_CMD_AMO_RW:
	case TLX_CMD_AMO_W:
	case TLX_CMD_WRITE_MEM:
	case TLX_CMD_WRITE_MEM_BE:
	case TLX_CMD_WRITE_META:
	case TLX_CMD_PR_WR_MEM:
	case TLX_CMD_FORCE_EVICT:
	case TLX_CMD_FORCE_UR:
	case TLX_CMD_WAKE_AFU_THREAD:
	case TLX_CMD_CONFIG_READ:
	    info_msg("AFU::resolve_tlx_afu_cmd: tlx cmd config read");
	    if(afu_event.tlx_afu_cmd_t == 0) {
		// tlx afu config read
		tlx_afu_config_read();
	    }
	    else if(afu_event.tlx_afu_cmd_t == 1) {
		
	    }
	    break;
	case TLX_CMD_CONFIG_WRITE:
	    info_msg("AFU::resolve_tlx_afu_cmd: tlx cmd config write");
	    if(afu_event.tlx_afu_cmd_t == 0) {
		info_msg("AFU::resolve_tlx_afu_cmd: getting BDF");
		// get BDF
		
	    }
	    else {
		// do configuration write
		tlx_afu_config_write();
	    }
	    break;
	default:
	    break;
    }
}

// process responses from ocse to AFU
void
AFU::resolve_tlx_afu_resp()
{
    uint8_t resp_data;

    tlx_afu_read_resp(&afu_event, afu_event.tlx_afu_resp_opcode, 
		afu_event.tlx_afu_resp_afutag, afu_event.tlx_afu_resp_code,
		afu_event.tlx_afu_resp_pg_size, afu_event.tlx_afu_resp_dl,
#ifdef	TLX4
		afu_event.tlx_afu_resp_host_tag, afu_event.tlx_afu_resp_cache_state,
#endif
		afu_event.tlx_afu_resp_dp, afu_event.tlx_afu_resp_addr_tag); 

    switch (afu_event.tlx_afu_resp_opcode) {
	case TLX_RSP_NOP:
	case TLX_RSP_RET_TLX_CREDITS:
	case TLX_RSP_TOUCH_RESP:
	case TLX_RSP_READ_RESP:
	case TLX_RSP_UGRADE_RESP:
	case TLX_RSP_READ_FAILED:
	case TLX_RSP_CL_RD_RESP:
	case TLX_RSP_WRITE_RESP:
	case TLX_RSP_WRITE_FAILED:
	case TLX_RSP_MEM_FLUSH_DONE:
	case TLX_RSP_INTRP_RESP:
	case TLX_RSP_READ_RESP_OW:
	case TLX_RSP_READ_RESP_XW:
	case TLX_RSP_WAKE_HOST_RESP:
	case TLX_RSP_CL_RD_RESP_OW:
	default:
	    break;
    }
}

void
AFU::tlx_afu_config_read()
{
    debug_msg("AFU::tlx_afu_config_read");
    
    afu_tlx_send_resp_and_data(&afu_event, afu_event.afu_tlx_resp_opcode, afu_event.afu_tlx_resp_dl, 
		afu_event.afu_tlx_resp_capptag, afu_event.afu_tlx_resp_dp, 
		afu_event.afu_tlx_resp_code, afu_event.afu_tlx_rdata_valid, 
		afu_event.afu_tlx_rdata_bus, afu_event.afu_tlx_rdata_bad);
    
}

void
AFU::tlx_afu_config_write()
{
    debug_msg("tlx_afu_config_write");
}


void
AFU::resolve_control_event ()
{

        
        for (std::map < uint16_t, MachineController * >::iterator it =
                    context_to_mc.begin (); it != context_to_mc.end (); ++it)
            it->second->disable_all_machines ();
        state = RESET;
	debug_msg("AFU: state = RESET");
        reset_delay = 1000;
}


void
AFU::resolve_response_event (uint32_t cycle)
{
    //if (!TagManager::is_in_use (afu_event.response_tag))
    //    error_msg ("AFU: received tag not in use");


    for (std::map < uint16_t, MachineController * >::iterator it =
                context_to_mc.begin (); it != context_to_mc.end (); ++it) {
        //if (it->second->has_tag (afu_event.response_tag)) {
            it->second->process_response (&afu_event, cycle);
         //   break;
        //}
    }
}

void
AFU::set_seed ()
{
    srand (time (NULL));
}

void
AFU::set_seed (uint32_t seed)
{
    srand (seed);
}

bool 
AFU::get_mmio_read_parity ()
{
    return (global_configs[2] & 0x8000000000000000LL) == 0x8000000000000000;
}
