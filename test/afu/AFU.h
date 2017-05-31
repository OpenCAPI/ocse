#ifndef __afu_h__
#define __afu_h__

#include "Descriptor.h"
#include "TagManager.h"
#include "MachineController.h"

extern "C" {
#include "tlx_interface.h"
#include "utils.h"
}

#include <string>
#include <vector>

#define RIGHT	1
#define LEFT	0

uint8_t memory[128];

class AFU
{
private:
    enum AFU_State
    { IDLE, RESET, READY, RUNNING, WAITING_FOR_DATA, WAITING_FOR_LAST_RESPONSES, HALT };

    AFU_EVENT afu_event;
    Descriptor descriptor;

    std::map < uint16_t, MachineController * >context_to_mc;
    std::map < uint16_t,
        MachineController * >::iterator highest_priority_mc;

    MachineController *machine_controller;

    AFU_State state;
    AFU_State config_state;
    AFU_State mem_state;

//    uint8_t  memory[128];
    uint64_t global_configs[3];	// stores MMIO registers for global configurations
    uint8_t  tlx_afu_cmd_max_credit;
    uint8_t  tlx_afu_data_max_credit;

    int reset_delay;

    void resolve_tlx_afu_cmd();
    void resolve_tlx_afu_resp();
    void tlx_afu_config_read();
    void tlx_afu_config_write();
    void tlx_pr_rd_mem();
    void tlx_pr_wr_mem();
    void byte_shift(unsigned char* array, uint8_t size, uint8_t offset, uint8_t direction);
    void resolve_control_event ();
    void resolve_response_event (uint32_t cycle);
    void set_seed ();
    void set_seed (uint32_t);
    bool afu_is_enabled();
    bool afu_is_reset();
    void reset ();
    void reset_machine_controllers ();
    bool get_machine_context();
    void request_assign_actag();

    bool get_mmio_read_parity ();
    bool set_jerror_not_run;

public:
    /* constructor sets up descriptor from config file, establishes server socket connection
       and waits for client to connect */
    AFU (int port, std::string filename, bool parity, bool jerror);

    /* starts the main loop of the afu test platform */
    void start ();

    /* destrutor close the socket connection */
    ~AFU ();

};


#endif
