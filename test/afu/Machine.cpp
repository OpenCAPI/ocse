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

    #include "Machine.h"
    #include "MachineController.h"

    #include <stdlib.h>
    static uint64_t translated_address;

    MachineController::Machine::Machine (uint16_t c)
    {
    reset ();

    config[0] = (config[0] & 0xFFFF0000FFFFFFFFLL) | ((uint64_t) c << 32);
    }

    void
    MachineController::Machine::reset ()
    {
    delay = 0;
    command = NULL;

    for (uint32_t i = 0; i < SIZE_CONFIG_TABLE; ++i)
        config[i] = 0;

    for (uint32_t i = 0; i < SIZE_CACHE_LINE; ++i)
        cache_line[i] = 0;
    }

    void
    MachineController::Machine::read_machine_config (AFU_EVENT* afu_event)
    {
    printf("Machine: config\n");
    printf("config[0] = 0x%016lx\n", config[0]);
    printf("config[1] = 0x%016lx\n", config[1]);
    printf("config[2] = 0x%016lx\n", config[2]);
    printf("config[3] = 0x%016lx\n", config[3]);

    context = (config[0] >> 32) & 0xFFFF;

    min_delay = (config[0] >> 16) & 0xFFFF;
    max_delay = config[0] & 0xFFFF;

    if (min_delay > max_delay)
        error_msg
        ("Machine: min_delay is larger than max_delay (min_delay = %d, max_delay = %d)",
         min_delay, max_delay);
    delay =
        (max_delay ==
         min_delay) ? max_delay : rand () % (max_delay - min_delay) +
        min_delay;

    abort = (config[1] >> 60) & 0x7;
    command_size = (config[1] >> 48) & 0xFFF;

    memory_base_address = config[2];

    memory_size = (uint16_t)config[1];
    printf("Machine: memory_size = 0x%x\n", memory_size);
    switch(memory_size) {
    case 1:
        afu_event->afu_tlx_vc3_pl = 0;
        break;
    case 2:
        afu_event->afu_tlx_vc3_pl = 1;
        break;
    case 4:
        afu_event->afu_tlx_vc3_pl = 2;
        break;
    case 8:
        afu_event->afu_tlx_vc3_pl = 3;
        break;
    case 16:
        afu_event->afu_tlx_vc3_pl = 4;
        break;
    case 64:
        afu_event->afu_tlx_vc3_dl = 1;
        break;
    case 128:
        afu_event->afu_tlx_vc3_dl = 2;
        break;
    default:
        break;
    }
    uint16_t command_code = (config[0] >> 48) & 0x1FFF;
    bool command_address_parity = get_command_address_parity ();
    bool command_code_parity = get_command_code_parity ();
    bool command_tag_parity = get_command_tag_parity ();
    bool buffer_read_parity = get_buffer_read_parity ();
    afu_event->afu_tlx_vc3_cmdflag = (config[1] >> 16);

    if (command)
        delete command;
    printf("command code = 0x%x\n", command_code);

    switch (command_code) {
        case AFU_CMD_AMO_RD:
        afu_event->afu_tlx_vc3_pl = (config[1] >> 24);
        //afu_event->afu_tlx_vc3_cmdflag = (config[1] >> 16);
        printf("Machine: amo_rd pl=0x%x and cmdflag=0x%x\n", afu_event->afu_tlx_vc3_pl,
            afu_event->afu_tlx_vc3_cmdflag);
        command = new LoadCommand (command_code, command_address_parity,
                 command_code_parity, command_tag_parity, buffer_read_parity);
        break;
        case AFU_CMD_AMO_RW:
        afu_event->afu_tlx_vc3_pl = (config[1] >> 24);
        printf("Machine: amo_rw pl=0x%x and cmdflag=0x%x\n", afu_event->afu_tlx_vc3_pl,
            afu_event->afu_tlx_vc3_cmdflag);
        command = new StoreCommand (command_code, command_address_parity,
                 command_code_parity, command_tag_parity, buffer_read_parity);
        break;
        case AFU_CMD_AMO_RW_T:
            printf("Machine: amo_rw_t pl = 0x%x and cmdflag = 0x%x\n", 
                afu_event->afu_tlx_vc3_pl,
                afu_event->afu_tlx_vc3_cmdflag);
            command = new StoreCommand(command_code, command_address_parity, 
                command_code_parity, command_tag_parity, buffer_read_parity);
            break;
        case AFU_CMD_AMO_W_T_P:
            printf("Machine: amo_w_t_p pl=0x%x and cmdflag=0x%x\n",
                afu_event->afu_tlx_vc3_pl,
                afu_event->afu_tlx_vc3_cmdflag);
            command = new StoreCommand(command_code, command_address_parity,
                command_code_parity, command_tag_parity, buffer_read_parity);
            break;
        case AFU_CMD_AMO_RD_T:
            printf("Machine: amo_rd.t pl = 0x%x and cmdflag=0x%x\n", 
                afu_event->afu_tlx_vc3_pl, afu_event->afu_tlx_vc3_cmdflag);
            memory_base_address = memory_base_address | 0xF000000000000000LL;
            printf("Machine: translated_address = 0x%llx\n", memory_base_address);
            command = new LoadCommand(command_code, command_address_parity,
                command_code_parity, command_tag_parity,
                buffer_read_parity);
            break;
    case AFU_CMD_PR_RD_WNITC:
    case AFU_CMD_RD_WNITC:
       printf("Machine: rd_wnitc pl = 0x%x and dl = 0x%x\n", afu_event->afu_tlx_vc3_pl,
    	afu_event->afu_tlx_vc3_dl);
        command = 
           new LoadCommand (command_code, command_address_parity,
    		     command_code_parity, command_tag_parity,
    		     buffer_read_parity);
       break;
    case AFU_CMD_XLATE_TOUCH:   // VC3
        printf("Machine: Sending AFU_CMD_XLATE_TOUCH\n");
        translated_address = memory_base_address & 0x00007FFF;
        printf("translated_address = 0x%x\n", translated_address);
        command = new OtherCommand(command_code, command_address_parity,
            command_code_parity, command_tag_parity, buffer_read_parity);
        break;
    case AFU_CMD_XLATE_RELEASE: // vc3
        printf("Machine: sending AFU_CMD_XLATE_RELEASE\n");
        //memory_base_address = memory_base_address | 0xF000000000000000LL;
        printf("memory_base_address = 0x%llx\n", memory_base_address);
        command = new OtherCommand(command_code, command_address_parity,
            command_code_parity, command_tag_parity, buffer_read_parity);
        break;
    case AFU_CMD_RD_WNITC_T:
        printf("translated_address = 0x%x\n", translated_address);
        printf("memory_base_address = 0x%llx\n", memory_base_address);
        memory_base_address = memory_base_address || 0xF000000000000000LL;
        printf("new memory_base_address = 0x%llx\n", memory_base_address);
        printf("Machine: Sending AFU_CMD_RD_WNITC_T\n");
        printf("memory_base_address = 0x%llx\n", memory_base_address);
        
        command = new LoadCommand(command_code, command_address_parity,
          command_code_parity, command_tag_parity, buffer_read_parity);
        break;
    case AFU_CMD_AMO_W:
    printf("Machine: amo_w: pl = 0x%x and cmdflag = 0x%x\n", afu_event->afu_tlx_vc3_pl,
        afu_event->afu_tlx_vc3_cmdflag);
    command = new StoreCommand ( command_code, command_address_parity,
        command_code_parity, command_tag_parity, buffer_read_parity);
    break;
    case AFU_CMD_DMA_PR_W:
    case AFU_CMD_DMA_W:
    printf("Machine: dma_w: pl = 0x%x and dl = 0x%x\n", afu_event->afu_tlx_vc3_pl,
    	afu_event->afu_tlx_vc3_dl);
    command = new StoreCommand ( command_code, command_address_parity,
    	command_code_parity, command_tag_parity, buffer_read_parity);
    break;
    case AFU_CMD_WAKE_HOST_THRD:
    case AFU_CMD_INTRP_REQ_D:
    case AFU_CMD_INTRP_REQ:
    printf("Machine: afu_cmd_intrp_req\n");
        command =
            new OtherCommand (command_code, command_address_parity,
                              command_code_parity, command_tag_parity,
                              buffer_read_parity);
        break;
    default:
        error_msg
        ("MachineController::Machine::read_machine_config(): command code 0x%x is currently not supported",
         command_code);
    }

    }

    void
    MachineController::Machine::record_command (bool error_state, uint16_t cycle)
    {
    uint16_t data = (error_state) ? 1 << 15 : 0;

    data |= cycle & 0x7FFF;
    config[1] = (config[1] & 0xFFFFFFFFFFFF0000LL) | ((uint64_t) data);
    }

    void
    MachineController::Machine::record_response (bool error_state, uint16_t cycle,
        uint8_t response_code)
    {
    uint16_t data = (error_state) ? 1 << 15 : 0;

    data |= cycle & 0x7FFF;
    config[1] = (config[1] & 0xFFFFFFFF0000FFFFLL) | ((uint64_t) data << 16);
    config[1] =
        (config[1] & 0xFFFFFF00FFFFFFFFLL) | ((uint64_t) response_code << 32);
    }

    void
    MachineController::Machine::clear_response ()
    {
    config[1] |= 0xFF00000000;
    }

    uint8_t MachineController::Machine::get_command_address_parity () const
    {
    return (uint8_t) ((config[1] & 0x800000000000) >> 47);
    }

    uint8_t
    MachineController::Machine::get_command_code_parity () const
    {
    return (uint8_t) ((config[1] & 0x400000000000) >> 46);
    }

    uint8_t
    MachineController::Machine::get_command_tag_parity () const
    {
    return (uint8_t) ((config[1] & 0x200000000000) >> 45);
    }

    uint8_t
    MachineController::Machine::get_buffer_read_parity () const
    {
    return (uint8_t) ((config[1] & 0x100000000000) >> 44);
    }

    void
    MachineController::Machine::change_machine_config (uint16_t index, uint64_t data)
    {
    config[index] = data;
    printf("Machine: config[%d] = 0x%016lx\n", index, data);
    }

    uint32_t MachineController::Machine::get_machine_config (uint32_t offset)
    {
    if (offset >= SIZE_CONFIG_TABLE * 2)
        error_msg
        ("Machine::change_machine_config config table offset exceeded size of config table");

    if (offset % 2 == 1)
        return (uint32_t) (config[offset / 2] & 0x00000000FFFFFFFFLL);
    else
        return (uint32_t) ((config[offset / 2] & 0xFFFFFFFF00000000LL) >> 32);
    }

    bool MachineController::Machine::attempt_new_command (AFU_EVENT * afu_event,
        uint32_t tag,
        bool error_state,
        uint16_t cycle)
    {

    // only send new command if
    // 1. previous command has completed
    // 2. delay is 0

    if (!is_enabled ())
        error_msg
        ("MachineController::Machine::attempt_new_command(): attemp to send new command when machine is not enabled");

    if ((!command || command->is_completed ()) && delay == 0) {
        debug_msg("Machine::attempt_new_command: read_machine_config");
    read_machine_config (afu_event);

        // randomly generates address within the range
        uint64_t
        address_offset =
            (rand () % (memory_size - (command_size - 1))) & ~(command_size -
                    1);
    debug_msg("Machine::attempt_new_command: command->send_command with tag = 0x%x", tag);
        command->send_command (afu_event, tag,
                               memory_base_address,
                               command_size, abort, context);

    resend_command = command;
        record_command (error_state, cycle);
        clear_response ();

        if (is_enabled_once ()) {
            disable_once ();
        }

        return true;
    }

    return false;
    }

    bool
    MachineController::Machine::attempt_resend_command(AFU_EVENT *afu_event, uint32_t tag, 
    	bool error_state, uint16_t cycle)
    {
    debug_msg("Machine::attempt_resend_command with afutag = 0x%x", tag);
    resend_command->send_command(afu_event, tag, memory_base_address, command_size, abort, context);

    return true;
    }

    void
    MachineController::Machine::advance_cycle ()
    {
    if (is_enabled () && (!command || command->is_completed ()) && delay > 0) {
        --delay;
    }

    if (!is_enabled ())
        delay = 0;
    }

    void
    MachineController::Machine::process_response (AFU_EVENT * afu_event,
        bool error_state,
        uint16_t cycle)
    {
    }

    void
    MachineController::Machine::process_buffer_write (AFU_EVENT * afu_event)
    {
    command->process_command (afu_event, cache_line);
    }

    void
    MachineController::Machine::process_buffer_read (AFU_EVENT * afu_event)
    {
    command->process_command (afu_event, cache_line);
    }

    void
    MachineController::Machine::disable_once ()
    {
    config[0] &= ~0x4000000000000000;
    }

    void
    MachineController::Machine::disable ()
    {
    config[0] &= ~0xC000000000000000;
    delay = 0;
    }

    bool
    MachineController::Machine::is_enabled () const
    {
    bool enable_always = ((config[0] >> 63) == 0x1);
    bool enable_once = (((config[0] >> 62) & 0x1) == 0x1);

    //    if(enable_always)
    //     printf("machine is enabled = 0x%d\n", enable_always);
    return enable_always || enable_once;
    }

    bool
    MachineController::Machine::is_enabled_once () const
    {
    return ((config[0] >> 62) & 0x1);
    }

    bool
    MachineController::Machine::is_completed () const
    {
    if (!command || command->is_completed ())
        return true;

    return false;

    }

    bool
    MachineController::Machine::is_restart () const
    {
    if (!command)
        error_msg
        ("MachineController::Machine: calling command->is_restart() when command is not defined");
    return command->is_restart ();
    }

    MachineController::Machine::~Machine ()
    {
    if (command)
        delete command;
    }


