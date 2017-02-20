#include <stdlib.h>

#include "Commands.h"

Command::Command (uint16_t c, bool comm_addr_par, bool comm_code_par, bool comm_tag_par, bool buff_read_par):code (c), completed (true), state (IDLE),
    command_address_parity (comm_addr_par), command_code_parity (comm_code_par),
    command_tag_parity (comm_tag_par), buffer_read_parity (buff_read_par)
{
}

bool Command::is_completed () const
{
    return
        completed;
}

uint32_t
Command::get_tag () const
{
    return tag;
}

OtherCommand::OtherCommand (uint16_t c, bool comm_addr_par,
                            bool comm_code_par, bool comm_tag_par,
                            bool buff_read_par):
    Command (c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par)
{
}

void
OtherCommand::send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                            uint64_t address, uint16_t command_size,
                            uint8_t abort, uint16_t context)
{
    if (Command::state != IDLE)
        error_msg
        ("OtherCommand: Attempting to send command before previous command is completed");

    Command::completed = false;

    uint32_t tag_parity = generate_parity (new_tag, ODD_PARITY);

    if (command_tag_parity)
        tag_parity = 1 - tag_parity;

    uint32_t code_parity = generate_parity (Command::code, ODD_PARITY);

    if (command_code_parity)
        code_parity = 1 - code_parity;

    uint32_t address_parity = generate_parity (address, ODD_PARITY);

    if (command_address_parity)
        address_parity = 1 - address_parity;

        error_msg ("OtherCommand: failed to send command");

    //if (afu_event->command_valid)
    //    debug_msg ("OtherCommand: command sent");

    Command::state = WAITING_RESPONSE;
    Command::tag = new_tag;
}

void
OtherCommand::process_command (AFU_EVENT * afu_event, uint8_t *)
{
    if (Command::state == IDLE) {
        error_msg
        ("OtherCommand: Attempt to process response when no command is currently active");
    }
}

bool OtherCommand::is_restart () const
{
    return (Command::code );
}

LoadCommand::LoadCommand (uint16_t c, bool comm_addr_par, bool comm_code_par,
                          bool comm_tag_par, bool buff_read_par):
    Command (c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par)
{
}

void
LoadCommand::send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                           uint64_t address, uint16_t command_size,
                           uint8_t abort, uint16_t context)
{
    if (Command::state != IDLE)
        error_msg
        ("LoadCommand: Attempting to send command before previous command is completed");

    Command::completed = false;

    uint32_t tag_parity = generate_parity (new_tag, ODD_PARITY);

    if (command_tag_parity)
        tag_parity = 1 - tag_parity;

    uint32_t code_parity = generate_parity (Command::code, ODD_PARITY);

    if (command_code_parity)
        code_parity = 1 - code_parity;

    uint32_t address_parity = generate_parity (address, ODD_PARITY);

    if (command_address_parity)
        address_parity = 1 - address_parity;
    debug_msg("LoadCommand::send_command: command = 0x%x", Command::code);

    debug_msg ("LoadCommand::send_command: command sent");
    Command::state = WAITING_DATA;
    Command::tag = new_tag;
}

void
LoadCommand::process_command (AFU_EVENT * afu_event, uint8_t * cache_line)
{
}

void
LoadCommand::process_buffer_write (AFU_EVENT * afu_event,
                                   uint8_t * cache_line)
{
    Command::state = WAITING_RESPONSE;

}

bool LoadCommand::is_restart () const
{
    return
        false;
}

StoreCommand::StoreCommand (uint16_t c, bool comm_addr_par,
                            bool comm_code_par, bool comm_tag_par,
                            bool buff_read_par):
    Command (c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par)
{
}


void
StoreCommand::send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                            uint64_t address, uint16_t command_size,
                            uint8_t abort, uint16_t context)
{
    if (Command::state != IDLE)
        error_msg
        ("StoreCommand: Attempting to send command before previous command is completed");

    Command::completed = false;

    uint32_t tag_parity = generate_parity (new_tag, ODD_PARITY);

    if (command_tag_parity)
        tag_parity = 1 - tag_parity;

    uint32_t code_parity = generate_parity (Command::code, ODD_PARITY);

    if (command_code_parity)
        code_parity = 1 - code_parity;

    uint32_t address_parity = generate_parity (address, ODD_PARITY);

    if (command_address_parity)
        address_parity = 1 - address_parity;


    debug_msg ("StoreCommand: command sent");
    Command::state = WAITING_READ;
    Command::tag = new_tag;
}

void
StoreCommand::process_command (AFU_EVENT * afu_event, uint8_t * cache_line)
{

}

void
StoreCommand::process_buffer_read (AFU_EVENT * afu_event,
                                   uint8_t * cache_line)
{
}

bool StoreCommand::is_restart () const
{
    return
        false;
}


