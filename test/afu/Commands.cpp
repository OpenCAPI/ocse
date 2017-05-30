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
    uint8_t  cmd_stream_id;
    uint8_t  cmd_dl, cmd_pl;
    uint64_t cmd_be;
    uint8_t  cmd_flag, cmd_endian, cmd_pg_size;
    uint16_t  cmd_bdf, cmd_actag, cmd_afutag;
    uint16_t cmd_pasid;
    int  rc, i;
    uint8_t  ea_addr[9];

    memcpy((void*)&ea_addr, (void*) &address, sizeof(uint64_t));

    cmd_dl = 0x00;	// 1=64 bytes, 2=128 bytes, 3=256 bytes
    cmd_pl = 0x03;	// 0=1B, 1=2B, 2=4B, 3=8B, 4=16B, 5=32B
    cmd_bdf = afu_event->afu_tlx_cmd_bdf;
    cmd_stream_id = afu_event->afu_tlx_cmd_stream_id;
    cmd_be = afu_event->afu_tlx_cmd_be;
    cmd_flag = afu_event->afu_tlx_cmd_flag;
    cmd_endian = afu_event->afu_tlx_cmd_endian;
    cmd_pasid = afu_event->afu_tlx_cmd_pasid;
    cmd_pg_size = afu_event->afu_tlx_cmd_pg_size;
    cmd_actag = afu_event->afu_tlx_cmd_actag;
    cmd_afutag = afu_event->afu_tlx_cmd_afutag;

    printf("LoadCommand: sending command = 0x%x\n", Command::code);
    //if (Command::state != IDLE)
    //    error_msg
    //    ("LoadCommand: Attempting to send command before previous command is completed");

    //Command::completed = false;

    debug_msg("calling afu_tlx_send_cmd with command = 0x%x and paddress = 0x%x cmd_actag = 0x%x", Command::code, address, cmd_actag);
    debug_msg("ACTAG = 0x%x BDF = 0x%x PASID = 0x%x", cmd_actag, cmd_bdf, cmd_pasid);
    rc = afu_tlx_send_cmd(afu_event, Command::code, cmd_actag, cmd_stream_id,
	ea_addr, cmd_afutag, cmd_dl, cmd_pl,
#ifdef	TLX4
	cmd_os,
#endif
	cmd_be, cmd_flag, cmd_endian, cmd_bdf, cmd_pasid, cmd_pg_size);
    printf("Commands: rc = 0x%x\n", rc);
   
    Command::state = WAITING_DATA;
    Command::tag = new_tag;
    printf("data = 0x");
    for(i=0; i<9; i++)
    	printf("%02x",(uint8_t)ea_addr[i]);
    printf("Command: send command exit\n");
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
    uint8_t  cmd_stream_id;
    uint8_t  cmd_dl, cmd_pl;
    uint64_t cmd_be;
    uint8_t  cmd_flag, cmd_endian, cmd_pg_size;
    uint16_t  cmd_bdf, cmd_actag, cmd_afutag;
    uint16_t cmd_pasid;
    int  rc;
    uint8_t  ea_addr[9];

    memcpy((void*)&ea_addr, (void*) &address, sizeof(uint64_t));

    cmd_dl = 0x01;	// 1=64 bytes, 2=128 bytes, 3=256 bytes
    cmd_pl = 0x03;	// 0=1B, 1=2B, 2=4B, 3=8B, 4=16B, 5=32B
    cmd_bdf = afu_event->afu_tlx_cmd_bdf;
    cmd_stream_id = afu_event->afu_tlx_cmd_stream_id;
    cmd_be = afu_event->afu_tlx_cmd_be;
    cmd_flag = afu_event->afu_tlx_cmd_flag;
    cmd_endian = afu_event->afu_tlx_cmd_endian;
    cmd_pasid = afu_event->afu_tlx_cmd_pasid;
    cmd_pg_size = afu_event->afu_tlx_cmd_pg_size;
    cmd_actag = afu_event->afu_tlx_cmd_actag;
    cmd_afutag = afu_event->afu_tlx_cmd_afutag;

    printf("StoreCommand: sending command = 0x%x\n", Command::code);
//    if (Command::state != IDLE)
//        error_msg
//        ("StoreCommand: Attempting to send command before previous command is completed");

//    Command::completed = false;
    debug_msg("calling afu_tlx_send_cmd with command = 0x%x and paddress = 0x%x cmd_actag = 0x%x", Command::code, address, cmd_actag);
    debug_msg("ACTAG = 0x%x BDF = 0x%x PASID = 0x%x", cmd_actag, cmd_bdf, cmd_pasid);
    rc = afu_tlx_send_cmd(afu_event, Command::code, cmd_actag, cmd_stream_id,
	ea_addr, cmd_afutag, cmd_dl, cmd_pl,
#ifdef	TLX4
	cmd_os,
#endif
	cmd_be, cmd_flag, cmd_endian, cmd_bdf, cmd_pasid, cmd_pg_size);
    printf("Commands: rc = 0x%x\n", rc);

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


