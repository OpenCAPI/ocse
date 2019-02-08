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

#include <stdlib.h>
#include "Commands.h"

//extern uint8_t memory[128];

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
    uint8_t  cmd_stream_id;
    uint8_t  cmd_dl, cmd_pl;
    uint64_t cmd_be;
    uint8_t  cmd_flag, cmd_endian, cmd_pg_size;
    uint16_t  cmd_bdf, cmd_actag, cmd_afutag;
    uint16_t cmd_pasid;
    int  rc, i;
    uint8_t  cmd_os, cmd_mad, ea_addr[9];
    uint8_t  cdata_bus[64], cdata_bdi;

    memcpy((void*)&ea_addr, (void*) &address, sizeof(uint64_t));

    //cmd_dl = 0x00;	// 1=64 bytes, 2=128 bytes, 3=256 bytes
    //cmd_pl = 0x03;	// 0=1B, 1=2B, 2=4B, 3=8B, 4=16B, 5=32B
    cmd_dl = afu_event->afu_tlx_vc3_dl;
    cmd_pl = afu_event->afu_tlx_vc3_pl;
    cmd_bdf = afu_event->afu_tlx_vc3_bdf;
    cmd_stream_id = afu_event->afu_tlx_vc3_stream_id;
    cmd_be = afu_event->afu_tlx_vc3_be;
    cmd_flag = afu_event->afu_tlx_vc3_cmdflag;
    cmd_endian = afu_event->afu_tlx_vc3_endian;
    cmd_pasid = afu_event->afu_tlx_vc3_pasid;
    cmd_pg_size = afu_event->afu_tlx_vc3_pg_size;
    cmd_actag = afu_event->afu_tlx_vc3_actag;
    cmd_afutag = new_tag;
    printf("OtherCommand: sending command = 0x%x\n", Command::code);

    debug_msg("calling afu_tlx_send_cmd with command = 0x%x and paddress = 0x%x cmd_actag = 0x%x", Command::code, address, cmd_actag);
    debug_msg("ACTAG = 0x%x BDF = 0x%x PASID = 0x%x", cmd_actag, cmd_bdf, cmd_pasid);
    switch(Command::code) {
	case AFU_CMD_INTRP_REQ:
	case AFU_CMD_WAKE_HOST_THRD:
//    if(Command::code == AFU_CMD_INTRP_REQ) {
	printf("Commands: AFU_CMD_INTRP_REQ or AFU_CMD_WAKE_HOST\n");
    	rc = afu_tlx_send_cmd_vc3(afu_event, Command::code, cmd_actag, 
            cmd_stream_id, ea_addr, cmd_afutag, cmd_dl, 
            cmd_pl, cmd_os, cmd_be, cmd_flag, cmd_endian, 
            cmd_bdf, cmd_pasid, cmd_pg_size, cmd_mad);
//    }
	    break;
	case AFU_CMD_INTRP_REQ_D:
//    else if(Command::code == AFU_CMD_INTRP_REQ_D) {
	    cmd_pl = 3;
	    printf("Commands: AFU_CMD_INTRP_REQ_D\n");
	    for(i=0; i<8; i++) {
	    	cdata_bus[i] = i;
	    }
 	    rc = afu_tlx_send_cmd_vc3_and_dcp3_data(afu_event, Command::code, 
            cmd_actag, cmd_stream_id, ea_addr, cmd_afutag, cmd_dl, 
            cmd_pl, cmd_os, cmd_be, cmd_flag, cmd_endian, cmd_bdf, 
            cmd_pasid, cmd_pg_size, cmd_mad, cdata_bdi, cdata_bus);
	    break;
	default:
	    break;
    }

    printf("Commands: rc = 0x%x\n", rc);
   
    Command::state = WAITING_DATA;
    Command::tag = new_tag;
    printf("data = 0x");
    for(i=0; i<9; i++)
    	printf("%02x",(uint8_t)ea_addr[i]);
    printf("\n");
    printf("OtherCommand: exit send command\n");
    
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
    uint8_t  cmd_stream_id, cmd_os, cmd_mad;
    uint8_t  cmd_dl, cmd_pl;
    uint64_t cmd_be;
    uint8_t  cmd_flag, cmd_endian, cmd_pg_size;
    uint16_t  cmd_bdf, cmd_actag, cmd_afutag;
    uint16_t cmd_pasid;
    int  rc, i;
    uint8_t  ea_addr[9];

    memcpy((void*)&ea_addr, (void*) &address, sizeof(uint64_t));

    //cmd_dl = 0x00;	// 1=64 bytes, 2=128 bytes, 3=256 bytes
    //cmd_pl = 0x03;	// 0=1B, 1=2B, 2=4B, 3=8B, 4=16B, 5=32B
    cmd_dl = afu_event->afu_tlx_vc3_dl;
    cmd_pl = afu_event->afu_tlx_vc3_pl;
    cmd_bdf = afu_event->afu_tlx_vc3_bdf;
    cmd_stream_id = afu_event->afu_tlx_vc3_stream_id;
    cmd_be = afu_event->afu_tlx_vc3_be;
    cmd_flag = afu_event->afu_tlx_vc3_cmdflag;
    cmd_endian = afu_event->afu_tlx_vc3_endian;
    cmd_pasid = afu_event->afu_tlx_vc3_pasid;
    cmd_pg_size = afu_event->afu_tlx_vc3_pg_size;
    cmd_actag = afu_event->afu_tlx_vc3_actag;
    //cmd_afutag = afu_event->afu_tlx_cmd_afutag;
    cmd_afutag = new_tag;
    printf("LoadCommand: sending command = 0x%x\n", Command::code);
    //if (Command::state != IDLE)
    //    error_msg
    //    ("LoadCommand: Attempting to send command before previous command is completed");

    //Command::completed = false;
    //switch(Command::code){
    //    case AFU_CMD_AMO_RD:
    //        cmd_pl = 2;
    //        cmd_flag = 0x1100;
    //        break;
    //    default:
    //        break;
    //}
    debug_msg("calling afu_tlx_send_cmd with command = 0x%x and paddress = 0x%x cmd_actag = 0x%x", Command::code, address, cmd_actag);
    debug_msg("ACTAG = 0x%x BDF = 0x%x PASID = 0x%x", cmd_actag, cmd_bdf, cmd_pasid);
    printf("cmd_flag = 0x%x, cmd_pl = 0x%x\n", cmd_flag, cmd_pl);
    rc = afu_tlx_send_cmd_vc3(afu_event, Command::code, cmd_actag, 
        cmd_stream_id, ea_addr, cmd_afutag, cmd_dl, cmd_pl,
	    cmd_os, cmd_be, cmd_flag, cmd_endian, cmd_bdf, cmd_pasid, 
        cmd_pg_size, cmd_mad);
    printf("Commands: rc = 0x%x\n", rc);
   
    Command::state = WAITING_DATA;
    Command::tag = new_tag;
    printf("data = 0x");
    for(i=0; i<9; i++)
    	printf("%02x",(uint8_t)ea_addr[i]);
    printf("\n");
    printf("Command: exit send load command\n");
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
    uint8_t  cmd_stream_id, cmd_mad, cdata_bdi;
    uint8_t  cmd_dl, cmd_pl, cmd_os;
    uint64_t cmd_be;
    uint8_t  cmd_flag, cmd_endian, cmd_pg_size, cdata_bad;
    uint16_t  cmd_bdf, cmd_actag, cmd_afutag;
    uint16_t cmd_pasid;
    int  rc;
//    uint32_t afutag;
    uint8_t  ea_addr[9], i;

    
    memcpy((void*)&ea_addr, (void*) &address, sizeof(uint64_t));
    
    //cmd_dl = 0x01;	// 1=64 bytes, 2=128 bytes, 3=256 bytes
    //cmd_pl = 0x03;	// 0=1B, 1=2B, 2=4B, 3=8B, 4=16B, 5=32B
    cmd_dl = afu_event->afu_tlx_vc3_dl;
    cmd_pl = afu_event->afu_tlx_vc3_pl;
    cmd_bdf = afu_event->afu_tlx_vc3_bdf;
    cmd_stream_id = afu_event->afu_tlx_vc3_stream_id;
    cmd_be = afu_event->afu_tlx_vc3_be;
    cmd_flag = afu_event->afu_tlx_vc3_cmdflag;
    cmd_endian = afu_event->afu_tlx_vc3_endian;
    cmd_pasid = afu_event->afu_tlx_vc3_pasid;
    cmd_pg_size = afu_event->afu_tlx_vc3_pg_size;
    cmd_actag = afu_event->afu_tlx_vc3_actag;
    //cmd_afutag = afu_event->afu_tlx_cmd_afutag;
    cmd_afutag = new_tag;
    cdata_bad = 0;

    printf("StoreCommand: sending command = 0x%x\n", Command::code);
    printf("memory = 0x");
    for(i=0; i<9; i++) {
	printf("%02x", memory[i]);
    }
    printf("\n");
    memcpy(afu_event->afu_tlx_dcp3_data_bus, memory, 64);

//    if (Command::state != IDLE)
//        error_msg
//        ("StoreCommand: Attempting to send command before previous command is completed");

//    Command::completed = false;
    debug_msg("calling afu_tlx_send_cmd_and_data with command = 0x%x and paddress = 0x%x cmd_actag = 0x%x", Command::code, address, cmd_actag);
    debug_msg("ACTAG = 0x%x BDF = 0x%x PASID = 0x%x", cmd_actag, cmd_bdf, cmd_pasid);
    rc = afu_tlx_send_cmd_vc3_and_dcp3_data(afu_event, Command::code, 
        cmd_actag, cmd_stream_id, ea_addr, cmd_afutag, cmd_dl, cmd_pl,
	    cmd_os, cmd_be, cmd_flag, cmd_endian, cmd_bdf, cmd_pasid, 
        cmd_pg_size, cmd_mad, cdata_bdi, afu_event->afu_tlx_dcp3_data_bus);
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


