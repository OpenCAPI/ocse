#include "MachineController.h"
#include "Machine.h"

#include <stdlib.h>

MachineController::MachineController ():machines (NUM_MACHINES),
    tag_to_machine ()
{
    flushed_state = false;

    for (uint32_t i = 0; i < machines.size (); ++i)
        machines[i] = new Machine (0);
}

MachineController::MachineController (uint16_t ctx):machines (NUM_MACHINES),
    tag_to_machine ()
{
    flushed_state = false;

    for (uint32_t i = 0; i < machines.size (); ++i)
        machines[i] = new Machine (ctx);

}

bool MachineController::send_command (AFU_EVENT * afu_event, uint32_t cycle)
{
    bool
    try_send = true;

    // allocate a tag
    uint32_t
    tag;

    if (!TagManager::request_tag (&tag)) {
        debug_msg ("MachineController::send_command: no more tags available");
        try_send = false;
    }

    // attempt to send a command with the allocated tag
    for (uint32_t i = 0; i < machines.size (); ++i) {
        if (try_send && machines[i]->is_enabled ()
                && machines[i]->attempt_new_command (afu_event, tag,
                        flushed_state,
                        (uint16_t) (cycle & 0x7FFF)))
        {
            debug_msg
            ("MachineController::send_command: machine id %d sent new command", i);
            try_send = false;
            tag_to_machine[tag] = machines[i];
	    debug_msg("MachineController::send_command tag = 0x%x machine = 0x%x", tag, machines[i]);
        }

        // regardless if a command is sent, notify machine to advanced one cycle in delaying phase
        machines[i]->advance_cycle ();
    }

    // tag was not used by any machine if try_send is still true therefore return it
    if (try_send)
        TagManager::release_tag (tag);

    return !try_send;
}

void
MachineController::process_response (AFU_EVENT * afu_event, uint32_t cycle)
{
}

void
MachineController::process_buffer_write (AFU_EVENT * afu_event)
{
}

void
MachineController::process_buffer_read (AFU_EVENT * afu_event)
{
}

void
MachineController::change_machine_config (uint32_t word_address,
        uint64_t data, uint32_t mmio_double)
{
    uint32_t i = word_address / (SIZE_CONFIG_TABLE * 2);

    if (i >= NUM_MACHINES) {
        warn_msg
        ("MachineController::change_machine_config: word address exceeded machine configuration space");
        return;
    }

    uint32_t offset = word_address % (SIZE_CONFIG_TABLE * 2);

    if (mmio_double) {
        machines[i]->change_machine_config (offset + 1, data & 0xFFFFFFFF);
        machines[i]->change_machine_config (offset,
                                            (data & 0xFFFFFFFF00000000LL) >>
                                            32);
    }
    else {
        machines[i]->change_machine_config (offset, data & 0xFFFFFFFF);
    }
}

uint64_t
MachineController::get_machine_config (uint32_t word_address,
                                       uint32_t mmio_double)
{
    uint32_t i = word_address / (SIZE_CONFIG_TABLE * 2);

    if (i >= NUM_MACHINES) {
        warn_msg
        ("MachineController::get_machine_config: word address exceeded machine configuration space");
        return 0xFFFFFFFFFFFFFFFFLL;
    }

    uint32_t offset = word_address % (SIZE_CONFIG_TABLE * 2);
    uint64_t data;

    if (mmio_double) {
        data = machines[i]->get_machine_config (offset);
        data = (data << 32) | machines[i]->get_machine_config (offset + 1);
    }
    else {
        data = machines[i]->get_machine_config (offset);
        data = (data << 32) | data;
    }

    return data;
}

void
MachineController::reset ()
{
    flushed_state = false;
    for (uint32_t i = 0; i < machines.size (); ++i)
        machines[i]->reset ();
}

bool MachineController::is_enabled () const
{
    for (uint32_t i = 0; i < machines.size (); ++i)
    {
        if (machines[i]->is_enabled ()) {
            return true;
        }
    }

    return
        false;
}

bool MachineController::all_machines_completed () const
{
    for (uint32_t i = 0; i < machines.size (); ++i)
    {
        if (!machines[i]->is_completed ()) {
            return false;
        }
    }

    return
        true;
}

void
MachineController::disable_all_machines ()
{
    for (uint32_t i = 0; i < machines.size (); ++i)
        machines[i]->disable ();
}

bool MachineController::has_tag (uint32_t tag) const
{
    if (tag_to_machine.find (tag) != tag_to_machine.end ())
        return true;

    return false;
}

MachineController::~
MachineController ()
{
    for (uint32_t i = 0; i < machines.size (); ++i)
        if (machines[i])
            delete machines[i];

}


