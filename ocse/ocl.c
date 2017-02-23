/*
 * Copyright 2014,2017 International Business Machines
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

/*
 * Description: ocl.c
 *
 *  This file contains the foundation for the TLX code for a single AFU.
 *  ocl_init() attempts to connect to an AFU simulator and initializes a
 *  ocl struct if successful.  Finally it starts a _ocl_loop thread for
 *  that AFU that will monitor any incoming socket data from either the
 *  simulator (AFU) or any clients (applications) that attach to this
 *  AFU.  The code in here is just the foundation for the ocl.  The code
 *  for handling jobs, commands and mmios are each in there own separate files.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/types.h>

#include "mmio.h"
#include "ocl.h"
#include "../common/debug.h"
#include "../common/tlx_interface.h"

// are there any pending commands with this context?
int _is_cmd_pending(struct ocl *ocl, int32_t context)
{
  struct cmd_event *cmd_event;

  if ( ocl->cmd == NULL ) {
    // no cmd struct
    return 0;
  }

  cmd_event = ocl->cmd->list;
  while ( cmd_event != NULL ) {
    if ( cmd_event->context == context ) {
      // found a matching element
      return 1;
    }
    cmd_event = cmd_event->_next;
  }

  // no matching elements found
  return 0;

}

// Attach to AFU
static void _attach(struct ocl *ocl, struct client *client)
{
	uint64_t wed;
	uint8_t ack;
	uint8_t buffer[MAX_LINE_CHARS];
	size_t size;

	// FIXME: This only works for dedicate mode
	// might work for afu-directed now - lgt

	// Get wed value from application
	// always do the get
        // pass the wed only for dedicated
	ack = OCSE_DETACH;
	size = sizeof(uint64_t);
	if (get_bytes_silent(client->fd, size, buffer, ocl->timeout,
			     &(client->abort)) < 0) {
	  warn_msg("Failed to get WED value from client");
	  client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	  goto attach_done;
	}

	// but need to save wed if master|slave for future consumption
	// interestingly, I can always save it
	// add to client type.
	memcpy((char *)&wed, (char *)buffer, sizeof(uint64_t));
	// wed came over in be format
	// since we are modeling the ocl register here, we should leave it be
	client->wed = wed; // ntohll(wed);

	// Send start to AFU
	// only add TLX_JOB_START for dedicated and master clients.
	// send an empty wed in the case of master
	// lgt - new idea:
	// track number of clients in ocl
	// if number of clients = 0, then add the start job
	// add llcmd add to client  (loop through clients in send_com)
	// increment number of clients (decrement where we handle the completion of the detach)
	switch (client->type) {
	case 'd':
	  if (ocl->attached_clients == 0) {
	  /*  if (add_job(ocl->job, TLX_JOB_START, client->wed) != NULL) {
	      // if dedicated, we can ack OCSE_ATTACH
	      // if master, we might want to wait until after the llcmd add is complete
	      // can I wait here for the START to finish?
	      ocl->idle_cycles = TLX_IDLE_CYCLES;
	      ack = OCSE_ATTACH;
	    } */
	  } 
	  break;
	case 'm':
	case 's':
	  if (ocl->attached_clients < ocl->max_clients) {
	    if (ocl->attached_clients == 0) {
	      /*if (add_job(ocl->job, TLX_JOB_START, 0L) != NULL) {
		// if master, we might want to wait until after the llcmd add is complete
		// can I wait here for the START to finish?
	      } */
	    } 
	    ocl->idle_cycles = TLX_IDLE_CYCLES;
	    ack = OCSE_ATTACH;
	  }
	  // running will be set by send/handle_aux2 routines
	  break;
	default:
	  // error?
	  break;
	}

	ocl->attached_clients++;
	info_msg( "Attached client context %d: current attached clients = %d: client type = %c\n", client->context, ocl->attached_clients, client->type );
	
	// for master and slave send llcmd add
        // master "wed" is 0x0005000000000000 can actually use client->context here as well since context = 0
	// slave "wed" is 0x000500000000hhhh where hhhh is the "handle" from client->context
	// now - about those llcmds :-)
	// put these in a separate list associated with the job?  ocl->pe maybe...  or another call to add_job?
	// new routine to job.c?  add_cmd?
	// should a slave know their master?
	if (client->type == 'm' || client->type == 's') {
	        //wed = TLX_LLCMD_ADD;
	//	wed = wed | (uint64_t)client->context;
		// add_pe adds to the client
	    //    if (add_pe(ocl->job, TLX_JOB_LLCMD, wed) != NULL) {
	//	}
	}

 attach_done:
	if (put_bytes(client->fd, 1, &ack, ocl->dbg_fp, ocl->dbg_id,
		      client->context) < 0) {
		client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
	}
}

// Client is detaching from the AFU
static void _detach(struct ocl *ocl, struct client *client)
{
	uint64_t wed;

	debug_msg("DETACH from client context 0x%02x", client->context);
	// if dedicated mode just drop the client
	// if afu-directed mode
	//   add llcmd terminate to ocl->job->pe
	//   add llcmd remove to ocl->job->pe
	// comment - check to see if send pe is called if the client state is CLIENT_NONE
	// allow the socket to close and the client struct to be freed.
	//if (client->type == 'm' || client->type == 's') {
	       // wed = TLX_LLCMD_TERMINATE;
	//	wed = wed | (uint64_t)client->context;
	     //   if (add_pe(ocl->job, TLX_JOB_LLCMD, wed) == NULL) {
		  // error
		  error_msg( "%s:_detach failed to add llcmd terminate for context=%d"PRIx64, ocl->name, client->context );
	//	}
	   //     wed = TLX_LLCMD_REMOVE;
	//	wed = wed | (uint64_t)client->context;
	      //  if (add_pe(ocl->job, TLX_JOB_LLCMD, wed) == NULL) {
		  // error
	//	  error_msg( "%s:_detach failed to add llcmd remove for context=%d"PRIx64, ocl->name, client->context );
	//	}
//	} else {
//	  if (client->type == 'd' ) {
	    client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
//	  }
//	}

	// we will let _ocl_loop call send_pe to issue the llcmds
	// when the jcack's come back, we will 
	//   send the detach response to the client and 
	//   free the client structure

	
}

// Client release from AFU
static void _free(struct ocl *ocl, struct client *client)
{
	struct cmd_event *mem_access;

	// DEBUG
	debug_context_remove(ocl->dbg_fp, ocl->dbg_id, client->context);

	info_msg("%s client disconnect from %s context %d", client->ip,
		 ocl->name, client->context);
	close_socket(&(client->fd));
	if (client->ip)
		free(client->ip);
	client->ip = NULL;
	mem_access = (struct cmd_event *)client->mem_access;
	if (mem_access != NULL) {
		if (mem_access->state != MEM_DONE) {
		//	mem_access->resp = TLX_RESPONSE_FAILED;
			mem_access->state = MEM_DONE;
		}
	}
	client->mem_access = NULL;
	client->mmio_access = NULL;
	client->state = CLIENT_NONE;

	ocl->attached_clients--;
	info_msg( "Detatched a client: current attached clients = %d\n", ocl->attached_clients );

	// where do we *really* free the client struct and it's contents???
	
}


// Handle events from AFU
static void _handle_afu(struct ocl *ocl)
{
	struct client *client;
	uint64_t error;
	uint8_t *buffer;
	int reset_done;
	int i;
	size_t size;

	 handle_mmio_ack(ocl->mmio, ocl->parity_enabled);
	if (ocl->cmd != NULL) {
		if (reset_done)
			ocl->cmd->credits = ocl->cmd->parms->credits;
		handle_response(ocl->cmd);
		//handle_cmd(ocl->cmd, ocl->parity_enabled, ocl->latency);
		handle_interrupt(ocl->cmd);

	}
}

static void _handle_client(struct ocl *ocl, struct client *client)
{
	struct mmio_event *mmio;
	struct cmd_event *cmd;
	uint8_t buffer[MAX_LINE_CHARS];
	int dw = 0;
	int eb_rd = 0;

	// Handle MMIO done
	/* if (client->mmio_access != NULL) {
		client->idle_cycles = TLX_IDLE_CYCLES;
		client->mmio_access = handle_mmio_done(ocl->mmio, client);
	} */
	// Client disconnected
	if (client->state == CLIENT_NONE)
		return;

	// Check for event from application
	cmd = (struct cmd_event *)client->mem_access;
	mmio = NULL;
	if (bytes_ready(client->fd, 1, &(client->abort))) {
		if (get_bytes(client->fd, 1, buffer, ocl->timeout,
			      &(client->abort), ocl->dbg_fp, ocl->dbg_id,
			      client->context) < 0) {
			client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
			return;
		}
		switch (buffer[0]) {
		case OCSE_DETACH:
		        debug_msg("DETACH request from client context %d on socket %d", client->context, client->fd);
		        //client_drop(client, TLX_IDLE_CYCLES, CLIENT_NONE);
		        _detach(ocl, client);
			break;
		case OCSE_ATTACH:
			_attach(ocl, client);
			break;
		case OCSE_MEM_FAILURE:
			if (client->mem_access != NULL)
				handle_aerror(ocl->cmd, cmd);
			client->mem_access = NULL;
			break;
		case OCSE_MEM_SUCCESS:
			if (client->mem_access != NULL)
				handle_mem_return(ocl->cmd, cmd, client->fd);
			client->mem_access = NULL;
			break;
		case OCSE_MMIO_MAP:
			handle_mmio_map(ocl->mmio, client);
			break;
		case OCSE_MMIO_WRITE64:
			dw = 1;
		case OCSE_MMIO_WRITE32:	/*fall through */
			mmio = handle_mmio(ocl->mmio, client, 0, dw, 0);
			break;
		case OCSE_MMIO_EBREAD:
                        eb_rd = 1;
		case OCSE_MMIO_READ64: /*fall through */
			dw = 1;
		case OCSE_MMIO_READ32:	/*fall through */
			mmio = handle_mmio(ocl->mmio, client, 1, dw, eb_rd);
			break;
		default:
		  error_msg("Unexpected 0x%02x from client on socket", buffer[0], client->fd);
		}

		if (mmio)
			client->mmio_access = (void *)mmio;

		if (client->state == CLIENT_VALID)
			client->idle_cycles = TLX_IDLE_CYCLES;
	}
}

// TLX thread loop
static void *_ocl_loop(void *ptr)
{
	struct ocl *ocl = (struct ocl *)ptr;
	struct cmd_event *event, *temp;
	int events, i, stopped, reset;
	uint8_t ack = OCSE_DETACH;

	stopped = 1;
	pthread_mutex_lock(ocl->lock);
	while (ocl->state != OCSE_DONE) {
		// idle_cycles continues to generate clock cycles for some
		// time after the AFU has gone idle.  Eventually clocks will
		// not be presented to an idle AFU to keep simulation
		// waveforms from getting huge with no activity cycles.
		if (ocl->state != OCSE_IDLE) {
		  // if we have clients or we are in the reset state, refresh idle_cycles 
		  // so that the afu clock will not be allowed to stop to save afu event simulator cycles
		  if ((ocl->attached_clients > 0) || (ocl->state == OCSE_RESET)) {
			ocl->idle_cycles = TLX_IDLE_CYCLES;
			if (stopped)
				info_msg("Clocking %s", ocl->name);
			fflush(stdout);
			stopped = 0;
		  }
		}
		if (ocl->idle_cycles) {
			// Clock AFU
//printf("before tlx_signal_afu_model in ocl_loop, events is 0x%3x \n", events);
			tlx_signal_afu_model(ocl->afu_event);
			// Check for events from AFU
			events = tlx_get_afu_events(ocl->afu_event);
//printf("after tlx_get_afu_events, events is 0x%3x \n", events);
			// Error on socket
			if (events < 0) {
				warn_msg("Lost connection with AFU");
				break;
			}
			// Handle events from AFU
			if (events > 0)
				_handle_afu(ocl);

			// Drive events to AFU
			//send_job(ocl->job);
			//send_pe(ocl->job);
			send_mmio(ocl->mmio);

			if (ocl->mmio->list == NULL)
				ocl->idle_cycles--;
		} else {
			if (!stopped)
				info_msg("Stopping clocks to %s", ocl->name);
			stopped = 1;
			lock_delay(ocl->lock);
		}

		// Skip client section if AFU descriptor hasn't been read yet
		if (ocl->client == NULL) {
			lock_delay(ocl->lock);
			continue;
		}
		// Check for event from application
		reset = 0;
		for (i = 0; i < ocl->max_clients; i++) {
			if (ocl->client[i] == NULL)
				continue;
			if ((ocl->client[i]->type == 'd') && 
			    (ocl->client[i]->state == CLIENT_NONE) &&
			    (ocl->client[i]->idle_cycles == 0)) {
			        // this was the old way of detaching a dedicated process app/afu pair
			        // we get the detach message, drop the client, and wait for idle cycle to get to 0
				put_bytes(ocl->client[i]->fd, 1, &ack,
					  ocl->dbg_fp, ocl->dbg_id,
					  ocl->client[i]->context);
				_free(ocl, ocl->client[i]);
				ocl->client[i] = NULL;  // aha - this is how we only called _free once the old way
				                        // why do we not free client[i]?
				                        // because this was a short cut pointer
				                        // the *real* client point is in client_list in ocse
				reset = 1;
				// for m/s devices we need to do this differently and not send a reset...
				// _handle_client - creates the llcmd's to term and remove
				// send_pe - sends the llcmd pe's to afu one at a time
				// _handle_afu calls _handle_aux2
				// _handle_aux2 finishes the llcmd pe's when jcack is asserted by afu
				//   when the remove llcmd is processed, we should put_bytes, _free and set client[i] to NULL
				continue;
			}
			if (ocl->state == OCSE_RESET)
				continue;
//printf("before handle client \n");
			_handle_client(ocl, ocl->client[i]);
			if (ocl->client[i]->idle_cycles) {
				ocl->client[i]->idle_cycles--;
			}
			if (client_cmd(ocl->cmd, ocl->client[i])) {
				ocl->client[i]->idle_cycles = TLX_IDLE_CYCLES;
			}
		}

		// Send reset to AFU
		if (reset == 1) {
			ocl->cmd->buffer_read = NULL;
			event = ocl->cmd->list;
			while (event != NULL) {
				if (reset) {
					warn_msg
					    ("Client dropped context before AFU completed");
					reset = 0;
				}
				info_msg("Dumping command tag=0x%02x",
					 event->tag);
				if (event->data) {
					free(event->data);
				}
				if (event->parity) {
					free(event->parity);
				}
				temp = event;
				event = event->_next;
				free(temp);
			}
			ocl->cmd->list = NULL;
			info_msg("No longer sending reset to AFU");
			//add_job(ocl->job, TLX_JOB_RESET, 0L);
		}

		lock_delay(ocl->lock);
	}

	// Disconnect clients
	for (i = 0; i < ocl->max_clients; i++) {
		if ((ocl->client != NULL) && (ocl->client[i] != NULL)) {
			// FIXME: Send warning to clients first?
			info_msg("Disconnecting %s context %d", ocl->name,
				 ocl->client[i]->context);
			close_socket(&(ocl->client[i]->fd));
		}
	}

	// DEBUG
	debug_afu_drop(ocl->dbg_fp, ocl->dbg_id);

	// Disconnect from simulator, free memory and shut down thread
	info_msg("Disconnecting %s @ %s:%d", ocl->name, ocl->host, ocl->port);
	if (ocl->client)
		free(ocl->client);
	if (ocl->_prev)
		ocl->_prev->_next = ocl->_next;
	if (ocl->_next)
		ocl->_next->_prev = ocl->_prev;
	if (ocl->cmd) {
		free(ocl->cmd);
	}
	if (ocl->job) {
		free(ocl->job);
	}
	if (ocl->mmio) {
		free(ocl->mmio);
	}
	if (ocl->host)
		free(ocl->host);
	if (ocl->afu_event) {
		tlx_close_afu_event(ocl->afu_event);
		free(ocl->afu_event);
	}
	printf("ocl->name is %s \n", ocl->name);
	if (ocl->name)
		free(ocl->name);
	printf("ocl->head move is next \n");
	if (*(ocl->head) == ocl)
		*(ocl->head) = ocl->_next;
	
	printf("pthread_mutex_unlock is next \n");
	pthread_mutex_unlock(ocl->lock);
	printf("ocl is next \n");
	free(ocl);
	pthread_exit(NULL);
}

// Initialize and start TLX thread
//
// The return value is encode int a 16-bit value divided into 4 for each
// possible adapter.  Then the 4 bits in each adapter represent the 4 possible
// AFUs on an adapter.  For example: afu0.0 is 0x8000 and afu3.0 is 0x0008.
uint16_t ocl_init(struct ocl **head, struct parms *parms, char *id, char *host,
		  int port, pthread_mutex_t * lock, FILE * dbg_fp)
{
	struct ocl *ocl;
	struct job_event *reset;
	uint16_t location;

	location = 0x8000;
	if ((ocl = (struct ocl *)calloc(1, sizeof(struct ocl))) == NULL) {
		perror("malloc");
		error_msg("Unable to allocation memory for ocl");
		goto init_fail;
	}
	ocl->timeout = parms->timeout;
	if ((strlen(id) != 6) || strncmp(id, "afu", 3) || (id[4] != '.')) {
		warn_msg("Invalid afu name: %s", id);
		goto init_fail;
	}
	if ((id[3] < '0') || (id[3] > '3')) {
		warn_msg("Invalid afu major: %c", id[3]);
		goto init_fail;
	}
	if ((id[5] < '0') || (id[5] > '3')) {
		warn_msg("Invalid afu minor: %c", id[5]);
		goto init_fail;
	}
	ocl->dbg_fp = dbg_fp;
	ocl->major = id[3] - '0';
	ocl->minor = id[5] - '0';
	ocl->dbg_id = ocl->major << 4;
	ocl->dbg_id |= ocl->minor;
	location >>= (4 * ocl->major);
	location >>= ocl->minor;
	if ((ocl->name = (char *)malloc(strlen(id) + 1)) == NULL) {
		perror("malloc");
		error_msg("Unable to allocation memory for ocl->name");
		goto init_fail;
	}
	strcpy(ocl->name, id);
	if ((ocl->host = (char *)malloc(strlen(host) + 1)) == NULL) {
		perror("malloc");
		error_msg("Unable to allocation memory for ocl->host");
		goto init_fail;
	}
	strcpy(ocl->host, host);
	ocl->port = port;
	ocl->client = NULL;
	ocl->idle_cycles = TLX_IDLE_CYCLES;
	ocl->lock = lock;

	// Connect to AFU
	ocl->afu_event = (struct AFU_EVENT *)malloc(sizeof(struct AFU_EVENT));
	if (ocl->afu_event == NULL) {
		perror("malloc");
		goto init_fail;
	}
	info_msg("Attempting to connect AFU: %s @ %s:%d", ocl->name,
		 ocl->host, ocl->port);
	if (tlx_init_afu_event(ocl->afu_event, ocl->host, ocl->port) !=
	    TLX_SUCCESS) {
		warn_msg("Unable to connect AFU: %s @ %s:%d", ocl->name,
			 ocl->host, ocl->port);
		goto init_fail;
	}
	// DEBUG
	debug_afu_connect(ocl->dbg_fp, ocl->dbg_id);

	// Initialize job handler
	debug_msg("%s @ %s:%d: job_init", ocl->name, ocl->host, ocl->port);
	/* if ((ocl->job = job_init(ocl->afu_event, &(ocl->state), ocl->name,
				 ocl->dbg_fp, ocl->dbg_id)) == NULL) {
		perror("job_init");
		goto init_fail;
	} */
	// Initialize mmio handler
	debug_msg("%s @ %s:%d: mmio_init", ocl->name, ocl->host, ocl->port);
	if ((ocl->mmio = mmio_init(ocl->afu_event, ocl->timeout, ocl->name,
				   ocl->dbg_fp, ocl->dbg_id)) == NULL) {
		perror("mmio_init");
		goto init_fail;
	}
	// Initialize cmd handler
	debug_msg("%s @ %s:%d: cmd_init", ocl->name, ocl->host, ocl->port);
	if ((ocl->cmd = cmd_init(ocl->afu_event, parms, ocl->mmio,
				 &(ocl->state), ocl->name, ocl->dbg_fp,
				 ocl->dbg_id))
	    == NULL) {
		perror("cmd_init");
		goto init_fail;
	}
	// Load in VSEC data (read in from ocse.parms file)
	ocl->vsec_oppa_version = parms->oppa_version;
	ocl->vsec_tlx_rev_level= parms->tlx_rev_level;
	ocl->vsec_image_loaded= parms->image_loaded;
	ocl->vsec_base_image= parms->base_image;
	// Set credits for AFU
	/* if (tlx_aux1_change(ocl->afu_event, ocl->cmd->credits) != TLX_SUCCESS) {
		warn_msg("Unable to set credits");
		goto init_fail;
	} */
	// Start ocl loop thread
	if (pthread_create(&(ocl->thread), NULL, _ocl_loop, ocl)) {
		perror("pthread_create");
		goto init_fail;
	}
	// Add ocl to list
	while ((*head != NULL) && ((*head)->major < ocl->major)) {
		head = &((*head)->_next);
	}
	while ((*head != NULL) && ((*head)->major == ocl->major) &&
	       ((*head)->minor < ocl->minor)) {
		head = &((*head)->_next);
	}
	ocl->_next = *head;
	if (ocl->_next != NULL)
		ocl->_next->_prev = ocl;
	*head = ocl;

	// Send reset to AFU
	debug_msg("%s @ %s:%d: No need to send reset job.", ocl->name, ocl->host, ocl->port);
	/* reset = add_job(ocl->job, TLX_JOB_RESET, 0L);
	while (ocl->job->job == reset) {	//infinite loop 
		lock_delay(ocl->lock);
	}  */

	// Read AFU descriptor
	debug_msg("%s @ %s:%d: Reading AFU config record and VSEC.", ocl->name, ocl->host,
	          ocl->port);
	ocl->state = OCSE_DESC;
	read_descriptor(ocl->mmio, ocl->lock);

	// Finish TLX configuration
	ocl->state = OCSE_IDLE;
	if (dedicated_mode_support(ocl->mmio)) {
		// AFU supports Dedicated Mode
		ocl->max_clients = 1;
	}
	if (directed_mode_support(ocl->mmio)) {
		// AFU supports Directed Mode
		ocl->max_clients = ocl->mmio->desc.num_of_processes;
	}
	if (ocl->max_clients == 0) {
		error_msg("AFU programming model is invalid");
		goto init_fail;
	}
	ocl->client = (struct client **)calloc(ocl->max_clients,
					       sizeof(struct client *));
	ocl->cmd->client = ocl->client;
	ocl->cmd->max_clients = ocl->max_clients;

	return location;

 init_fail:
	if (ocl) {
		if (ocl->afu_event) {
			tlx_close_afu_event(ocl->afu_event);
			free(ocl->afu_event);
		}
		if (ocl->host)
			free(ocl->host);
		if (ocl->name)
			free(ocl->name);
		free(ocl);
	}
	pthread_mutex_unlock(lock);
	return 0;
}
