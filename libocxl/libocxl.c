/*
 * Copyright 2014,2015 International Business Machines
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

// first implement ocxl_afu_open_dev and required stack - check
// next implement ocxl_afu_attach and required stack
// then mmio helpers
// then lpc helpers

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include "libocxl.h"
#include "libocxl_internal.h"
#include "../common/utils.h"

#define API_VERSION            1
#define API_VERSION_COMPATIBLE 1

#ifdef DEBUG
#define DPRINTF(...) printf(__VA_ARGS__)
#else
#define DPRINTF(...)
#endif

#ifndef MAX
#define MAX(a,b)(((a)>(b))?(a):(b))
#endif /* #ifndef MAX */

#ifndef MIN
#define MIN(a,b)(((a)<(b))?(a):(b))
#endif /* #ifndef MIN */

/*
 * System constants
 */

#define MAX_LINE_CHARS 1024

#define FOURK_MASK        0xFFFFFFFFFFFFF000L

#define DSISR 0x4000000040000000L
#define ERR_BUFF_MAX_COPY_SIZE 4096

static int _delay_1ms()
{
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;
	return nanosleep(&ts, &ts);
}

static int _testmemaddr(uint8_t * memaddr)
{
	int fd[2];
	int ret = 0;
	if (pipe(fd) >= 0) {
		if (write(fd[1], memaddr, 1) > 0)
			ret = 1;
	}

	close(fd[0]);
	close(fd[1]);

	return ret;
}

static void _all_idle(struct ocxl_afu_h *afu)
{
	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_all_idle");
	afu->int_req.state = LIBOCXL_REQ_IDLE;
	afu->open.state = LIBOCXL_REQ_IDLE;
	afu->attach.state = LIBOCXL_REQ_IDLE;
	afu->mmio.state = LIBOCXL_REQ_IDLE;
	afu->mapped = 0;
	afu->global_mapped = 0;
	afu->attached = 0;
	afu->opened = 0;
}

static int _handle_dsi(struct ocxl_afu_h *afu, uint64_t addr)
{
	uint16_t size;
	int i;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_dsi");
	// Only track a single DSI at a time
	pthread_mutex_lock(&(afu->event_lock));
	i = 0;
	while (afu->events[i] != NULL) {
		if (afu->events[i]->header.type == OCXL_EVENT_DATA_STORAGE) {
			pthread_mutex_unlock(&(afu->event_lock));
			return 0;
		}
		++i;
	}
	assert(i < EVENT_QUEUE_MAX);

	size = sizeof(struct ocxl_event_header) +
	    sizeof(struct ocxl_event_data_storage);
	afu->events[i] = (struct ocxl_event *)calloc(1, size);
	afu->events[i]->header.type = OCXL_EVENT_DATA_STORAGE;
	afu->events[i]->header.size = size;
	afu->events[i]->header.process_element = afu->context;
	afu->events[i]->fault.addr = addr & FOURK_MASK;
	afu->events[i]->fault.dsisr = DSISR;

	do {
		i = write(afu->pipe[1], &(afu->events[i]->header.type), 1);
	}
	while ((i == 0) || (errno == EINTR));
	pthread_mutex_unlock(&(afu->event_lock));
	return i;
}

static int _handle_interrupt(struct ocxl_afu_h *afu)
{
  // LGT idea
	/* uint64_t irq; */
	/* uint8_t size; */
	/* uint8_t data[64]; */
	/* uint8_t data_valid; */
  // HMP idea
	uint16_t size;
	//uint8_t data[sizeof(irq)];
	struct ocxl_irq_h *irq;
	uint64_t addr;
	uint8_t cmd_flag;
	uint8_t adata[sizeof(addr)];
	int i;

	if (!afu) fatal_msg("_handle_interrupt:NULL afu passed");

	DPRINTF("AFU INTERRUPT\n");

	// in opencapi, we should get a 64 bit address (and maybe data)
	// we should find that address in the afu's irq list
	// if we find it, we should put some stuff(?) in the event array

	// propose
	// byte to say if there is data
	// 8 bytes of address aka irq
	// ? bytes of data size
	// size bytes of data

	// LGT idea
	/* if (get_bytes_silent(afu->fd, sizeof(data_valid), &data_valid, 1000, 0) < 0) { */
	/* 	warn_msg("Socket failure getting interrupt data valid"); */
	/* 	_all_idle(afu); */
	/* 	return -1; */
	/* } */
	/* if (get_bytes_silent(afu->fd, sizeof(irq), (uint8_t *)&irq, 1000, 0) < 0) { */
	/* 	warn_msg("Socket failure getting IRQ"); */
	/* 	_all_idle(afu); */
	/* 	return -1; */
	/* } */
	/* // memcpy(&irq, data, sizeof(irq)); */
	/* irq = ntohs(irq); */
	
	/* // this might not be required as intrp_req.d is not allowed in Power */
	/* if (data_valid) { */
	/*   if (get_bytes_silent(afu->fd, sizeof(size), &size, 1000, 0) < 0) { */
	/*     warn_msg("Socket failure getting interrupt data size"); */
	/*     _all_idle(afu); */
	/*     return -1; */
	/*   } */
	/*   if (get_bytes_silent(afu->fd, size, data, 1000, 0) < 0) { */
	/*     warn_msg("Socket failure getting data"); */
	/*     _all_idle(afu); */
	/*     return -1; */
	/*   }	   */
	/* } */

	// HMP idea
	//buffer[0] = OCSE_INTERRUPT (already read)
	//buffer[1] = event->cmd_flag
	//buffer[2] = event->addr 

	if (get_bytes_silent(afu->fd, 1, &cmd_flag, 1000, 0) < 0) {
		warn_msg("Socket failure getting cmd_flags");
		_all_idle(afu);
		return -1;
	}
	if (get_bytes_silent(afu->fd, sizeof(addr), adata, 1000, 0) < 0) {
		warn_msg("Socket failure getting address");
		_all_idle(afu);
		return -1;
	}
	memcpy(&addr, adata, sizeof(addr));
	addr = ntohs(addr);
	printf("OK, interrupt request made it over socket to client!!\n");

	// TODO Update the rest of this to actually search for address and then do 
	// whatever is needed if it's valid.....

	// search for addr in irq list of afu
	// if we don't find it, warn_msg
	// if we do find it, add an event if it is new for this irq
	irq = afu->irq;
	while (irq != NULL) {
	  if ( irq == (struct ocxl_irq_h *)addr ) {
	    break;
	  }
	  irq = irq->_next;
	}
	if ( irq == NULL ) {
	  warn_msg( "_handle_interrupt: no matching irqs allocated in this application" );
	  return -1;
	}

	// we have the matching irq pointer

	// Only track a single interrupt at a time
	// but what about a second afu_interrupt to a different irq address?  
	// should that be saved or coalecsed?
	// this code would coalesce them
	pthread_mutex_lock(&(afu->event_lock));
	i = 0;
	while (afu->events[i] != NULL) {
		if (afu->events[i]->header.type == OCXL_EVENT_AFU_INTERRUPT) {
			// we could search deeper here to see if this event is for the
			// incoming irq.  if it is, return, if not, check the next event
			pthread_mutex_unlock(&(afu->event_lock));
			return 0;
		}
		++i;
	}
	assert(i < EVENT_QUEUE_MAX);

	size = sizeof(struct ocxl_event_header) +
	    sizeof(struct ocxl_event_afu_interrupt);
	afu->events[i] = (struct ocxl_event *)calloc(1, size);
	afu->events[i]->header.type = OCXL_EVENT_AFU_INTERRUPT;
	afu->events[i]->header.size = size;
	afu->events[i]->header.process_element = afu->context; // might not need this
	afu->events[i]->irq.irq = addr;  // which came in and matched irq
	afu->events[i]->irq.flags = cmd_flag;

	do {
		i = write(afu->pipe[1], &(afu->events[i]->header.type), 1);
	}
	while ((i == 0) || (errno == EINTR));
	pthread_mutex_unlock(&(afu->event_lock));
	return i;
}

static int _handle_afu_error(struct ocxl_afu_h *afu)
{
	uint64_t error;
	uint16_t size;
	uint8_t data[sizeof(error)];
	int i;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_afu_error");
	DPRINTF("AFU ERROR\n");
	if (get_bytes_silent(afu->fd, sizeof(error), data, 1000, 0) < 0) {
		warn_msg("Socket failure getting AFU ERROR");
		_all_idle(afu);
		return -1;
	}
	memcpy(&error, data, sizeof(error));
	error = ntohll(error);

	// Only track a single AFU error at a time
	pthread_mutex_lock(&(afu->event_lock));
	i = 0;
	while (afu->events[i] != NULL) {
		if (afu->events[i]->header.type == OCXL_EVENT_AFU_ERROR) {
			pthread_mutex_unlock(&(afu->event_lock));
			return 0;
		}
		++i;
	}
	assert(i < EVENT_QUEUE_MAX);

	size = sizeof(struct ocxl_event_header) +
	    sizeof(struct ocxl_event_afu_error);
	afu->events[i] = (struct ocxl_event *)calloc(1, size);
	afu->events[i]->header.type = OCXL_EVENT_AFU_ERROR;
	afu->events[i]->header.size = size;
	afu->events[i]->header.process_element = afu->context;
	afu->events[i]->afu_error.error = error;

	do {
		i = write(afu->pipe[1], &(afu->events[i]->header.type), 1);
	}
	while ((i == 0) || (errno == EINTR));
	pthread_mutex_unlock(&(afu->event_lock));
	return i;
}

static void _handle_read(struct ocxl_afu_h *afu, uint64_t addr, uint16_t size)
{
	uint8_t buffer[MAX_LINE_CHARS];

	DPRINTF("_handle_read: addr @ 0x%016" PRIx64 ", size = %d\n", addr, size);
	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_read");
	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		DPRINTF("READ from invalid addr @ 0x%016" PRIx64 "\n", addr);
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, buffer) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	buffer[0] = OCSE_MEM_SUCCESS;
	memcpy(&(buffer[1]), (void *)addr, size);
	if (put_bytes_silent(afu->fd, size + 1, buffer) != size + 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	DPRINTF("READ from addr @ 0x%016" PRIx64 "\n", addr);
}

static void _handle_write_be(struct ocxl_afu_h *afu, uint64_t addr, uint16_t size,
			     uint8_t * data, uint64_t be)
{
	uint8_t buffer;
	uint64_t enable;
	uint64_t be_copy;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_write_be");
	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		DPRINTF("WRITE to invalid addr @ 0x%016" PRIx64 "\n", addr);
		buffer = OCSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}

	// we'll have to loop through data byte by byte
	// and if the corresponding bit of be is on, 
	// write the data byte to the address offset by the loop index
	// or something like that.
	// the trick is that be is likely to be little endian
	// something like this maybe
	// be_copy = be;
	// for (i=0;i<64;i++) {
	//   enable = be_copy && 0x0000000000000001; // mask everything but bit 0
	//   if (enable) {
	//     *((char *)addr + i) = data[i];  // add i to addr and deref???
	//   }
	//   be_copy = be_copy >> 1; // shift be_copy right 1 bit.
	// }
	//memcpy((void *)addr, data, size);
	//buffer = OCSE_MEM_SUCCESS;
	//if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
	//	afu->opened = 0;
	//	afu->attached = 0;
	//}
	DPRINTF("WRITE to addr @ 0x%016" PRIx64 "\n", addr);
}

static void _handle_write(struct ocxl_afu_h *afu, uint64_t addr, uint16_t size,
			  uint8_t * data)
{
	uint8_t buffer;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_write");
	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		DPRINTF("WRITE to invalid addr @ 0x%016" PRIx64 "\n", addr);
		buffer = OCSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	memcpy((void *)addr, data, size);
	buffer = OCSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	DPRINTF("WRITE to addr @ 0x%016" PRIx64 "\n", addr);
}

static void _handle_touch(struct ocxl_afu_h *afu, uint64_t addr, uint8_t size)
{
	uint8_t buffer;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_touch");
	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		DPRINTF("TOUCH of invalid addr @ 0x%016" PRIx64 "\n", addr);
		buffer = (uint8_t) OCSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	buffer = OCSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	DPRINTF("TOUCH of addr @ 0x%016" PRIx64 "\n", addr);
}

static void _handle_ack(struct ocxl_afu_h *afu)
{
	uint8_t data[sizeof(uint64_t)];

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_ack");
	DPRINTF("MMIO ACK\n");
	if ((afu->mmio.type == OCSE_MMIO_READ64) | (afu->mmio.type == OCSE_GLOBAL_MMIO_READ64) | (afu->mmio.type == OCSE_MMIO_EBREAD)) {
		if (get_bytes_silent(afu->fd, sizeof(uint64_t), data, 1000, 0) <
		    0) {
			warn_msg("Socket failure getting MMIO Ack");
			_all_idle(afu);
			afu->mmio.data = 0xFEEDB00FFEEDB00FL;
		} else {
			memcpy(&(afu->mmio.data), data, sizeof(uint64_t));
			afu->mmio.data = ntohll(afu->mmio.data);
		}
	}
	if ((afu->mmio.type == OCSE_MMIO_READ32) | (afu->mmio.type == OCSE_GLOBAL_MMIO_READ32)) {
		if (get_bytes_silent(afu->fd, sizeof(uint32_t), data, 1000, 0) <
		    0) {
			warn_msg("Socket failure getting MMIO Read 32 data");
			afu->mmio.data = 0xFEEDB00FL;
			_all_idle(afu);
		} else {
			memcpy(&(afu->mmio.data), data, sizeof(uint32_t));
			debug_msg("KEM:0x%08x", afu->mmio.data);
			afu->mmio.data = ntohl(afu->mmio.data);
			debug_msg("KEM:0x%08x", afu->mmio.data);
		}
	}
	afu->mmio.state = LIBOCXL_REQ_IDLE;
}


static void _handle_DMO_OPs(struct ocxl_afu_h *afu, uint8_t amo_op, uint8_t op_size, uint64_t addr,
			  uint8_t function_code, uint64_t op1, uint64_t op2)
{

	uint8_t atomic_op;
	uint8_t atomic_le;
	uint8_t buffer;
	uint8_t wbuffer[9];
	uint32_t lvalue, op_A, op_1, op_2;
	uint64_t llvalue, op_Al, op_1l, op_2l;
	int op_ptr;
	char wb;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_DMO_OPs");
	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		DPRINTF("READ from invalid addr @ 0x%016" PRIx64 "\n", addr);
		return;
	}
	
	// Size is now a uint16_t and it represents the size of the data buffer
	//  size = 4 means single op and op_size = 4
	//  size = 8 could mean single op & op_size=8 OR two ops and op_size = 4
	//  size = 16 means two ops and op_size = 8
	// Need to pull ops out of buffer that got passed in 
	// If we determine op size, can create that and might make it easier for porting existing code
	// lgt and possibly the endian hint - not coded yet
	op_ptr = (int) (addr & 0x000000000000000c);
	// at this point, op1 and op2 are memcpy's of the data that sent over ddata
	// no byte swapping has taken place, however, we have stored them here as little endian 64 bit ints
	// if we use int ops, we'll get defacto byte swapping as we go.  that might not be what we want
	switch (op_ptr) {
		case 0x0:
			if ((op_size == 4) && (amo_op != OCSE_AMO_RD)) { // only amo_wr & amo_rw have immediate data
			        // OP1 is in ((__u8 *)(&op1))[0 to 3]
			        // OP2 is in ((__u8 *)(&op2))[0 to 3]
			        // don't shift as the 32bits we want are already le on the left,
			        // so the cast will grab the correct end
 			        // op_1 = (uint32_t) op1;// (op1 >> 32);
				// op_2 = (uint32_t) op2;// (op2 >> 32);
				memcpy( (void *)&op_1, (void *)&op1, op_size);
				memcpy( (void *)&op_2, (void *)&op2, op_size);
				// printf(" case 0: op_1 is %08"PRIx32 "\n", op_1);
				// printf(" case 0: op_2 is %08"PRIx32 "\n", op_2);
			} else if ((op_size == 8) && (amo_op != OCSE_AMO_RD)) {
				op_1l = op1;
				op_2l = op2;
				// printf(" case 0: op_1l is %016"PRIx64 "\n", op_1l);
			}
			break;
		case 0x4:
			if ((op_size == 4) && (amo_op != OCSE_AMO_RD)) { // only amo_wr & amo_rw have immediate data
			        // OP1 is in (__u8 *)(&op1)[4 to 7]
			        // OP2 is in (__u8 *)(&op2)[4 to 7]
			        // if the ops are really be, we have to handle them differently
			        // I think we should switch to memcpy to extract the data...
			        // the below  worked because the mcp afu replicated the ops,
			        // architecturally, it is not correct, but how to change it?
				// op_1 = (uint32_t) op1;
				// op_2 = (uint32_t) op2;
				memcpy( (void *)&op_1, (void *)&op1 + 4, op_size);
				memcpy( (void *)&op_2, (void *)&op2 + 4, op_size);
				// printf(" case 4: op_1 is %08"PRIx32 "\n", op_1);
				// printf(" case 4: op_2 is %08"PRIx32 "\n", op_2);
			} else if (op_size == 8) {
				DPRINTF("INVALID op_size  0x%x for  addr  0x%016" PRIx64 "\n", op_size, addr);
				buffer = (uint8_t) OCSE_MEM_FAILURE;
				if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
					afu->opened = 0;
					afu->attached = 0;
				}
				return;
			}
			break;
		case 0x8:
			if ((op_size == 4) && (amo_op != OCSE_AMO_RD)) { // only amo_wr & amo_rw have immediate data
			        // OP1 is in (__u8 *)(&op2)[0 to 3] !!!
			        // OP2 is in (__u8 *)(&op1)[0 to 3] !!!
				// op_1 = (uint32_t) (op1 >>32);
				// op_2 = (uint32_t) (op2 >> 32);
				memcpy( (void *)&op_1, (void *)&op1, op_size);
				memcpy( (void *)&op_2, (void *)&op2, op_size);
				// printf(" case 8: op_1 is %08"PRIx32 "\n", op_1);
				// printf(" case 8: op_2 is %08"PRIx32 "\n", op_2);
			} else if ((op_size == 8) && (amo_op != OCSE_AMO_RD)) {
				op_1l = op2;
				op_2l = op1;
	                        // printf(" case 8: op_1l is %016"PRIx64 "\n", op_1l);
			}
			break;
		case 0xc:
			if ((op_size == 4) && (amo_op != OCSE_AMO_RD)) { // only amo_wr & amo_rw have immediate data
			        // OP1 is in (__u8 *)(&op2)[4 to 7] !!!
			        // OP2 is in (__u8 *)(&op1)[4 to 7] !!!
				// op_1 = (uint32_t) op2;
				// op_2 = (uint32_t) op1;
				memcpy( (void *)&op_1, (void *)&op2 + 4, op_size);
				memcpy( (void *)&op_2, (void *)&op1 + 4, op_size);
				// printf(" case c: op_1 is %08"PRIx32 "\n", op_1);
				// printf(" case c: op_2 is %08"PRIx32 "\n", op_2);
			} else if (op_size == 8) {
				DPRINTF("INVALID op_size  0x%x for  addr  0x%016" PRIx64 "\n", op_size, addr);
				buffer = (uint8_t) OCSE_MEM_FAILURE;
				if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
					afu->opened = 0;
					afu->attached = 0;
				}
				return;
			}
			break;
		default:
			warn_msg("received invalid value op_ptr value of 0x%x ", op_ptr);
			break;
	}

	atomic_op = function_code;
	//TODO Here is where I stopped updating this function from CAPI2 to OPEN CAPI
	// Remove and read atomic_le from bit7 of data[0]
	// if atomic_le == 1, afu is le, so no data issues (ocse is always le).
	// if atomic_le == 0, we have to swap op1/op2 data before ops, and also swap
	// data returned by fetches
	if ((atomic_op & 0x80) == 0x80) {
		atomic_le = 1;
		atomic_op &= 0x3F;
	} else
		atomic_le = 0;

	debug_msg("_handle_DMO_OPs:  atomic_op = 0x%2x and atomic_le = 0x%x ", atomic_op, atomic_le);

	DPRINTF("READ from addr @ 0x%016" PRIx64 "\n", addr);
	if (op_size == 0x4) {
		memcpy((char *) &lvalue, (void *)addr, op_size);
		op_A = (uint32_t)(lvalue);
	        debug_msg("op_A is %08"PRIx32 " and op_1 is %08"PRIx32 , op_A, op_1);
		if (atomic_le == 0) {
			op_1 = ntohl(op_1);
			op_2 = ntohl(op_2);
		}
	} else if (op_size == 0x8) {

		memcpy((char *) &llvalue, (void *)addr, op_size);
		op_Al = (uint64_t)(llvalue);
		if (atomic_le == 0) {
			op_1l = ntohll(op_1l);
			op_2l = ntohll(op_2l);
		}
	        debug_msg("op_Al is %016"PRIx64 " and op_1l is %016"PRIx64 , op_Al, op_1l);
	        debug_msg("llvalue read from location -> by addr is %016" PRIx64 " and addr is 0x%016" PRIx64 , llvalue, addr);
	} else // need else error bc only valid sizes are 4 or 8
		warn_msg("unsupported op_size of 0x%2x \n", op_size);

	switch (atomic_op) {
			/* addr = location of an address aligned 4 or 8 byte first operand (op_A),
 *  which is modified with operand provided by AFU (op_1 or op_1l). AFU also provides the function
 *  encode (op_code). The result is returned to memory, the original value is returned to the AFU as completion data */
			case AMO_ARMWF_ADD:
				if  (op_size == 4) {
				debug_msg("ADD %08"PRIx32" to %08"PRIx32 " store it & return op_A ", op_A, op_1);
					op_1 += op_A;
					wb = 1;
				} else {
				debug_msg("ADD %016"PRIx64" to %016"PRIx64 " store it & return op_Al ", op_Al, op_1l);
					op_1l += op_Al;
					wb = 2;
				}
				break;
			case AMO_ARMWF_XOR:
				if  (op_size == 4) {
				debug_msg("XOR %08"PRIx32" with %08"PRIx32 " store it & return op_A ", op_A, op_1);
					op_1 ^= op_A;
					wb = 1;
				} else {
				debug_msg("XOR %016"PRIx64" with %016"PRIx64 " store it & return op_Al ", op_Al, op_1l);
					op_1l ^= op_Al;
					wb = 2;
				}
				break;
			case AMO_ARMWF_OR:
				if  (op_size == 4) {
				debug_msg("OR %08"PRIx32" with %08"PRIx32 " store it & return op_A ", op_A, op_1);
					op_1 |= op_A;
					wb = 1;
				} else {
				debug_msg("OR %016"PRIx64" with %016"PRIx64 " store it & return op_Al ", op_Al, op_1l);
					op_1l |= op_Al;
					wb = 2;
				}
				break;
			case AMO_ARMWF_AND:
				if  (op_size == 4) {
				debug_msg("AND %08"PRIx32" with %08"PRIx32 " store it & return op_A ", op_A, op_1);
					op_1 &= op_A;
					wb = 1;
				} else {
				debug_msg("AND %016"PRIx64" with %016"PRIx64 " store it & return op_Al ", op_Al, op_1l);
					op_1l &= op_Al;
					wb = 2;
				}
				break;
			case AMO_ARMWF_CAS_MAX_U:
				if  (op_size == 4) {
				debug_msg("UNSIGNED COMPARE %08"PRIx32" with %08"PRIx32 " , store larger & return op_A ", op_A, op_1);
					if (op_A > op_1)
						op_1 = op_A;
					wb = 1;
				} else {
				debug_msg("UNSIGNED COMPARE %016"PRIx64" with %016"PRIx64 " , store larger & return op_Al  ", op_Al, op_1l);
					if (op_Al > op_1l)
						op_1l = op_Al;
					wb = 2;
				}
				break;
			case AMO_ARMWF_CAS_MAX_S:
				// sign extend op_A and op_1 and then cast as int and do comparison
				if (op_size == 4) {
					op_A = sign_extend(op_A);
					op_1 = sign_extend(op_1);
				debug_msg("SIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store larger & return op_A ", op_A, op_1);
					if ((int32_t)op_A > (int32_t)op_1)
						op_1 = op_A;
					wb = 1;
				} else {
					op_Al = sign_extend64(op_Al);
					op_1l = sign_extend64(op_1l);
				debug_msg("SIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store larger & return op_Al ", op_Al, op_1l);
					if ((int64_t)op_Al > (int64_t)op_1l)
						op_1l = op_Al;
					wb = 2;
				};
				break;
			case AMO_ARMWF_CAS_MIN_U:
				if  (op_size == 4) {
				debug_msg("UNSIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store smaller & return op_A ", op_A, op_1);
					if (op_A < op_1)
						op_1 = op_A;
					wb = 1;
				} else {
				debug_msg("UNSIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store smaller & return op_Al ", op_Al, op_1l);
					if (op_Al < op_1l)
						op_1l = op_Al;
					wb = 2;
				}
				break;
			case AMO_ARMWF_CAS_MIN_S:
				if (op_size == 4) {
					op_A = sign_extend(op_A);
					op_1 = sign_extend(op_1);
				debug_msg("SIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store smaller & return op_A ", op_A, op_1);
					if ((int32_t)op_A < (int32_t)op_1)
						op_1 = op_A;
					wb = 1;
				} else {
					op_Al = sign_extend64(op_Al);
					op_1l = sign_extend64(op_1l);
				debug_msg("SIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store smaller & return op_Al ", op_Al, op_1l);
					if ((int64_t)op_Al < (int64_t)op_1l)
						op_1l = op_Al;
					wb = 2;
				}
				break;
			/* addr = location of an address aligned 4 or 8 byte first operand (op_A),
 * which is compared to the operand provided by AFU (op_1 or (op_1l). AFU also provides the function
 * encode (op_code. If result of compare is true, the third operand provided by AFU (op_2 or op_2l)
 * is written to memory at location specified for op_A. Original value of op_A is returned to AFU. */
			case AMO_ARMWF_CAS_U:
				if  (op_size == 4) {
				debug_msg("COMPARE & SWAP  %08"PRIx32" with %08"PRIx32 " ,store op_2 & return op_A ", op_A, op_1);
					op_1 = op_2;
					wb = 1;
				} else {
				debug_msg("COMPARE & SWAP  %016"PRIx64" with %016"PRIx64 " ,store op_2l & return op_Al ", op_Al, op_1l);
					op_1l = op_2l;
					wb = 2;
				}
				break;
			case AMO_ARMWF_CAS_E:
				if  (op_size == 4) {
				debug_msg("COMPARE & SWAP == %08"PRIx32" with %08"PRIx32 " ,if true store op_2 & return op_A ", op_A, op_1);
					if (op_A == op_1)
						op_1 = op_2;
					else
						op_1 = op_A;
					wb = 1;
				} else {
				debug_msg("COMPARE & SWAP == %016"PRIx64" with %016"PRIx64 " ,if true store op_2l & return op_Al ", op_Al, op_1l);
					if (op_Al == op_1l)
						op_1l = op_2l;
					else
						op_1l = op_Al;
					wb = 2;
				}
				break;
			case AMO_ARMWF_CAS_NE:
				if  (op_size == 4) {
				debug_msg("COMPARE & SWAP != %08"PRIx32" with %08"PRIx32 " ,if true, store op_2 & return op_A ", op_A, op_1);
					if (op_A != op_1)
						op_1 = op_2;
					else
						op_1 = op_A;
					wb = 1;
				} else {
				debug_msg("COMPARE & SWAP != %016"PRIx64" with %016"PRIx64 " ,if true, store op_2l & return op_Al ", op_Al, op_1l);
					if (op_Al != op_1l)
						op_1l = op_2l;
					else
						op_1l = op_Al;
					wb = 2;
				}
				break;
			/* addr = location of two address aligned 4 or 8 byte operands.
 * The first operand A is found at the address specified; second operand A2 is found at
 * addr + 4 or addr +8, depending on widths of operands.
 *  • cannot target locations at 32n-2bin2dec(‘1L’), where n = 1,2,3... (armwf_inc_b, armwf_inc_e)
 *  • cannot target locations at 32n, when n = 0, 1, 2, 3... (armwf_dec_b)
 * The original value from memory, or (1 << (s*8 -1)) is returned (s = 4 or 8) */
			case AMO_ARMWF_INC_B:
				if  (op_size == 4) {
					memcpy((char *) &lvalue, (void *)addr+4, op_size);
					op_1 = (uint32_t)(lvalue);
				debug_msg("COMPARE & INC Bounded %08"PRIx32" with %08"PRIx32 ", if !=, inc op_A, ret orig op_A, else..", op_A, op_1);
					if (op_A != op_1)
						op_1 = op_A +1;
					else {
						op_1 = op_A;
						op_A = MIN_INT32;
						//op_A = (1 << 31);
					     }
					wb = 1;
				} else {
					memcpy((char *) &llvalue, (void *)addr+8, op_size);
					op_1l = (uint64_t)(llvalue);
				debug_msg("COMPARE & INC Bounded %016"PRIx64" with %016"PRIx64 ", if !=, inc op_A, ret orig op_a, else..", op_Al, op_1l);
					if (op_Al != op_1l)
						op_1l = op_Al +1;
					else  {
						op_1l = op_Al;
						op_Al = MIN_INT64;
						//op_Al = (1ULL << 63);
					      }
					wb = 2;
				}
				break;
			case AMO_ARMWF_INC_E:
				if  (op_size == 4) {
					memcpy((char *) &lvalue, (void *)addr+4, op_size);
					op_1 = (uint32_t)(lvalue);
				debug_msg("COMPARE & INC Equal %08"PRIx32" with %08"PRIx32 ", if =, inc op_A, ret orig op_A, else..", op_A, op_1);
					if (op_A == op_1)
						op_1 = op_A +1;
					else   {
						op_1 = op_A;
						op_A = MIN_INT32;
						//op_A = (1 << 31);
					       }
					wb = 1;
				} else {
					memcpy((char *) &llvalue, (void *)addr+8, op_size);
					op_1l = (uint64_t)(llvalue);
				debug_msg("COMPARE & INC Equal %016"PRIx64" with %016"PRIx64 ", if =, inc op_A, ret orig op_a, else..", op_Al, op_1l);
					if (op_Al == op_1l)
						op_1l = op_A +1;
					else    {
						op_1l = op_Al;
						op_Al = MIN_INT64;
						//op_Al = (int64_t) (1ULL <<63);
						}
					wb = 2;
				}
				break;
			case AMO_ARMWF_DEC_B:
				if  (op_size == 4) {
					memcpy((char *) &lvalue, (void *)addr-4, op_size);
					op_1 = (uint32_t)(lvalue);
				debug_msg("COMPARE & DEC Bounded %08"PRIx32" with %08"PRIx32 ", if != dec op_A, ret orig op_A, else..", op_A, op_1);
					if (op_A != op_1)
						op_1 = op_A -1;
					else  {
						op_1 = op_A;
						op_A = MIN_INT32;
						//op_A = (1 << 31);
					      }
					wb = 1;
				} else {
					memcpy((char *) &llvalue, (void *)addr-8, op_size);
					op_1l = (uint64_t)(llvalue);
				debug_msg("COMPARE & DEC Bounded %016"PRIx64" with %016"PRIx64 ", if !=, dec op_A, ret orig op_a, else..", op_Al, op_1l);
					if (op_Al != op_1l)
						op_1l = op_Al -1;
					else   {
						op_1l = op_Al;
						op_Al = MIN_INT64;
						//op_Al = (1ULL << 63);
					       }
					wb = 2;
				}
				break;
			/* addr = location of an address aligned 4 or 8 byte first operand (op_A),
 *  which is modified with operand provided by AFU (op_1 or op_1l). AFU also provides the function
 *  encode (op_code). The result is returned to memory, the original value is returned to the AFU as completion data */
			case AMO_ARMW_ADD:
				if  (op_size == 4) {
				debug_msg("ADD %08"PRIx32" to %08"PRIx32 " and store it  ", op_A, op_1);
					op_1 += op_A;
				} else {
				debug_msg("ADD %016"PRIx64" to %016"PRIx64 " and store it  ", op_Al, op_1l);
					op_1l += op_Al;
				}
				wb = 0;
				break;

			case AMO_ARMW_XOR:
				if  (op_size == 4) {
				debug_msg("XOR %08"PRIx32" with %08"PRIx32 " and store it  ", op_A, op_1);
					op_1 ^= op_A;
				} else {
				debug_msg("XOR %016"PRIx64" with %016"PRIx64 " and store it  ", op_Al, op_1l);
					op_1l ^= op_Al;
				}
				wb = 0;
				break;
			case AMO_ARMW_OR:
				if  (op_size == 4) {
				debug_msg("OR %08"PRIx32" with %08"PRIx32 " and store it  ", op_A, op_1);
					op_1 |= op_A;
				} else {
				debug_msg("OR %016"PRIx64" with %016"PRIx64 " and store it  ", op_Al, op_1l);
					op_1l |= op_Al;
				}
				wb = 0;
				break;
			case AMO_ARMW_AND:
				if  (op_size == 4) {
				debug_msg("AND %08"PRIx32" with %08"PRIx32 " and store it ", op_A, op_1);
					op_1 &= op_A;
				} else {
				debug_msg("AND %016"PRIx64" with %016"PRIx64 " and store it  ", op_Al, op_1l);
					op_1l &= op_Al;
				}
				wb = 0;
				break;
			case AMO_ARMW_CAS_MAX_U:
				if  (op_size == 4) {
				debug_msg("UNSIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store the larger ", op_A, op_1);
					if (op_A > op_1)
						op_1 = op_A;
				} else {
				debug_msg("UNSIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store the larger  ", op_Al, op_1l);
					if (op_Al > op_1l)
						op_1l = op_Al;
				}
				wb = 0;
				break;

			case AMO_ARMW_CAS_MAX_S:
				// sign extend op_A and op_1 and then cast as int and do comparison
				if (op_size == 4) {
					op_A = sign_extend(op_A);
					op_1 = sign_extend(op_1);
				debug_msg("SIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store the larger ", op_A, op_1);
					if ((int32_t)op_A > (int32_t)op_1)
						op_1 = op_A;
					wb = 0;
				} else {
					op_Al = sign_extend64(op_Al);
					op_1l = sign_extend64(op_1l);
				debug_msg("SIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store the larger  ", op_Al, op_1l);
					if ((int64_t)op_Al > (int64_t)op_1l)
						op_1l = op_Al;
					wb = 0;
				}
				break;
			case AMO_ARMW_CAS_MIN_U:
				if  (op_size == 4) {
				debug_msg("UNSIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store the smaller ", op_A, op_1);
					if (op_A < op_1)
						op_1 = op_A;
				} else {
				debug_msg("UNSIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store the smaller  ", op_Al, op_1l);
					if (op_Al < op_1l)
						op_1l = op_Al;
				}
				wb = 0;
				break;
			case AMO_ARMW_CAS_MIN_S:
				if (op_size == 4) {
					op_A = sign_extend(op_A);
					op_1 = sign_extend(op_1);
				debug_msg("SIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store the smaller ", op_A, op_1);
					if ((int32_t)op_A < (int32_t)op_1)
						op_1 = op_A;
					wb = 0;
				} else {
					op_Al = sign_extend64(op_Al);
					op_1l = sign_extend64(op_1l);
				debug_msg("SIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store the smaller  ", op_Al, op_1l);
					if ((int64_t)op_Al < (int64_t)op_1l)
						op_1l = op_Al;
					wb = 0;
				}
				break;
			/* addr = location of two address aligned 4 or 8 byte operands.
 * The first operand A is at addr; second operand A2 is at addr+  or addr+8, depending on widths of operands.
 * The address must be naturally aligned and cannot target locations at 32n-2bin2dec(‘1L’), where n = 1,2,3...
 * The AFU provides a third operand, op_1 or op_1, and will be stored at addr and addr+4 if A1 == A2. */
			case AMO_ARMW_CAS_T:
				if  (op_size == 4) {
					memcpy((char *) &lvalue, (void *)addr+4, op_size);
					op_2 = (uint32_t)(lvalue);
				debug_msg("STORE TWIN compare %08"PRIx32" with %08"PRIx32 ", if == store op_1 to both locations", op_A, op_2);
					if (op_A == op_2)
						op_2 = op_1;
					else
						op_1 = op_A;
					wb = 0;
				} else {
					memcpy((char *) &llvalue, (void *)addr+8, op_size);
					op_2l = (uint64_t)(llvalue);
				debug_msg("STORE TWIN compare %016"PRIx64" with %016"PRIx64 ", if == store op_1l to both locations", op_Al, op_2l);
					if (op_Al == op_2l)
						op_2l = op_1l;
					else
						op_1l = op_Al;
					wb = 0;
				}
				break;
			default:
				wb = 0xf;
				warn_msg("Unsupported AMO command 0x%04x", atomic_op);
				break;
			}
	// every VALID op has a write to store something to the original EA, unless STORE TWIN !=
	if (wb != 0xf) {
		if (op_size == 4) {
			memcpy ((void *)addr, &op_1, op_size);
			DPRINTF("WRITE to addr @ 0x%016" PRIx64 " with results of 0x%08" PRIX32 " \n", addr, op_1);
			// if this was STORE TWIN, write op_2 to addr+4
			if ((atomic_op) == AMO_ARMW_CAS_T) {
				memcpy ((void *)addr+4, &op_2, op_size);
				DPRINTF("WRITE to addr+4 @ 0x%016" PRIx64 " with results of 0x%08" PRIX32 " \n", addr+4, op_2);
			}
		} else  {// only other supported size is 8
			memcpy ((void *)addr, &op_1l, op_size);
			DPRINTF("WRITE to addr @ 0x%016" PRIx64 " with results of 0x%016" PRIX64 "\n", addr, op_1l);
			// if this was STORE TWIN, write op_2l to addr+8
			if ((atomic_op) == AMO_ARMW_CAS_T) {
				memcpy ((void *)addr+8, &op_2l, op_size);
				DPRINTF("WRITE to addr+8 @ 0x%016" PRIx64 " with results of 0x%016" PRIX64 " \n", addr+8, op_2l);
			}
		}
	}

// only AMO_ARMWF_* commands return back original data from EA, otherwise just MEM ACK
	switch (wb)  {
			case 0:
				buffer = OCSE_MEM_SUCCESS;
				if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
					afu->opened = 0;
					afu->attached = 0;
				}
				break;
			case 1:
				wbuffer[0] = OCSE_MEM_SUCCESS;
				if (atomic_le == 0)
					op_A = htonl(op_A);
				memcpy(&(wbuffer[1]), (void *)&op_A, op_size);
				if (put_bytes_silent(afu->fd, op_size + 1, wbuffer) != op_size + 1) {
					afu->opened = 0;
					afu->attached = 0;
				}
				DPRINTF("READ from addr @ 0x%016" PRIx64 "\n", addr);
				break;
			case 2:
				wbuffer[0] = OCSE_MEM_SUCCESS;
				if (atomic_le == 0)
					op_Al = htonll(op_Al);
				memcpy(&(wbuffer[1]), (void *)&op_Al, op_size);
				if (put_bytes_silent(afu->fd, op_size + 1, wbuffer) != op_size + 1) {
					afu->opened = 0;
					afu->attached = 0;
				}
				DPRINTF("READ from addr @ 0x%016" PRIx64 "\n", addr);
				break;

			default:
				warn_msg("invalid wb! ");
				wb = 0;
				break;
			}


}



static void _req_max_int(struct ocxl_afu_h *afu)
{
	uint8_t *buffer;
	int size;
	uint16_t value;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_req_max_int");
	size = 1 + sizeof(uint16_t);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = OCSE_MAX_INT;
	value = htons(afu->int_req.max);
	memcpy((char *)&(buffer[1]), (char *)&value, sizeof(uint16_t));
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->int_req.max = 0;
		_all_idle(afu);
		return;
	}
	free(buffer);
	afu->int_req.state = LIBOCXL_REQ_PENDING;
}

static void _ocse_attach(struct ocxl_afu_h *afu)
{
	uint8_t *buffer;
	// uint64_t *wed_ptr;
	int size;
	// int offset;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_ocse_attach");
	size = 1; // + sizeof(uint64_t);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = OCSE_ATTACH;
	// lgt - remove - offset = 1;
	// lgt - remove - wed_ptr = (uint64_t *) & (buffer[offset]);
	// lgt - remove - *wed_ptr = htonll(afu->attach.wed);
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->attach.state = LIBOCXL_REQ_IDLE;
		return;
	}
	free(buffer);
	afu->attach.state = LIBOCXL_REQ_PENDING;
}

static void _mmio_map(struct ocxl_afu_h *afu)
{
	uint8_t *buffer;
	uint32_t *flags_ptr;
	uint32_t flags;
	int size;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_mmio_map");
	size = 1 + sizeof(uint32_t);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = afu->mmio.type;
	flags = (uint32_t) afu->mmio.data;
	flags_ptr = (uint32_t *) & (buffer[1]);
	*flags_ptr = htonl(flags);
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mmio.state = LIBOCXL_REQ_IDLE;
		return;
	}
	free(buffer);
	afu->mmio.state = LIBOCXL_REQ_PENDING;
}

static void _mmio_write64(struct ocxl_afu_h *afu)
{
	uint8_t *buffer;
	uint64_t data;
	uint32_t addr;
	int size, offset;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_mmio_write64");
	size = 1 + sizeof(addr) + sizeof(data);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = afu->mmio.type;
	offset = 1;
	addr = htonl(afu->mmio.addr);
	memcpy((char *)&(buffer[offset]), (char *)&addr, sizeof(addr));
	offset += sizeof(addr);
	data = htonll(afu->mmio.data);
	memcpy((char *)&(buffer[offset]), (char *)&data, sizeof(data));
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mmio.state = LIBOCXL_REQ_IDLE;
		return;
	}
	free(buffer);
	afu->mmio.state = LIBOCXL_REQ_PENDING;
}

static void _mmio_write32(struct ocxl_afu_h *afu)
{
	uint8_t *buffer;
	uint32_t data;
	uint32_t addr;
	int size, offset;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_mmio_write32");
	size = 1 + sizeof(addr) + sizeof(data);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = afu->mmio.type;
	offset = 1;
	addr = htonl(afu->mmio.addr);
	memcpy((char *)&(buffer[offset]), (char *)&addr, sizeof(addr));
	offset += sizeof(addr);
	data = htonl(afu->mmio.data);
	memcpy((char *)&(buffer[offset]), (char *)&data, sizeof(data));
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mmio.state = LIBOCXL_REQ_IDLE;
		return;
	}
	free(buffer);
	afu->mmio.state = LIBOCXL_REQ_PENDING;
}

static void _mmio_read(struct ocxl_afu_h *afu)
{
	uint8_t *buffer;
	uint32_t addr;
	int size, offset;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_mmio_read");
	size = 1 + sizeof(addr);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = afu->mmio.type;
	offset = 1;
	addr = htonl(afu->mmio.addr);
	memcpy((char *)&(buffer[offset]), (char *)&addr, sizeof(addr));
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
	        warn_msg("_mmio_read: put_bytes_silent failed");
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mmio.state = LIBOCXL_REQ_IDLE;
		afu->mmio.data = 0xFEEDB00FFEEDB00FL;
		return;
	}
	free(buffer);
	afu->mmio.state = LIBOCXL_REQ_PENDING;
}

static void *_psl_loop(void *ptr)
{
	struct ocxl_afu_h *afu = (struct ocxl_afu_h *)ptr;
	uint8_t buffer[MAX_LINE_CHARS];
	uint8_t op_size, function_code, amo_op;
	uint64_t addr, wr_be;
	uint16_t size;
	uint32_t value, lvalue;
	uint64_t llvalue, op1, op2;
	int rc;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_psl_loop");
	afu->opened = 1;

	while (afu->opened) {
		_delay_1ms();
		// Send any requests to OCSE over socket
		if (afu->int_req.state == LIBOCXL_REQ_REQUEST)
			_req_max_int(afu);
		if (afu->attach.state == LIBOCXL_REQ_REQUEST)
			_ocse_attach(afu);
		if (afu->mmio.state == LIBOCXL_REQ_REQUEST) {
			switch (afu->mmio.type) {
			case OCSE_MMIO_MAP:
			case OCSE_GLOBAL_MMIO_MAP:
				_mmio_map(afu);
				break;
			case OCSE_MMIO_WRITE64:
			case OCSE_GLOBAL_MMIO_WRITE64:
				_mmio_write64(afu);
				break;
			case OCSE_MMIO_WRITE32:
			case OCSE_GLOBAL_MMIO_WRITE32:
				_mmio_write32(afu);
				break;
			case OCSE_MMIO_EBREAD:
			case OCSE_MMIO_READ64:
			case OCSE_MMIO_READ32:	
			case OCSE_GLOBAL_MMIO_READ64:
			case OCSE_GLOBAL_MMIO_READ32: /*fall through */
				_mmio_read(afu);
				break;
			default:
				break;
			}
		}

		// Process socket input from OCSE
		rc = bytes_ready(afu->fd, 1000, 0);
		if (rc == 0)
			continue;
		if (rc < 0) {
			warn_msg("Socket failure testing bytes_ready");
			_all_idle(afu);
			break;
		}
		if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
			warn_msg("Socket failure getting OCL event");
			_all_idle(afu);
			break;
		}

		DPRINTF("OCL EVENT\n");
		switch (buffer[0]) {
		case OCSE_OPEN:
			if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
				warn_msg("Socket failure getting OPEN context");
				_all_idle(afu);
				break;
			}
			afu->context = (uint16_t) buffer[0];
			afu->open.state = LIBOCXL_REQ_IDLE;
			break;
		case OCSE_ATTACH:
			afu->attach.state = LIBOCXL_REQ_IDLE;
			break;
		case OCSE_DETACH:
		        info_msg("detach response from from ocse");
			afu->mapped = 0;
			afu->global_mapped = 0;
			afu->attached = 0;
			afu->opened = 0;
			afu->open.state = LIBOCXL_REQ_IDLE;
			afu->attach.state = LIBOCXL_REQ_IDLE;
			afu->mmio.state = LIBOCXL_REQ_IDLE;
			afu->int_req.state = LIBOCXL_REQ_IDLE;
			break;
		case OCSE_MAX_INT:
			size = sizeof(uint16_t);
			if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) <
			    0) {
				warn_msg
				    ("Socket failure getting max interrupt acknowledge");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&value, (char *)buffer,
			       sizeof(uint16_t));
			// afu->irqs_max = ntohs(value);
			afu->int_req.state = LIBOCXL_REQ_IDLE;
			break;
		case OCSE_QUERY: {
    		        // update to reflect opencapi configuration information
		        // right now we only save the cr_device and cr_vendor
		        size = sizeof(uint32_t) + // AFU_CTL_ACTAG_LEN_EN_S
			       sizeof(uint16_t) + // max_irqs
			  sizeof(uint32_t) + // OCAPI_TL_MAXAFU
			  sizeof(uint32_t) + // AFU_INFO_REVID
			  sizeof(uint32_t) + // AFU_CTL_PASID_BASE
			  sizeof(uint32_t) + // AFU_CTL_ACTAG_BASE
			  sizeof(uint16_t) + // cr_device
			  sizeof(uint16_t) + // cr_vendor
			  sizeof(uint32_t) + // AFU_CTL_EN_RST_INDEX
			  sizeof(uint32_t) + // pp_MMIO_offset_high
			  sizeof(uint32_t) + // pp_MMIO_offset_low
			  sizeof(uint32_t) + // pp_MMIO_BAR
			  sizeof(uint32_t) ; // pp_MMIO_stride
			if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) <
			    0) {
				warn_msg("Socket failure getting OCSE query");
				_all_idle(afu);
				break;
			}
			// from pcie 0 header
			// device id
			// vendor id
			// revision id
			// maybe subsystem id and subsystem vendor id
			// from vsec's
			// tl version capability and configuration
			// lpc size = lpc memory always starts at 0
			// there is a bit of cleverness in the mmio space...  need to think more about this.
			// from afu_descriptor vsec
			// mmio offset, stride
			// number of pasid s and offset
			// and stuff
			memcpy((char *)&value, (char *)&(buffer[0]), 4); // AFU_CTL_ACTAG_LEN_EN_S
			//afu->irqs_min = (long)(value);
			memcpy((char *)&value, (char *)&(buffer[4]), 2); // max_irqs
			//afu->irqs_max = (long)(value);
                	memcpy((char *)&value, (char *)&(buffer[6]), 4); // OCAPI_TL_MAXAFU
			//afu->modes_supported = (long)(value);
                	memcpy((char *)&llvalue, (char *)&(buffer[10]), 4); // AFU_INFO_REVID
			//afu->mmio_len = (long)(llvalue & 0x00ffffffffffffff);
                	memcpy((char *)&llvalue, (char *)&(buffer[14]), 4); // AFU_CTL_PASID_BASE
			//afu->mmio_off = (long)(llvalue);
                	memcpy((char *)&llvalue, (char *)&(buffer[18]), 4); // AFU_CTL_ACTAG_BASE
			//afu->eb_len = (long)(llvalue);
                	memcpy((char *)&value, (char *)&(buffer[22]), 2); // cr_device
			afu->cr_device = value;
                        memcpy((char *)&value, (char *)&(buffer[24]), 2); // cr_vendor
			afu->cr_vendor = value;
                        memcpy((char *)&lvalue, (char *)&(buffer[26]), 4); // AFU_CTL_EN_RST_INDEX
			//afu->cr_class = ntohl(lvalue);
                        memcpy((char *)&lvalue, (char *)&(buffer[30]), 4); // pp_MMIO_offset_high
			//afu->pp_MMIO_offset_high = ntohl(lvalue);
                        memcpy((char *)&lvalue, (char *)&(buffer[30]), 4); // pp_MMIO_offset_low
			//afu->pp_MMIO_offset_low = ntohl(lvalue);
                        memcpy((char *)&lvalue, (char *)&(buffer[34]), 4); // pp_MMIO_BAR
			//afu->pp_MMIO_BAR = ntohl(lvalue);
                        memcpy((char *)&lvalue, (char *)&(buffer[38]), 4); // pp_MMIO_stride
			//afu->pp_MMIO_stride = ntohl(lvalue);
			//no better place to put this right now
			// afu->prefault_mode = OCXL_PREFAULT_MODE_NONE;
			break;
		}
		case OCSE_MEMORY_READ:
			DPRINTF("AFU MEMORY READ\n");
			if (get_bytes_silent(afu->fd, sizeof( size ), buffer, 1000, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory read size");
				_all_idle(afu);
				break;
			}
			// size = (uint16_t *)buffer;
			memcpy( (char *)&size, buffer, sizeof( size ) );
			size = ntohs(size);
			DPRINTF( "of size=%d \n", size );
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory read addr");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
			addr = ntohll(addr);
			DPRINTF("from addr 0x%016" PRIx64 "\n", addr);
			_handle_read(afu, addr, size);
			break;
		case OCSE_MEMORY_WRITE:
			DPRINTF("AFU MEMORY WRITE\n");
			if (get_bytes_silent(afu->fd, sizeof( size ), buffer, 1000, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory write size");
				_all_idle(afu);
				break;
			}
			//size = (uint16_t) buffer[0];
			memcpy( (char *)&size, buffer, sizeof( size ) );
			size = ntohs(size);
			DPRINTF( "of size=%d \n", size );
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
						 -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory write addr");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
			addr = ntohll(addr);
			DPRINTF("to addr 0x%016" PRIx64 "\n", addr);
			if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) <
			    0) {
				warn_msg
				    ("Socket failure getting memory write data");
				_all_idle(afu);
				break;
			}
			_handle_write(afu, addr, size, buffer);
			break;
		// add the case for ocse_memory_be_write
		// need to size, addr and data as above in ocse_memory_write
	        // and then need to get byte enable in manner similar to addr (maybe)
		case OCSE_WR_BE:
			DPRINTF("AFU MEMORY WRITE BE\n");
			if (get_bytes_silent(afu->fd, sizeof(size), buffer, 1000, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory write be size");
				_all_idle(afu);
				break;
			}
			memcpy( (char *)&size, buffer, sizeof( size ) );
			size = ntohs(size);
			DPRINTF( "of size=%d \n", size );
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory write be addr");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
			addr = ntohll(addr);
			DPRINTF("to addr 0x%016" PRIx64 "\n", addr);
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory write be byte enable");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&wr_be, (char *)buffer, sizeof(uint64_t));
			wr_be = ntohll(wr_be);
			DPRINTF("byte enable mask= 0x%016" PRIx64 "\n", wr_be);

			if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) <
			    0) {
				warn_msg
				    ("Socket failure getting memory write data");
				_all_idle(afu);
				break;
			}
			_handle_write_be(afu, addr, size, buffer, wr_be);
			break;

		case OCSE_AMO_WR:
		case OCSE_AMO_RW:
			DPRINTF("AFU AMO_WRITE OR AMO_READ/WRITE\n");
			amo_op = buffer[0];
			if (get_bytes_silent(afu->fd, sizeof(size), buffer, 1000, 0) < 0) {
				warn_msg
				    ("Socket failure getting amo_wr or amo_rw size");
				_all_idle(afu);
				break;
			}
			memcpy( (char *)&size, buffer, sizeof( size ) );
			size = ntohs(size);
			DPRINTF( "of size=%d \n", size );
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting amo_wr or amo_rw addr");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
			addr = ntohll(addr);
			DPRINTF("to addr 0x%016" PRIx64 "\n", addr);
				if (get_bytes_silent(afu->fd, 17, buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting amo_wr or amo_rw cmd_flag and op1/op2 data");
				_all_idle(afu);
				break;
			}
			function_code = (uint8_t) buffer[0];
			DPRINTF("amo_wr or amo_rw cmd_flag= 0x%x\n", function_code);

			// TODO FIX THIS TO CORRECTLY EXTRACT OP_1 and OP_2 if needed !!!
			memcpy((char *)&op1, (char *)&buffer[1], sizeof(uint64_t));
			debug_msg("op1 bytes 1-8 are 0x%016" PRIx64, op1);
			//op1 = ntohll (op1);
			//printf("op1 bytes 1-8 are 0x%016" PRIx64 " \n", op1);
			memcpy((char *)&op2, (char *)&buffer[9], sizeof(uint64_t));
			debug_msg("op2 bytes 1-8 are 0x%016" PRIx64, op2);
			
			_handle_DMO_OPs(afu, amo_op, op_size, addr, function_code, op1, op2);
			break;

		case OCSE_AMO_RD:
			DPRINTF("AFU AMO READ \n");
			amo_op = buffer[0];
			if (get_bytes_silent(afu->fd, sizeof(size), buffer, 1000, 0) < 0) {
				warn_msg
				    ("Socket failure getting amo_rd size");
				_all_idle(afu);
				break;
			}
			memcpy( (char *)&size, buffer, sizeof( size ) );
			size = ntohs(size);
			DPRINTF( "of size=%d \n", size );
			op_size = (uint8_t) size;
			DPRINTF( "of op_size=%d \n", op_size );
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting amo_rd addr");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
			addr = ntohll(addr);
			DPRINTF("to addr 0x%016" PRIx64 "\n", addr);
			if (get_bytes_silent(afu->fd, 1, buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting amo_rd cmd_flag");
				_all_idle(afu);
				break;
			}
			function_code = (uint8_t) buffer[0];
			DPRINTF("amo_rd cmd_flag= 0x%x\n", function_code);

			_handle_DMO_OPs(afu, amo_op, op_size, addr, function_code, 0, 0);
			break;


		case OCSE_MEMORY_TOUCH:
			DPRINTF("AFU MEMORY TOUCH\n");
			if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory touch size");
				_all_idle(afu);
				break;
			}
			size = buffer[0];
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory touch addr");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
			addr = ntohll(addr);
			_handle_touch(afu, addr, size);
			break;
		case OCSE_MMIO_ACK:
			_handle_ack(afu);
			break;
		case OCSE_INTERRUPT:
			if (_handle_interrupt(afu) < 0) {
				perror("Interrupt Failure");
				goto psl_fail;
			}
			break;
		case OCSE_AFU_ERROR:
			if (_handle_afu_error(afu) < 0) {
				perror("AFU ERROR Failure");
				goto psl_fail;
			}
			break;
		default:
			DPRINTF("UNKNOWN CMD IS 0x%2x \n", buffer[0]);
			break;
		}
	}

 psl_fail:
	afu->attached = 0;
	pthread_exit(NULL);
}

static int _ocse_connect(uint16_t * afu_map, int *fd)
{
	char *ocse_server_dat_path;
	FILE *fp;
	uint8_t buffer[MAX_LINE_CHARS];
	struct sockaddr_in ssadr;
	struct hostent *he;
	char *host, *port_str;
	int port;

	// Get hostname and port of OCSE server
	DPRINTF("AFU CONNECT\n");
	ocse_server_dat_path = getenv("OCSE_SERVER_DAT");
	if (!ocse_server_dat_path) ocse_server_dat_path = "ocse_server.dat";
	fp = fopen(ocse_server_dat_path, "r");
	if (!fp) {
		perror("fopen:ocse_server.dat");
		goto connect_fail;
	}
	do {
		if (fgets((char *)buffer, MAX_LINE_CHARS - 1, fp) == NULL) {
			perror("fgets:ocse_server.dat");
			fclose(fp);
			goto connect_fail;
		}
	}
	while (buffer[0] == '#');
	fclose(fp);
	host = (char *)buffer;
	port_str = strchr((char *)buffer, ':');
	*port_str = '\0';
	port_str++;
	if (!host || !port_str) {
		warn_msg
		    ("ocxl_afu_open_dev:Invalid format in ocse_server.data");
		goto connect_fail;
	}
	port = atoi(port_str);

	info_msg("Connecting to host '%s' port %d", host, port);

	// Connect to OCSE server
	if ((he = gethostbyname(host)) == NULL) {
		herror("gethostbyname");
		puts(host);
		goto connect_fail;
	}
	memset(&ssadr, 0, sizeof(ssadr));
	memcpy(&ssadr.sin_addr, he->h_addr_list[0], he->h_length);
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	if ((*fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		goto connect_fail;
	}
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	if (connect(*fd, (struct sockaddr *)&ssadr, sizeof(ssadr)) < 0) {
		perror("connect");
		goto connect_fail;
	}
	strcpy((char *)buffer, "OCSE");
	buffer[4] = (uint8_t) OCSE_VERSION_MAJOR;
	buffer[5] = (uint8_t) OCSE_VERSION_MINOR;
	if (put_bytes_silent(*fd, 6, buffer) != 6) {
		warn_msg("ocxl_afu_open_dev:Failed to write to socket!");
		goto connect_fail;
	}
	if (get_bytes_silent(*fd, 1, buffer, -1, 0) < 0) {
		warn_msg("ocxl_afu_open_dev:Socket failed open acknowledge");
		close_socket(fd);
		goto connect_fail;
	}
	if (buffer[0] != (uint8_t) OCSE_CONNECT) {
		warn_msg("ocxl_afu_open_dev:OCSE bad acknowledge");
		close_socket(fd);
		goto connect_fail;
	}
	if (get_bytes_silent(*fd, sizeof(uint16_t), buffer, 1000, 0) < 0) {
		warn_msg("ocxl_afu_open_dev:afu_map");
		close_socket(fd);
		goto connect_fail;
	}
	memcpy((char *)afu_map, (char *)buffer, 2);
	*afu_map = (long)ntohs(*afu_map);
	return 0;

 connect_fail:
	errno = ENODEV;
	return -1;
}

static struct ocxl_adapter_h *_new_adapter(uint16_t afu_map, uint16_t position,
					  int fd)
{
	struct ocxl_adapter_h *adapter;
	uint16_t mask = 0xf000;
	int id_num = 0;

	if (position == 0)
		return NULL;

	adapter = (struct ocxl_adapter_h *)
	    calloc(1, sizeof(struct ocxl_adapter_h));
	while ((position & mask) == 0) {
		mask >>= 4;
		++id_num;
	}
	adapter->map = afu_map;
	adapter->position = position;
	adapter->mask = mask;
	adapter->fd = fd;
	adapter->id = calloc(6, sizeof(char));
	sprintf(adapter->id, "card%d", id_num);
	return adapter;
}

static struct ocxl_afu_h *_new_afu(uint16_t afu_map, uint16_t position, int fd)
{
	uint8_t *buffer;
	int size;
	struct ocxl_afu_h *afu;
	uint16_t adapter_mask = 0xf000;
	uint16_t afu_mask = 0x8000;
	int major = 0;
	int minor = 0;

	if (position == 0) {
		errno = ENODEV;
		return NULL;
	}
	while ((position & adapter_mask) == 0) {
		adapter_mask >>= 4;
		afu_mask >>= 4;
		++major;
	}
	while ((position & afu_mask) == 0) {
		afu_mask >>= 1;
		++minor;
	}

	afu = (struct ocxl_afu_h *)calloc(1, sizeof(struct ocxl_afu_h));
	if (afu == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	if (pipe(afu->pipe) < 0)
		return NULL;

	pthread_mutex_init(&(afu->event_lock), NULL);
	afu->fd = fd;
	afu->map = afu_map;
	afu->dbg_id = (major << 4) | minor;
	debug_msg("opened host-side socket %d", afu->fd);

	// Send OCSE query
	size = 1 + sizeof(uint8_t);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = OCSE_QUERY;
	buffer[1] = afu->dbg_id;
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		errno = ENODEV;
		return NULL;
	}
	free(buffer);

	afu->adapter = major;
	afu->position = position;
	afu->id = calloc(7, sizeof(char));
	_all_idle(afu);
	sprintf(afu->id, "afu%d.%d", major, minor);

	return afu;
}

// this routine may need some work - it does not wait for a detach response from ocse
static void _release_afus(struct ocxl_afu_h *afu)
{
	struct ocxl_afu_h *current;
	uint8_t rc = OCSE_DETACH;
	int adapter;

	if (afu == NULL)
		return;

	current = afu->_head;
	while (current->adapter < afu->adapter)
		current = current->_next;

	adapter = afu->adapter;
	current = afu;
	while ((current != NULL) && (current->adapter == adapter)) {
		afu = current;
		current = current->_next;
		if (afu->fd) {
			put_bytes_silent(afu->fd, 1, &rc);
			close_socket(&(afu->fd));
		}
		if (afu->id)
			free(afu->id);
		pthread_mutex_destroy(&(afu->event_lock));
		free(afu);
	}
}

// this routine may need some work - it does not wait for a detach response from ocse
static void _release_adapters(struct ocxl_adapter_h *adapter)
{
	struct ocxl_adapter_h *current;
	uint8_t rc = OCSE_DETACH;

	if (!adapter)
		fatal_msg("NULL adapter passed to libocxl.c:_release_adapters");
	_release_afus(adapter->afu_list);
	current = adapter;
	while (current != NULL) {
		adapter = current;
		current = current->_next;
		// Disconnect from OCSE
		if (adapter->fd) {
			put_bytes_silent(adapter->fd, 1, &rc);
			close_socket(&(adapter->fd));
		}
		free(adapter->id);
		free(adapter);
	}
}

static struct ocxl_afu_h *_ocse_open(int *fd, uint16_t afu_map, uint8_t major,
				     uint8_t minor, char afu_type)
{
	struct ocxl_afu_h *afu;
	uint8_t *buffer;
	uint16_t position;

	if ( !fd )
		fatal_msg( "NULL fd passed to libocxl.c:_ocse_open" );
	position = 0x8000;
	position >>= 4 * major;
	position >>= minor;
	if ((afu_map & position) != position) {
		warn_msg("open: AFU not in system");
		close_socket(fd);
		errno = ENODEV;
		return NULL;
	}

	// Create struct for AFU
	afu = _new_afu(afu_map, position, *fd);
	if (afu == NULL)
		return NULL;

	buffer = (uint8_t *) calloc(1, MAX_LINE_CHARS);
	buffer[0] = (uint8_t) OCSE_OPEN;
	buffer[1] = afu->dbg_id;
	buffer[2] = afu_type;
	afu->fd = *fd;
	if (put_bytes_silent(afu->fd, 3, buffer) != 3) {
		warn_msg("open:Failed to write to socket");
		free(buffer);
		goto open_fail;
	}
	free(buffer);

	afu->irq = NULL;
	afu->_head = afu;
	afu->adapter = major;
	afu->id = (char *)malloc(7);
	afu->open.state = LIBOCXL_REQ_PENDING;

	// Start thread
	if (pthread_create(&(afu->thread), NULL, _psl_loop, afu)) {
		perror("pthread_create");
		close_socket(&(afu->fd));
		goto open_fail;
	}

	// Wait for open acknowledgement
	while (afu->open.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened) {
		pthread_join(afu->thread, NULL);
		goto open_fail;
	}

	sprintf(afu->id, "afu%d.%d", major, minor);

	return afu;

 open_fail:
	pthread_mutex_destroy(&(afu->event_lock));
	free(afu);
	errno = ENODEV;
	return NULL;
}

struct ocxl_adapter_h *ocxl_adapter_next(struct ocxl_adapter_h *adapter)
{
	struct ocxl_adapter_h *head;
	uint16_t afu_map, afu_mask;
	int fd;

	// First adapter
	if (adapter == NULL) {
		// Query OCSE
		if (_ocse_connect(&afu_map, &fd) < 0)
			return NULL;
		// No devices?
		assert(afu_map != 0);
		afu_mask = 0x8000;
		// Find first AFU and return struct for it
		while ((afu_map & afu_mask) != afu_mask)
			afu_mask >>= 1;
		head = _new_adapter(afu_map, afu_mask, fd);
		head->_head = head;
		return head;
	}
	// Return next adapter if already set
	if (adapter->_next != NULL) {
		adapter->_next->fd = adapter->fd;
		adapter->fd = 0;
		return adapter->_next;
	}
	// Find next adapter
	afu_mask = adapter->position;
	afu_map = adapter->map;
	while (((afu_mask & ~adapter->mask) == 0) && (afu_mask != 0))
		afu_mask >>= 1;

	// Find first AFU on another adapter
	while (((afu_map & afu_mask) != afu_mask) && (afu_mask != 0))
		afu_mask >>= 1;

	// No more AFUs
	if (afu_mask == 0) {
		_release_adapters(adapter->_head);
		return NULL;
	}
	// Update pointers and return next adapter
	adapter->_next = _new_adapter(afu_map, afu_mask, adapter->fd);
	adapter->_next->_head = adapter->_head;
	adapter->fd = 0;
	return adapter->_next;
}

char *ocxl_adapter_dev_name(struct ocxl_adapter_h *adapter)
{
	if (adapter == NULL)
		return NULL;

	return adapter->id;
}

void ocxl_adapter_free(struct ocxl_adapter_h *adapter)
{
	struct ocxl_adapter_h *head, *current;

	if (adapter == NULL)
		return;

	// If removing head then update all head pointers to next
	current = head = adapter->_head;
	while ((head == adapter) && (current != NULL)) {
		current->_head = head->_next;
		current = current->_next;
	}

	// Update list to skip adapter being removed
	current = adapter->_head;
	while (current != NULL) {
		if (current->_next == adapter)
			current->_next = adapter->_next;
		current = current->_next;
	}

	// Free memory for adapter
	_release_afus(adapter->afu_list);
	if (adapter->id)
		free(adapter->id);
	close_socket(&(adapter->fd));
	free(adapter);
}

struct ocxl_afu_h *ocxl_adapter_afu_next(struct ocxl_adapter_h *adapter,
				       struct ocxl_afu_h *afu)
{
	struct ocxl_afu_h *head;
	uint16_t afu_map, afu_mask;
	int fd;

	if (adapter == NULL)
		return NULL;

	afu_mask = adapter->position;

	// Query OCSE
	if (adapter->fd == 0) {
		if (_ocse_connect(&afu_map, &fd) < 0)
			return NULL;
	} else {
		afu_map = adapter->map;
	}

	// First afu
	if (afu == NULL) {
		// No devices?
		assert(afu_map != 0);
		// Find first AFU and return struct for it
		afu_mask = adapter->mask & 0x8888;
		while ((afu_map & afu_mask) != afu_mask)
			afu_mask >>= 1;
		head = _new_afu(afu_map, afu_mask, adapter->fd);
		adapter->fd = 0;
		head->_head = head;
		if (head != NULL)
			head->_head = head;
		return head;
	}
	// Return next afu if already set
	if (afu->_next != NULL) {
		afu->_next->fd = afu->fd;
		afu->fd = 0;
		return afu->_next;
	}
	// Find next afu on this adapter
	afu_mask = afu->position >> 1;
	while (((afu_mask & adapter->mask) != 0)
	       && ((afu_mask & afu->map) == 0))
		afu_mask >>= 1;

	// No more AFUs on this adapter
	if ((afu_mask & adapter->mask) == 0) {
		_release_afus(adapter->afu_list);
		return NULL;
	}
	// Update pointers and return next afu
	afu->_next = _new_afu(afu_map, afu_mask, afu->fd);
	afu->_next->_head = afu->_head;
	afu->fd = 0;
	return afu->_next;
}

struct ocxl_afu_h *ocxl_afu_next(struct ocxl_afu_h *afu)
{
	struct ocxl_afu_h *head;
	uint16_t afu_map, afu_mask;
	int fd;

	if ((afu == NULL) || (afu->fd == 0)) {
		// Query OCSE
		if (_ocse_connect(&afu_map, &fd) < 0)
			return NULL;
	} else {
		afu_map = afu->map;
	}

	// First afu
	if (afu == NULL) {
		// No devices?
		assert(afu_map != 0);
		afu_mask = 0x8000;
		// Find first AFU and return struct for it
		while ((afu_map & afu_mask) != afu_mask)
			afu_mask >>= 1;
		head = _new_afu(afu_map, afu_mask, fd);
		head->_head = head;
		return head;
	}
	// Return next afu if already set
	if (afu->_next != NULL) {
		afu->_next->fd = afu->fd;
		afu->fd = 0;
		return afu->_next;
	}
	// Find next afu
	afu_mask = afu->position;
	afu_mask >>= 1;
	while ((afu_mask != 0) && ((afu_mask & afu->map) == 0))
		afu_mask >>= 1;

	// No more AFUs
	if (afu_mask == 0) {
		_release_afus(afu->_head);
		return NULL;
	}
	// Update pointers and return next afu
	afu->_next = _new_afu(afu_map, afu_mask, afu->fd);
	afu->_next->_head = afu->_head;
	afu->fd = 0;
	return afu->_next;
}

char *ocxl_afu_dev_name(struct ocxl_afu_h *afu)
{
	if (!afu) {
		errno = EINVAL;
		return NULL;
	}
	return afu->id;
}

char *ocxl_afu_name(struct ocxl_afu_h *afu)
{
	if (!afu) {
		errno = EINVAL;
		return NULL;
	}
	// FIXME - needs to return the value extracted from the afu descriptor dvsec
	// a name like IBM,MC
	return afu->id;
}

struct ocxl_afu_h *ocxl_name_afu_next(char *afu_name, struct ocxl_afu_h *afu)
{
  // use ocxl_afu_next to loop through all the afus
  // use ocxl_afu_name to get the name of the current afu
  // if the name matches, return this afu
  // if not, try the next afu
  ocxl_for_each_afu(afu)
  {
    if ( strcmp( afu->id, afu_name ) ) break;
  }
  return afu;
}

struct ocxl_afu_h *ocxl_afu_open_dev(char *path)
{
	uint16_t afu_map;
	uint8_t major, minor;
	char *afu_id;
	char afu_type;
	int fd;

	if ( !path )
		return NULL;
	if ( _ocse_connect(&afu_map, &fd) < 0 )
		return NULL;

	// Discover AFU position
        // lgt - this part will change for opencapi, but is ok for now.
	//       afu_type will always be directed, may not have a master/slave distinction
	//       major and minor are yet to be defined.
	afu_id = strrchr(path, '/');
	afu_id++;
	if ((afu_id[3] < '0') || (afu_id[3] > '3')) {
		warn_msg("Invalid afu major: %c", afu_id[3]);
		errno = ENODEV;
		return NULL;
	}
	if ((afu_id[5] < '0') || (afu_id[5] > '3')) {
		warn_msg("Invalid afu minor: %c", afu_id[5]);
		errno = ENODEV;
		return NULL;
	}
	major = afu_id[3] - '0';
	minor = afu_id[5] - '0';
	afu_type = afu_id[6];

	return _ocse_open(&fd, afu_map, major, minor, afu_type);
}

struct ocxl_afu_h *ocxl_afu_open_h(struct ocxl_afu_h *afu)
{
	uint8_t major, minor;
	uint16_t mask;
	char afu_type;
	enum ocxl_views view = OCXL_VIEW_SLAVE;

	if (afu == NULL) {
		errno = EINVAL;
		return NULL;
	}
	// Query OCSE
	if (afu->fd == 0) {
		if (_ocse_connect(&(afu->map), &afu->fd) < 0)
			return NULL;
	}

	mask = 0xf000;
	major = minor = 0;
	while (((mask & afu->position) != afu->position) && (mask != 0)) {
		mask >>= 4;
		major++;
	}
	mask &= 0x8888;
	while (((mask & afu->position) != afu->position) && (mask != 0)) {
		mask >>= 1;
		minor++;
	}
	switch (view) {
	case OCXL_VIEW_DEDICATED:
		afu_type = 'd';
		// afu->mode = OCXL_MODE_DEDICATED;
		break;
	case OCXL_VIEW_MASTER:
		afu_type = 'm';
		// afu->mode = OCXL_MODE_DIRECTED;
		break;
	case OCXL_VIEW_SLAVE:
		afu_type = 's';
		// afu->mode = OCXL_MODE_DIRECTED;
		break;
	default:
		errno = ENODEV;
		return NULL;
	}
	return _ocse_open(&(afu->fd), afu->map, major, minor, afu_type);
}

void ocxl_afu_free(struct ocxl_afu_h *afu)
{
	uint8_t buffer;
	int rc;

	if (!afu) {
		warn_msg("ocxl_afu_free: No AFU given");
		goto free_done_no_afu;
	}
	if (!afu->opened)
		goto free_done;

	DPRINTF("AFU FREE\n");
	buffer = OCSE_DETACH;
	rc = put_bytes_silent(afu->fd, 1, &buffer);
	if (rc == 1) {
	        debug_msg("detach request sent from from host on socket %d", afu->fd);
		while (afu->attached)	/*infinite loop */
			_delay_1ms();
	}
	debug_msg("closing host side socket %d", afu->fd);
	close_socket(&(afu->fd));
	afu->opened = 0;
	pthread_join(afu->thread, NULL);

 free_done:
	if (afu->id != NULL)
		free(afu->id);
 free_done_no_afu:
	pthread_mutex_destroy(&(afu->event_lock));
	free(afu);
}

int ocxl_afu_opened(struct ocxl_afu_h *afu)
{
	if (!afu) {
		errno = EINVAL;
		return -1;
	}
	return afu->opened;
}

int ocxl_afu_attach(struct ocxl_afu_h *afu, uint64_t amr)
{
	if (!afu) {
		errno = EINVAL;
		return -1;
	}
	DPRINTF("AFU ATTACH\n");
	if (!afu->opened) {
		warn_msg("ocxl_afu_attach: Must open AFU first");
		errno = ENODEV;
		return -1;
	}

	if (afu->attached) {
		warn_msg("ocxl_afu_attach: AFU already attached");
		errno = ENODEV;
		return -1;
	}
	// Perform OCSE attach
	// lgt - dont need to send amr
	// we don't model the change in permissions
	afu->attach.state = LIBOCXL_REQ_REQUEST;
	while (afu->attach.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	afu->attached = 1;

	return 0;
}

/* int ocxl_afu_attach_full(struct ocxl_afu_h *afu, uint64_t wed, */
/* 			uint16_t num_interrupts, uint64_t amr) */
/* { */
/* 	if (!afu) { */
/* 		errno = EINVAL; */
/* 		return -1; */
/* 	} */
/* 	// Request maximum interrupts */
/* 	afu->int_req.max = num_interrupts; */

/* 	return ocxl_afu_attach(afu, wed); */
/* } */

int ocxl_afu_get_process_element(struct ocxl_afu_h *afu)
{
	DPRINTF("AFU GET PROCESS ELEMENT\n");
	if (!afu->opened) {
		warn_msg("ocxl_afu_get_process_element: Must open AFU first");
		errno = ENODEV;
		return -1;
	}

	if (!afu->attached) {
		warn_msg("ocxl_afu_get_process_element: Must attach AFU first");
		errno = ENODEV;
		return -1;
	}
	return afu->context;
}

int ocxl_afu_fd(struct ocxl_afu_h *afu)
{
	if (!afu) {
		warn_msg("ocxl_afu_attach_full: No AFU given");
		errno = ENODEV;
		return -1;
	}
	return afu->pipe[0];
}

int ocxl_get_api_version(struct ocxl_afu_h *afu, long *valp)
{
	if ((afu == NULL) || (!afu->opened))
		return -1;
	*valp = API_VERSION;
	return 0;
}

int ocxl_get_api_version_compatible(struct ocxl_afu_h *afu, long *valp)
{
	if ((afu == NULL) || (!afu->opened))
		return -1;
	*valp = API_VERSION_COMPATIBLE;
	return 0;
}

int ocxl_get_num_irqs(struct ocxl_afu_h *afu, long *valp)
{
	if (!afu) {
		warn_msg("ocxl_get_irqs_max: No AFU given");
		errno = ENODEV;
		return -1;
	}
	*valp = 0; // FIXME - return the number of interrupts discovered in afu descriptor or something like that;
	return 0;
}

int ocxl_get_irqs_max(struct ocxl_afu_h *afu, long *valp)
{
	if (!afu) {
		warn_msg("ocxl_get_irqs_max: No AFU given");
		errno = ENODEV;
		return -1;
	}
	*valp = 0; // afu->irqs_max;
	return 0;
}

int ocxl_get_irqs_min(struct ocxl_afu_h *afu, long *valp)
{
	if (!afu) {
		warn_msg("ocxl_get_irqs_min: No AFU given");
		errno = ENODEV;
		return -1;
	}
	*valp = 0; // afu->irqs_min;
	return 0;
}

int ocxl_set_irqs_max(struct ocxl_afu_h *afu, long value)
{
	if (!afu) {
		warn_msg("ocxl_set_irqs_max: No AFU given");
		errno = ENODEV;
		return -1;
	}
	//if (value > afu->irqs_max)
	// 	warn_msg("ocxl_set_irqs_max: value is greater than limit, ignoring \n");
	//else
	//	afu->irqs_max = value;
	//TODO	 Send the new irqs_max value back to psl's client struct
	return 0;
}


struct ocxl_irq_h *ocxl_afu_new_irq(struct ocxl_afu_h *afu)
{
  // create an irq, link it to the afu, and return the address of the irq to the caller
  struct ocxl_irq_h *new_irq;
  struct ocxl_irq_h *current_irq;

        if (!afu) {
		warn_msg("ocxl_afu_new_irq: No AFU given");
		errno = ENODEV;
		return NULL;
	}

	new_irq = (struct ocxl_irq_h *)malloc( sizeof(struct ocxl_irq_h) );

	if (!new_irq) {
	        // allocation failed
		errno = ENOMEM;
		warn_msg("ocxl_afu_new_irq: insufficient memory");
		return NULL;
	}

	new_irq->_next = NULL;
	new_irq->afu = afu;

	// add new irq to the end of the afu's list of irqs
	if (afu->irq == NULL) {
	  // this is the first new irq
	  afu->irq = new_irq;
	  return new_irq;
	}

	// scan the list for the last irq
	current_irq = afu->irq;
	while (current_irq->_next != NULL) {
	    current_irq = current_irq->_next;
	}
	// we have the last one now
	current_irq->_next = new_irq;

	return new_irq;
}

struct ocxl_irq_h *ocxl_afu_irq_next(struct ocxl_afu_h *afu, struct ocxl_irq_h *irq)
{
  // given an afu, and a null irq, return the address of the first irq
  // if given an irq handle, get the next(?) one on the afu.
  // how is order managed?  new irqs are appended...
        if (!irq) {
	  // maybe this is the first call
	  if (!afu) {
		warn_msg("ocxl_afu_irq_next: no current irq and no AFU given");
		errno = ENODEV;
		return NULL;
	  }
	  // return the first irq in the afu;
	  return afu->irq;
	} 
	
	// return the next irq in the list
	return irq->_next;
}

void ocxl_irq_free(struct ocxl_irq_h *irq)
{
  // remove this irq from it's afu and free the storage
  struct ocxl_afu_h *afu;
  struct ocxl_irq_h *current_irq;

        if (!irq) {
		warn_msg("ocxl_irq_free: No irq given");
		errno = ENODEV;
		return;
	}

	afu = irq->afu;

	// find this irq in the list on the afu
	if (afu->irq == irq) {
	  // irq is the first in the list
	  afu->irq = irq->_next;
	  free( irq );
	  return;
	}

	current_irq = afu->irq;
	// the current irq is not it, take a peek a the next irq
	while (current_irq->_next != NULL) {
	  if (current_irq->_next == irq) {
	    // the next irq is the one we are looking for
	    // make the current irq skip over it and free it
	    current_irq->_next = irq->_next;
	    free( irq );
	    return;
	  } else {
	    // the next irq is not it, so make it the current irq
	    current_irq = current_irq->_next;
	  }
	}

	// if we get here, we didn't find irq in the afu!
	warn_msg("ocxl_irq_free: irq not found in afu");
	return;
}

int ocxl_event_pending(struct ocxl_afu_h *afu)
{
	if (afu->events[0] != NULL)
		return 1;

	return 0;
}

int ocxl_read_event(struct ocxl_afu_h *afu, struct ocxl_event *event)
{
	uint8_t type;
	int i;

	if (afu == NULL || event == NULL) {
		errno = EINVAL;
		return -1;
	}
	// Function will block until event occurs
	pthread_mutex_lock(&(afu->event_lock));
	while (afu->opened && !afu->events[0]) {	/*infinite loop */
		pthread_mutex_unlock(&(afu->event_lock));
		if (_delay_1ms() < 0)
			return -1;
		pthread_mutex_lock(&(afu->event_lock));
	}

	// Copy event data, free and move remaining events in queue
	memcpy(event, afu->events[0], afu->events[0]->header.size);
	free(afu->events[0]);
	for (i = 1; i < EVENT_QUEUE_MAX; i++)
		afu->events[i - 1] = afu->events[i];
	afu->events[EVENT_QUEUE_MAX - 1] = NULL;
	pthread_mutex_unlock(&(afu->event_lock));
	if (read(afu->pipe[0], &type, 1) > 0)
		return 0;
	return -1;
}

int ocxl_read_expected_event(struct ocxl_afu_h *afu, struct ocxl_event *event,
			    uint32_t type, uint16_t irq)
{
	if (!afu)
		return -1;
	if (ocxl_read_event(afu, event) < 0)
		return -1;

	if (event->header.type != type)
		return -1;

	if ((event->header.type == OCXL_EVENT_AFU_INTERRUPT) &&
	    (event->irq.irq != irq))
		return -1;

	return 0;
}

int ocxl_mmio_map(struct ocxl_afu_h *afu, uint32_t flags)
{
	DPRINTF("MMIO MAP\n");
	if (!afu->opened) {
		printf("ocxl_mmio_map: Must open first!\n");
		goto map_fail;
	}

	if (!afu->attached) {
		printf("ocxl_mmio_map: Must attach first!\n");
		goto map_fail;
	}

	if (flags & ~(OCXL_MMIO_FLAGS)) {
		printf("ocxl_mmio_map: Invalid flags!\n");
		goto map_fail;
	}
	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_MMIO_MAP;
	afu->mmio.data = (uint64_t) flags;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	afu->mapped = 1;

	return 0;
 map_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_mmio_unmap(struct ocxl_afu_h *afu)
{
	afu->mapped = 0;
	return 0;
}

int ocxl_mmio_write64(struct ocxl_afu_h *afu, uint64_t offset, uint64_t data)
{
	if (offset & 0x7) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto write64_fail;

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_MMIO_WRITE64;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.data = data;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
		goto write64_fail;

	return 0;

 write64_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_mmio_read64(struct ocxl_afu_h *afu, uint64_t offset, uint64_t * data)
{
	if (offset & 0x7) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto read64_fail;

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_MMIO_READ64;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	*data = afu->mmio.data;

	if (!afu->opened)
		goto read64_fail;

	return 0;

 read64_fail:
	errno = ENODEV;
	return -1;
}

/* int ocxl_errinfo_read(struct ocxl_afu_h *afu, void *dst, off_t off, size_t len) */
/* { */
/*         off_t aligned_start, last_byte; */
/* 	off_t index1, index2; */
/* 	uint8_t *buffer; */
/* 	size_t total_read_length; */

/* 	if ((afu == NULL) || !afu->mapped)   { */
/* 		errno = ENODEV; */
/* 		return -1; */
/* 	} */
/* 	if (len == 0 || off < 0 || (size_t)off >= afu->eb_len) */
/* 		return 0; */

/* 	/\* calculate aligned read window *\/ */
/* 	len = MIN((size_t)(afu->eb_len - off), len); */
/* 	aligned_start = off & 0xfff8; */
/* 	last_byte = aligned_start + len + (off & 0x7); */
/* 	total_read_length = (((off & 0x7) + len + 0x7) >>3) << 3  ; */
/* 	buffer = (uint8_t* )calloc(total_read_length +8, sizeof(uint8_t)); */
/* 	if (!buffer) */
/* 		return -ENOMEM; */
/* 	uint64_t *wbuf = (uint64_t *)buffer; */
/* 	uint8_t *bbuf = (uint8_t *)buffer; */

/* 	/\* max we can copy in one read is PAGE_SIZE *\/ */
/* 	if (total_read_length > ERR_BUFF_MAX_COPY_SIZE) { */
/* 		total_read_length = ERR_BUFF_MAX_COPY_SIZE; */
/* 		len = ERR_BUFF_MAX_COPY_SIZE - (off & 0x7); */
/* 	} */

/* 	/\* perform aligned read from the mmio region *\/ */
/*         index1 = 0; */
/* 	while (aligned_start <= last_byte)  { */
/* 	// Send MMIO request to OCSE */
/* 		afu->mmio.type = OCSE_MMIO_EBREAD; */
/* 		afu->mmio.addr = (uint32_t) aligned_start ; */
/* 		afu->mmio.state = LIBOCXL_REQ_REQUEST; */
/* 		while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/\*infinite loop *\/ */
/* 			_delay_1ms(); */
/* 		if (!afu->opened) */
/* 			goto bread64_fail; */
/* 		// if offset, have to potentially do BE->LE swap */
/*         	if ((off & 0x7) >0)  */
/*                 	afu->mmio.data = htonll(afu->mmio.data); */
/*         	wbuf[index1] = afu->mmio.data; */
/*         	aligned_start = aligned_start + 8; */
/*                 ++index1; */
/*         } */
/* 	memcpy(&wbuf[0], &bbuf[off & 0x7], len); */
/* 	// if offset we have to do LE->BE swap back	 */
/*  	if ((off & 0x7) > 0)    { */
/*                 index2 = 0; */
/* 	       total_read_length = len; */
/*                 while (total_read_length !=0)  { */
/*                         if (total_read_length < 8)  */
/*                         // set total_read_length to 0 */
/* 				total_read_length = 0; */
/*                         else                    { */
/* 				wbuf[index2]= htonll(wbuf[index2]); */
/*                 		++index2; */
/*                         	total_read_length = total_read_length -8;  */
/*                 	} */
/* 		} */
/* 	}  */
/* 	memcpy(dst, &wbuf[0], len); */
/* 	free(buffer); */
/* 	// return # of bytes read */
/* 	return len; */

/*  bread64_fail: */
/*         if (buffer) */
/*           free(buffer); */
/* 	errno = ENODEV; */
/* 	return -1; */
/* } */

int ocxl_mmio_write32(struct ocxl_afu_h *afu, uint64_t offset, uint32_t data)
{
	if (offset & 0x3) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto write32_fail;

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_MMIO_WRITE32;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.data = (uint64_t) data;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
		goto write32_fail;

	return 0;

 write32_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_mmio_read32(struct ocxl_afu_h *afu, uint64_t offset, uint32_t * data)
{
	if (offset & 0x3) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto read32_fail;

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_MMIO_READ32;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	*data = (uint32_t) afu->mmio.data;

	if (!afu->opened)
		goto read32_fail;

	return 0;

 read32_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_global_mmio_map(struct ocxl_afu_h *afu, uint32_t flags)
{
	DPRINTF("GLOBAL MMIO MAP\n");
	if (!afu->opened) {
		printf("ocxl_global_mmio_map: Must open first!\n");
		goto map_fail;
	}

	if (!afu->attached) {
		printf("ocxl_global_mmio_map: Must attach first!\n");
		goto map_fail;
	}

	if (flags & ~(OCXL_MMIO_FLAGS)) {
		printf("ocxl_global_mmio_map: Invalid flags!\n");
		goto map_fail;
	}
	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_GLOBAL_MMIO_MAP;
	afu->mmio.data = (uint64_t) flags;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	afu->global_mapped = 1;

	return 0;
 map_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_global_mmio_unmap(struct ocxl_afu_h *afu)
{
	afu->global_mapped = 0;
	return 0;
}

int ocxl_global_mmio_write64(struct ocxl_afu_h *afu, uint64_t offset, uint64_t data)
{
	if (offset & 0x7) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->global_mapped)
		goto write64_fail;

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_GLOBAL_MMIO_WRITE64;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.data = data;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
		goto write64_fail;

	return 0;

 write64_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_global_mmio_read64(struct ocxl_afu_h *afu, uint64_t offset, uint64_t * data)
{
	if (offset & 0x7) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->global_mapped)
		goto read64_fail;

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_GLOBAL_MMIO_READ64;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	*data = afu->mmio.data;

	if (!afu->opened)
		goto read64_fail;

	return 0;

 read64_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_global_mmio_write32(struct ocxl_afu_h *afu, uint64_t offset, uint32_t data)
{
	if (offset & 0x3) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->global_mapped)
		goto write32_fail;

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_GLOBAL_MMIO_WRITE32;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.data = (uint64_t) data;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
		goto write32_fail;

	return 0;

 write32_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_global_mmio_read32(struct ocxl_afu_h *afu, uint64_t offset, uint32_t * data)
{
	if (offset & 0x3) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->global_mapped)
		goto read32_fail;

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_GLOBAL_MMIO_READ32;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	*data = (uint32_t) afu->mmio.data;

	if (!afu->opened)
		goto read32_fail;

	return 0;

 read32_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_get_cr_device(struct ocxl_afu_h *afu, long cr_num, long *valp)
{
	if (afu == NULL)
		return -1;
        //uint16_t crnum = cr_num;
	// For now, don't worry about cr_num
	//*valp =  htons(afu->cr_device);
	*valp =  (long)afu->cr_device;
	return 0;
}

int ocxl_get_cr_vendor(struct ocxl_afu_h *afu, long cr_num, long *valp)
{
	if (afu == NULL)
		return -1;
        //uint16_t crnum = cr_num;
	// For now, don't worry about cr_num
	//*valp =  htons(afu->cr_vendor);
	*valp =  (long)afu->cr_vendor;
	return 0;
}

int ocxl_get_cr_class(struct ocxl_afu_h *afu, long cr_num, long *valp)
{
	if (afu == NULL)
		return -1;
        //uint16_t crnum = cr_num;
	// For now, don't worry about cr_num
	//*valp =  htonl(afu->cr_class);
	*valp =  0; // afu->cr_class;
	return 0;
}

int ocxl_get_mmio_size(struct ocxl_afu_h *afu, long *valp)
{
	if (afu == NULL)
                   return -1;
        // FixMe
        // for now just return constant, later will read value from file
        // this is the mmio stride for this afu
        *valp = 0x04000000;
        return 0;
}

int ocxl_get_global_mmio_size(struct ocxl_afu_h *afu, long *valp)
{
	if (afu == NULL)
                   return -1;
        // FixMe
        // for now just return constant, later will read value from file
        // Is this the offset of the per process mmio area ???
        *valp = 0x04000000;
        return 0;
}

int ocxl_errinfo_size(struct ocxl_afu_h *afu, size_t *valp)
{
	if (afu == NULL)
		return -1;
	*valp =  0; // afu->eb_len;
	return 0;
}

int ocxl_get_pp_mmio_len(struct ocxl_afu_h *afu, long *valp)
{
	if (afu == NULL)
		return -1;
	*valp =  0; //   afu->mmio_len;
	return 0;
}

int ocxl_get_pp_mmio_off(struct ocxl_afu_h *afu, long *valp)
{
	if (afu == NULL)
		return -1;
	*valp =  0; //   afu->mmio_off;
	return 0;
}

int ocxl_get_modes_supported(struct ocxl_afu_h *afu, long *valp)
{
//List of the modes this AFU supports. One per line.
//Valid entries are: "dedicated_process" and "afu_directed"
	if (afu == NULL)
		return -1;
	*valp =  0; //   afu->modes_supported;
	return 0;
}

int ocxl_get_mode(struct ocxl_afu_h *afu, long *valp)
{
	if (afu == NULL)
		return -1;
	*valp =  0; //   afu->mode;
	return 0;
}

int ocxl_set_mode(struct ocxl_afu_h *afu, long value)
{
//Writing will change the mode provided that no user contexts are attached.
	if (afu == NULL)
		return -1;
        //check to be sure no contexts are attached before setting this, could be hard to tell?
	// afu->mode = value;
        // do we also need to change afu_type to match mode now??
	return 0;
}

int ocxl_get_prefault_mode(struct ocxl_afu_h *afu, enum ocxl_prefault_mode *valp)
{
//Get the mode for prefaulting in segments into the segment table
//when performing the START_WORK ioctl. Possible values:
//       none: No prefaulting (default)
//       work_element_descriptor: Treat the work element
//           descriptor as an effective address and
//           prefault what it points to.
//       all: all segments process calling START_WORK maps.
	if (afu == NULL)
		return -1;
	*valp =  0; //   afu->prefault_mode;
	return 0;
}

int ocxl_set_prefault_mode(struct ocxl_afu_h *afu, enum ocxl_prefault_mode value)
{
//Set the mode for prefaulting in segments into the segment table
//when performing the START_WORK ioctl. Possible values:
//       none: No prefaulting (default)
//       work_element_descriptor: Treat the work element
//           descriptor as an effective address and
//           prefault what it points to.
//       all: all segments process calling START_WORK maps.
	if (afu == NULL)
		return -1;
	//if ((value == OCXL_PREFAULT_MODE_NONE) |
	//(value == OCXL_PREFAULT_MODE_WED) |
	//(value == OCXL_PREFAULT_MODE_ALL))
	//	afu->prefault_mode = value;
//Probably should return error msg if value wasn't a "good" value
	return 0;
}

int ocxl_get_base_image(struct ocxl_adapter_h *adapter, long *valp)
{
	if (adapter == NULL)
                   return -1;
        // for now just return constant, later will read value from file
        *valp = 0x0;
        return 0;
}


int ocxl_get_caia_version(struct ocxl_adapter_h *adapter, long *majorp,long *minorp)
{
	if (adapter == NULL)
                   return -1;
        // for now just return constant, later will read value from file
        *majorp = 0x1;
        *minorp = 0x0;
        return 0;
}

int ocxl_get_image_loaded(struct ocxl_adapter_h *adapter, enum ocxl_image *valp)
{
	if (adapter == NULL)
                   return -1;
        // for now just return constant, later will read value from file
        *valp = OCXL_IMAGE_USER;
        return 0;
}

int ocxl_get_psl_revision(struct ocxl_adapter_h *adapter, long *valp)
{
	if (adapter == NULL)
                   return -1;
        // for now just return constant, later will read value from file
        *valp = 0x0;
        return 0;
}

/* inline */
/* int ocxl_afu_attach_work(struct ocxl_afu_h *afu, */
/* 			struct ocxl_ioctl_start_work *work) */
/* { */
/* 	if (afu == NULL ||  work == NULL) { */
/* 		errno = EINVAL; */
/* 		return -1; */
/* 	} */
/* 	afu->int_req.max = work->num_interrupts; */
/* ; */
/* 	return ocxl_afu_attach(afu, work->work_element_descriptor); */
/* } */

inline
struct ocxl_ioctl_start_work *ocxl_work_alloc()
{
	return calloc(1, sizeof(struct ocxl_ioctl_start_work));
}

inline
int ocxl_work_free(struct ocxl_ioctl_start_work *work)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	free(work);
	return 0;
}

inline
int ocxl_work_get_amr(struct ocxl_ioctl_start_work *work, __u64 *valp)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	*valp = work->amr;
	return 0;
}

inline
int ocxl_work_get_num_irqs(struct ocxl_ioctl_start_work *work, __s16 *valp)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	*valp = work->num_interrupts;
	return 0;
}

inline
int ocxl_work_get_wed(struct ocxl_ioctl_start_work *work, __u64 *valp)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	*valp = work->work_element_descriptor;
	return 0;
}

inline
int ocxl_work_set_amr(struct ocxl_ioctl_start_work *work, __u64 amr)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	work->amr = amr;
	if (amr)
		work->flags |= OCXL_START_WORK_AMR;
	else
		work->flags &= ~(OCXL_START_WORK_AMR);
	return 0;
}

inline
int ocxl_work_set_num_irqs(struct ocxl_ioctl_start_work *work, __s16 irqs)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	work->num_interrupts = irqs;
	if (irqs >= 0)
		work->flags |= OCXL_START_WORK_NUM_IRQS;
	else
		work->flags &= ~(OCXL_START_WORK_NUM_IRQS);
	return 0;
}

inline
int ocxl_work_set_wed(struct ocxl_ioctl_start_work *work, __u64 wed)
{
	if (work == NULL) {
		errno = EINVAL;
		return -1;
	}
	work->work_element_descriptor = wed;
	return 0;
}

