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
#include "libocxl_lpc.h"
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

// handle routines that catch calls from libocxl._psl_loop
// are found in libocxl.c

// routines that are called by user applications.
ocxl_err ocxl_lpc_map(ocxl_afu_h afu, uint32_t flags)
{
        struct ocxl_afu *my_afu;
	my_afu = (struct ocxl_afu *)afu;
	debug_msg("ocxl_lpc_map:");
	if (!my_afu->opened) {
		warn_msg("ocxl_lpc_map: Must open first!");
		goto lpcmap_fail;
	}

	if (!my_afu->attached) {
		warn_msg("ocxl_lpc_map: Must attach first!");
		goto lpcmap_fail;
	}

	if (flags & ~(OCXL_LPC_FLAGS)) {
		warn_msg("ocxl_lpc_map: Invalid flags!");
		goto lpcmap_fail;
	}

	// Send mem map to OCSE
	my_afu->mem.type = OCSE_LPC_MAP;
	my_afu->mem.data = (uint8_t *)&(flags);
	my_afu->mem.state = LIBOCXL_REQ_REQUEST;
	while (my_afu->mem.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	my_afu->lpc_mapped = 1;

	return 0;
 lpcmap_fail:
	errno = ENODEV;
	return -1;
}

ocxl_err ocxl_lpc_unmap(ocxl_afu_h afu)
{
        struct ocxl_afu *my_afu;
	my_afu = (struct ocxl_afu *)afu;
	my_afu->lpc_mapped = 0;
	return 0;
}

// read size bytes from *data to offset in afu
//    size = 64, 128, or 256
//    offset is size aligned
//    *data is size aligned
ocxl_err ocxl_lpc_write(ocxl_afu_h afu, uint64_t offset, uint8_t *val, uint64_t size )
{
        // TODO we're going to allow byte alignment and parse the size into naturally aligned accesses
        //      or we could force natural alignment on the caller...
        // phase 1 - size is a power of 2, <= 64, data is size long, offset is naturally aligned
        //           that is, it will fit in a single 64 Byte write event
        // phase 2 - size is a power of 2, <= 256, aribitrary and offset is byte aligned
        //           that is, we have to break it up *somewhere* along the flow into up to 4 legal write event packets
        // phase 3 - size is aribitrary and offset is byte aligned
        //           that is, we have to break it up somewhere along the flow into legal write event packets

        struct ocxl_afu *my_afu;
	my_afu = (struct ocxl_afu *)afu;

        debug_msg("ocxl_lpc_write: %d bytes to lpc offset 0x%016lx", size, offset);

        if (!my_afu) {
	      warn_msg("NULL afu passed to ocxl_lpc_write");
	      goto write_fail;
	}

        if (!my_afu->lpc_mapped) {
	      warn_msg("afu lpc space is not mapped");
	      goto write_fail;
	}

        // check size legality
	switch (size) {
	case 1:
	case 2:
	case 4:
	case 8:
	case 16:
	case 32:
	case 64:
	      break;
	case 128:
	case 256:
	      warn_msg("size support under construction");
	      break;
	default:
	        warn_msg("unsupported size");
		errno = EINVAL;
		return -1;
		break;
	}

        debug_msg("ocxl_lpc_write: legal size = %d bytes", size);

        // check address alignment against size
	if ( offset & (size - 1) ) {
	      warn_msg("ocxl_lpc_write: afu lpc address offset is not size aligned");
	      /* errno = EINVAL; */
	      /* return -1; */
	  }

        debug_msg("ocxl_lpc_write: legal alignment");

	// Send memory write to OCSE - phase 2 - should we break it up here?  or in ocse?
	my_afu->mem.type = OCSE_LPC_WRITE;
	my_afu->mem.addr = offset;
	my_afu->mem.size = size;
	my_afu->mem.data = val;
	my_afu->mem.be = 0;
	my_afu->mem.state = LIBOCXL_REQ_REQUEST;
	while (my_afu->mem.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!my_afu->opened)
		goto write_fail;

	return 0;

 write_fail:
	errno = ENODEV;
	return -1;
}

// read 64 bytes from *data to offset in afu
//    offset is size aligned
//    *data is size aligned
//    byte_enable
ocxl_err ocxl_lpc_write_be(ocxl_afu_h afu, uint64_t offset, uint8_t *val, uint64_t byte_enable )
{

        struct ocxl_afu *my_afu;
	my_afu = (struct ocxl_afu *)afu;

	debug_msg("ocxl_lpc_write_be: to lpc offset 0x%016lx, with enable 0x%016lx", offset, byte_enable);

        if (!my_afu) {
	      warn_msg("NULL afu passed to ocxl_lpc_write_be");
	      goto write_fail;
	}

        if (!my_afu->lpc_mapped) {
	      warn_msg("afu lpc space is not mapped");
	      goto write_fail;
	}

        // check address alignment against size
	if ( offset & 0x3F ) {
	      warn_msg("ocxl_lpc_write_be: afu lpc address offset is not 64 byte aligned");
	      errno = EINVAL;
	      return -1;
	  }

	// Send memory write to OCSE - always 64 byte
	my_afu->mem.type = OCSE_LPC_WRITE_BE;
	my_afu->mem.addr = offset;
	my_afu->mem.size = 64;
	my_afu->mem.data = val;
	my_afu->mem.be = byte_enable;
	my_afu->mem.state = LIBOCXL_REQ_REQUEST;
	while (my_afu->mem.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!my_afu->opened)
		goto write_fail;

	return 0;

 write_fail:
	errno = ENODEV;
	return -1;
}

// read size bytes from offset (in afu) to *data
//    size = 64, 128, or 256
//    offset is size aligned
//    *data is size aligned
ocxl_err ocxl_lpc_read(ocxl_afu_h afu, uint64_t offset, uint8_t *out, uint64_t size )
{
        // TODO we're going to allow byte alignment and parse the size into naturally aligned accesses
        //      or we could force natural alignment on the caller...
        // phase 1 - size is a power of 2, <= 64, data is size long, offset is naturally aligned
        //           that is, it will fit in a single 64 Byte read event
        // phase 2 - size is a power of 2, <= 256, aribitrary and offset is naturally aligned
        //           that is, we have to break it up *somewhere* along the flow into up to 4 legal read event packets
        // phase 3 - size is aribitrary and offset is byte aligned
        //           that is, we have to break it up somewhere along the flow into legal write event packets

        struct ocxl_afu *my_afu;
	my_afu = (struct ocxl_afu *)afu;

        debug_msg("ocxl_lpc_read: %d bytes from lpc offset 0x%016lx", size, offset);

        if (!my_afu) {
	      warn_msg("NULL afu passed to ocxl_lpc_write");
	      goto read_fail;
	}

        if (!my_afu->lpc_mapped) {
	      warn_msg("afu lpc space is not mapped");
	      goto read_fail;
	}

        // check size legality
	switch (size) {
	case 1:
	case 2:
	case 4:
	case 8:
	case 16:
	case 32:
	case 64:
	      break;
	case 128:
	case 256:
	      warn_msg("size support under construction");
	      break;
	default:
	        warn_msg("unsupported size");
		errno = EINVAL;
		return -1;
		break;
	}

        debug_msg("ocxl_lpc_read: legal size = %d bytes", size);

        // check address alignment against size
	if ( offset & (size - 1) ) {
	      warn_msg("ocxl_lpc_read: afu lpc address offset is not size aligned");
	      /* errno = EINVAL; */
	      /* return -1; */
	  }

        debug_msg("ocxl_lpc_read: legal alignment");

	// Send memory write to OCSE - phase 3 - should we break it up here?  or in ocse?  here
	// we will ask ocse for legal partial or full sizes.  that is, naturally aligned powers of 2 <= 256
	// phase 3 - loop through size, reading by greatest available naturally aligned address/size, incrementing offset and repeating...???
	// we'll get back a buffer of a matching size to append to "out"
	my_afu->mem.type = OCSE_LPC_READ;
	my_afu->mem.addr = offset;
	my_afu->mem.size = size;
	my_afu->mem.state = LIBOCXL_REQ_REQUEST;
	while (my_afu->mem.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	// copy the data by copying the pointer
	if (my_afu->mem.data == NULL) {
	      warn_msg("afu lpc memory not returned");
	      goto read_fail;
	}

	// we expect mem.data to be a full length buffer of the data we are reading
	// that is, the length of mem.data should match mem.size
	memcpy( out, my_afu->mem.data, my_afu->mem.size );
	free( my_afu->mem.data );

	if (!my_afu->opened)
		goto read_fail;

	return 0;

 read_fail:
	errno = ENODEV;
	return -1;
}

