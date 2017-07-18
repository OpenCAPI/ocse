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

// handle routines that catch calls from libocxl._psl_loop
// are found in libocxl.c

// routines that are called by user applications.
int ocxl_lpc_map(struct ocxl_afu_h *afu, uint32_t flags)
{
	DPRINTF("LPC MAP\n");
	if (!afu->opened) {
		printf("ocxl_lpc_map: Must open first!\n");
		goto lpcmap_fail;
	}

	if (!afu->attached) {
		printf("ocxl_lpc_map: Must attach first!\n");
		goto lpcmap_fail;
	}

	if (flags & ~(OCXL_LPC_FLAGS)) {
		printf("ocxl_lpc_map: Invalid flags!\n");
		goto lpcmap_fail;
	}
	// Send MMIO map to OCSE
	afu->lpc.type = OCSE_LPC_MAP;
	afu->lpc.data = (uint8_t *)&(flags);
	afu->lpc.state = LIBOCXL_REQ_REQUEST;
	while (afu->lpc.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	afu->lpc_mapped = 1;

	return 0;
 lpcmap_fail:
	errno = ENODEV;
	return -1;
}

int ocxl_lpc_unmap(struct ocxl_afu_h *afu)
{
	afu->lpc_mapped = 0;
	return 0;
}

// read size bytes from *data to offset in afu
//    size = 64, 128, or 256
//    offset is size aligned
//    *data is size aligned
int ocxl_lpc_write(struct ocxl_afu_h *afu, uint64_t offset, uint8_t *data, uint64_t size )
{
	if (offset & 0x7) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto write_fail;

	// Send MMIO map to OCSE
	afu->lpc.type = OCSE_LPC_WRITE;
	afu->lpc.addr = offset;
	afu->lpc.size = size;
	afu->lpc.data = data;
	afu->lpc.state = LIBOCXL_REQ_REQUEST;
	while (afu->lpc.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
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
int ocxl_lpc_read(struct ocxl_afu_h *afu, uint64_t offset, uint8_t *data, uint64_t size )
{
	if (offset & 0x7) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto read_fail;

	// Send MMIO map to OCSE
	afu->lpc.type = OCSE_LPC_READ;
	afu->lpc.addr = offset;
	afu->lpc.size = size;
	afu->lpc.data = data;
	afu->lpc.state = LIBOCXL_REQ_REQUEST;
	while (afu->lpc.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
		goto read_fail;

	return 0;

 read_fail:
	errno = ENODEV;
	return -1;
}

