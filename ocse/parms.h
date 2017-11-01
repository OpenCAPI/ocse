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

#ifndef _PARMS_H_
#define _PARMS_H_

#include <stdio.h>
#include "../common/tlx_interface.h"

struct parms {
	unsigned int timeout;
	unsigned int seed;
	unsigned int pagesize;
	unsigned int host_CL_size;
	unsigned int resp_percent;
	unsigned int paged_percent;
	unsigned int retry_percent;
	unsigned int failed_percent;
	unsigned int pending_percent;
	unsigned int derror_percent;
	unsigned int int_retry_percent;
	unsigned int int_failed_percent;
	unsigned int int_pending_percent;
	unsigned int int_derror_percent;
	unsigned int bdi_resp_err_percent;
	unsigned int bdi_cmd_err_percent;
	unsigned int reorder_percent;
	unsigned int buffer_percent;
};

// Randomly decide to allow response to AFU
int allow_resp(struct parms *parms);

// Randomly decide to allow PAGED response
int allow_paged(struct parms *parms);

// Randomly decide to allow RETRY response
int allow_retry(struct parms *parms);

// Randomly decide to allow FAILED response
int allow_failed(struct parms *parms);

// Randomly decide to allow PENDING response
int allow_pending(struct parms *parms);

// Randomly decide to allow dERROR response
int allow_derror(struct parms *parms);

// Randomly decide to allow RETRY response for interrupt
int allow_int_retry(struct parms *parms);

// Randomly decide to allow FAILED response for interrupt
int allow_int_failed(struct parms *parms);

// Randomly decide to allow PENDING response for interrupt
int allow_int_pending(struct parms *parms);

// Randomly decide to allow dERROR response for interrupt
int allow_int_derror(struct parms *parms);

// Randomly decide to allow setting of BDI bit
int allow_bdi_resp_err(struct parms *parms);

// Randomly decide to allow setting of BDI bit
int allow_bdi_cmd_err(struct parms *parms);

// Randomly decide to allow command to be handled out of order
int allow_reorder(struct parms *parms);

// Randomly decide to allow bogus buffer activity
int allow_buffer(struct parms *parms);

// Open and parse parms file
struct parms *parse_parms(char *filename, FILE * dbg_fp);

#endif				/* _PARMS_H_ */
