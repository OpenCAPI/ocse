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
#include "sys/mman.h"
#include <signal.h>

#include "libocxl_internal.h"
#include "libocxl.h"
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

// maybe put these in a global structure to help with name space
ocxl_cache_page_proxy *ocxl_cache_page_list = NULL;
uint32_t ocxl_next_host_tag = 0;
uint32_t ocxl_cache_access_installed = 0;
struct sigaction ocxl_sigaction;

static int _delay_1ms()
{
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;
	return nanosleep(&ts, &ts);
}

// scans through the list of cached addresses.  returns line address if found
uint8_t _is_host_tag_reused( uint32_t host_tag, uint64_t addr )
{
        ocxl_cache_page_proxy *this_page;
        ocxl_cache_line_proxy *this_line;
	uint8_t evict_fill = 0;

	this_page = ocxl_cache_page_list;
	while (this_page != NULL) {
	        this_line = this_page->_next_line;
		while (this_line != NULL) {
		        // if the next_host_tag matches
		        if ( this_line->host_tag == host_tag ) {
			        // check the ea
			        if ( this_line->ea != ( addr & ~((uint64_t)(this_line->size) - 1) ) ) {
				        debug_msg( "_is_host_tag_reused: reusing host tag 0x%06x", host_tag );
				        evict_fill = 1;
					this_line->ef_expected = 1;
					return evict_fill;
				}
			}
			this_line = this_line->_next_line;
		}
		this_page = this_page->_next_page;
	}

	return evict_fill;
}

// scans through the list of cached addresses.  returns line address if found
static struct ocxl_cache_line_proxy *_is_line_cached( ocxl_cache_page_proxy *this_page, uint64_t addr )
{
        ocxl_cache_line_proxy *this_line;

	this_line = this_page->_next_line;
	while (this_line != NULL) {
	        // if the address matches
	        if ( this_line->ea == ( addr & ~((uint64_t)(this_line->size) - 1) ) ) {
		        return this_line;
		}
		this_line = this_line->_next_line;
	}
	
	return NULL;
}

// scans through the list of cached addresses.  returns line address if found
static struct ocxl_cache_page_proxy *_is_page_cached( uint64_t addr )
{
        ocxl_cache_page_proxy *this_page;

	this_page = ocxl_cache_page_list;
	while (this_page != NULL) {
	        // if the address matches
	        if ( ( this_page->ea == ( addr & ~( (uint64_t)(this_page->size) - 1 ) ) ) // &&
		     // ( this_page->_next_line != NULL )                                    
		     ) {
		        // the page's ea contains addr AND there are lines cached 
		        return this_page;
		}
		this_page = this_page->_next_page;
	}
	
	return NULL;
}

// this routine tests the accessibility of memaddr within this users space
// if we can read it, we assume we "own" it.  If we cannot read it, we return 0
// and subsequently return a read or write failed message to the afu and set a
// data segment/storage interrupt
static int _testmemaddr(uint8_t * memaddr)
{
	int fd[2];
	int ret = 0;
	ocxl_cache_page_proxy *this_page;

	// this test cannot be done as is because of the mprotect scheme we use for cache support
	// rethink testing of address ownership within the user space of the host app
	// return 1;

	// first, look to see if the page in which the address resides has been cached
	this_page = _is_page_cached( (uint64_t)memaddr );

	// if it has (this_page != NULL), check to see if any lines are cached and un-protect it so we can test the accessibility
	if ( this_page != NULL ) {
	  if ( this_page->_next_line != NULL ) {
	    mprotect( (void *)this_page->ea, this_page->size, PROT_READ | PROT_WRITE | PROT_EXEC );
	  }
	}

	// test the accessiblity of memaddr
	if (pipe(fd) >= 0) {
		if (write(fd[1], memaddr, 1) > 0)
			ret = 1;
	}

	// if this_page != NULL, reprotect the page
	// since the page is now reprotected, a non-cache read or write will hit the sigsegv handler
	// and the line will be castout of the afu through the normal process...  I hope
	if ( this_page != NULL ) {
	  if ( this_page->_next_line != NULL ) {
	    mprotect( (void *)this_page->ea, this_page->size, PROT_NONE );
	  }
	}

	close(fd[0]);
	close(fd[1]);

	return ret;
}

// this is where we will "fix" the cached address if the sigsegv is caused by a cacheline access
// that is, we will tell the afu to evict the line
// we will wait for the castout (i.e. eviction) to occur
//       castout will unprotect the address
// we will return to the failing instruction and now it should work
// how do we know if the sigsegv is because of our cache access (normal) or a real error case?
// where do we install the handler?  handler is installed when we open the afu
static void _cache_access( int sig, siginfo_t *si, void *unused )
{
        ocxl_cache_page_proxy *this_page;
        ocxl_cache_line_proxy *this_line;
	uint8_t buffer[32];
	int buffer_len;
	uint16_t size;
	uint32_t host_tag;
	uint8_t *host_tag_p;
	uint8_t *size_p;

	printf( "_cache_access\n" );
	// si->si_code - SEGV_MAPERR is bad - die

	// find the EA in the cache proxy list - 
	//       where do I get the EA that caused the signal? si->si_addr
	//       cache proxy list has to be global
	this_page = ocxl_cache_page_list;
	while ( this_page != NULL ) {
    	        printf( "_cache_access: si_addr = 0x%016lx, masked by size-1 (0x%08x) = 0x%016lx, cached addr = 0x%016lx\n", 
			(uint64_t)(si->si_addr), 
			this_page->size-1, 
			(uint64_t)(si->si_addr) & ~((uint64_t)(this_page->size) - 1), 
			this_page->ea );
	        if ( this_page->ea == ((uint64_t)(si->si_addr) & ~((uint64_t)this_page->size - 1)) ) {
		        printf( "_cache_access: found address: 0x%016lx == 0x%016lx \n", 
				this_page->ea, 
				(uint64_t)(si->si_addr) & ~((uint64_t)this_page->size - 1) );
			
			// send a force_evict for each line in the page to the appropriate afu - must have afu handle in the cache proxy
			// build the ocse message template
			buffer_len = 0;
			// 1 OCSE_FORCE_EVICT
			buffer[buffer_len] = OCSE_FORCE_EVICT;
			buffer_len++;
			
			// 4 host_tag
			host_tag = 0;
			host_tag_p = &buffer[buffer_len];
			memcpy( &buffer[buffer_len], &host_tag, sizeof( host_tag ) );
			buffer_len = buffer_len + sizeof( host_tag );
		  
			// 2 size
			size = 0;
			size_p = &buffer[buffer_len];
			memcpy( &buffer[buffer_len], &size, sizeof( size ) );
			buffer_len = buffer_len + sizeof( size );
		  
			this_line = this_page->_next_line;
			while ( this_line != NULL ) {
			        // insert host_tag and size to buffer
			        host_tag = htonl( this_line->host_tag );
				memcpy( host_tag_p, &host_tag, sizeof( host_tag ) );

				size = htons( this_line->size );
				memcpy( size_p, &size, sizeof( size ) );
			  
				if ( put_bytes_silent( this_line->afu->fd, buffer_len, buffer ) != buffer_len ) {
				  debug_msg( "_cache_access: socket failure" );
				  exit( EXIT_FAILURE );
				}
				debug_msg( "_cache_access: FORCE_EVICT 0x%016lx sent host_tag 0x%06x, size %d", 
					   this_line->ea, this_line->host_tag, this_line->size );
				
				this_line = this_line->_next_line;	  
			}
			// WAIT for the response from a castout or castout.push - ok - this is dangerous.  Will it work?
			// Function will block until wake host thread occurs and matches thread id
			this_page->castout_required = 1;
			while ( this_page->castout_required == 1 ) {	/*infinite loop */
		                if (_delay_1ms() < 0) exit( EXIT_FAILURE );
			}
			// the afu should have updated the line if needed
			// via castout which will manage the line protection and existance
			// TODO free the page we just evicted
			debug_msg( "_cache_access: FORCE_EVICT of all lines in page 0x%016lx castout completed", this_page->ea );      
			return;
		} 
		// debug_msg( "_cache_access: 0x%016lx != 0x%016lx", this_line->ea, (uint64_t)(si->si_addr) );
		this_page = this_page->_next_page;
	}

	//       if the EA is not in the list, this must be a real error, so die somehow.
	printf( "_cache_access: address not found\n" );
	exit( EXIT_FAILURE );
}

ocxl_wait_event *ocxl_wait_list = NULL;

ocxl_wait_event *_alloc_wait_event( uint16_t tid )
{
  ocxl_wait_event *this_wait_event;

  // scan for tid in list first - return it if you find it
  // scan list
  // pthread_mutex_lock(&(this_wait_event->wait_lock));
  this_wait_event = ocxl_wait_list;
  // pthread_mutex_unlock(&(this_wait_event->wait_lock));

  debug_msg( "_alloc_wait_event: list=0x%016llx ; this=0x%016llx", (uint64_t)ocxl_wait_list, (uint64_t)this_wait_event );

  while ( this_wait_event != NULL ) {
    // pthread_mutex_lock(&(this_wait_event->wait_lock));
      debug_msg( "_alloc_wait_event: checking @ 0x%016llx -> 0x%04x = 0x%04x", (uint64_t)this_wait_event, this_wait_event->tid, tid );
    if ( this_wait_event->tid == tid ) {
      // match
      // pthread_mutex_unlock(&(this_wait_event->wait_lock));
      debug_msg( "_alloc_wait_event: match @ 0x%016llx -> 0x%04x = 0x%04x", (uint64_t)this_wait_event, this_wait_event->tid, tid );
      return this_wait_event;
    }
  
    this_wait_event = this_wait_event->_next;
    // pthread_mutex_unlock(&(this_wait_event->wait_lock));
  }

  // if not found, create it
  this_wait_event = (ocxl_wait_event *)calloc( 1, sizeof(ocxl_wait_event) );
  this_wait_event->tid = tid;
  this_wait_event->enabled = 0;
  this_wait_event->received = 0;

  debug_msg( "_alloc_wait_event: new wait event @ 0x%016llx -> 0x%04x", (uint64_t)this_wait_event, this_wait_event->tid );

  // put it at the head of the list
  this_wait_event->_next = ocxl_wait_list;
  ocxl_wait_list = this_wait_event;

  debug_msg( "_alloc_wait_event: list starts @ 0x%016llx", (uint64_t)ocxl_wait_list );

  return this_wait_event;
}

void _free_wait_event( ocxl_wait_event *free_wait_event )
{
  ocxl_wait_event *this_wait_event;

  if ( ocxl_wait_list == NULL ) {
    // somehow the list is empty so just free what we got
    free( free_wait_event );
    return;
  }

  if ( ocxl_wait_list == free_wait_event ) {
    // free_wait_event is the first in the list, so do it specially
    ocxl_wait_list = free_wait_event->_next;
    free( free_wait_event );
    return;
  }

  // scan the list
  this_wait_event = ocxl_wait_list;
  while ( this_wait_event != NULL ) {
    if ( this_wait_event->_next == free_wait_event ) {
      // found it - adjust the pointer, free, and leave
      this_wait_event->_next = free_wait_event->_next;
      free( free_wait_event );
      return;
    } else {
      // next!
      this_wait_event = this_wait_event->_next;
    }
  }

  // we've been through the list, but free_wait_event was not there...  free it anyway
  free( free_wait_event );
  return;
}

static void _all_idle(struct ocxl_afu *afu_h)
{
	if (!afu_h)
		fatal_msg("NULL afu passed to libocxl.c:_all_idle");
	afu_h->int_req.state = LIBOCXL_REQ_IDLE;
	afu_h->open.state = LIBOCXL_REQ_IDLE;
	afu_h->attach.state = LIBOCXL_REQ_IDLE;
	afu_h->mmio.state = LIBOCXL_REQ_IDLE;
	afu_h->mem.state = LIBOCXL_REQ_IDLE;
	afu_h->mapped = 0;
	afu_h->global_mapped = 0;
	afu_h->attached = 0;
	afu_h->opened = 0;
}

static int _handle_dsi(struct ocxl_afu *afu, uint64_t addr)
{
	int i;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_dsi");
	// Only track a single DSI at a time
	pthread_mutex_lock(&(afu->event_lock));
	i = 0;
	while (afu->events[i] != NULL) {
		if (afu->events[i]->type == OCXL_EVENT_TRANSLATION_FAULT) {
			pthread_mutex_unlock(&(afu->event_lock));
			return 0;
		}
		++i;
	}
	assert(i < EVENT_QUEUE_MAX);

	afu->events[i] = (struct ocxl_event *)calloc(1, sizeof( ocxl_event ) );
	afu->events[i]->type = OCXL_EVENT_TRANSLATION_FAULT;
	// afu->events[i]->header.size = size;
	// afu->events[i]->header.process_element = afu->context;
	afu->events[i]->translation_fault.addr = (void *)(addr & FOURK_MASK);
	afu->events[i]->translation_fault.dsisr = DSISR;

	do {
		i = write(afu->pipe[1], &(afu->events[i]->type), 1);
	}
	while ((i == 0) || (errno == EINTR));
	pthread_mutex_unlock(&(afu->event_lock));
	return i;
}

static int _handle_wake_host_thread(struct ocxl_afu *afu)
{
        ocxl_wait_event *this_wait_event;
	uint64_t addr;
	uint8_t cmd_flag;
	uint8_t adata[8];

	if (!afu) fatal_msg("_handle_wake_host_thread:NULL afu passed");

	debug_msg("AFU WAKE HOST THREAD");

	// in opencapi, we should get a 64 bit address (to be interpretted as a thread id)
	// we should find a match to that thread id in our ocxl_wait_list

	//buffer[0] = OCSE_WAKE (already read)
	//buffer[1] = event->cmd_flag
	//buffer[2] = event->addr 

	if (get_bytes_silent(afu->fd, 1, &cmd_flag, 1000, 0) < 0) {
		warn_msg("Socket failure getting cmd_flags");
		_all_idle(afu);
		return -1;
	}
	if (get_bytes_silent(afu->fd, 8, adata, 1000, 0) < 0) {
		warn_msg("Socket failure getting address");
		_all_idle(afu);
		return -1;
	}
	memcpy(&addr, adata, 8);
	// addr = ntohs(addr);
	debug_msg("_handle_wake_host_thread: received wake_host_thread thread id 0x%016lx", addr);

	
	// scan list
	// pthread_mutex_lock(&(this_wait_event->wait_lock));
	this_wait_event = _alloc_wait_event( (uint16_t)addr );
	// pthread_mutex_unlock(&(this_wait_event->wait_lock));

	debug_msg("_handle_wake_host_thread: waking @ 0x%016llx -> 0x%04x", (uint64_t)this_wait_event, addr);
	this_wait_event->received = 1;
	
	return 0;
}

static int _handle_interrupt(struct ocxl_afu *afu, uint8_t data_is_valid)
{

	uint16_t data_size;
	struct ocxl_irq *irq;
	uint64_t addr;
	uint8_t cmd_flag;
	uint8_t adata[8];
	uint8_t ddata[32];
	int i;

	if (!afu) fatal_msg("_handle_interrupt:NULL afu passed");

	debug_msg( "_handle_interrupt for afu %d:", afu->context );

	// in opencapi, we should get a 64 bit address (and maybe data)
	// we should find that address in the afu's irq list
	// if we find it, we should put some stuff in the event array

	//buffer[0] = OCSE_INTERRUPT (already read)
	//buffer[1] = event->cmd_flag
	//buffer[2] = event->addr 

	if (get_bytes_silent(afu->fd, 1, &cmd_flag, 1000, 0) < 0) {
		warn_msg("Socket failure getting cmd_flags");
		_all_idle(afu);
		return -1;
	}
	if (get_bytes_silent(afu->fd, 8, adata, 1000, 0) < 0) {
		warn_msg("Socket failure getting address");
		_all_idle(afu);
		return -1;
	}
	memcpy(&addr, adata, 8);
	// addr = ntohs(addr);
	debug_msg("_handle_interrupt: afu %d received intrp_req addr 0x%016lx", afu->context, addr);
	
	if (data_is_valid) {  //this is an AFU_CMD_INTRP_REQ_D
	// For now, up to 32bytes of data is sent over, pulled  from the addr offset 
	// in the 64B data flit, If you prefer  it floating in a 64B buffer, edit _handle_interrupt in cmd.c
		if (get_bytes_silent(afu->fd, sizeof(uint16_t), ddata, 1000, 0) < 0) {
			warn_msg("Socket failure getting data_size");
			_all_idle(afu);
			return -1;
		}
		memcpy((char *)&data_size, (char *)ddata, sizeof(uint16_t));
	  	if (get_bytes_silent(afu->fd, data_size, ddata, 1000, 0) < 0) { 
	    		 warn_msg("Socket failure getting interrupt data "); 
	     		_all_idle(afu); 
	     		return -1; 

		}
	}

	// TODO Update the rest of this to actually search for address and then do 
	// whatever is needed if it's valid.....

	// search for addr in irq list of afu
	// if we don't find it, warn_msg
	// if we do find it, add an event if it is new for this irq
	irq = afu->irq;
	while (irq != NULL) {
	  debug_msg("_handle_interrupt: compare irq id to addr : 0x%016lx ?= 0x%016lx", irq->id, addr);
	  if ( irq->id == addr ) {
	    break;
	  }
	  irq = irq->_next;
	}
	if ( irq == NULL ) {
	  warn_msg( "_handle_interrupt: no matching irqs allocated in this application" );
	  return OCXL_NO_IRQ;
	}

	// we have the matching irq pointer

	// Only track a single interrupt at a time
	// but what about a second afu_interrupt to a different irq address?  
	// should that be saved or coalecsed?
	// this code would coalesce them
	pthread_mutex_lock(&(afu->event_lock));
	i = 0;
	while (afu->events[i] != NULL) {
		if (afu->events[i]->type == OCXL_EVENT_IRQ) {
			// we could search deeper here to see if this event is for the
			// incoming irq.  if it is, increment count and return, if not, check the next event
			pthread_mutex_unlock(&(afu->event_lock));
			return 0;
		}
		++i;
	}
	assert(i < EVENT_QUEUE_MAX);

	afu->events[i] = (ocxl_event *)calloc(1, sizeof( ocxl_event ) );
	afu->events[i]->type = OCXL_EVENT_IRQ;
	//afu->events[i]->header.size = size;
	//afu->events[i]->header.process_element = afu->context; // might not need this
	afu->events[i]->irq.irq = irq->irq;  // which came in and matched irq
	afu->events[i]->irq.handle = addr;  // which came in and matched irq
	afu->events[i]->irq.count = 1;  
	// should we store data from an interrupt d at the info pointer?
	// afu->events[i]->irq.flags = cmd_flag;
	// notice we don't put ddata anywhere - that is because we don't have a place for it in Power ISA's interrupt scheme

	do {
		i = write(afu->pipe[1], &(afu->events[i]->type), 1);
	}
	while ((i == 0) || (errno == EINTR));
	pthread_mutex_unlock(&(afu->event_lock));
	return i;
}

static int _xlate_addr(struct ocxl_afu *afu, uint64_t *addr, uint8_t form_flag)
{
      ocxl_ea_area *this_ea;
      uint64_t base, base_mask;
      uint64_t offset, offset_mask;
      uint64_t eaddr;
      uint64_t taddr;

      if ( (form_flag & 0x80) != 0x80 ) {
	// addr represents an ea, so just return
	return 0;
      }

      // return 0; // since we are using ta=ea, we can get away with this while we figure out the real way

      // we received a taddr, give back the host eaddr
      // look for the ta in the translation table list afu->eas
      this_ea = afu->eas;
      while ( this_ea != NULL ) {
	// compare part of addr to ta based on pg_size
	taddr = *addr;
	if ( this_ea->ta == ( taddr & (~(uint64_t)0 << this_ea->pg_size)) ) break; // found matching ea, use this entry
	this_ea = this_ea->_next;
      }

      if ( this_ea == NULL ) return 0xC;  // we didn't find a matching ta; return 0x0C to say the ta is not recognized

      // if we have a match, modify the ea from this_ea addr that came in to be the ea matching the ta + the extra bits.
      base = this_ea->ea ;

      // grab the offset part of the address
      base_mask = ~(uint64_t)0 << this_ea->pg_size;
      offset_mask = ~base_mask;
      offset = taddr & offset_mask;

      // add the offset to the ta
      eaddr = base + offset;

      debug_msg( "_xlate_addr: translated 0x%016llx with offset mask 0x%016llx to base 0x%016llx + offset 0x%016llx = 0x%016llx", taddr, offset_mask, base, offset, eaddr );
      
      // since we are using ta=ea, we should be able to check that the address we calculate equals the address we received.
      // if (taddr != eaddr) return 0xC;

      // we don't check write permission yet
      *addr = eaddr;
      return 0;
}

// puts a new cache line at the beginning of the cache line list
// returns a pointer to the new entry
static ocxl_cache_page_proxy *_cache_page( struct ocxl_afu *afu, uint64_t addr )
{
        ocxl_cache_page_proxy *this_page;

	// we need to check to see if we've cached it already...
	this_page = _is_page_cached( addr );

	if ( this_page == NULL ) {
	        // it is not, so allocate the line
	  this_page = (ocxl_cache_page_proxy *)calloc( 1, sizeof(ocxl_cache_page_proxy) );

		//put at head of list
		this_page->afu = afu;
		this_page->_next_line = NULL;
		this_page->_next_page = ocxl_cache_page_list;
		ocxl_cache_page_list = this_page;

		// set the characteristics of the line
		this_page->castout_required = 0;
		this_page->size = sysconf(_SC_PAGE_SIZE);
		this_page->ea = addr & ~((uint64_t)(this_page->size) - 1); //TODO page size???
	        // this_page->cache_state = 0x0; // initially invalid
		// ocxl_next_host_tag = ocxl_next_host_tag + (size/64); 
	}

	// check the state of the line
	// if the line already has a state, like s, we are getting a synonym...  yuck.
	// send the synonym_detected and return a NULL???
	// or return the line and the ocse message code to send back: success vs synonym
	// OR should we expect ocse to handle the synonym behavior???

	return this_page;
}

// puts a new cache line at the beginning of the cache line list
// returns a pointer to the new entry
static ocxl_cache_line_proxy *_cache_line( struct ocxl_cache_page_proxy *this_page, uint64_t addr, uint64_t size )
{
        ocxl_cache_line_proxy *this_line;

	// we need to check to see if we've cached it already...
	this_line = _is_line_cached( this_page, addr );

	if ( this_line == NULL ) {
	        // it is not, so allocate the line
	  this_line = (ocxl_cache_line_proxy *)calloc( 1, sizeof(ocxl_cache_line_proxy) );

		//put at head of list
		this_line->afu = this_page->afu;
		this_line->_next_line = this_page->_next_line;
		this_page->_next_line = this_line;

		// set the characteristics of the line
		this_line->ea = addr;
		this_line->size = size;
	        this_line->cache_state = 0x0; // initially invalid
		this_line->host_tag = ocxl_next_host_tag;
		// ocxl_next_host_tag = ocxl_next_host_tag + (size/64); 
	}

	return this_line;
}

// Handle the castout and castout.push from the afu
// lookup the host tag in the cache proxy page/line list
// update memory (if push), clear the line, clear the castout require field
//   castout_required bit should free the signal handler
//   if castout required was not set, then this is a cache management castout
//   and we can update the state or free the line in the case of setting the cache state to invalid 
static void _handle_castout(struct ocxl_afu *afu)
{
        uint8_t buffer[MAX_LINE_CHARS];
	uint16_t size;
	uint8_t op_code;
	uint8_t cmd_flag;
	uint8_t cache_state;
	uint32_t host_tag;
	
	ocxl_cache_page_proxy *this_page;
	ocxl_cache_line_proxy *this_line;
	ocxl_cache_line_proxy *prev_line;

	if ( afu == NULL ) fatal_msg("_handle_castout: NULL afu passed to libocxl.c:_handle_castout");
	
	// retrieve op_code(1), cmdflag(1), host_tag(4), cachestate(1), size(2), and optionally data(size)
	if (get_bytes_silent(afu->fd, sizeof(op_code), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_castout: Socket failure getting ca op_code ");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&op_code, buffer, sizeof( op_code ) );

	if (get_bytes_silent(afu->fd, sizeof( cmd_flag ), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_castout: Socket failure getting cmd_flag ");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&cmd_flag, buffer, sizeof( cmd_flag ) );

	if (get_bytes_silent(afu->fd, sizeof( host_tag ), buffer, -1, 0) < 0) {
	      warn_msg("_handle_castout: Socket failure getting host_tag");
	      _all_idle(afu);
	      return;
	}
	memcpy( (uint8_t *)&host_tag, buffer, sizeof( host_tag ) );
	host_tag = ntohl( host_tag );
	
        if (get_bytes_silent(afu->fd, sizeof( cache_state ), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_castout: Socket failure getting cache_state ");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&cache_state, buffer, sizeof( cache_state ) );

	if (get_bytes_silent(afu->fd, sizeof( size ), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_castout: Socket failure getting size");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&size, buffer, sizeof( size ) );
	size = ntohs( size );

	if ( op_code == AFU_CMD_CASTOUT_PUSH ) {
	        if (get_bytes_silent(afu->fd, size, buffer, -1, 0) < 0) {
		        warn_msg("_handle_castout: Socket failure getting data");
			_all_idle(afu);
			return;
		}
	}
	
	debug_msg("_handle_castout: host_tag=0x%06x, size=%d, cmd_flag=%x", host_tag, size, cmd_flag);

	// scan the cache proxy list to see if this host tag exists AND has the ef_expected bit set
	// loop through the page list
	this_page = ocxl_cache_page_list;
	while ( this_page != NULL ) {
  	        // now scan this lines within the page
	        // track the previous line just in case we need to free this_line
	        prev_line = NULL;
		this_line = this_page->_next_line;
		while ( this_line != NULL ) {
		  debug_msg("_handle_castout: this_line->host_tag= 0x%06x, host_tag=0x%06x, ef_expected=0x%02x", this_line->host_tag, host_tag, this_line->ef_expected );
		        if ( ( this_line->host_tag == host_tag ) && ( this_line->ef_expected == 1 ) ) {
			        // we matched - castout this line as invalid
			        debug_msg("_handle_castout: EVICT FILL matched this_line ea=0x%016llx host_tag=0x%06x,host_tag=0x%06x", this_line->ea, this_line->host_tag, host_tag);
			        if ( op_code == AFU_CMD_CASTOUT_PUSH ) {
				        // update the memory - if it was a push
				        // un protect the page update memory, and reprotect the page
				        mprotect( (void *)this_page->ea, this_page->size, PROT_READ | PROT_WRITE | PROT_EXEC );
					memcpy( (void *)(this_line->ea), (void *)buffer, size );
					mprotect( (void *)this_page->ea, this_page->size, PROT_NONE );
				}

				// if the final state is I, free the line
				if ( cache_state == 0x0 ) {
				        // we can free this_line here
				        // look carefully at this
					if ( prev_line == NULL ) {
					        // this_line is at the head of the list
					        this_page->_next_line = this_line->_next_line;
					} else {
					        prev_line->_next_line = this_line->_next_line;
					}
					free( this_line );
					// we've taken care of the line and freed it
				} else {
				        // we manage the line
				        this_line->cache_state = cache_state;
				}

				// if the page is now empty we can un-mprotect the page 
				// we can also clear the castout required bit,
				// we can invalidate this page and reset the castout required bit
				// - the page may be removed from page list by the sigsegv handler
				if ( this_page->_next_line == NULL ) {
				        mprotect( (void *)this_page->ea, this_page->size, PROT_READ | PROT_WRITE | PROT_EXEC );
					// this_page->cache_state = 0;
					this_page->castout_required = 0;
				}
				
				debug_msg("_handle_castout: EVICT FILL complete");
				return;
			} else {
			        debug_msg("_handle_castout: EVICT FILL did not match this_line->host_tag= 0x%06x,host_tag=0x%06x", this_line->host_tag, host_tag);
			        prev_line = this_line;
				this_line = this_line->_next_line;
			}
		}

		this_page = this_page->_next_page;
	}


	// we did not find an entry that was expecting to be castout due to the ef hint
	// find host tag in the cache proxy list
	// loop through the page list
	this_page = ocxl_cache_page_list;
	while ( this_page != NULL ) {
  	        // now scan this lines within the page
	        // track the previous line just in case we need to free this_line
	        prev_line = NULL;
		this_line = this_page->_next_line;
		while ( this_line != NULL ) {
		  debug_msg("_handle_castout: this_line host_tag=0x%06x, host_tag=0x%06x, ef_expected=0x%02x", this_line->host_tag, host_tag, this_line->ef_expected );
		        if ( this_line->host_tag == host_tag ) {
			        // we matched
			        debug_msg("_handle_castout: matched this_line ea=0x%016llx, host_tag= 0x%06x,host_tag=0x%06x", this_line->ea, this_line->host_tag, host_tag);
			        if ( op_code == AFU_CMD_CASTOUT_PUSH ) {
				        // update the memory - if it was a push
				        // un protect the page, update memory, reprotect the memory
				        mprotect( (void *)this_page->ea, this_page->size, PROT_READ | PROT_WRITE | PROT_EXEC );
					memcpy( (void *)(this_line->ea), (void *)buffer, size );
					mprotect( (void *)this_page->ea, this_page->size, PROT_NONE );
				}

				// if the final state is I, free the line
				if ( cache_state == 0x0 ) {
				        // we can free this_line here
				        // look carefully at this
					if ( prev_line == NULL ) {
					        // this_line is at the head of the list
					        this_page->_next_line = this_line->_next_line;
					} else {
					        prev_line->_next_line = this_line->_next_line;
					}
					free( this_line );
					// we've taken care of the line and freed it
				} else {
				        // we manage the line
				        this_line->cache_state = cache_state;
				}

				// if the page is now empty we can un-mprotect the page 
				// we can also clear the castout required bit,
				// we can invalidate this page and reset the castout required bit
				// - the page may be removed from page list by the sigsegv handler
				if ( this_page->_next_line == NULL ) {
				        mprotect( (void *)this_page->ea, this_page->size, PROT_READ | PROT_WRITE | PROT_EXEC );
					// this_page->cache_state = 0;
					this_page->castout_required = 0;
				}
				
				debug_msg("_handle_castout: complete");
				return;
			} else {
			        debug_msg("_handle_castout: did not match this_line->host_tag= 0x%06x,host_tag=0x%06x", this_line->host_tag, host_tag);
			        prev_line = this_line;
				this_line = this_line->_next_line;
			}
		}

		this_page = this_page->_next_page;
	}

	// if not found!
	if ( this_page == NULL ) {
		warn_msg("_handle_castout: castout of line that is not cached" );
	}
	
}

// Handle the synonym_done from the afu
// lookup the host tag in the cache proxy page/line list
// if we find it, clear the synonym detected bit
// if the line is invalid, free it
// if we didn't find it, assume that a castout invalidated and freed it so just return
static void _handle_synonym_done(struct ocxl_afu *afu)
{
        uint8_t buffer[MAX_LINE_CHARS];
	uint16_t size;
	uint8_t op_code;
	uint32_t host_tag;
	
	ocxl_cache_page_proxy *this_page;
	ocxl_cache_line_proxy *this_line;
	ocxl_cache_line_proxy *prev_line;

	if ( afu == NULL ) fatal_msg("_handle_synonym_done: NULL afu passed to libocxl.c:_handle_synonym_done");
	
	// retrieve op_code(1), host_tag(4), size(2)
	if (get_bytes_silent(afu->fd, sizeof(op_code), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_synonym_done: Socket failure getting ca op_code ");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&op_code, buffer, sizeof( op_code ) );

	if (get_bytes_silent(afu->fd, sizeof( host_tag ), buffer, -1, 0) < 0) {
	      warn_msg("_handle_synonym_done: Socket failure getting host_tag");
	      _all_idle(afu);
	      return;
	}
	memcpy( (uint8_t *)&host_tag, buffer, sizeof( host_tag ) );
	host_tag = ntohl( host_tag );
	
	if (get_bytes_silent(afu->fd, sizeof( size ), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_synonym_done: Socket failure getting size");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&size, buffer, sizeof( size ) );
	size = ntohs( size );

	debug_msg("_handle_synonym_done: host_tag=0x%06x, size=%d", host_tag, size);

	// find host tag in the cache proxy list
	// loop through the page list
	this_page = ocxl_cache_page_list;
	while ( this_page != NULL ) {
  	        // now scan this lines within the page
	        // track the previous line just in case we need to free this_line
	        prev_line = NULL;
		this_line = this_page->_next_line;
		while ( this_line != NULL ) {
		        debug_msg("_handle_synonym_done: this_line->host_tag= 0x%06x,host_tag=0x%06x", this_line->host_tag, host_tag);
		        if ( this_line->host_tag == host_tag ) {
			        // we matched
			        debug_msg("_handle_synonym_done: matched this_line->host_tag= 0x%06x,host_tag=0x%06x", this_line->host_tag, host_tag);
				this_line->synonym_detected = 0x0;
				
				// set new protection based on final cache_state - set by _handle_ca_read or castout

				// if the final state is I, free the line
				if ( this_line->cache_state == 0x0 ) {
				        // we can free this_line here
				        // look carefully at this
					if ( prev_line == NULL ) {
					        // this_line is at the head of the list
					        this_page->_next_line = this_line->_next_line;
					} else {
					        prev_line->_next_line = this_line->_next_line;
					}
					free( this_line );
					// we've taken care of the line and freed it
				}

				// if the page is now empty we can un-mprotect the page 
				// we can also clear the castout required bit,
				// we can invalidate this page and reset the castout required bit
				// - the page may be removed from page list by the sigsegv handler
				if ( this_page->_next_line == NULL ) {
				        mprotect( (void *)this_page->ea, this_page->size, PROT_READ | PROT_WRITE | PROT_EXEC );
					// this_page->cache_state = 0;
					this_page->castout_required = 0;
				}
				
				return;
			} else {
			        debug_msg("_handle_synonym_done: did not match this_line->host_tag= 0x%06x,host_tag=0x%06x", this_line->host_tag, host_tag);
			        prev_line = this_line;
				this_line = this_line->_next_line;
			}
		}

		this_page = this_page->_next_page;
	}

	// if not found! - it is ok - assume a castout freed the line
	return;
	//if ( this_page == NULL ) {
	//	warn_msg("_handle_synonym_done: castout of line that is not cached" );
	//}
	
}

// Handle the upgrade_state command from the afu
// the address will be a naturally aligned 64, 128 or 256 byte line
// the line will be treated as multiple 64 byte lines if longer that 64
// build the upgrade_resp or synonym_detected response
// protect the page/line(s)
//   we mprotect the page/lines so that we will get a SIGSEGV signal if the host user code references the line that is cached in the afu
// actually - mprotect the page in which the line is found.
// if an address is accessed with the protected page, we have to force_evict every line cached within that page and unprotect the page
static void _handle_upgrade_state(struct ocxl_afu *afu)
{
	uint8_t buffer[MAX_LINE_CHARS];
	uint64_t addr;
	uint16_t size;
	uint8_t cmd_flag;
	uint8_t form_flag;
	uint8_t ef;
	uint32_t host_tag;
	int rc;

	ocxl_cache_page_proxy *cache_page;
	ocxl_cache_line_proxy *cache_line;

	if ( afu == NULL ) fatal_msg("_handle_upgrade_state: NULL afu passed to libocxl.c:_handle_upgrade_state");
	
	// retrieve size(2), addr(8), cmd_flag(1), and form_flag(1) from socket
	if (get_bytes_silent(afu->fd, sizeof( size ), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_upgrade_state: Socket failure getting size");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&size, buffer, sizeof( size ) );
	size = ntohs(size);

	if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer, -1, 0) < 0) {
	      warn_msg("_handle_upgrade_state: Socket failure getting addr");
	      _all_idle(afu);
	      return;
	}
	memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
	addr = ntohll(addr);
	
	if (get_bytes_silent(afu->fd, sizeof( cmd_flag ), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_upgrade_state: Socket failure getting cmd_flag ");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&cmd_flag, buffer, sizeof( cmd_flag ) );

	if (get_bytes_silent(afu->fd, sizeof(uint32_t), buffer, -1, 0) < 0) {
	      warn_msg("_handle_upgrade_state: Socket failure getting next host tag");
	      _all_idle(afu);
	      return;
	}
	memcpy((char *)&ocxl_next_host_tag, (char *)buffer, sizeof(uint32_t));
	ocxl_next_host_tag = ntohl(ocxl_next_host_tag);
	
	if (get_bytes_silent(afu->fd, sizeof( form_flag ), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_upgrade_state: Socket failure getting form_flag ");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&form_flag, buffer, sizeof( form_flag ) );

	debug_msg("_handle_upgrade_state: addr @ 0x%016" PRIx64 ", size = %d, cmd = %x, form = %x", addr, size, cmd_flag, form_flag);
	
	// at this point, addr is either an ea, ta, (or eventually pa) depending on the form flag.
	// so lets call a routine to translate the address if form flag is the right value
	rc = _xlate_addr( afu, &addr, form_flag );
	if ( rc == 0xc ) {
	        // bad translation
	        // need to add the reason code to the mem failure message
		warn_msg("_handle_upgrade_state: from TA that was invalid addr @ 0x%016" PRIx64 "", addr);
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = (uint8_t) 0xc;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	
	debug_msg("_handle_upgrade_state: addr @ 0x%016" PRIx64 ", size = %d", addr, size);

	// addr now represents an EA
	// first is the address in a region we have cached?
	// if the address is in a page we have protected, we cannot do this ownership test
	// maybe we should just remove it for cacheable reads...
	// we need to make sure we own this address
	if (!_testmemaddr((uint8_t *) addr)) {
	        if (_handle_dsi(afu, addr) < 0) {
		        perror("_handle_ca_read: DSI Failure");
			return;
		}
		warn_msg("_handle_upgrade_state: from invalid addr @ 0x%016" PRIx64 "", addr);
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = 0xe;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}

	// determine if we are reusing the incoming host_tag
	// if there is a line with this host_tag and the ea does not match, we need to set the EF hint
	// and we need to note that a ef castout is expected for the line that we found.
	ef = _is_host_tag_reused( ocxl_next_host_tag, addr );

	// we need to find or create the page and line entry for this ea
	// we need to build a response and then "cache" the address
	// depending on the op_code, we can choose various cache states to send back.
	// we also get to decide whether or not to set the evict/fill hint.
	// for now, let's send back E for ME and MES, and S for S
	cache_page = _cache_page( afu, addr );
	cache_line = _cache_line( cache_page, addr, (uint64_t)size );

	// cache_line->cache_state may be I or E
	// I here means the line is newly requested so we can proceed to set the state and send OCSE_CA_MEM_SUCCESS
	// S, E, or M means it was cached before so we need to send synonym_detected OCSE_CA_SYNONYM_DETECTED
	// the only difference between the two messages is the data packet really

	int bufsiz;
	bufsiz = 0;

	if ( cache_line->cache_state == 0x0 ) {
	        // new cacheable read - send OCSE_CA_MEM_SUCCESS, adjust and send cache_state.
	        buffer[bufsiz] = OCSE_CA_UPGRADE_RESP;
		bufsiz++;

		// pick a state based on cmd_flag 
		switch (cmd_flag) {
		case 0x08:
		  cache_line->cache_state = 0x3; // Modified
		  break;
		case 0x09:
		  cache_line->cache_state = 0x4; // Exclusive - invalid data
		  break;
		default:
		  warn_msg("_handle_upgrade_state: invalid cmd_flag 0x%02x received", cmd_flag );
		  return;
		}

		buffer[bufsiz] = cache_line->cache_state;
		bufsiz++;

		buffer[bufsiz] = ef; // evict and fill
		bufsiz++;

		host_tag = ntohl( cache_line->host_tag );
		memcpy( &(buffer[bufsiz]), (void *)&host_tag, sizeof(host_tag) );
		bufsiz = bufsiz + sizeof( host_tag );
		debug_msg("_handle_upgrade_state: upgrade resp for addr @ 0x%016llx, host_tag=0x%06x, ef=0x%02x", addr, cache_line->host_tag, ef);
	} else {
	        // upgrade state of previously cached line - send OCSE_CA_SYNONYM_DETECTED, adjust and send cache_state
	        cache_line->synonym_detected = 0x1;
	        
		buffer[bufsiz] = OCSE_CA_SYNONYM_DETECTED;
		bufsiz++;

		// pick a state based on cmd_flag 
		switch (cmd_flag) {
		case 0x08:
		  cache_line->cache_state = 0x3; // modified
		  break;
		case 0x09:
		  cache_line->cache_state = 0x4; // exclusuve, invalidate data
		  break;
		default:
		  warn_msg("_handle_upgrade_state: invalid cmd_flag 0x%02x received", cmd_flag );
		  return;
		}

		buffer[bufsiz] = cache_line->cache_state;
		bufsiz++;

		host_tag = ntohl( cache_line->host_tag );
		memcpy( &(buffer[bufsiz]), (void *)&host_tag, sizeof(host_tag) );
		bufsiz = bufsiz + sizeof( host_tag );
		debug_msg("_handle_upgrade_state: synonym detected for addr @ 0x%016" PRIx64, addr);
	}
	if (put_bytes_silent(afu->fd, bufsiz, buffer) != bufsiz) {
	        afu->opened = 0;
		afu->attached = 0;
	}

	// finally, (re)protect the page
	if ( mprotect( (char *)(cache_page->ea), cache_page->size, PROT_NONE ) == -1 ) {
	        // could not protect (therefore cache) the address
	        perror("mprotect");
		exit( EXIT_FAILURE );
	}
	debug_msg("_handle_upgrade_state: protected addr 0x%016"PRIx64" including line 0x%016"PRIx64, cache_page->ea, cache_line->ea );
}

// Handle the read_s, read_me, and read_mes commands from the afu
// the address will be a naturally aligned 64, 128 or 256 byte line
// the line will be treated as multiple 64 byte lines if longer that 64
// build the cl_read_resp
// protect the page/line(s)
//   we mprotect the page/lines so that we will get a SIGSEGV signal if the host user code references the line that is cached in the afu
// actually - mprotect the page in which the line is found.
// if an address is accessed with the protected page, we have to force_evict every line cached within that page and unprotect the page
static void _handle_ca_read(struct ocxl_afu *afu)
{
	uint8_t buffer[MAX_LINE_CHARS];
	uint64_t addr;
	uint16_t size;
	uint8_t op_code;
	uint8_t form_flag;
	uint8_t ef;
	uint32_t host_tag;
	int rc;

	ocxl_cache_page_proxy *cache_page;
	ocxl_cache_line_proxy *cache_line;

	if ( afu == NULL ) fatal_msg("_handle_ca_read: NULL afu passed to libocxl.c:_handle_ca_read");
	
	// retrieve op_code(1), size(1), form_flag, and address from socket
	if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
	      warn_msg("_handle_ca_read: Socket failure getting ca op_code ");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&op_code, buffer, sizeof( op_code ) );

	if (get_bytes_silent(afu->fd, sizeof( size ), buffer, 1000, 0) < 0) {
	      warn_msg("_handle_ca_read: Socket failure getting ca memory read size");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&size, buffer, sizeof( size ) );
	size = ntohs(size);

	if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
	      warn_msg("_handle_ca_read: Socket failure getting ca form_flag ");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&form_flag, buffer, sizeof( form_flag ) );

	if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer, -1, 0) < 0) {
	      warn_msg("_handle_ca_read: Socket failure getting addr");
	      _all_idle(afu);
	      return;
	}
	memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
	addr = ntohll(addr);
	// debug_msg("_handle_ca_read: addr @ 0x%016" PRIx64 ", size = %d, form = %x", addr, size, form_flag);
	
	if (get_bytes_silent(afu->fd, sizeof(uint32_t), buffer, -1, 0) < 0) {
	      warn_msg("_handle_ca_read: Socket failure getting next host tag");
	      _all_idle(afu);
	      return;
	}
	memcpy((char *)&ocxl_next_host_tag, (char *)buffer, sizeof(uint32_t));
	ocxl_next_host_tag = ntohl(ocxl_next_host_tag);
	debug_msg("_handle_ca_read: addr @ 0x%016" PRIx64 ", size = %d, form = %x", addr, size, form_flag);
	
	// at this point, addr is either an ea, ta, (or eventually pa) depending on the form flag.
	// so lets call a routine to translate the address if form flag is the right value
	rc = _xlate_addr( afu, &addr, form_flag );
	if ( rc == 0xc ) {
	        // bad translation
	        // need to add the reason code to the mem failure message
		warn_msg("_handle_ca_read: CA READ from TA that was invalid addr @ 0x%016" PRIx64 "", addr);
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = (uint8_t) 0xc;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	
	debug_msg("_handle_ca_read: addr @ 0x%016" PRIx64 ", size = %d", addr, size);

	// addr now represents an EA
	// first is the address in a region we have cached?
	// if the address is in a page we have protected, we cannot do this ownership test
	// maybe we should just remove it for cacheable reads...
	// we need to make sure we own this address
	if (!_testmemaddr((uint8_t *) addr)) {
	        if (_handle_dsi(afu, addr) < 0) {
		        perror("_handle_ca_read: DSI Failure");
			return;
		}
		warn_msg("_handle_ca_read: CA READ from invalid addr @ 0x%016" PRIx64 "", addr);
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = 0xe;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}

	// determine if we are reusing the incoming host_tag
	// if there is a line with this host_tag and the ea does not match, we need to set the EF hint
	// and we need to note that a ef castout is expected for the line that we found.
	ef = _is_host_tag_reused( ocxl_next_host_tag, addr );

	// we need to find or create the page and line entry for this ea
	// we need to build a response and then "cache" the address
	// depending on the op_code, we can choose various cache states to send back.
	// we also get to decide whether or not to set the evict/fill hint.
	// for now, let's send back E for ME and MES, and S for S
	cache_page = _cache_page( afu, addr );
	cache_line = _cache_line( cache_page, addr, (uint64_t)size );

	// cache_line->cache_state may be I or E
	// I here means the line is newly requested so we can proceed to set the state and send OCSE_CA_MEM_SUCCESS
	// S, E, or M means it was cached before so we need to send synonym_detected OCSE_CA_SYNONYM_DETECTED
	// the only difference between the two messages is the data packet really

	int bufsiz;
	bufsiz = 0;

	if ( cache_line->cache_state == 0x0 ) {
	        // new cacheable read - send OCSE_CA_MEM_SUCCESS, adjust and send cache_state
	        buffer[bufsiz] = OCSE_CA_MEM_SUCCESS;
		bufsiz++;

		// pick a state based on op_code - for now, always E
		switch (op_code) {
		case AFU_CMD_READ_S:
		case AFU_CMD_READ_S_T:
		  //cache_line->cache_state = 0x1; // just shared for now
		  //break;
		case AFU_CMD_READ_ME:
		case AFU_CMD_READ_ME_T:
		case AFU_CMD_READ_MES:
		case AFU_CMD_READ_MES_T:
		  cache_line->cache_state = 0x2; // just exclusive for now
		  break;
		default:
		  warn_msg(" _cache: invalid op_code 0x%02x received", op_code );
		  return;
		}

		buffer[bufsiz] = cache_line->cache_state;
		bufsiz++;

		buffer[bufsiz] = ef; // evict and fill
		bufsiz++;

		host_tag = ntohl( cache_line->host_tag );
		memcpy( &(buffer[bufsiz]), (void *)&host_tag, sizeof(host_tag) );
		bufsiz = bufsiz + sizeof( host_tag );

		// oh rats - addr could be in a protected region so I can't just memcopy it...
		mprotect( (char *)(cache_page->ea), cache_page->size, PROT_READ );
		memcpy( &(buffer[bufsiz]), (void *)addr, size);
		bufsiz = bufsiz + size;
		debug_msg("_handle_ca_read: cl rd resp for addr @ 0x%016llx, host_tag=0x%06x, ef = 0x%02x", addr, cache_line->host_tag, ef);
	} else {
	        // cacheable read of previously cached line - send OCSE_CA_SYNONYM_DETECTED, adjust and send cache_state
	        cache_line->synonym_detected = 0x1;
	        
		buffer[bufsiz] = OCSE_CA_SYNONYM_DETECTED;
		bufsiz++;

		// pick a state based on op_code - for now, always E
		switch (op_code) {
		case AFU_CMD_READ_S:
		case AFU_CMD_READ_S_T:
		  //cache_line->cache_state = 0x1; // just shared for now
		  //break;
		case AFU_CMD_READ_ME:
		case AFU_CMD_READ_ME_T:
		case AFU_CMD_READ_MES:
		case AFU_CMD_READ_MES_T:
		  cache_line->cache_state = 0x2; // just exclusive for now
		  break;
		default:
		  warn_msg(" _cache: invalid op_code 0x%02x received", op_code );
		  return;
		}

		buffer[bufsiz] = cache_line->cache_state;
		bufsiz++;

		host_tag = ntohl( cache_line->host_tag );
		memcpy( &(buffer[bufsiz]), (void *)&host_tag, sizeof(host_tag) );
		bufsiz = bufsiz + sizeof( host_tag );
		debug_msg("_handle_ca_read: synonym detected for addr @ 0x%016" PRIx64, addr);
	}
	if (put_bytes_silent(afu->fd, bufsiz, buffer) != bufsiz) {
	        afu->opened = 0;
		afu->attached = 0;
	}

	// finally, (re)protect the page
	if ( mprotect( (char *)(cache_page->ea), cache_page->size, PROT_NONE ) == -1 ) {
	        // could not protect (therefore cache) the address
	        perror("mprotect");
		exit( EXIT_FAILURE );
	}
	debug_msg("_handle_ca_read: protected addr 0x%016"PRIx64" including line 0x%016"PRIx64, cache_page->ea, cache_line->ea );
}

static void _handle_read(struct ocxl_afu *afu)
{
	uint8_t buffer[MAX_LINE_CHARS];
	uint64_t addr;
	uint16_t size;
	uint8_t form_flag;
	int rc;

	if ( afu == NULL ) fatal_msg("NULL afu passed to libocxl.c:_handle_read");
	
	if (get_bytes_silent(afu->fd, sizeof( size ), buffer, 1000, 0) < 0) {
	      warn_msg("Socket failure getting memory read size");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&size, buffer, sizeof( size ) );
	size = ntohs(size);

	if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
	      warn_msg("Socket failure getting form_flag ");
	      _all_idle(afu);
	      return;
	}
	memcpy( (char *)&form_flag, buffer, sizeof( form_flag ) );

	if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer, -1, 0) < 0) {
	      warn_msg("Socket failure getting memory read addr");
	      _all_idle(afu);
	      return;
	}
	memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
	addr = ntohll(addr);
	debug_msg("_handle_read: addr @ 0x%016" PRIx64 ", size = %d, form = %x", addr, size, form_flag);
	
	// at this point, addr is either an ea, ta, (or eventually pa) depending on the form flag.
	// so lets call a routine to translate the address if form flag is the right value
	rc = _xlate_addr( afu, &addr, form_flag );
	if ( rc == 0xc ) {
	        // bad translation
	        // need to add the reason code to the mem failure message
		warn_msg("READ from TA that was invalid addr @ 0x%016" PRIx64 "", addr);
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = (uint8_t) 0xc;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	
	debug_msg("_handle_read: addr @ 0x%016" PRIx64 ", size = %d", addr, size);
	if (!_testmemaddr((uint8_t *) addr)) {
	        if (_handle_dsi(afu, addr) < 0) {
		        perror("DSI Failure");
			return;
		}
		warn_msg("READ from invalid addr @ 0x%016" PRIx64 "", addr);
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = 0xe;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
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
	debug_msg("READ from addr @ 0x%016" PRIx64 "", addr);
}

static void _handle_write_be(struct ocxl_afu *afu)
{
        uint8_t buffer[2];
        uint64_t addr;
	uint16_t size;
	uint8_t *data;
	uint64_t be;
	uint8_t form_flag;
	uint64_t enable;
	uint64_t be_copy;
	int rc, i;

	if (!afu) fatal_msg("NULL afu passed to libocxl.c:_handle_write_be");

	if (get_bytes_silent(afu->fd, sizeof(size), (uint8_t *)&size, 1000, 0) < 0) {
	  warn_msg("Socket failure getting memory write be size");
	  _all_idle(afu);
	  return;
	}
	size = ntohs(size);
	debug_msg( "  of size=%d ", size );

	if (get_bytes_silent(afu->fd, 1, &form_flag, 1000, 0) < 0) {
	  warn_msg("Socket failure getting form_flag ");
	  _all_idle(afu);
	  return;
	}
	debug_msg( "  form_flag=%x", form_flag);
	
	if (get_bytes_silent(afu->fd, sizeof(uint64_t), (uint8_t *)&addr, -1, 0) < 0) {
	  warn_msg("Socket failure getting memory write be addr");
	  _all_idle(afu);
	  return;
	}
	addr = ntohll(addr);
	debug_msg("  to addr 0x%016" PRIx64 "", addr);

	if (get_bytes_silent(afu->fd, sizeof(uint64_t), (uint8_t *)&be, -1, 0) < 0) {
	  warn_msg("Socket failure getting memory write be byte enable");
	  _all_idle(afu);
	  return;
	}
	be = ntohll(be);
	debug_msg("  with byte enable mask= 0x%016" PRIx64 "", be);

	data = (uint8_t *)malloc( size );
	if (get_bytes_silent(afu->fd, size, data, 1000, 0) < 0) {
	  warn_msg("Socket failure getting memory write data");
	  _all_idle(afu);
	  free( data );
	  return;
	}

	rc = _xlate_addr( afu, &addr, form_flag );
	if ( rc == 0xc ) {
	        // bad translation
	        // need to add the reason code to the mem failure message
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = 0xc;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		free( data );
		return;
	}

	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		warn_msg("WRITE to invalid addr @ 0x%016" PRIx64 "", addr);
		buffer[0] = OCSE_MEM_FAILURE;
		buffer[1] = 0xe;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		free( data );
		return;
	}

	// we'll have to loop through data byte by byte
	// and if the corresponding bit of be is on, 
	// write the data byte to the address offset by the loop index

	be_copy = be;

	for ( i=0; i<64; i++ ) {
	        enable = be_copy && 0x0000000000000001; // mask everything but bit 0
		if (enable) {
		          *((char *)addr + i) = data[i];  // add i to addr and deref???
		}
		be_copy = be_copy >> 1; // shift be_copy right 1 bit.
	}
	
	buffer[0] = OCSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, buffer) != 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	free( data );
}

static void _handle_write(struct ocxl_afu *afu)
{
	uint8_t buffer[MAX_LINE_CHARS];
	uint64_t addr;
	uint16_t size;
	uint8_t form_flag;
	int rc;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_write");

	// retrieve additional field from socket
	if (get_bytes_silent(afu->fd, sizeof( size ), buffer, 1000, 0) < 0) {
	  warn_msg("Socket failure getting memory write size");
	  _all_idle(afu);
	  return;
	}
	memcpy( (char *)&size, buffer, sizeof( size ) );
	size = ntohs(size);
	debug_msg( "  of size=%d ", size );

	if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
	  warn_msg("Socket failure getting form_flag ");
	  _all_idle(afu);
	  return;
	}
	memcpy( (char *)&form_flag, buffer, sizeof( form_flag ) );
	debug_msg( "  with form_flag=%x", form_flag);

	if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
			     -1, 0) < 0) {
	  warn_msg("Socket failure getting memory write addr");
	  _all_idle(afu);
	  return;
	}
	memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
	addr = ntohll(addr);
	debug_msg("  to addr 0x%016" PRIx64 "", addr);

	if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) < 0) {
	  warn_msg("Socket failure getting memory write data");
	  _all_idle(afu);
	  return;
	}

	rc = _xlate_addr( afu, &addr, form_flag );
	if ( rc == 0xc ) {
	        // bad translation
	        // need to add the reason code to the mem failure message
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = 0xc;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}

	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
		        debug_msg( "_handle_write: write to invalid addr @ 0x016lx", addr );
			perror("DSI Failure");
			return;
		}
		warn_msg("WRITE to invalid addr @ 0x%016" PRIx64 "", addr);
		buffer[0] = OCSE_MEM_FAILURE;
		buffer[1] = 0xe;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}

	memcpy((void *)addr, buffer, size);

	buffer[0] = OCSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, buffer) != 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
}

// this routine will become more random and configurable over time using the 
// parms from ocse, or creating a libocxl parms routine.
static int _allow_kill_xlate( uint8_t *cmd_flag )
{
  int kill_chance = 10; // constant 80% chance we'll allow kill xlate
  int kill_context_chance = 5; // constant 5% chance we'll allow kill xlate of all the ea's in a context
  int kill_afu_chance = 5; // constant 5% chance we'll allow kill xlate all the ea's in an afu

  int allow_kill, allow_context, allow_afu;

  // percent_chance from parms.c
  allow_kill = rand() % 100 < kill_chance;
  allow_context = rand() % 100 < kill_context_chance;
  allow_afu = rand() % 100 < kill_afu_chance;

  if ( allow_kill != 0 ){
    *cmd_flag = 0;
    // these questions strenghten cmd_flag
    if ( allow_context != 0 ) {
      // should we allow all ea's for this context to be killed
      *cmd_flag = 0x0; // 0x1;
    } else if ( allow_afu != 0 ) {
      // should we allow all ea's for this afu to be killed
      *cmd_flag = 0x0; // 0xF;
    }
  } 

  allow_kill = 0; // remove this later
  return allow_kill;
}

// when we get a kill_xlate_done message
// go through all the ea's and free the kill_xlate_pending ones
static void _handle_kill_xlate_done( struct ocxl_afu *afu )
{
      ocxl_ea_area *this_ea;
      ocxl_ea_area *prev_ea;
      ocxl_ea_area *next_ea;
      uint64_t ea;
      uint8_t code;

      // read the rest of the socket
      if (get_bytes_silent(afu->fd, sizeof( ea ), (uint8_t *)&ea, 1000, 0) < 0) {
	  warn_msg("_handle_kill_xlate_done: Socket failure getting kill_xlate_done address");
	  _all_idle(afu);
	  return;
	}
      ea = ntohll(ea);

      if (get_bytes_silent(afu->fd, sizeof( code ), &code, 1000, 0) < 0) {
	  warn_msg("_handle_kill_xlate_done: Socket failure getting kill_xlate_done address");
	  _all_idle(afu);
	  return;
	}

      debug_msg( "_handle_kill_xlate_done: of address=0x%016x response code =0x%02x", ea, code );

      this_ea = afu->eas;
      prev_ea = NULL;

      // loop through the eas, looking for those with a pending kill_xlate
      // if we find one pending, compare the ea's and remove it if we have a "match"
      // ea's match differently depending on the kill_xlate cmd flag which is assumed to be 0
      // other cmd flag values will cause additional ea's kills to be completed/removed
      while (this_ea != NULL ) {
	    // first save the _next pointer because we may free this_ea
	    next_ea = this_ea->_next;
	    
	    if ( this_ea->kill_xlate_pending == 1) {
	          // does this_ea ea match the ea we are done with?
	          // or if ea is 0, we probably are done with a kill_xlate with cmd_flag=0xf, so kill the ea if it pending
	          if ( ( this_ea->ea == ea ) || ( ea == 0 ) ) {
		        // we found an ea that we want to free
			// update the previous next pointer.
			if (prev_ea == NULL) {
			  // the previous ea _next pointer is the afu eas pointer
			  afu->eas = this_ea->_next;
			} else {
			  prev_ea->_next = this_ea->_next;
			}

			// free this_ea
			debug_msg( "_handle_kill_xlate_done: done for addr @ 0x%016" PRIx64, this_ea->ea );
			free( this_ea );
		  } else {
		    // not a match, advance the prev_ea pointer
		    prev_ea = this_ea;
		  }
	    } else {
	      // just advance the pointers
	      prev_ea = this_ea;
	    }
	    
	    // finally update the this_ea pointer to continue the scan
	    this_ea = next_ea;
      }

      return;
}

static void _kill_xlate_all( struct ocxl_afu *afu )
{
        ocxl_ea_area *this_ea;
        uint8_t cmd_flag = 0;
	uint64_t ea;
	uint8_t pg_size;
	uint16_t bdf;
	uint32_t pasid;
	uint8_t buffer[17];
	uint8_t *ea_buffer_p;
	uint8_t *pg_size_buffer_p;
	int size;

	if ( !afu ) fatal_msg("_kill_xlate_all: NULL afu passed to libocxl.c:_kill_xlate_all");

	if ( afu->eas == NULL ) return; // no translated addresses to kill

	cmd_flag = 0x0; // kill all translated addresses - one at a time - this is the way the hardware/os does it
	// cmd_flag = 0xf; // kill all the translated addresses with a single kill
	ea = 0;
	pg_size = 0;
	bdf = 0;
	pasid = 0;
		
	// init message buffer
	size = 0;
	// 1 OCSE_KILL_XLATE
	buffer[size] = OCSE_KILL_XLATE;
	size++;

	// 1 cmd_flag
	buffer[size] = cmd_flag;
	size++;

	// 8 ea
	ea = htonll( ea );
	ea_buffer_p = &buffer[size];
	memcpy( ea_buffer_p, &ea, sizeof( ea ) );
	size = size + sizeof( ea );
		
	// 1 pg siz
	pg_size = 0;
	pg_size_buffer_p = &buffer[size];
	buffer[size] = pg_size;
	size++;

	if ( cmd_flag == 0xf ) {
	        this_ea = afu->eas;
		while (this_ea != NULL ) {
		        this_ea->kill_xlate_pending = 1;
			this_ea = this_ea->_next;
		}
		if (put_bytes_silent(afu->fd, size, buffer) != size) {
		        afu->opened = 0;
			afu->attached = 0;
			debug_msg( "_kill_xlate_all with 0xF: KILL XLATE ALL socket failure" );
		}
		debug_msg( "_kill_xlate_all with 0xF: KILL_XLATE addr @ 0x%016" PRIx64 ", cmd_flag %d, pg_size %d, bdf %d, pasid %d", ntohll( ea ), cmd_flag, pg_size, ntohs(bdf), ntohl(pasid) );
	}

	if ( cmd_flag == 0x0 ) {
	        // 2 bdf
	        // bdf[15:8]=bus, bdf[7:3]=dev, bdf[2:0]=fcn
	        bdf = afu->bus;
		bdf = bdf << 5;
		bdf = bdf + afu->dev;
		bdf = bdf << 3;
		bdf = bdf + afu->fcn;
		bdf = htons( bdf );
		memcpy( &buffer[size], &bdf, sizeof( bdf ) );
		size = size + sizeof( bdf );

		// 4 pasid
		pasid = afu->context;
		pasid = htonl( pasid );
		memcpy( &buffer[size], &pasid, sizeof( pasid ) );
		size = size + sizeof( pasid );

		this_ea = afu->eas;
		while ( this_ea != NULL ) {
		        if ( this_ea->kill_xlate_pending == 1 ) {
			        this_ea = this_ea->_next;
				continue;
			}
			// insert ea and pg_size to buffer
			ea = htonll( this_ea->ea );
			memcpy( ea_buffer_p, &ea, sizeof( ea ) );
			*pg_size_buffer_p = this_ea->pg_size;
			
			// set this_ea to pending and transmit buffer
			this_ea->kill_xlate_pending = 1;
			if (put_bytes_silent(afu->fd, size, buffer) != size) {
			        afu->opened = 0;
				afu->attached = 0;
				debug_msg( "KILL XLATE ALL socket failure" );
			}
			debug_msg( "_kill_xlate_all: KILL_XLATE addr @ 0x%016" PRIx64 ", cmd_flag %d, pg_size %d, bdf %d, pasid %d", ntohll( ea ), cmd_flag, pg_size, ntohs(bdf), ntohl(pasid) );

			this_ea = this_ea->_next;	  
		}
	}
	
	// wait some time for the afu to respond to the kill_xlate's that are pending
	while (afu->eas != NULL) {
	  this_ea = afu->eas;
	  while ( this_ea != NULL ) {
	    if ( this_ea->kill_xlate_pending != 1 ) {
	      this_ea = this_ea->_next;
	    } else {
	      break;
	    }
	  }
	  if ( this_ea == NULL ) {
	    // nothing pending
	    break;
	  } 
	  // something is pending, wait a little bit
	  _delay_1ms();
	}

	return;
}

static void _force_evict_all( struct ocxl_afu *afu )
{
	uint8_t buffer[17];
	uint32_t host_tag;
	uint8_t *host_tag_p;
	uint16_t size;
	uint8_t *size_p;
	int buffer_len;

	ocxl_cache_page_proxy *this_page;
	ocxl_cache_line_proxy *this_line;

	if ( !afu ) fatal_msg("_force_evict_all: NULL afu passed to libocxl.c:_force_evict_all");

	if ( ocxl_cache_page_list == NULL ) return; // no lines have been cached

	// build the ocse message template
	buffer_len = 0;
	// 1 OCSE_FORCE_EVICT
	buffer[buffer_len] = OCSE_FORCE_EVICT;
	buffer_len++;
	
	// 4 host_tag
	host_tag = 0;
	host_tag_p = &buffer[buffer_len];
	memcpy( &buffer[buffer_len], &host_tag, sizeof( host_tag ) );
	buffer_len = buffer_len + sizeof( host_tag );
	
	// 2 size
	size = 0;
	size_p = &buffer[buffer_len];
	memcpy( &buffer[buffer_len], &size, sizeof( size ) );
	buffer_len = buffer_len + sizeof( size );
	
	this_page = ocxl_cache_page_list;
	while ( this_page != NULL ) {
	        this_page->castout_required = 0;
		
	        this_line = this_page->_next_line;
		while ( this_line != NULL ) {
		        this_page->castout_required = 1;
		        // insert host_tag and size to buffer
		        host_tag = htonl( this_line->host_tag );
			memcpy( host_tag_p, &host_tag, sizeof( host_tag ) );

			size = htons( this_line->size );
			memcpy( size_p, &size, sizeof( size ) );
	  
			if (put_bytes_silent(afu->fd, buffer_len, buffer) != buffer_len) {
			  afu->opened = 0;
			  afu->attached = 0;
			  debug_msg( "_force_evict_all: socket failure" );
			}
			debug_msg( "_force_evict_all: FORCE_EVICT addr @ 0x%016" PRIx64 ", host_tag %06x, size %d", 
				   this_line->ea, this_line->host_tag, this_line->size );

			this_line = this_line->_next_line;
		}

		// wait for this pages lines to be castout
		while ( this_page->castout_required == 1 ) {	/*infinite loop */
		        if (_delay_1ms() < 0) exit( EXIT_FAILURE );
		}

		// proceed to the next page and casout its lines
		this_page = this_page->_next_page;
	}

	// all the lines have been castout
	return;
}

// add random capp kill_xlate command to the socket here.  Summary
// select a random ea entry, all eas for this context, or all eas for the afu
//   eventuall modify parms.c and use it and the ocse.parms file.  read them in during _afu_alloc
//   allow_kill_xlate will return a cmd_flag to indicate just the ea, eas in this context, or eas in this afu
// generate the kill xlate message to ocse
// allow libocxl to continue so that it can accept afu commands and responses as well as allow user code to contine
// the afu *MAY* send xlate_release messages for the addresses it is processing
// while we are waiting for the kill xlate done response, the afu may be finishing with a list of .t form commands
// eventually the afu will send a kill xlate done response.
static void _handle_kill_xlate( struct ocxl_afu *afu )
{
        ocxl_ea_area *this_ea;
        uint8_t cmd_flag = 0;
	uint64_t ea;
	uint8_t pg_size;
	uint16_t bdf;
	uint32_t pasid;
	uint8_t buffer[17];
	int size;

	if (!afu) fatal_msg("_handle_kill_xlate: NULL afu passed to libocxl.c:_handle_kill_xlate");

	// find an ea to kill
	this_ea = afu->eas;
	while (this_ea != NULL ) {
	  if ( _allow_kill_xlate( &cmd_flag ) != 0 ) {
	    // found one
	    if ( this_ea->kill_xlate_pending == 1 ) {
	      // if it is already pending, just return.  Think about skipping this one and looking for another one to kill
	      // debug_msg( "_handle_kill_xlate: ea selected 0x%016lx, but it already has a kill pending", this_ea->ea );
	      return;
	    }
	    // no, really, we found one :-)
	    debug_msg( "_handle_kill_xlate: ea selected 0x%016lx", this_ea->ea );
	    // mark it pending
	    this_ea->kill_xlate_pending = 1;
	    // set ea, cmd_flag, page size, bdf, and pasid. capptag and opcode will be built by ocse
	    ea = this_ea->ea;
	    pg_size = this_ea->pg_size;
	    pasid = afu->context;
	    // bdf[15:8]=bus, bdf[7:3]=dev, bdf[2:0]=fcn
	    bdf = afu->bus;
	    bdf = bdf << 5;
	    bdf = bdf + afu->dev;
	    bdf = bdf << 3;
	    bdf = bdf + afu->fcn;
	    break;
	  }
	  // advance to next ea
	  this_ea = this_ea->_next;
	}
	
	if ( this_ea == NULL ) {
	  // decided not to kill any eas
	  // this debug message generates a lot of noise - only turn it on when abolutely necessary
	  // debug_msg( "_handle_kill_xlate: NO EA selected" );
	  return;
	}

	// this_ea is the one we want to kill, cmd_flag tells if we are going to strengthen that...
	// if we strengthen it, mark all ea's pending kill
	switch ( cmd_flag ) {
	case 0x0:
	  break;
	case 0x1:
	  // for 0x1, clear ea, page_size
	  ea = 0;
	  pg_size = 0;
	case 0xf:
	  // for 0xF, also clear bdf, and pasid
	  bdf = 0;
	  pasid = 0;
	  // for 0x1 and 0xF, mark all ea's pending
	  // done with this_ea so we can reuse it here
	  this_ea = afu->eas;
	  while (this_ea != NULL ) {
	    this_ea->kill_xlate_pending = 1;
	    this_ea = this_ea->_next;
	  }
	  break;
	default:
	  warn_msg(" _handle_kill_xlate: invalid/reserved cmd_flag %x generated, kill_xlate not sent", cmd_flag );
	  return;
	}

	// build the ocse message and send it
	size = 0;
	// 1 OCSE_KILL_XLATE
	buffer[size] = OCSE_KILL_XLATE;
	size++;

	// 1 cmd_flag
	buffer[size] = cmd_flag;
	size++;

	// 8 ea
	ea = htonll( ea );
	memcpy( &buffer[size], &ea, sizeof( ea ) );
	size = size + sizeof( ea );

	// 1 pg siz
	buffer[size] = pg_size;
	size++;

	// 2 bdf
	bdf = htons( bdf );
	memcpy( &buffer[size], &bdf, sizeof( bdf ) );
	size = size + sizeof( bdf );

	// 4 pasid
	pasid = htonl( pasid );
	memcpy( &buffer[size], &pasid, sizeof( pasid ) );
	size = size + sizeof( pasid );

	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		afu->opened = 0;
		afu->attached = 0;
		debug_msg( "KILL XLATE socket failure" );
	}
	debug_msg( "_handle_kill_xlate: KILL_XLATE addr @ 0x%016" PRIx64 ", cmd_flag %d, pg_size %d, bdf %d, pasid %d", ntohll( ea ), cmd_flag, pg_size, ntohs(bdf), ntohl(pasid) );
}

static void _handle_xlate( struct ocxl_afu *afu, uint8_t ocse_message )
{
        uint64_t addr;
        uint64_t ta;
	uint8_t cmd_flag;
	uint8_t pg_size;
	uint8_t buffer[10];
	int size;
	struct ocxl_ea_area *prev;
	struct ocxl_ea_area *this;

	if (!afu) fatal_msg("NULL afu passed to libocxl.c:_handle_xlate");

	debug_msg("_handle_xlate");
	// retrieve additional bytes from socket
	// touch and release will send addr
	if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer, -1, 0) < 0) {
	        warn_msg("Socket failure getting memory touch addr");
		_all_idle(afu);
		return;
	}
	memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
	addr = ntohll(addr);
	debug_msg("  of addr 0x%016" PRIx64, addr);

	// touch and release will send cmd_flag
	if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
		warn_msg("Socket failure getting form_flag ");
		_all_idle(afu);
		return;
	}
	memcpy( (char *)&cmd_flag, buffer, sizeof( cmd_flag ) );
	debug_msg( "  cmd_flag=%x", cmd_flag);

	// TODO check pg size; decide if to fail cmd for various other reasons and send back a fail resp code
	// this is the routine that now has to look at the function_code (cmd_flag) and do some extra processing
	// if the touch is requesting a TA, we have to build a translation table entry and return a "TA"
	// add data to the OCSE_MEM_SUCCESS message

	// if this is a release, search the eas' for a matching translated address, and free it.
	// if this is a touch, possibly create an eas 
	size = 0;
	buffer[size] = OCSE_MEM_SUCCESS;
	size++;


	switch ( ocse_message ) {
	case OCSE_XLATE_RELEASE:
	        // search ea list for ta matching addr
   	        // pg_size will also have to match
	        // also need to pull page size
	        if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
		  warn_msg("Socket failure getting pg_size");
		  _all_idle(afu);
		  return;
		}
		memcpy( (char *)&pg_size, buffer, sizeof( pg_size ) );
		debug_msg( "  pg_size=%x", pg_size);

	        this = afu->eas;
		prev = NULL;
	        while (this != NULL) {
		  if ( this->ta == (addr & (~(uint64_t)0 << this->pg_size)) ) break; // found matching ta, use values
		  prev = this;
		  this = this->_next;
		}
		// if this = NULL, we didn't find an ea entry - just return success
		if ( this == NULL ) {
		        return;
		}

		// pg_size should match - but what if it doesn't?  do we silently not release?
		
		if ( this->pg_size != pg_size ) {
		  warn_msg( "RELEASE of ta @ 0x%016lx did not have a matching page size.  expected %d, received %d.  releasing anyway", addr, this->pg_size, pg_size );
		}

		// release this entry
		if ( prev == NULL ) {
		  // update the afu->eas to point to this->_next
		  afu->eas = this->_next;
		} else {
		  // update prev->_next to point to this->_next
		  prev->_next = this->_next;
		}
		// free this
		free( this );
		debug_msg("RELEASE of addr @ 0x%016" PRIx64 "", addr);
	        break;
	case OCSE_MEMORY_TOUCH:
	        // Other function codes (0x4=heavy weight touch, 0x2=write access requested, and 0x1=age out) are not supported at this time
	        // if function code is request a ta 
	        // add a reason code to the fail message
	        if (!_testmemaddr((uint8_t *) addr)) {
		        if (_handle_dsi(afu, addr) < 0) {
			        perror("DSI Failure");
				return;
			}
			warn_msg("TOUCH of invalid page of addr @ 0x%016" PRIx64 "", addr);
			buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
			buffer[1] = 0xe;
			if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			        afu->opened = 0;
				afu->attached = 0;
			}
			return;
		}

	        if ( (cmd_flag & 0x08 ) == 0x08 ) {
		        // create a translation table entry
		        // translation table entry contains ea, ta (= ea), pa=0, mem_hit=0
		        // scan list for an matching EA (addr) entry
		        // if we find it, break and use it
		        // else add list entry to front and use it
		        this = afu->eas;
			while (this != NULL) {
			        if ( this->ea == (addr & (~(uint64_t)0 << this->pg_size)) ) break; // found matching ea, use values; address matching must be based on the based address of a given pg_size
				this = this->_next;
			}
		
			if (this == NULL ) {
			        // we didn't find an existing entry
			        // add entry to head of list
			        this = (struct ocxl_ea_area *)calloc( 1, sizeof( struct ocxl_ea_area ) );
				this->pg_size = 0x10; // 2^16 (64k) pages to represent the linux environment - this could maybe be random
				this->ea = addr & (~(uint64_t)0 << this->pg_size); // ea and ta must be truncated to represent the base address of a give pg_size.
				this->ta = this->ea | (~(uint64_t)0 << 60);
				this->pa = 0x0;
				this->mh = 0;
				this->_next = afu->eas;
				afu->eas = this;
			}

			// and add ta, pa to ocse_mem_success message
			ta = htonll(this->ta);
			memcpy( (char *)&(buffer[size]), (char *)&ta, sizeof( ta ) );
			size = size + sizeof( ta );
		
			buffer[size] = this->pg_size;
			size++;
			debug_msg("TOUCH of addr @ 0x%016llx to ta=0x%016llx pgsize=0x%02x, buffer size=%d", addr, this->ta, this->pg_size, size);
		}
	        break;
	default:
	        break;
	}

	// and send the success or message that has been built
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		afu->opened = 0;
		afu->attached = 0;
		debug_msg("_handle_xlate: some kind of put_bytes_silent failure");
	}

	return;

}

static void _handle_ack(struct ocxl_afu *afu)
{
	uint8_t data[sizeof(uint64_t)];
	uint8_t resp_code;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_ack");
	debug_msg("MMIO ACK");

	if (get_bytes_silent(afu->fd, 1, &resp_code, 1000, 0) < 0) {
		warn_msg("Socket failure getting resp_code");
		_all_idle(afu);
	} 

	if (resp_code !=0) // TODO update this to handle resp code retry requests
		error_msg ("handle_ack: AFU sent RD or WR FAILED response code = 0x%d ", resp_code);

	if ( ( afu->mmio.type == OCSE_MMIO_MAP ) | 
	     ( afu->mmio.type == OCSE_GLOBAL_MMIO_MAP ) | 
	     ( afu->mmio.type == OCSE_LPC_SYSTEM_MAP ) ) {
	        afu->mmios[afu->mmio_count].afu = afu;

		switch (afu->mmio.type) {
		case OCSE_MMIO_MAP:
		        afu->mmios[afu->mmio_count].type = OCXL_PER_PASID_MMIO;
			afu->mmios[afu->mmio_count].start = afu->per_pasid_mmio.start;
			afu->mmios[afu->mmio_count].length = afu->per_pasid_mmio.length;
			break;
		case OCSE_GLOBAL_MMIO_MAP:
		        afu->mmios[afu->mmio_count].type = OCXL_GLOBAL_MMIO;
			afu->mmios[afu->mmio_count].start = afu->global_mmio.start;
			afu->mmios[afu->mmio_count].length = afu->global_mmio.length;
			break;
		case OCSE_LPC_SYSTEM_MAP:
		        // convert mem_size to length 
		        afu->mmios[afu->mmio_count].type = OCXL_LPC_SYSTEM_MEM;
			afu->mmios[afu->mmio_count].start = (char *)afu->mem_base_address;
			debug_msg("_handle_ack: converting mem_size %d to length", afu->mem_size );
			afu->mmios[afu->mmio_count].length = afu->mem_size!=0 ? (uint64_t)0x1 << (afu->mem_size-1) : 0x0 ;
			debug_msg("_handle_ack: converted mem_size 0x%x to length 0x%016lx", afu->mem_size, afu->mmios[afu->mmio_count].length );
			break;
		default:
		        break;
		}
	}

	if ((afu->mmio.type == OCSE_MMIO_READ64) | (afu->mmio.type == OCSE_GLOBAL_MMIO_READ64) ) {
		if (get_bytes_silent(afu->fd, sizeof(uint64_t), data, 1000, 0) < 0) {
			warn_msg("Socket failure getting MMIO Ack");
			_all_idle(afu);
			afu->mmio.data = 0xFEEDB00FFEEDB00FL;
		} else {
			memcpy(&(afu->mmio.data), data, sizeof(uint64_t));
			afu->mmio.data = ntohll(afu->mmio.data);
		}
	}

	if ((afu->mmio.type == OCSE_MMIO_READ32) | (afu->mmio.type == OCSE_GLOBAL_MMIO_READ32)) {
		if (get_bytes_silent(afu->fd, sizeof(uint32_t), data, 1000, 0) < 0) {
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


static void _handle_DMO_OPs(struct ocxl_afu *afu, uint8_t amo_op)
{

	uint8_t op_size;
	uint8_t form_flag;
	uint64_t addr;
	uint8_t function_code; // aka cmd_flag
	uint8_t cmd_endian;
	uint64_t op1, op2;
	uint8_t atomic_op;
	uint8_t atomic_le;
	uint8_t buffer[2];
	uint8_t wbuffer[9];
	uint32_t lvalue, op_A, op_1, op_2;
	uint64_t llvalue, op_Al, op_1l, op_2l;
	int op_ptr;
	int rc;
	char wb;

	if (!afu) fatal_msg("NULL afu passed to libocxl.c:_handle_DMO_OPs");

	if (get_bytes_silent(afu->fd, sizeof(uint8_t), (uint8_t *)&op_size, -1, 0) < 0) {
	  warn_msg("Socket failure getting amo_wr or amo_rw size");
	  _all_idle(afu);
	  return;
	}
	debug_msg( "  op_size=%d ", op_size );

	if (get_bytes_silent(afu->fd, sizeof(uint8_t), (uint8_t *)&form_flag, -1, 0) < 0) {
	  warn_msg("Socket failure getting form_flag ");
	  _all_idle(afu);
	  return;
	}
	debug_msg( "  form_flag=%x", form_flag);

	if (get_bytes_silent(afu->fd, sizeof(uint64_t), (uint8_t *)&addr, -1, 0) < 0) {
	  warn_msg("Socket failure getting amo_wr or amo_rw addr");
	  _all_idle(afu);
	  return;
	}
	addr = ntohll(addr);
	debug_msg("  to addr 0x%016" PRIx64 "", addr);

	rc = _xlate_addr( afu, &addr, form_flag );
	if ( rc == 0xc ) {
	        // bad translation
	        // need to add the reason code to the mem failure message
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = 0xc;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}

	if (get_bytes_silent(afu->fd, sizeof(uint8_t), (uint8_t *)&function_code, -1, 0) < 0) {
	  warn_msg("Socket failure getting function_code ");
	  _all_idle(afu);
	  return;
	}
	debug_msg( "  function_code=%x", function_code);

	if (get_bytes_silent(afu->fd, sizeof(uint8_t), (uint8_t *)&cmd_endian, -1, 0) < 0) {
	  warn_msg("Socket failure getting cmd_endian ");
	  _all_idle(afu);
	  return;
	}
	debug_msg( "  cmd_endian=%x", cmd_endian);

	// If amo op is a read, we don't get op1 and op2 in the socket
	if (amo_op == OCSE_AMO_RD) {
	  op1 = 0;
	  op2 = 0;
	} else {
	  if (get_bytes_silent(afu->fd, sizeof(uint64_t), (uint8_t *)&op1, -1, 0) < 0) {
	    warn_msg("Socket failure getting amo_wr or amo_rw addr");
	    _all_idle(afu);
	    return;
	  }
	  debug_msg("  op1 0x%016" PRIx64, op1);
	  
	  if (get_bytes_silent(afu->fd, sizeof(uint64_t), (uint8_t *)&op2, -1, 0) < 0) {
	    warn_msg("Socket failure getting amo_wr or amo_rw addr");
	    _all_idle(afu);
	    return;
	  }
	  debug_msg("  op2 0x%016" PRIx64, op2);
	}

	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		warn_msg("READ2 from invalid addr @ 0x%016" PRIx64 "", addr);
		buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
		buffer[1] = 0xe;
		if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
			afu->opened = 0;
			afu->attached = 0;
		}
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
				debug_msg("INVALID op_size  0x%x for  addr  0x%016" PRIx64 "", op_size, addr);
				buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
				buffer[1] = 0xb;
				if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
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
				debug_msg("INVALID op_size  0x%x for  addr  0x%016" PRIx64 "", op_size, addr);
				buffer[0] = (uint8_t) OCSE_MEM_FAILURE;
				buffer[1] = 0xb;
				if (put_bytes_silent(afu->fd, 2, buffer) != 2) {
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
	if (cmd_endian == 0)
		atomic_le = 1;
	else
	    atomic_le = 0;
	//cmd_endian == 0 when afu is LE, our old logic needs atomic_le == 1 for LE
	// if atomic_le == 1, afu is le, so no data issues (ocse is always le).
	// if atomic_le == 0, we have to swap op1/op2 data before ops, and also swap
	// data returned by fetches
	
	debug_msg("_handle_DMO_OPs:  atomic_op = 0x%2x and atomic_le = 0x%x ", atomic_op, atomic_le);

	debug_msg("READ from addr @ 0x%016" PRIx64 "", addr);
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
		warn_msg("unsupported op_size of 0x%2x ", op_size);

	switch (atomic_op) {
			case AMO_WRMWF_ADD:
				if  (op_size == 4) {
				debug_msg("ADD %08"PRIx32" to %08"PRIx32 " store it & only return op_A for amo_rw ", op_A, op_1);
					op_1 += op_A;
					wb = 1;
				} else {
				debug_msg("ADD %016"PRIx64" to %016"PRIx64 " store it & return op_Al for amo_rw ", op_Al, op_1l);
					op_1l += op_Al;
					wb = 2;
				}
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_WRMWF_XOR:
				if  (op_size == 4) {
				debug_msg("XOR %08"PRIx32" with %08"PRIx32 " store it & return op_A  for amo_rw", op_A, op_1);
					op_1 ^= op_A;
					wb = 1;
				} else {
				debug_msg("XOR %016"PRIx64" with %016"PRIx64 " store it & return op_Al for amo_rw ", op_Al, op_1l);
					op_1l ^= op_Al;
					wb = 2;
				}
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_WRMWF_OR:
				if  (op_size == 4) {
				debug_msg("OR %08"PRIx32" with %08"PRIx32 " store it & return op_A  for amo_rw", op_A, op_1);
					op_1 |= op_A;
					wb = 1;
				} else {
				debug_msg("OR %016"PRIx64" with %016"PRIx64 " store it & return op_Al for amo_rw ", op_Al, op_1l);
					op_1l |= op_Al;
					wb = 2;
				}
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_WRMWF_AND:
				if  (op_size == 4) {
				debug_msg("AND %08"PRIx32" with %08"PRIx32 " store it & return op_A for amo_rw ", op_A, op_1);
					op_1 &= op_A;
					wb = 1;
				} else {
				debug_msg("AND %016"PRIx64" with %016"PRIx64 " store it & return op_Al for amo_rw ", op_Al, op_1l);
					op_1l &= op_Al;
					wb = 2;
				}
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_WRMWF_CAS_MAX_U:
				if  (op_size == 4) {
				debug_msg("UNSIGNED COMPARE %08"PRIx32" with %08"PRIx32 " , store larger & return op_A for amo_rw ", op_A, op_1);
					if (op_A > op_1)
						op_1 = op_A;
					wb = 1;
				} else {
				debug_msg("UNSIGNED COMPARE %016"PRIx64" with %016"PRIx64 " , store larger & return op_Al for amo_rw  ", op_Al, op_1l);
					if (op_Al > op_1l)
						op_1l = op_Al;
					wb = 2;
				}
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_WRMWF_CAS_MAX_S:
				// sign extend op_A and op_1 and then cast as int and do comparison
				if (op_size == 4) {
					op_A = sign_extend(op_A);
					op_1 = sign_extend(op_1);
				debug_msg("SIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store larger & return op_A for amo_rw ", op_A, op_1);
					if ((int32_t)op_A > (int32_t)op_1)
						op_1 = op_A;
					wb = 1;
				} else {
					op_Al = sign_extend64(op_Al);
					op_1l = sign_extend64(op_1l);
				debug_msg("SIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store larger & return op_Al for amo_rw ", op_Al, op_1l);
					if ((int64_t)op_Al > (int64_t)op_1l)
						op_1l = op_Al;
					wb = 2;
				}
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_WRMWF_CAS_MIN_U:
				if  (op_size == 4) {
				debug_msg("UNSIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store smaller & return op_A for amo_rw ", op_A, op_1);
					if (op_A < op_1)
						op_1 = op_A;
					wb = 1;
				} else {
				debug_msg("UNSIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store smaller & return op_Al for amo_rw ", op_Al, op_1l);
					if (op_Al < op_1l)
						op_1l = op_Al;
					wb = 2;
				}
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_WRMWF_CAS_MIN_S:
				if (op_size == 4) {
					op_A = sign_extend(op_A);
					op_1 = sign_extend(op_1);
				debug_msg("SIGNED COMPARE %08"PRIx32" with %08"PRIx32 " store smaller & return op_A for amo_rw ", op_A, op_1);
					if ((int32_t)op_A < (int32_t)op_1)
						op_1 = op_A;
					wb = 1;
				} else {
					op_Al = sign_extend64(op_Al);
					op_1l = sign_extend64(op_1l);
				debug_msg("SIGNED COMPARE %016"PRIx64" with %016"PRIx64 " store smaller & return op_Al for amo_rw ", op_Al, op_1l);
					if ((int64_t)op_Al < (int64_t)op_1l)
						op_1l = op_Al;
					wb = 2;
				}
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_ARMWF_CAS_U:
				if ((amo_op == OCSE_AMO_WR) || (amo_op == OCSE_AMO_RD)) {
					info_msg("INVALID FUNCTION CODE FOR AMO_WR or AMO_RD - treated as NOP ");
					wb = 0; 
					break; }
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
				if ((amo_op == OCSE_AMO_WR) || (amo_op == OCSE_AMO_RD)) {
					info_msg("INVALID FUNCTION CODE FOR AMO_WR or AMO_RD - treated as NOP ");
					wb = 0; 
					break; }
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
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_ARMWF_CAS_NE: //0x0a 
				if ((amo_op == OCSE_AMO_WR) || (amo_op == OCSE_AMO_RD)) {
					info_msg("INVALID FUNCTION CODE FOR AMO_WR or AMO_RD - treated as NOP ");
					wb = 0; 
					break; }
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
				if (amo_op == OCSE_AMO_WR)
					wb = 0;
				break;
			case AMO_ARMWF_INC_B: //0xc0
			//case AMO_W_CAS_T:
				if (amo_op == OCSE_AMO_RW)  {
					info_msg("INVALID FUNCTION CODE FOR AMO_RW - treated as NOP ");
					wb = 0; 
					break; }
				if (amo_op == OCSE_AMO_WR) { //this is the amo_wr store & compare twin

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
				   }
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
				if ((amo_op == OCSE_AMO_WR) || (amo_op == OCSE_AMO_RW)) {
					info_msg("INVALID FUNCTION CODE FOR AMO_WR or AMO_RW - treated as NOP ");
					wb = 0; 
					break; }
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
				if ((amo_op == OCSE_AMO_WR) || (amo_op == OCSE_AMO_RW)) {
					info_msg("INVALID FUNCTION CODE FOR AMO_WR or AMO_RW - treated as NOP ");
					wb = 0; 
					break; }
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
			default:
				wb = 0xf;
				warn_msg("Unsupported AMO command 0x%04x", atomic_op);
				break;
			}
	// every VALID op has a write to store something to the original EA, unless STORE TWIN !=
	if (wb != 0xf) {
		if (op_size == 4) {
			memcpy ((void *)addr, &op_1, op_size);
			debug_msg("WRITE to addr @ 0x%016" PRIx64 " with results of 0x%08" PRIX32 " ", addr, op_1);
			// if this was STORE TWIN, write op_2 to addr+4
			if ((atomic_op) == AMO_W_CAS_T) {
				memcpy ((void *)addr+4, &op_2, op_size);
				debug_msg("WRITE to addr+4 @ 0x%016" PRIx64 " with results of 0x%08" PRIX32 " ", addr+4, op_2);
			}
		} else  {// only other supported size is 8
			memcpy ((void *)addr, &op_1l, op_size);
			debug_msg("WRITE to addr @ 0x%016" PRIx64 " with results of 0x%016" PRIX64 "", addr, op_1l);
			// if this was STORE TWIN, write op_2l to addr+8
			if ((atomic_op) == AMO_W_CAS_T) {
				memcpy ((void *)addr+8, &op_2l, op_size);
				debug_msg("WRITE to addr+8 @ 0x%016" PRIx64 " with results of 0x%016" PRIX64 " ", addr+8, op_2l);
			}
		}
	}

	// only AMO_ARMWF_* commands return back original data from EA, otherwise just MEM ACK
	switch (wb)  {
			case 0:
				buffer[0] = OCSE_MEM_SUCCESS;
				if (put_bytes_silent(afu->fd, 1, buffer) != 1) {
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
				debug_msg("READ from addr @ 0x%016" PRIx64 "", addr);
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
				debug_msg("READ from addr @ 0x%016" PRIx64 "", addr);
				break;

			default:
				warn_msg("invalid wb! ");
				wb = 0;
				break;
			} 


}



static void _req_max_int(struct ocxl_afu *afu)
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

static void _ocse_attach(struct ocxl_afu *afu)
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

static void _mmio_map(struct ocxl_afu *afu)
{
	uint8_t *buffer;
	//uint32_t *flags_ptr;
	//uint32_t flags;
	int size;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_mmio_map");
	size = 1; // + sizeof(uint32_t);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = afu->mmio.type;
	// flags = (uint32_t) afu->mmio.data;
	// flags_ptr = (uint32_t *) & (buffer[1]);
	// *flags_ptr = htonl(flags);
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

static void _mmio_write64(struct ocxl_afu *afu)
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
	debug_msg( "_mmio_write64: type = %02x, offset = %08x", afu->mmio.type, afu->mmio.addr );
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

static void _mmio_write32(struct ocxl_afu *afu)
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
	debug_msg( "_mmio_write32: type = %02x, offset = %08x", afu->mmio.type, afu->mmio.addr );
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

static void _mmio_read(struct ocxl_afu *afu)
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
	debug_msg( "_mmio_read: type = %02x, offset = %08x", afu->mmio.type, afu->mmio.addr );
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

static void _mem_map(struct ocxl_afu *afu)
{
        // _mem_map doesn't really need to do anything for ocse...  the fact that we have a socket is enough
        // all the information we need is over in ocse already as it has gone through the config space

        if (!afu)
	      fatal_msg("NULL afu passed to libocxl.c:_mem_map");

	afu->mem.state = LIBOCXL_REQ_IDLE; // make pending if we really have to send something to ocse...
	return;
}

static void _mem_read(struct ocxl_afu *afu)
{
	uint8_t *buffer;
	int buffer_length;
	int buffer_offset;

	uint32_t offset;
	uint32_t size;

	debug_msg("_mem_read:");

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_mem_read");

	// buffer length = 1 byte for type, buffer remainder?, 4 bytes for offset, 4 bytes for size
	buffer_length = 1 + sizeof(offset) + sizeof(size);
	debug_msg("_mem_read: buffer length %d", buffer_length);
	buffer = (uint8_t *)malloc( buffer_length );

	debug_msg("_mem_read: buffer[0]");
	buffer[0] = afu->mem.type;

	buffer_offset = 1;
	debug_msg( "_mem_read: buffer[%d]", buffer_offset );
	offset = htonl(afu->mem.addr);
	memcpy( (char *)&(buffer[buffer_offset]), (char *)&offset, sizeof(offset));
	buffer_offset += sizeof(offset);

	debug_msg( "_mem_read: buffer[%d]", buffer_offset );
	size = htonl(afu->mem.size);
	memcpy((char *)&(buffer[buffer_offset]), (char *)&size, sizeof(size));

	if (put_bytes_silent(afu->fd, buffer_length, buffer) != buffer_length) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mem.state = LIBOCXL_REQ_IDLE;
		return;
	}

	free(buffer);
	afu->mem.state = LIBOCXL_REQ_PENDING;
}

static void _mem_write(struct ocxl_afu *afu)
{
	uint8_t *buffer;
	int buffer_length;
	int buffer_offset;

	uint32_t offset;
	uint32_t size;

	debug_msg("_mem_write:");

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_mem_write");

	// buffer length = 1 byte for type, buffer remainder?, 4 bytes for offset, n bytes for size, m bytes for data
	buffer_length = 1 + sizeof(offset) + sizeof(size) + afu->mem.size;
	debug_msg("_mem_write: buffer length %d", buffer_length);
	buffer = (uint8_t *)malloc( buffer_length );

	debug_msg("_mem_write: buffer[0]");
	buffer[0] = afu->mem.type;

	buffer_offset = 1;
	debug_msg( "_mem_write: buffer[%d]", buffer_offset );
	offset = htonl(afu->mem.addr); 
	memcpy( (char *)&(buffer[buffer_offset]), (char *)&offset, sizeof(offset));
	buffer_offset += sizeof(offset);

	debug_msg( "_mem_write: buffer[%d]", buffer_offset );
	size = htonl(afu->mem.size);
	memcpy((char *)&(buffer[buffer_offset]), (char *)&size, sizeof(size));
	buffer_offset += sizeof(size);

	// data = htonll(afu->mmio.data);
	debug_msg( "_mem_write: buffer[%d]", buffer_offset );
	memcpy( (char *)&(buffer[buffer_offset]), afu->mem.data, afu->mem.size );
	if (put_bytes_silent(afu->fd, buffer_length, buffer) != buffer_length) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mem.state = LIBOCXL_REQ_IDLE;
		return;
	}

	free(buffer);
	afu->mem.state = LIBOCXL_REQ_PENDING;
}

static void _mem_write_be(struct ocxl_afu *afu)
{
	uint8_t *buffer;
	int buffer_length;
	int buffer_offset;

	uint32_t offset;
	uint64_t be;

	debug_msg("_mem_write_be:");

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_mem_write");

	// buffer length = 1 byte for type, 4 bytes for offset, 8 bytes for be, 64 bytes for data
	buffer_length = 1 + sizeof(offset) + sizeof( be ) + afu->mem.size;
	debug_msg("_mem_write_be: buffer length %d", buffer_length);
	buffer = (uint8_t *)malloc( buffer_length );

	debug_msg("_mem_write_be: buffer[0]");
	buffer[0] = afu->mem.type;

	buffer_offset = 1;
	debug_msg( "_mem_write_be: buffer[%d]", buffer_offset );
	offset = htonl(afu->mem.addr);
	memcpy( (char *)&(buffer[buffer_offset]), (char *)&offset, sizeof(offset));
	buffer_offset += sizeof(offset);

	debug_msg( "_mem_write: buffer[%d]", buffer_offset );
	be = htonl(afu->mem.be);
	memcpy((char *)&(buffer[buffer_offset]), (char *)&be, sizeof(be));
	buffer_offset += sizeof(be);

	// data = htonll(afu->mmio.data);
	debug_msg( "_mem_write: buffer[%d]", buffer_offset );
	memcpy( (char *)&(buffer[buffer_offset]), afu->mem.data, afu->mem.size );
	if (put_bytes_silent(afu->fd, buffer_length, buffer) != buffer_length) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mem.state = LIBOCXL_REQ_IDLE;
		return;
	}

	free(buffer);
	afu->mem.state = LIBOCXL_REQ_PENDING;
}

static void _amo_read(struct ocxl_afu *afu)
{
	uint8_t *buffer;
	int buffer_length;
	int buffer_offset;

	uint32_t offset;
	uint32_t size;

	size = afu->mem.size;
	debug_msg("_amo_read:");

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_amo_read");

	// buffer length = 1 byte for type, buffer remainder?, 4 bytes for offset, 4 bytes for size, 1 byte for cmd_flag, 1 byte for endian
	buffer_length = 1 + sizeof(offset) + sizeof(size) + 1 + 1 ;
	debug_msg("_amo_read: buffer length %d", buffer_length);
	buffer = (uint8_t *)malloc( buffer_length );

	debug_msg("_amo_read: buffer[0]");
	buffer[0] = afu->mem.type;

	buffer_offset = 1;
	debug_msg( "_amo_read: buffer[%d]", buffer_offset );
	offset = htonl(afu->mem.addr);
	memcpy( (char *)&(buffer[buffer_offset]), (char *)&offset, sizeof(offset));
	buffer_offset += sizeof(offset);

	debug_msg( "_amo_read: buffer[%d]", buffer_offset );
	size = htonl(afu->mem.size);
	memcpy((char *)&(buffer[buffer_offset]), (char *)&size, sizeof(size));
	buffer_offset += sizeof(size);

	debug_msg( "_amo_read: buffer[%d]", buffer_offset );
	buffer[buffer_offset] = afu->mem.cmd;
	buffer_offset += 1;

	debug_msg( "_amo_read: buffer[%d]", buffer_offset );
        buffer[buffer_offset] = 0; // constant endianness for now
	buffer_offset += 1;

	if (put_bytes_silent(afu->fd, buffer_length, buffer) != buffer_length) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mem.state = LIBOCXL_REQ_IDLE;
		return;
	}

	free(buffer);
	afu->mem.state = LIBOCXL_REQ_PENDING;
}

static void _amo_write(struct ocxl_afu *afu)
{
	uint8_t *buffer;
	int buffer_length;
	int buffer_offset;

	uint32_t offset;
	uint32_t size, hsize;

	debug_msg("_amo_read:");

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_amo_write");

	// buffer length = 1 byte for type, 
	//                 4 bytes for offset, 
	//                 4 bytes for size, 
	//                 1 byte for cmd_flag, 
	//                 1 byte for endian, 
	//                 size bytes for val
	size = afu->mem.size;
	hsize = afu->mem.size;


	debug_msg( "_amo_write: size=%d", size );
	buffer_length = 1 + sizeof(offset) + sizeof(size) + 1 + 1 + size ;
	debug_msg("_amo_write: buffer length %d", buffer_length);
	buffer = (uint8_t *)malloc( buffer_length );

	debug_msg("_amo_write: buffer[0]");
	buffer[0] = afu->mem.type;

	buffer_offset = 1;
	debug_msg( "_amo_write: buffer[%d]", buffer_offset );
	offset = htonl(afu->mem.addr);
	memcpy( (char *)&(buffer[buffer_offset]), (char *)&offset, sizeof(offset));
	buffer_offset += sizeof(offset);

	debug_msg( "_amo_write: buffer[%d]", buffer_offset );
	size = htonl(afu->mem.size);
	memcpy((char *)&(buffer[buffer_offset]), (char *)&size, sizeof(hsize));
	buffer_offset += sizeof(hsize);
	debug_msg( "_amo_write: size=%d", hsize );

	debug_msg( "_amo_write: buffer[%d]", buffer_offset );
	buffer[buffer_offset] = afu->mem.cmd;
	buffer_offset += 1;

	debug_msg( "_amo_write: buffer[%d]", buffer_offset );
        buffer[buffer_offset] = 0; // constant endianness for now
	buffer_offset += 1;

	// data = htonll(afu->mmio.data);
	debug_msg( "_amo_write: buffer[%d]", buffer_offset );
	memcpy( (char *)&(buffer[buffer_offset]), afu->mem.data, afu->mem.size );
	buffer_offset += hsize;
	debug_msg( "_amo_write: buffer[%d]", buffer_offset );

	if (put_bytes_silent(afu->fd, buffer_length, buffer) != buffer_length) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mem.state = LIBOCXL_REQ_IDLE;
		return;
	}

	free(buffer);
	afu->mem.state = LIBOCXL_REQ_PENDING;
}

static void _amo_readwrite(struct ocxl_afu *afu)
{
	uint8_t *buffer;
	int buffer_length;
	int buffer_offset;

	uint32_t offset;
	uint32_t size, hsize;

	//size will be adjusted later in mmio.c for cmd_flag > 7
	size = afu->mem.size;
	hsize = afu->mem.size;
	debug_msg("_amo_readwrite:");

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_amo_readwrite");

	// buffer length = 1 byte for type, 
	//                 4 bytes for offset, 
	//                 4 bytes for size, 
	//                 1 byte for cmd_flag, 
	//                 1 byte for endian, 
	//                 ?size bytes for valv
	//                 ?size bytes for valw (for some cmds_flags)

	// buffer length depends on cmd_flag, allocate maximum
	buffer_length = 1 + sizeof(offset) + sizeof(size) + 1 + 1 + size + size ;
	debug_msg("_amo_readwrite: buffer length %d", buffer_length);
	buffer = (uint8_t *)malloc( buffer_length );

	debug_msg("_amo_readwrite: buffer[0]");
	buffer[0] = afu->mem.type;

	buffer_offset = 1;
	debug_msg( "_amo_readwrite: buffer[%d]", buffer_offset );
	offset = htonl(afu->mem.addr);
	memcpy( (char *)&(buffer[buffer_offset]), (char *)&offset, sizeof(offset));
	buffer_offset += sizeof(offset);

	debug_msg( "_amo_readwrite: buffer[%d]", buffer_offset );
	size = htonl(afu->mem.size);
	memcpy((char *)&(buffer[buffer_offset]), (char *)&size, sizeof(hsize));
	buffer_offset += sizeof(hsize);

	debug_msg( "_amo_readwrite: buffer[%d]", buffer_offset );
	buffer[buffer_offset] = afu->mem.cmd;
	buffer_offset += 1;

	debug_msg( "_amo_readwrite: buffer[%d]", buffer_offset );
        buffer[buffer_offset] = 0; // constant endianness for now
	buffer_offset += 1;
	debug_msg( "_amo_readwrite: size=%d", hsize );

	// if mem.cmd is 0-7, 9, or 10
	// data = htonll(afu->mmio.data);
	// CLIENTS MUST SEND NULL PTR for datav when cmd_flg= 0x8!
	if ( afu->mem.data != NULL ) {
	  debug_msg( "_amo_readwrite: buffer data[%d]", buffer_offset );
	  memcpy( (char *)&(buffer[buffer_offset]), afu->mem.data, afu->mem.size );
	  buffer_offset += hsize;
	}

	// if mem.cmd is 8, 9, or 10
	// data = htonll(afu->mmio.datab);
	if ( afu->mem.datab != NULL ) {
	  debug_msg( "_amo_readwrite: buffer datab[%d]", buffer_offset );
	  memcpy( (char *)&(buffer[buffer_offset]), afu->mem.datab, afu->mem.size );
	  buffer_offset += hsize;
	}

	if (put_bytes_silent(afu->fd, buffer_offset, buffer) != buffer_offset) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mem.state = LIBOCXL_REQ_IDLE;
		return;
	}

	free(buffer);
	afu->mem.state = LIBOCXL_REQ_PENDING;
}

static void _handle_mem_ack(struct ocxl_afu *afu)
{
	uint8_t resp_code;

	debug_msg( "_handle_mem_ack" );

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_handle_mem_ack");

	if (get_bytes_silent(afu->fd, 1, &resp_code, 1000, 0) < 0) {
		warn_msg("Socket failure getting resp_code");
		_all_idle(afu);
	} 
	if (resp_code !=0) // TODO update this to handle resp code retry requests
		error_msg ("handle_mem_ack: AFU sent RD or WR FAILED response code = 0x%d ", resp_code);
	if ( ( afu->mem.type == OCSE_LPC_READ ) || 
	     ( afu->mem.type == OCSE_AFU_AMO_RD ) || 
	     ( afu->mem.type == OCSE_AFU_AMO_RW ) ) {
	        // assuming it all worked, we already know the size in afu->mem.size
	        debug_msg( "_handle_mem_ack: getting %d bytes from socket", afu->mem.size );
		afu->mem.data = (uint8_t *)malloc( afu->mem.size );
		if (get_bytes_silent(afu->fd, afu->mem.size, afu->mem.data, 1000, 0) < 0) {
		      warn_msg("Socket failure getting MEM Ack data");
		      free( afu->mem.data );
		      _all_idle(afu);
		}
	}

	afu->mem.state = LIBOCXL_REQ_IDLE;
}


static void *_psl_loop(void *ptr)
{
	struct ocxl_afu *afu = (struct ocxl_afu *)ptr;
	uint8_t buffer[MAX_LINE_CHARS];
	uint16_t size;
	uint8_t bvalue;
	uint16_t value;
	uint32_t lvalue;
	uint64_t llvalue;
	int rc;
	int offset;

	if (!afu)
		fatal_msg("NULL afu passed to libocxl.c:_psl_loop");
	afu->opened = 1;
	//srand( time( 0 ) );

	while (afu->opened) {
		_delay_1ms();
		// Send any requests to OCSE over socket
		// add the potential to randomly generate an kill_xlate
		// should we do it independent of the various REQ's that we can make?
		if (afu->int_req.state == LIBOCXL_REQ_REQUEST)
			_req_max_int(afu);
		if (afu->attach.state == LIBOCXL_REQ_REQUEST)
			_ocse_attach(afu);
		if (afu->mmio.state == LIBOCXL_REQ_REQUEST) {
			switch (afu->mmio.type) {
			case OCSE_MMIO_MAP:
			case OCSE_GLOBAL_MMIO_MAP:
			case OCSE_LPC_SYSTEM_MAP:
			case OCSE_LPC_SPECIAL_PURPOSE_MAP:
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
		if (afu->mem.state == LIBOCXL_REQ_REQUEST) {
			switch (afu->mem.type) {
			case OCSE_LPC_SYSTEM_MAP:
				_mem_map(afu);
				break;
			case OCSE_LPC_WRITE:
				_mem_write(afu);
				break;
			case OCSE_LPC_WRITE_BE:
				_mem_write_be(afu);
				break;
			case OCSE_LPC_READ:
				_mem_read(afu);
				break;
			// when the amo operation appears here, it represents a CAPP amo command
			case OCSE_AFU_AMO_RD:
				_amo_read(afu);
				break;
			case OCSE_AFU_AMO_WR:
				_amo_write(afu);
				break;
			case OCSE_AFU_AMO_RW:
				_amo_readwrite(afu);
				break;
			default:
				break;
			}
		}

		_handle_kill_xlate( afu );

		// Process socket input from OCSE
		rc = bytes_ready(afu->fd, 1000, 0);
		if (rc == 0) {
		        // debug_msg("Socket open - no bytes to read - testing to see if socket is still tested while in the signal handler");
			continue;
		}
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

		debug_msg("OCL EVENT = 0x%02x", buffer[0]);
		switch (buffer[0]) {
		case OCSE_OPEN:
			if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
				warn_msg("Socket failure getting OPEN context");
				_all_idle(afu);
				break;
			}
			afu->context = (uint16_t) buffer[0];
			afu->open.state = LIBOCXL_REQ_IDLE;
			info_msg("PASID = context = %d", afu->context);
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
			afu->mem.state = LIBOCXL_REQ_IDLE;
			afu->int_req.state = LIBOCXL_REQ_IDLE;
			break;
		case OCSE_MAX_INT:
			size = sizeof(uint16_t);
			if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) < 0) {
				warn_msg("Socket failure getting max interrupt acknowledge");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&value, (char *)buffer, sizeof(uint16_t));
			// afu->irqs_max = ntohs(value);
			afu->int_req.state = LIBOCXL_REQ_IDLE;
			break;
		case OCSE_QUERY: {
		        size = 
			  sizeof(uint16_t) + // device_id
			  sizeof(uint16_t) + // vendor_id
			  sizeof(uint8_t)  + // afu_version_major
			  sizeof(uint8_t)  + // afu_version_minor
			  sizeof(uint64_t) + // global_mmio_offset
			  sizeof(uint32_t) + // global_mmio_size
			  sizeof(uint64_t) + // pp_mmio_offset
			  sizeof(uint32_t) + // pp_mmio_stride
			  sizeof(uint64_t) + // mem_base_address
			  sizeof(uint8_t)  ; // mem_size

			if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) <
			    0) {
				warn_msg("Socket failure getting OCSE query");
				_all_idle(afu);
				break;
			}

			offset = 0;

                	memcpy((char *)&value, (char *)&(buffer[offset]), 2); // device_id
			afu->device_id = value;
			offset += sizeof(uint16_t);

                        memcpy((char *)&value, (char *)&(buffer[offset]), 2); // vendor_id
			afu->vendor_id = value;
			offset += sizeof(uint16_t);

                        memcpy((char *)&bvalue, (char *)&(buffer[offset]), 1); // afu_version_major
			afu->afu_version_major = bvalue;
			offset += sizeof(uint8_t);

                        memcpy((char *)&bvalue, (char *)&(buffer[offset]), 1); // afu_version_minor
			afu->afu_version_minor = bvalue;
			offset += sizeof(uint8_t);

			afu->global_mmio.type = OCXL_GLOBAL_MMIO;

                        memcpy((char *)&llvalue, (char *)&(buffer[offset]), 8); // global_mmio_offset
			// afu->global_mmio_offset = llvalue;
			afu->global_mmio.start = (char *)llvalue;
			offset += sizeof(uint64_t);

                        memcpy((char *)&lvalue, (char *)&(buffer[offset]), 4); // global_mmio_size
			// afu->global_mmio_size = lvalue;
			afu->global_mmio.length = lvalue;
			offset += sizeof(uint32_t);

			afu->per_pasid_mmio.type = OCXL_PER_PASID_MMIO;

                        memcpy((char *)&llvalue, (char *)&(buffer[offset]), 8); // pp_mmio_offset
			// afu->pp_mmio_offset = llvalue;
			afu->per_pasid_mmio.start = (char *)llvalue;
			offset += sizeof(uint64_t);

                        memcpy((char *)&lvalue, (char *)&(buffer[offset]), 4); // pp_mmio_stride
			// afu->pp_mmio_stride = lvalue;
			afu->per_pasid_mmio.length = lvalue;
			offset += sizeof(uint32_t);

			// we will only allow 4 mmio(memory) areas per attach.  
			//     global mmio registers
			//     per pasid mmio registers 
			//     lpc system memory
			//     lpc special purpose memory.
			// we will only allow 1 per pasid area per attach and it must be the full area for this pasid,
			// that is, the full stride.  and the offset is 0 from this pasid's (context) area

			afu->mmio_count = 0;
			afu->mmio_max = 4;
			
                        memcpy((char *)&llvalue, (char *)&(buffer[offset]), 8); // mem_base_address
			afu->mem_base_address = llvalue;
			offset += sizeof(uint64_t);

                        memcpy((char *)&bvalue, (char *)&(buffer[offset]), 1); // mem_size
			afu->mem_size = bvalue;
			offset += sizeof(uint8_t);

			break;
		}
		case OCSE_MEMORY_READ:
			debug_msg("AFU MEMORY READ");
			_handle_read( afu );
			break;
		case OCSE_MEMORY_WRITE:
			debug_msg("AFU MEMORY WRITE");
			_handle_write( afu );
			break;
		// add the case for ocse_memory_be_write
		// need to size, addr and data as above in ocse_memory_write
	        // and then need to get byte enable in manner similar to addr (maybe)
		case OCSE_WR_BE:
			debug_msg("AFU MEMORY WRITE BE");
			_handle_write_be(afu);
			break;
			
		// When amo operations appear here, they represent AP amo commands
		case OCSE_AMO_WR:
		case OCSE_AMO_RW:
			if ( buffer[0] == OCSE_AMO_WR ) debug_msg("AFU AMO_WRITE ");
			else debug_msg("AFU AMO__READ/WRITE");
			_handle_DMO_OPs(afu, buffer[0]);
			break;

		case OCSE_AMO_RD:
			debug_msg("AFU AMO READ ");
			_handle_DMO_OPs(afu, buffer[0]);
			break;


		case OCSE_XLATE_RELEASE:
			debug_msg("AFU XLATE RELEASE");
			_handle_xlate( afu, OCSE_XLATE_RELEASE );
			break;
		case OCSE_KILL_XLATE_DONE:
			debug_msg("AFU KILL XLATE DONE");
			_handle_kill_xlate_done( afu );
			debug_msg("AFU KILL XLATE DONE done");
			break;
		case OCSE_MEMORY_TOUCH:
			debug_msg("AFU XLATE TOUCH");
			_handle_xlate( afu, OCSE_MEMORY_TOUCH );
			debug_msg("AFU XLATE TOUCH done");
			break;
		case OCSE_MMIO_ACK:
			_handle_ack(afu);
			break;
		case OCSE_LPC_ACK:
			_handle_mem_ack(afu);
			break;
		case OCSE_INTERRUPT_D:
			debug_msg("AFU INTERRUPT D");
			if (_handle_interrupt(afu, 1) < 0) {
				perror("Interrupt d Failure");
				goto ocl_fail;
			}
			break;
		case OCSE_INTERRUPT:
			debug_msg("AFU INTERRUPT");
			if (_handle_interrupt(afu, 0) < 0) {
				perror("Interrupt Failure");
				goto ocl_fail;
			}
			break;
		case OCSE_WAKE_HOST_THREAD:
			debug_msg("AFU WAKE HOST THREAD");
			if (_handle_wake_host_thread(afu) < 0) {
				perror("Wake Host Thread Failure");
				goto ocl_fail;
			}
			break;
		case OCSE_CA_MEMORY_READ:
			debug_msg("AFU CACHEABLE READ OPERATION");
			_handle_ca_read( afu );
			break;
		case OCSE_UPGRADE_STATE:
			debug_msg("AFU CACHE UPGRADE STATE OPERATION");
			_handle_upgrade_state( afu );
			break;
		case OCSE_CASTOUT:
			debug_msg("AFU CASTOUT OPERATION");
			_handle_castout( afu );
			break;
		case OCSE_CA_SYNONYM_DONE:
			debug_msg("AFU CASTOUT OPERATION");
			_handle_synonym_done( afu );
			break;
		/* case OCSE_AFU_ERROR: */
		/* 	if (_handle_afu_error(afu) < 0) { */
		/* 		perror("AFU ERROR Failure"); */
		/* 		goto ocl_fail; */
		/* 	} */
		/* 	break; */
		default:
			debug_msg("UNKNOWN CMD IS 0x%2x ", buffer[0]);
			break;
		}
	}

 ocl_fail:
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
	debug_msg("AFU CONNECT");
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

	// afu_map contains a 1 at each position a tlx interface exists - i.e. the bus numbers that have been "discovered"
	memcpy((char *)afu_map, (char *)buffer, 2);
	*afu_map = (long)ntohs(*afu_map);
	debug_msg("opened host-side socket %d", *fd);

	// install a sigsegv signal handler
	if ( ocxl_cache_access_installed == 0 ) {
	  ocxl_sigaction.sa_flags = SA_SIGINFO;
	  sigemptyset( &ocxl_sigaction.sa_mask );
	  ocxl_sigaction.sa_sigaction = _cache_access;
	  if ( sigaction( SIGSEGV, &ocxl_sigaction, NULL ) == -1 ) {
	    perror( "sigaction" );
	  }
	  ocxl_cache_access_installed = 1;
	}
	return 0;

 connect_fail:
	errno = ENODEV;
	return -1;
}

ocxl_err _alloc_afu( ocxl_afu_h *afu_out ) 
{
	struct ocxl_afu *afu;

	debug_msg( "_alloc_afu" );
	afu = (struct ocxl_afu *)calloc(1, sizeof(struct ocxl_afu));
	if (afu == NULL) {
         	error_msg( "Could not alloc memory for afu structure" );
		return OCXL_NO_MEM;
	}

	*afu_out = (ocxl_afu_h)afu;

	return OCXL_OK;
}

ocxl_err _find_afu_nth( int fd, const char *name, uint8_t card_index, int16_t afu_index, uint8_t *bus, uint8_t *dev, uint8_t *fcn, uint8_t *afuid )
{
	uint8_t *buffer;
	int size;
	int offset;

	// Send OCSE query

	// size is message type (1), name length (1), name (name_length), card_index (1), afu_index_valid (1), afu_index (1)
	size = 1 + 1 + strlen( name ) + 1 + 1 + 1;
	buffer = (uint8_t *) malloc(size);
	
	offset = 0;
	buffer[offset] = OCSE_FIND_NTH;
	offset = offset + 1;

	buffer[offset] = strlen( name );
	offset = offset + 1;

	memcpy( &buffer[offset], name, strlen(name) ); // don't copy the '\0'
	offset = offset + strlen(name);
	
	buffer[offset] = card_index;
	offset = offset + 1;

	if (afu_index < 0 ) {
	  buffer[offset] = 0;  // afu index is not valid
	} else {
	  buffer[offset] = 1;  // afu index is not valid
	}
	offset = offset + 1;

	buffer[offset] = afu_index;
	offset = offset + 1;

	if (put_bytes_silent( fd, size, buffer ) != size) {
		free(buffer);
		close_socket(&fd);
		return OCXL_NO_DEV;
	}
	
	buffer[0] = 0; 
	
	if (get_bytes_silent( fd, 1, buffer, -1, 0) < 0) {
		warn_msg("ocxl_afu_open:Socket failed");
		close_socket(&fd);
		return OCXL_NO_DEV;
	}

	if ( buffer[0] == (uint8_t)OCSE_FAILED ) {
		warn_msg("ocxl_afu_open_by_id:Socket failed FIND by name");
		close_socket(&fd);
		return OCXL_NO_DEV;
	}
	if (buffer[0] != (uint8_t) OCSE_FIND_ACK) {
		warn_msg("ocxl_afu_open_by_id:OCSE bad acknowledge");
		close_socket(&fd);
		return OCXL_NO_DEV;
	}

	// read out bus, device, function, and afuid 
	if (get_bytes_silent( fd, 4, buffer, -1, 0) < 0) {
		warn_msg("ocxl_afu_open:Socket failed FIND by name and id");
		close_socket(&fd);
		return OCXL_NO_DEV;
	}

	*bus = buffer[0];
	*dev = buffer[1];
	*fcn = buffer[2];
	*afuid = buffer[3];

	free( buffer );
	return OCXL_OK;
}

ocxl_err _find_afu( int fd, const char *name, uint8_t *bus, uint8_t *dev, uint8_t *fcn, uint8_t *afuid )
{
	uint8_t *buffer;
	int size;

	// Send OCSE query
	size = 1 + 1 + strlen( name );
	buffer = (uint8_t *) malloc(size);
	buffer[0] = OCSE_FIND;
	buffer[1] = strlen( name );
	memcpy( &buffer[2], name, strlen(name) ); // don't copy the '\0'
	if (put_bytes_silent( fd, size, buffer ) != size) {
		free(buffer);
		close_socket(&fd);
		return OCXL_NO_DEV;
	}
	
	buffer[0] = 0; 
	
	if (get_bytes_silent( fd, 1, buffer, -1, 0) < 0) {
		warn_msg("ocxl_afu_open:Socket failed");
		close_socket(&fd);
		return OCXL_NO_DEV;
	}

	if ( buffer[0] == (uint8_t)OCSE_FAILED ) {
		warn_msg("ocxl_afu_open:Socket failed FIND by name");
		close_socket(&fd);
		return OCXL_NO_DEV;
	}
	if (buffer[0] != (uint8_t) OCSE_FIND_ACK) {
		warn_msg("ocxl_afu_open_dev:OCSE bad acknowledge");
		close_socket(&fd);
		return OCXL_NO_DEV;
	}

	// read out bus, device, function, and afuid 
	if (get_bytes_silent( fd, 4, buffer, -1, 0) < 0) {
		warn_msg("ocxl_afu_open:Socket failed FIND by name");
		close_socket(&fd);
		return OCXL_NO_DEV;
	}

	*bus = buffer[0];
	*dev = buffer[1];
	*fcn = buffer[2];
	*afuid = buffer[3];

	free( buffer );
	return OCXL_OK;
}

ocxl_err _query_afu( struct ocxl_afu *afu_h, int fd, uint8_t bus, uint8_t dev, uint8_t fcn, uint8_t afuid )
{
	uint8_t *buffer;
	int size;

	debug_msg( "_query_afu" );
	if ( pipe( afu_h->pipe ) < 0 )
		return OCXL_NO_DEV;

	pthread_mutex_init( &(afu_h->event_lock), NULL);

	afu_h->fd = fd;
	afu_h->bus = bus;
	afu_h->dev = dev;
	afu_h->fcn = fcn;
	afu_h->ocxl_id.afu_index = afuid;

	// Send OCSE query
	size = 1 + ( 4 * sizeof( uint8_t ) );
	buffer = (uint8_t *) malloc(size);
	buffer[0] = OCSE_QUERY;
	buffer[1] = bus;
	buffer[2] = dev;
	buffer[3] = fcn;
	buffer[4] = afuid;
	if (put_bytes_silent(afu_h->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu_h->fd));
		return OCXL_NO_DEV;
	}
	free(buffer);
	_all_idle( afu_h );

	afu_h->id = calloc(15, sizeof(char));
	sprintf(afu_h->id, "afu%02x.%02x.%02x.%02x", bus, dev, fcn, afuid);

	return OCXL_OK;
}

ocxl_err _open_afu( struct ocxl_afu *afu_h )
{
	uint8_t *buffer;

	debug_msg( "_open_afu" );
	buffer = (uint8_t *) calloc(1, MAX_LINE_CHARS);
	buffer[0] = (uint8_t) OCSE_OPEN;
	buffer[1] = afu_h->bus;
	buffer[2] = afu_h->dev;
	buffer[3] = afu_h->fcn;
	buffer[4] = afu_h->ocxl_id.afu_index;
	if (put_bytes_silent(afu_h->fd, 5, buffer) != 5) {
		warn_msg("open:Failed to write to socket");
		free(buffer);
		goto open_fail;
	}
	free(buffer);

	afu_h->irq = NULL;
	// afu_h->_head = afu_h;
	afu_h->open.state = LIBOCXL_REQ_PENDING;

	// Start thread
	if (pthread_create(&(afu_h->thread), NULL, _psl_loop, afu_h)) {
		perror("pthread_create");
		close_socket(&(afu_h->fd));
		goto open_fail;
	}

	// Wait for open acknowledgement
	while (afu_h->open.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu_h->opened) {
		pthread_join(afu_h->thread, NULL);
		goto open_fail;
	}

	return OCXL_OK;

 open_fail:
	pthread_mutex_destroy(&(afu_h->event_lock));
	free( afu_h );
	return OCXL_INTERNAL_ERROR;
}

void ocxl_enable_messages( uint64_t sources )
{
  // we should think about using this to enable debug messages in at least libocxl code...  maybe even enable debug messages in ocse...
  // for now, just return
  warn_msg( "ocxl_enable_messages is not supported in ocse" );
  return;
}

void ocxl_afu_enable_messages( ocxl_afu_h *afu, uint64_t sources )
{
  // we should think about using this to enable debug messages in at least libocxl code...  maybe even enable debug messages in ocse...
  // for now, just return
  warn_msg( "ocxl_afu_enable_messages is not supported in ocse" );
  return;
}

void ocxl_set_error_message_handler( void (*handler)( ocxl_err error, const char *message ) )
{
  // we should think about using this to redirect message to some other file
  // for now, just return
  warn_msg( "ocxl_set_error_message_handler is not supported in ocse" );
  return;
}

void ocxl_afu_set_error_message_handler( ocxl_afu_h *afu, void (*handler)( ocxl_err error, const char *message ) )
{
  // we should think about using this to redirect message to some other file
  // for now, just return
  warn_msg( "ocxl_afu_set_error_message_handler is not supported in ocse" );
  return;
}

const char *ocxl_err_to_string( ocxl_err err )
{
  // we could probably convert the number to a string based on the ocxl_er type
  // for now, just return
  warn_msg( "ocxl_err_to_string is not supported in ocse" );
  return "";
}

const ocxl_identifier *ocxl_afu_get_identifier( ocxl_afu_h afu )
{
	if (!afu) {
		errno = EINVAL;
		return NULL;
	}

	return &afu->ocxl_id;
}

const char *ocxl_afu_get_device_pathname( ocxl_afu_h afu )
{
	char *pathname = NULL;

	if (!afu) {
		errno = EINVAL;
		return NULL;
	}
	// return /dev/ocxl/<name>.<domain>:<bus>:<device>.<function>.<index>
	// use sprintf and strcpy to build pathname
	sprintf( pathname, "/dev/ocxl/%s.0000:%02x:%02x.%x.%x", 
		 (char *)&(afu->ocxl_id.afu_name[0]),
		 afu->bus, 
		 afu->dev, 
		 afu->fcn, 
		 afu->ocxl_id.afu_index );

	return pathname;
}

const char *ocxl_afu_get_sysfs_pathname( ocxl_afu_h afu )
{
	char *pathname = NULL;

	if (!afu) {
		errno = EINVAL;
		return NULL;
	}
	// return /dev/sysfs/class/ocxl/<name>.<domain>:<bus>:<device>.<function>.<index>
	// use sprintf and strcpy to build pathname
	sprintf( pathname, "/dev/sysfs/class/ocxl/%s.0000:%02x:%02x.%x.%x", 
		 (char *)&(afu->ocxl_id.afu_name[0]),
		 afu->bus, 
		 afu->dev, 
		 afu->fcn, 
		 afu->ocxl_id.afu_index );

	return pathname;
	return NULL;
}

ocxl_err ocxl_afu_open_from_dev( const char *path, ocxl_afu_h *afu )
{
	uint16_t afu_map;
	uint8_t bus, dev, fcn, afuid;
	char *my_afuid;
	char *afu_id;
	char *afu_name;
	char *dev_domain;
	char *dev_bus;
	char *dev_device;
	char *dev_function;
	char *afu_index;
	int rc;
	int fd;

	// is there a way to see if this is already done?

	if ( !path ) return OCXL_NO_DEV;

	// allocate afu structure
	rc = _alloc_afu( afu );
	if (  rc != 0 ) return rc;

	if ( _ocse_connect(&afu_map, &fd) < 0 ) return OCXL_NO_DEV;

	// check the map after we know the bus or maybe just ignore it and let query fail...

	// parse the given pathname and query the "afu" bus, device, function, and index that we've asked for
	// Discover AFU position
	// ocapi - /dev/ocxl/<afu_name>.<domain>:<bus>:<device>.<function>.<afu_index>
	// we initially support only 1 afu per function per bus. bus maps to major
	// e.g. /dev/ocxl/IBM,MEMCPY3.0000:00:00.1.0

	afu_id = strrchr(path, '/');
	afu_id++;
	debug_msg("afu id = %s", afu_id);

	// copy to a non-constant string...
	my_afuid = malloc( strlen( afu_id ) + 1 );
	strcpy( my_afuid, afu_id );

	// see populate_metadata in the real libocxl for a nicer way to do this
	// afu_id is now <afu_name>.<domain>:<bus>:<device>.<function>.<afu_index>
	// we can discard domain
	afu_name = strtok( my_afuid, "." );  // something like "IBM,MEMCPY"
	dev_domain = strtok( NULL, ":" );  // probably "0000"
	dev_bus = strtok( NULL, ":" );     // two chars "bb" (0 to FF) (256 "slots") (from shimhost.dat tlxb)
	dev_device = strtok( NULL, "." );  // two chars "dd" (0) (always 0)
	dev_function = strtok( NULL, "." );// one char  "f"  (0 to 7)  (8 "slots") (from discovery always 1 for now)
	afu_index = strtok( NULL, "." );   // two chars "ii" (0 to 63) (64 "slots") (from discovery always 0 for now)

	debug_msg( "afu name = %s, domain = %s, bus = %s, device = %s, function = %s, afu control index = %s", 
		   afu_name, dev_domain, dev_bus, dev_device, dev_function, afu_index );

	// There are too many potential afus to created an effective map
	// so, afu_map only represents the "bus" values that are available according to ocse
	// AND, we have limited the number of buses to 16.
	// So we do an initial check on bus vs afu_map and let ocse do the other work

	if (dev_bus == NULL) {
		debug_msg("err: dev_bus not set");
		return OCXL_INVALID_ARGS;
	}
	bus = (uint8_t)strtol( dev_bus, NULL, 16 );

	if (dev_device == NULL) {
		debug_msg("err: dev_device not set");
		return OCXL_INVALID_ARGS;
	}
	dev = (uint8_t)strtol( dev_device, NULL, 16 );

	if (dev_function == NULL) {
		debug_msg("err: dev_function not set");
		return OCXL_INVALID_ARGS;
	}
	fcn = (uint8_t)strtol( dev_function, NULL, 16 );

	if (afu_index == NULL) {
		debug_msg("err: afu_index not set");
		return OCXL_INVALID_ARGS;
	}
	afuid = (uint8_t)strtol( afu_index, NULL, 16 );

	// makes sure we test to see that bus, dev, and fcn are within syntactic limits

	strcpy( (char *)&((*afu)->ocxl_id.afu_name[0]), afu_name );

	debug_msg("major number = 0x%01x", bus);

	rc = _query_afu( *afu, fd, bus, dev, fcn, afuid );

	// open the "afu"
	rc = _open_afu( *afu );

	return OCXL_OK;
}

ocxl_err ocxl_afu_open( const char *name, ocxl_afu_h *afu ) {

        uint8_t bus, dev, fcn, afuid;
	int rc;
	uint16_t afu_map;
	int fd;

	// connect
	// is there a way to see if this is already done?

	// allocate afu structure
	rc = _alloc_afu( afu );
	if (  rc != 0 ) return rc;

	if ( _ocse_connect(&afu_map, &fd) < 0 ) return OCXL_NO_DEV;

	// find name - returns bus, device, function, afu_index
	strcpy( (char *)&((*afu)->ocxl_id.afu_name[0]), name );

	// new routine here
	rc = _find_afu( fd, name, &bus, &dev, &fcn, &afuid );
	if (  rc != 0 ) return rc;

	// query
	rc = _query_afu( *afu, fd, bus, dev, fcn, afuid );
	if (  rc != 0 ) return rc;

	// open the "afu"
	rc = _open_afu( *afu );
	if (  rc != 0 ) return rc;

	return OCXL_OK;
}

ocxl_err ocxl_afu_open_specific( const char *name, const char *physical_function, int16_t afu_index, ocxl_afu_h *afu ) {
  // real code builds the device path name and calls ocxl_afu_open_by_dev
  // we can call open_dev because physical function + afu_index contains the information we really use there.
	int rc;
	uint16_t afu_map;
	int fd;

	// _alloc_afu
	rc = _alloc_afu( afu );
	if (  rc != 0 ) return rc;

	// _connect
	if ( _ocse_connect(&afu_map, &fd) < 0 ) return OCXL_NO_DEV;

	// parse physical function into domain, bus, dev, and fcn
        uint16_t domain;
	uint8_t bus, device, function;
        int found = sscanf( physical_function, "%hu:%hhu:%hhu.%hhu", &domain, &bus, &device, &function );
        if (found != 4) {
	  warn_msg( "physical function could not be parsed into domain, bus, device, and function" );
	  return OCXL_NO_DEV;
        }
	
	// _query_afu
	rc = _query_afu( *afu, fd, bus, device, function, afu_index );
	if (  rc != 0 ) return rc;

	// open the "afu"
	rc = _open_afu( *afu );
	if (  rc != 0 ) return rc;

	return OCXL_OK;
}

void _afu_free( ocxl_afu_h afu )
{
	uint8_t buffer;
	int rc;

	if (!afu) {
		warn_msg("_afu_free: No AFU given");
		goto free_done_no_afu;
	}

	if (!afu->opened)
		goto free_done;

	// detach
	buffer = OCSE_DETACH;
	rc = put_bytes_silent(afu->fd, 1, &buffer);
	if (rc == 1) {
	        debug_msg("_afu_free:detach request sent from from host on socket %d", afu->fd);
		while (afu->attached)	/*infinite loop */
			_delay_1ms();
	}
	debug_msg( "_afu_free: closing host side socket %d", afu->fd );
	// free some other stuff in the afu like the irq list
	close_socket(&(afu->fd));
	afu->opened = 0;
	pthread_join(afu->thread, NULL);

 free_done:
	if (afu->id != NULL)
		free( afu->id );
 free_done_no_afu:
	pthread_mutex_destroy( &(afu->event_lock) );
	free( afu );
}

ocxl_err ocxl_afu_close( ocxl_afu_h afu )
{
        struct ocxl_afu *my_afu;
	struct ocxl_irq *irq;
	int i;

	my_afu = (struct ocxl_afu *)afu;

	// if there are any irq's, free them
	irq = my_afu->irq;
	while ( irq != NULL ) {
	  my_afu->irq = irq->_next;
	  free( irq );
	  irq = my_afu->irq;
	}

	// mmio unmap
	for (i=0; i < my_afu->mmio_count; i++ ) {
	  ocxl_mmio_unmap( &(my_afu->mmios[i]) );
	}
	
	// Free eas
	// if any eas are not kill pending, then issue a kill_xlate.
	debug_msg( "ocxl_afu_close: sending xlate_kills");
	_kill_xlate_all( afu ); // this one makes sure a kill_xlate has been sent for every address in the translation cache

	// castout remaining cache lines
	// if any lines are still in the proxy cache, issue a force_evict.
	debug_msg( "ocxl_afu_close: sending force_evicts");
	_force_evict_all( afu ); // this one makes sure a kill_xlate has been sent for every address in the translation cache

	debug_msg("ocxl_afu_close: finally free structures");
	_afu_free( afu );

	return OCXL_OK;
}

ocxl_err ocxl_afu_attach( ocxl_afu_h afu, __attribute__((unused)) uint64_t flags )
{
	if (!afu) {
		errno = EINVAL;
		return OCXL_NO_DEV;
	}
	debug_msg("AFU ATTACH");
	if (!afu->opened) {
		warn_msg("ocxl_afu_attach: Must open AFU first");
		errno = ENODEV;
		return OCXL_NO_DEV;
	}

	if (afu->attached) {
		warn_msg("ocxl_afu_attach: AFU already attached");
		errno = ENODEV;
		return OCXL_NO_DEV;
	}
	// Perform OCSE attach
	// lgt - dont need to send amr - in fact, the parameter is gone now
	// we don't model the change in permissions
	afu->attach.state = LIBOCXL_REQ_REQUEST;
	while (afu->attach.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	afu->attached = 1;

	return OCXL_OK;
}

int ocxl_afu_get_event_fd( ocxl_afu_h afu )
{ 
	if (!afu) {
		warn_msg("ocxl_afu_get_event_fd: No AFU given");
		errno = ENODEV;
		return -1;
	}
	return afu->pipe[0];
}

int ocxl_irq_get_fd( ocxl_afu_h afu, ocxl_irq_h irq )
{ 
  // I don't think this is correct.  I appears that the irq can have it's own path back to the code...  but I'm not
  // sure yet.  We'll just use the afu pipe as the path for now
	if (!afu) {
		warn_msg("ocxl_afu_get_event_fd: No AFU given");
		errno = ENODEV;
		return -1;
	}
	return afu->pipe[0];
}

ocxl_err ocxl_irq_alloc( ocxl_afu_h afu, void *info, ocxl_irq_h *irq_handle )
{
        // create an irq, link it to the afu, and return the address of the irq to the caller
        struct ocxl_irq *new_irq;
        struct ocxl_irq *current_irq;

        if (!afu) {
		warn_msg("ocxl_afu_new_irq: No AFU given");
		errno = ENODEV;
		return OCXL_NO_DEV;
	}

	new_irq = (struct ocxl_irq *)malloc( sizeof(struct ocxl_irq) );

	if (!new_irq) {
	        // allocation failed
		errno = ENOMEM;
		warn_msg("ocxl_afu_new_irq: insufficient memory");
		return OCXL_NO_IRQ;
	}

	new_irq->irq = afu->irq_count; // the index of this new irq is the current counter value
	new_irq->id = (uint64_t)new_irq;  // the id of this new irq is the address of the irq
	new_irq->_next = NULL;
	new_irq->afu = afu;
	*irq_handle = (ocxl_irq_h)new_irq->irq;

	// add new irq to the end of the afu's list of irqs
	if (afu->irq == NULL) {
	  // this is the first new irq
	  afu->irq = new_irq;
	  afu->irq_count++;   
	  return OCXL_OK;
	}

	// scan the list for the last irq
	current_irq = afu->irq;
	while (current_irq->_next != NULL) {
	    current_irq = current_irq->_next;
	}
	// we have the last one now
	current_irq->_next = new_irq;
	afu->irq_count++;

	return OCXL_OK;
}

uint64_t ocxl_irq_get_handle( ocxl_afu_h afu, ocxl_irq_h irq )
{
  // scan the irq list of the afu for an irq with a matching ocxl_irq_h
  // return the id of the irq we found or 0 if none found
        struct ocxl_irq *current_irq;

	current_irq = afu->irq;
	while (current_irq != NULL) {
	  if (current_irq->irq  == irq) {
	    // this is the irq we are looking for
	    // return the id in current_irq
	    return current_irq->id;
	  } else {
	    // follow the linked list
	    current_irq = current_irq->_next;
	  }
	}

	// if we get here, we didn't find irq in the afu!
	warn_msg("ocxl_irq_free: irq not found in afu");
	return 0;
}

uint16_t ocxl_afu_event_check_versioned( ocxl_afu_h afu, int timeout, ocxl_event *events, uint16_t event_count, uint16_t event_api_version )
{
	int i;
 	uint8_t type; 

	// check for null afu
	if (afu == NULL) {
		warn_msg("ocxl_afu_event_check: NULL afu!");
		return OCXL_NO_DEV;
	}

	// we support event_api_version = 0 for now...
	if (event_api_version != 0 ) {
		warn_msg("ocxl_afu_event_check_versioned: event api version must be 0, continuing as if 0 had be sent.");
	}

	// we support event_count = 1 for now...
	if (event_count != 1) {
		warn_msg("ocxl_afu_event_check_versioned: event count must be 1, continuing as if 1 had be sent.");
	}

	// read an event - if not one, just wait here
	//     we ignore timeout for now
	debug_msg("ocxl_read_event: waiting for event");
	pthread_mutex_lock(&(afu->event_lock));
	while (afu->opened && !afu->events[0]) {	/*infinite loop */
		pthread_mutex_unlock(&(afu->event_lock));
		if (_delay_1ms() < 0)
			return -1;
		pthread_mutex_lock(&(afu->event_lock));
	}

	debug_msg("ocxl_read_event: received event");
	// Copy event data, free and move remaining events in queue
	memcpy( events, afu->events[0], sizeof( ocxl_event ) );
	free(afu->events[0]);
	for (i = 1; i < EVENT_QUEUE_MAX; i++)
		afu->events[i - 1] = afu->events[i];
	afu->events[EVENT_QUEUE_MAX - 1] = NULL;
	pthread_mutex_unlock(&(afu->event_lock));
	if (read(afu->pipe[0], &type, 1) > 0)
		return 1;

	return -1;
}

uint16_t ocxl_afu_event_check( ocxl_afu_h afu, int timeout, ocxl_event *events, uint16_t event_count )
{
	uint16_t event_api_version = 0;

	return ocxl_afu_event_check_versioned( afu, timeout, events, event_count, event_api_version );
}

ocxl_err ocxl_afu_get_p9_thread_id(ocxl_afu_h afu, uint16_t *thread_id)
{
  // obtain the current thread id - with pthread_self()
  // app must pass thread id to afu for afu to use in subsequent wake host thread command
  *thread_id = (uint16_t)pthread_self();
  return 0;
}

ocxl_err ocxl_mmio_map_advanced( ocxl_afu_h afu, ocxl_mmio_type type, size_t size, int prot, uint64_t flags, off_t offset, ocxl_mmio_h *region )
{
        ocxl_err err = OCXL_INVALID_ARGS;

	debug_msg( "MMIO (and lpc memory) MAP" );
	if (afu == NULL) {
		warn_msg("ocxl_mmio_map_advanced: NULL afu!");
		err = OCXL_NO_CONTEXT;
		goto map_fail;
	}

	if (!afu->opened) {
		warn_msg("ocxl_mmio_map_advanced: Must open afu first!");
		err = OCXL_NO_CONTEXT;
		goto map_fail;
	}

	// it turns out it is not necessary for the afu to be attached prior to mapping the mmio regions
	//if (!afu->attached) {
	//	warn_msg("ocxl_mmio_map_advanced: Must attach afu first!");
	//	err = OCXL_NO_CONTEXT;
	//	goto map_fail;
	//}

	if (afu->mmio_count == afu->mmio_max) {
		warn_msg("ocxl_mmio_map_advanced: insufficient memory to map the new mmio area!");
		err = OCXL_NO_MEM;
		goto map_fail;
	}

	if ( size == 0 ) {
	  switch (type) {
	  case OCXL_GLOBAL_MMIO:
	    size = afu->global_mmio.length;
	    break;
	  case OCXL_PER_PASID_MMIO:
	    size = afu->per_pasid_mmio.length;
	    break;
	  case OCXL_LPC_SYSTEM_MEM:
	    // if mem_size == 0, there is no mem
	    // otherwise size is 2**mem_size
	    if ( afu->mem_size == 0 ) {
	      warn_msg("ocxl_mmio_map_advanced: no lpc system memory available!");
	      err = OCXL_NO_MEM;
	      goto map_fail;
	    }
	    size = (size_t)0x1 << (afu->mem_size - 1);
	    break;
	  case OCXL_LPC_SPECIAL_PURPOSE_MEM:
	    // Send LPC SPECIAL PURPOSE MEMORY map to OCSE
	    // check template major/minor for legality of this
	    // afu->mmio.type = OCSE_LPC_SPECIAL_PURPOSE_MAP;
	    warn_msg("ocxl_mmio_map_advanced: lpc special purpose memory map not yet supported!");
	    goto map_fail;
	  default:
	    err = OCXL_INVALID_ARGS;
	    goto map_fail;
	    break;
	  }
	}

	switch (type) {
	case OCXL_GLOBAL_MMIO:
	  if ( size + offset > afu->global_mmio.length ) {
	    warn_msg("ocxl_mmio_map_advanced: insufficient global mmio memory available!");
	    err = OCXL_NO_MEM;
	    goto map_fail;
	  }
	  afu->mmio.type = OCSE_GLOBAL_MMIO_MAP;
	  break;
	case OCXL_PER_PASID_MMIO:
	  if ( size + offset > afu->per_pasid_mmio.length ) {
	    warn_msg("ocxl_mmio_map_advanced: insufficient per pasid mmio memory available!");
	    err = OCXL_NO_MEM;
	    goto map_fail;
	  }
	  afu->mmio.type = OCSE_MMIO_MAP;
	  break;
	case OCXL_LPC_SYSTEM_MEM:
	  if ( ( size + offset ) > ( (uint64_t)0x1 << (afu->mem_size - 1) ) ) {
	    warn_msg("ocxl_mmio_map_advanced: insufficient lpc system memory available!");
	    err = OCXL_NO_MEM;
	    goto map_fail;
	  }
	  afu->mmio.type = OCSE_LPC_SYSTEM_MAP;
	  break;
	case OCXL_LPC_SPECIAL_PURPOSE_MEM:
	default:
	  err = OCXL_INVALID_ARGS;
	  goto map_fail;
	  break;
	}

	afu->mmio.state = LIBOCXL_REQ_REQUEST;

	// wait for _psl_loop to see and process mmio libocxl_req_request and set to libocxl_req_idle
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	switch (type) {
	case OCXL_GLOBAL_MMIO:
	  afu->global_mapped = 1;
	  break;
	case OCXL_PER_PASID_MMIO:
	  afu->mapped = 1;
	  break;
	case OCXL_LPC_SYSTEM_MEM:
	  afu->lpc_mapped = 1;
	  break;
	case OCXL_LPC_SPECIAL_PURPOSE_MEM:
	  afu->lpc_special_mapped = 1;
	  break;
	default:
	  err = OCXL_INVALID_ARGS;
	  goto map_fail;
	  break;
	}

	
	*region = (ocxl_mmio_h)&(afu->mmios[afu->mmio_count]);
	afu->mmio_count++;
	  
	return OCXL_OK;

 map_fail:
	return err;
}

ocxl_err ocxl_mmio_map( ocxl_afu_h afu, ocxl_mmio_type type, ocxl_mmio_h *region )
{
	return ocxl_mmio_map_advanced( afu, type, 0, PROT_READ | PROT_WRITE, 0, 0, region );
}

ocxl_err ocxl_mmio_get_info( ocxl_mmio_h region, void **address, size_t *size )
{
  // malloc the mmio area (but it is not to be used by the application software directly
  // return the size of the area and the virtual address (EA) of the area
  // the application is permitted to send the EA, or a derivative of it, to the accelerator
  // the accelerator may access "LPC memory" via that EA.
  // Can we do this for the global and per pasid mmio regions?  We don't have to, 
  // but it would be a consistant approach.  The question may be the shear size
  // of the various memory areas.
  // if the accelerator is going to use a direct access to accelerator memory, the use
  // this routine is not required.  the helper function (ocxl_mmio_* and ocxl_lpc_*)
  // handle the memory via the connection to the afu handle
  region->ocxl_ea = malloc( region->length );
  if (region->ocxl_ea == NULL) {
    // unsuccessful malloc
    warn_msg( "ocxl_mmio_get_info: unable to malloc requested size 0x%016llx", (uint64_t)region->length );
    return OCXL_NO_MEM;
  }

  *address = region->ocxl_ea;
  *size = region->length;
  return OCXL_OK;
}

ocxl_err ocxl_mmio_unmap( ocxl_mmio_h region )
{
// since we've created a static array for the areas, this is tricky...
  if ( region->ocxl_ea != NULL ) {
    free( region->ocxl_ea );
  }

  switch ( region->type ) {
  case OCXL_GLOBAL_MMIO:
    region->afu->global_mapped = 0;
    break;
  case OCXL_PER_PASID_MMIO:
    region->afu->mapped = 0;
    break;
  case OCXL_LPC_SYSTEM_MEM:
    region->afu->lpc_mapped = 0;
    break;
  default:
    break;
  }

  // but what about mmio_count?
  
  return OCXL_OK;
}

ocxl_err ocxl_mmio_write64( ocxl_mmio_h mmio, off_t offset, ocxl_endian endian, uint64_t value )
{
	ocxl_err err;

	//debug_msg("ocxl_mmio_write64: entered");

	if (mmio->afu == NULL) {
	  err = OCXL_NO_MEM;
	  goto write64_fail;
	}
	//debug_msg("ocxl_mmio_write64: mmio->afu ok");

	if (mmio->type == OCXL_GLOBAL_MMIO) {
	  if (!mmio->afu->global_mapped) {
	    err = OCXL_NO_MEM;
	    goto write64_fail;
	  }
	} else {
	  if (!mmio->afu->mapped) {
	    err = OCXL_NO_MEM;
	    goto write64_fail;
	  }
	}
	//debug_msg("ocxl_mmio_write64: mmio->afu->*mapped ok");

	if ( offset & 0x7 ) {
		warn_msg("ocxl_mmio_write64: offset not properly aligned!");
		errno = EINVAL;
		err = OCXL_OUT_OF_BOUNDS;
		goto write64_fail;
	}

	debug_msg("ocxl_mmio_write64: passed parameter checks");

	/* if ( offset >= my_afu->mmio_length ) { */
	/* 	warn_msg("ocxl_mmio_write64: offset out of bounds!"); */
	/* 	errno = EINVAL; */
	/* 	return OCXL_OUT_OF_BOUNDS; */
	/* } */

	// Send MMIO map to OCSE
	if (mmio->type == OCXL_GLOBAL_MMIO) {
	  mmio->afu->mmio.type = OCSE_GLOBAL_MMIO_WRITE64;
	} else {
	  mmio->afu->mmio.type = OCSE_MMIO_WRITE64;
	}
	mmio->afu->mmio.addr = (uint32_t) offset;
	// should I use endian here???  maybe
	mmio->afu->mmio.data = value;
	mmio->afu->mmio.state = LIBOCXL_REQ_REQUEST;

	debug_msg("ocxl_mmio_write64: waiting for idle");

	while (mmio->afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	debug_msg("ocxl_mmio_write64: mmio acked");

	if (!mmio->afu->opened) {
	  err = OCXL_NO_DEV;
	  goto write64_fail;
	}

	//debug_msg("ocxl_mmio_write64: leaving normally");
	return OCXL_OK;

 write64_fail:
	//debug_msg("ocxl_mmio_write64: leaving abnormally");
	return err;
}

ocxl_err ocxl_mmio_read64( ocxl_mmio_h mmio, off_t offset, ocxl_endian endian, uint64_t *out )
{
	ocxl_err err;

	if (mmio->afu == NULL) {
	  err = OCXL_NO_MEM;
	  goto read64_fail;
	}

	if (mmio->type == OCXL_GLOBAL_MMIO) {
	  if (!mmio->afu->global_mapped) {
	    err = OCXL_NO_MEM;
	    goto read64_fail;
	  }
	} else {
	  if (!mmio->afu->mapped) {
	    err = OCXL_NO_MEM;
	    goto read64_fail;
	  }
	}


	if ( offset & 0x7 ) {
		warn_msg("ocxl_mmio_read64: offset not properly aligned!");
		errno = EINVAL;
		err = OCXL_OUT_OF_BOUNDS;
		goto read64_fail;
	}

	/* if ( offset >= my_afu->mmio_length ) { */
	/* 	warn_msg("ocxl_mmio_read64: offset out of bounds!"); */
	/* 	errno = EINVAL; */
	/* 	return OCXL_OUT_OF_BOUNDS; */
	/* } */

	// Send MMIO map to OCSE
	if (mmio->type == OCXL_GLOBAL_MMIO) {
	  mmio->afu->mmio.type = OCSE_GLOBAL_MMIO_READ64;
	} else {
	  mmio->afu->mmio.type = OCSE_MMIO_READ64;
	}
	mmio->afu->mmio.addr = (uint32_t) offset;
	mmio->afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (mmio->afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	// should use endian here...  maybe
	*out = mmio->afu->mmio.data;

	if (!mmio->afu->opened) {
	  err = OCXL_NO_DEV;
	  goto read64_fail;
	}


	return OCXL_OK;

 read64_fail:
	return err;
}

ocxl_err ocxl_mmio_write32( ocxl_mmio_h mmio, off_t offset, ocxl_endian endian, uint32_t value )
{
	ocxl_err err;

	if (mmio->afu == NULL) {
	  err = OCXL_NO_MEM;
	  goto write32_fail;
	}

	if (mmio->type == OCXL_GLOBAL_MMIO) {
	  if (!mmio->afu->global_mapped) {
	    err = OCXL_NO_MEM;
	    goto write32_fail;
	  }
	} else {
	  if (!mmio->afu->mapped) {
	    err = OCXL_NO_MEM;
	    goto write32_fail;
	  }
	}

	if (offset & 0x3) {
		warn_msg("ocxl_mmio_write32: offset not properly aligned!");
		errno = EINVAL;
		err = OCXL_OUT_OF_BOUNDS;
		goto write32_fail;
	}
	/* if ( offset >= my_afu->mmio_length ) { */
	/* 	warn_msg("ocxl_mmio_write32: offset out of bounds!"); */
	/* 	errno = EINVAL; */
	/* 	return OCXL_OUT_OF_BOUNDS; */
	/* } */

	// Send MMIO map to OCSE
	if (mmio->type == OCXL_GLOBAL_MMIO) {
	  mmio->afu->mmio.type = OCSE_GLOBAL_MMIO_WRITE32;
	} else {
	  mmio->afu->mmio.type = OCSE_MMIO_WRITE32;
	}
	mmio->afu->mmio.addr = (uint32_t) offset;
	mmio->afu->mmio.data = (uint64_t) value;
	mmio->afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (mmio->afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!mmio->afu->opened){
	  err = OCXL_NO_DEV;
	  goto write32_fail;
	}

	return OCXL_OK;

 write32_fail:
	return err;
}

ocxl_err ocxl_mmio_read32( ocxl_mmio_h mmio, off_t offset, ocxl_endian endian, uint32_t *out )
{
	ocxl_err err;

	if (mmio->afu == NULL) {
	  err = OCXL_NO_MEM;
	  goto read32_fail;
	}

	if (mmio->type == OCXL_GLOBAL_MMIO) {
	  if (!mmio->afu->global_mapped) {
	    err = OCXL_NO_MEM;
	    goto read32_fail;
	  }
	} else {
	  if (!mmio->afu->mapped) {
	    err = OCXL_NO_MEM;
	    goto read32_fail;
	  }
	}

	if (offset & 0x3) {
		warn_msg("ocxl_mmio_read32: offset not properly aligned!");
		errno = EINVAL;
		err = OCXL_OUT_OF_BOUNDS;
		goto read32_fail;
	}

	/* if ( offset >= my_afu->mmio_length ) { */
	/* 	warn_msg("ocxl_mmio_read32: offset out of bounds!"); */
	/* 	errno = EINVAL; */
	/* 	return OCXL_OUT_OF_BOUNDS; */
	/* } */

	// Send MMIO map to OCSE
	if (mmio->type == OCXL_GLOBAL_MMIO) {
	  mmio->afu->mmio.type = OCSE_GLOBAL_MMIO_READ32;
	} else {
	  mmio->afu->mmio.type = OCSE_MMIO_READ32;
	}
	mmio->afu->mmio.addr = (uint32_t) offset;
	mmio->afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (mmio->afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	*out = (uint32_t) mmio->afu->mmio.data;

	if (!mmio->afu->opened) {
	  err = OCXL_NO_DEV;
	  goto read32_fail;
	}

	return OCXL_OK;

 read32_fail:
	errno = ENODEV;
	return err;
}

ocxl_err ocxl_global_mmio_write64( ocxl_afu_h afu, uint64_t offset, uint64_t val)
{
	if ((afu == NULL) || !afu->global_mapped)
		goto write64_fail;

	if (offset & 0x7) {
		warn_msg("ocxl_global_mmio_write64: offset not properly aligned!");
		errno = EINVAL;
		return OCXL_OUT_OF_BOUNDS;
	}

	/* if ( offset >= my_afu->mmio_offset ) { */
	/* 	warn_msg("ocxl_global_mmio_write64: offset out of bounds!"); */
	/* 	errno = EINVAL; */
	/* 	return OCXL_OUT_OF_BOUNDS; */
	/* } */

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_GLOBAL_MMIO_WRITE64;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.data = val;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
		goto write64_fail;

	return OCXL_OK;

 write64_fail:
	errno = ENODEV;
	return OCXL_NO_DEV;
}

ocxl_err ocxl_global_mmio_read64( ocxl_afu_h afu, uint64_t offset, uint64_t *out)
{
	if ((afu == NULL) || !afu->global_mapped)
		goto read64_fail;

	if (offset & 0x7) {
		warn_msg("ocxl_global_mmio_read64: offset not properly aligned!");
		errno = EINVAL;
		return OCXL_OUT_OF_BOUNDS;
	}

	/* if ( offset >= my_afu->mmio_offset ) { */
	/* 	warn_msg("ocxl_global_mmio_read64: offset out of bounds!"); */
	/* 	errno = EINVAL; */
	/* 	return OCXL_OUT_OF_BOUNDS; */
	/* } */

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_GLOBAL_MMIO_READ64;
	afu->mmio.addr = (uint32_t)offset;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	*out = afu->mmio.data;

	if (!afu->opened)
		goto read64_fail;

	return OCXL_OK;

 read64_fail:
	errno = ENODEV;
	return OCXL_NO_DEV;
}

ocxl_err ocxl_global_mmio_write32( ocxl_afu_h afu, uint64_t offset, uint32_t val)
{
	if ((afu == NULL) || !afu->global_mapped)
		goto write32_fail;

	if (offset & 0x3) {
		warn_msg("ocxl_global_mmio_write32: offset not properly aligned!");
		errno = EINVAL;
		return OCXL_OUT_OF_BOUNDS;
	}

	/* if ( offset >= my_afu->mmio_offset ) { */
	/* 	warn_msg("ocxl_global_mmio_write32: offset out of bounds!"); */
	/* 	errno = EINVAL; */
	/* 	return OCXL_OUT_OF_BOUNDS; */
	/* } */

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_GLOBAL_MMIO_WRITE32;
	afu->mmio.addr = (uint32_t)offset;
	afu->mmio.data = (uint64_t)val;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
		goto write32_fail;

	return OCXL_OK;

 write32_fail:
	errno = ENODEV;
	return OCXL_NO_DEV;
}

ocxl_err ocxl_global_mmio_read32( ocxl_afu_h afu, uint64_t offset, uint32_t *out)
{
	if ((afu == NULL) || !afu->global_mapped)
		goto read32_fail;

	if (offset & 0x3) {
		warn_msg("ocxl_global_mmio_read32: invalid offset alignment");
		errno = EINVAL;
		return OCXL_OUT_OF_BOUNDS;
	}
	
	/* if (offset >= my_afu->mmio_offset) { */
	/* 	warn_msg("ocxl_global_mmio_read32: offset out of bounds"); */
	/* 	errno = EINVAL; */
	/* 	return OCXL_OUT_OF_BOUNDS; */
	/* } */

	// Send MMIO map to OCSE
	afu->mmio.type = OCSE_GLOBAL_MMIO_READ32;
	afu->mmio.addr = (uint32_t)offset;
	afu->mmio.state = LIBOCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBOCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	*out = (uint32_t) afu->mmio.data;

	if (!afu->opened)
		goto read32_fail;

	return OCXL_OK;

 read32_fail:
	errno = ENODEV;
	return OCXL_NO_DEV;
}

size_t ocxl_afu_get_mmio_size( ocxl_afu_h afu )
{
	if (afu == NULL)
                   return OCXL_NO_DEV;

        // this is the mmio stride for this afu
        return afu->per_pasid_mmio.length;
}

size_t ocxl_afu_get_global_mmio_size( ocxl_afu_h afu )
{
	if (afu == NULL)
                   return OCXL_NO_DEV;

        // this is the per pasid mmio offset for this afu
	// there might be a more accurate method - look for it
        return afu->global_mmio.length;

}

void  ocxl_afu_get_version( ocxl_afu_h afu, uint8_t *major, uint8_t *minor )
{
	// if (my_afu == NULL)
        //           return OCXL_NO_DEV;

        // these are from the afu descriptor that we retrieved when we opened the afu
	*major = afu->afu_version_major;
	*minor = afu->afu_version_minor;

        return;

}

uint32_t  ocxl_afu_get_pasid( ocxl_afu_h afu )
{
	// if (my_afu == NULL)
        //           return OCXL_NO_DEV;

        // we use the term context as the equivalent for the pasid
        return afu->context;

}

ocxl_err ocxl_afu_set_ppc64_amr( ocxl_afu_h afu, uint64_t amr)
{
	afu->ppc64_amr = amr;

	return OCXL_OK;
}

// ocxl_wait should behave very much like read_event
// however, I don't think we can use the event structure as is
// maybe create another event struct so that interrupt events and 
// wake host thread events cannot collide or stall each other.
// only one waitasec at a time in a context/afu pair
int ocxl_wait()
{
  // multi thread safe?
  // obtain the current thread id
  // put it in the wait event
  // a wake host thread command from the afu must supply a matching thread id for this to wake to clear
  // we'll need to add a way to have multiple active wait events for a given application
  // and remove it when the wake occurs

        ocxl_wait_event *this_wait_event;

        this_wait_event = _alloc_wait_event( (uint16_t)pthread_self() );
	
	info_msg( "ocxl_wait: waiting for wake host thread @ 0x%016llx -> 0x%04x", 
		   (uint64_t)this_wait_event, 
		   this_wait_event->tid );
	
	// enable this wake event
	this_wait_event->enabled = 1;
	
	// Function will block until wake host thread occurs and matches thread id
	// pthread_mutex_lock( &(this_wait_event->wait_lock) );
	while ( this_wait_event->received == 0 ) {	/*infinite loop */
	        // pthread_mutex_unlock( &(this_wait_event->wait_lock) );
	        // debug_msg( "ocxl_wait: stil waiting for wake host thread @ 0x%016llx -> 0x%04x", 
		//	   (uint64_t)this_wait_event, 
		//	   this_wait_event->tid );
		if (_delay_1ms() < 0)
			return -1;
		// pthread_mutex_lock(&(this_wait_event->wait_lock));
	}

	// free wait event - remove it from wait event list
	this_wait_event->enabled = 0;
	this_wait_event->received = 0;
	// pthread_mutex_unlock( &(this_wait_event->wait_lock) );

	_free_wait_event( this_wait_event );

	return OCXL_OK;
}
