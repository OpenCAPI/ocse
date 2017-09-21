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

#ifndef _LIBOCXL_H
#define _LIBOCXL_H

//#include <linux/types.h>
#include <misc/ocxl.h>
#include <stdbool.h>
#include <stddef.h>  // for size_t
#include <stdint.h>
#include <stdio.h>  // for off_t

#ifdef __cplusplus
extern "C" {
#endif

#define OCXL_KERNEL_API_VERSION 1

#define OCXL_SYSFS_CLASS "/sys/class/ocxl"
#define OCXL_DEV_DIR "/dev/ocxl"

  typedef enum {
    OCXL_MMIO_BIG_ENDIAN = 0x0,
    OCXL_MMIO_LITTLE_ENDIAN = 0x1, 
    OCXL_MMIO_HOST_ENDIAN = 0x2
  } ocxl_endian;

#define OCXL_MMIO_ENDIAN_MASK 0x3
#define OCXL_MMIO_FLAGS 0x3

#define AFU_NAME_MAX 24
  typedef struct ocxl_identifier {
    uint8_t afu_index;
    const char afu_name[AFU_NAME_MAX + 1];
  } ocxl_identifier;

/*
 * Opaque types
 */
// deprecate struct ocxl_adapter_h;
// deprecate struct ocxl_ioctl_start_work;
  typedef void *ocxl_afu_h;
#define OCXL_INVALID_AFU NULL

  typedef uint16_t ocxl_irq_h; 
#define OCXL_INVALID_IRQ UINT16_MAX;

  /*
   * various return codes from ocxl functions
   */
  typedef enum {
    OCXL_OK = 0,
    OCXL_NO_MEM = -1,
    OCXL_NO_DEV = -2,
    OCXL_NO_CONTEXT = -3,
    OCXL_NO_IRQ = -4,
    OCXL_INTERNAL_ERROR = -5,
    OCXL_ALREADY_DONE = -6,
    OCXL_OUT_OF_BOUNDS = -7,
  } ocxl_err;

  /*
   * ocxl event types
   */
  typedef enum {
    OCXL_EVENT_IRQ = 0,
    OCXL_EVENT_TRANSLATION_FAULT = 1,
  } ocxl_event_type;

  /*
   * the data for a triggered irq event
   */
  typedef struct {
    uint16_t irq;
    uint64_t id;
    void *info;
    uint64_t count;
  } ocxl_event_irq;

  /*
   * the data for a triggered translation fault event
   */
  typedef struct {
    void *addr;
    //#ifdef __ARCH_PPC64
    uint64_t dsisr;
    //#endif
  } ocxl_event_translation_fault;

  /*
   * an ocxl event
   * 
   * may be an afu interrupt or a translation fault
   */
  typedef struct ocxl_event {
    ocxl_event_type type;
    union {
      ocxl_event_irq irq;
      ocxl_event_translation_fault translation_fault;
      uint64_t padding[16];
    };
  } ocxl_event;

  /* 
   *setup routines 
   */
  void ocxl_want_verbose_errors( int verbose );
  void ocxl_set_errmsg_filehandle( FILE *handle );

  /* 
   * afu get functions - get some info from afu 
   */
  // return the identifier structure for the afu - name and index
  const ocxl_identifier *ocxl_afu_get_identifier( ocxl_afu_h afu );
  // return the canonical device pathname of the afu
  const char *ocxl_afu_get_device_path( ocxl_afu_h afu );
  // return the canonical sysfs pathname of the afu
  const char *ocxl_afu_get_sysfs_path( ocxl_afu_h afu );
  /*
   * Returns the file descriptor for the open AFU to use with event loops.
   * Returns -1 if the AFU is not open.
   */
  int ocxl_afu_get_fd( ocxl_afu_h afu );
  // return the size of the global mmio space for this afu
  size_t ocxl_afu_get_global_mmio_size( ocxl_afu_h afu );
  // return the size of the per process mmio space for this afu
  size_t ocxl_afu_get_mmio_size( ocxl_afu_h afu );
  // return the "major" and "minor" version numbers of the given afu
  ocxl_err ocxl_afu_get_version( ocxl_afu_h afu, uint8_t *major, uint8_t *minor );

  /* 
   * afu operations - like open, attach and free 
   */
  ocxl_err ocxl_afu_open_specific( const char *name, const char *physical_function, int16_t afu_index, ocxl_afu_h *afu ); // new
  ocxl_err ocxl_afu_open_by_id( const char *name, uint8_t card_index, int16_t afu_index, ocxl_afu_h *afu ); // new
  // open an afu by passing in the device path name
  ocxl_err ocxl_afu_open_from_dev( char *path, ocxl_afu_h *afu );
  // close an afu but keep the structures and info that we obtained during the open
  ocxl_err ocxl_afu_close( ocxl_afu_h afu );
  // close an afu and free the structures and info that we obtained during the open
  // void ocxl_afu_free( ocxl_afu_h afu ); // depricate
  // open an afu by passing in the simple afu_name
  ocxl_err ocxl_afu_open( const char *name, ocxl_afu_h *afu );  // modified
  // attach this process to the afu we have opened - permits the afu to utilze the virtual address space of this process
  ocxl_err ocxl_afu_attach( ocxl_afu_h afu );

  /* 
   * high level wrappers 
   * platform specific: PPC64
   * if we want to model this in ocse, perhaps we should expose it all the time rather than hide it behind __ARCH_PPC64
   */
#ifdef __ARCH_PPC64
  ocxl_err ocxl_afu_use( ocxl_afu_h afu, uint64_t amr, ocxl_endian global_endianess, enum ocxl_endian per_pasid_endianess );
  ocxl_err ocxl_afu_use_from_dev( const char *path, ocxl_afu_h *afu, uint64_t amr, enum ocxl_endian global_endianess, enum ocxl_endian per_pasid_endianess );
  ocxl_err ocxl_afu_use_by_name( const char *name, ocxl_afu_h *afu, uint64_t amr, enum ocxl_endian global_endianess, enum ocxl_endian per_pasid_endianess );
#endif

  /* 
   * afu irq functions 
   */
  // returns an interrupt handle describing the a new interrupt of the given afu
  ocxl_err ocxl_afu_irq_alloc( ocxl_afu_h afu, void *info, ocxl_irq_h *irq_handle );
  // free the data structures of an afu interrupt
  // ocxl_err ocxl_afu_irq_free( ocxl_afu_h afu, ocxl_irq_h *irq_handle );
  uint64_t ocxl_afu_irq_get_id( ocxl_afu_h afu, ocxl_irq_h irq );
  // check/read an event
  uint16_t ocxl_afu_event_check( ocxl_afu_h afu, struct timeval *timeout, ocxl_event *events, uint16_t event_count );

  /*
   * platform specific: PPC64
   * if we want to model this in ocse, perhaps we should expose it all the time rather than hide it behind __ARCH_PPC64
   */
#ifdef __ARCH_PPC64
  ocxl_err ocxl_afu_set_ppc_amr( ocxl_afu_h afu, uint64_t amr );
#endif

  /* 
   * afu mmio functions 
   */
  /*
   * The below assessors will byte swap based on what is passed to map.  Also a
   * full memory barrier 'sync' will proceed a write and follow a read.  More
   * relaxed assessors can be created using a pointer derived from ocxl_mmio_ptr().
   */
  ocxl_err ocxl_global_mmio_map( ocxl_afu_h afu, ocxl_endian endian );
  ocxl_err ocxl_mmio_map( ocxl_afu_h afu, ocxl_endian endian );

  /*
   * AFU global MMIO functions
   *
   * The below assessors will access the global area assoicated with the 
   * PASID that has been connected to the context of the afu.  One may call 
   * ocxl_get_global_mmio_size to obtain information on the upper bound of this
   * area.
   */
  ocxl_err ocxl_global_mmio_read32( ocxl_afu_h afu, size_t offset, uint32_t *out );
  ocxl_err ocxl_global_mmio_read64( ocxl_afu_h afu, size_t offset, uint64_t *out );
  ocxl_err ocxl_global_mmio_write32( ocxl_afu_h afu, size_t offset, uint32_t val );
  ocxl_err ocxl_global_mmio_write64( ocxl_afu_h afu, size_t offset, uint64_t val );
  /*
   * AFU per process MMIO functions
   *
   * The below assessors will access the per process area assoicated with the 
   * PASID that has been connected to the context of the afu.
   */
  ocxl_err ocxl_mmio_read32( ocxl_afu_h afu, size_t offset, uint32_t *out );
  ocxl_err ocxl_mmio_read64( ocxl_afu_h afu, size_t offset, uint64_t *out );
  ocxl_err ocxl_mmio_write32( ocxl_afu_h afu, size_t offset, uint32_t val );
  ocxl_err ocxl_mmio_write64( ocxl_afu_h afu, size_t offset, uint64_t val );
  
  ocxl_err ocxl_global_mmio_unmap( ocxl_afu_h afu );
  ocxl_err ocxl_mmio_unmap( ocxl_afu_h afu );



/*
 * "wait a sec"
 */
// a routine that models the behavior of the Power ISA wait instruction
// the routine will block until someone issues a "wake_host_thead" or asb_notify
ocxl_err ocxl_sleep( ocxl_afu_h afu );

// the followin notion can be found in libocxl_lpc.  they are not part of the normal reference user api
// think about an lpc or "host agent memory" set of helper functions
// maybe a map function
// read function
// write function
// and an unmap

#ifdef __cplusplus
}
#endif

#endif
