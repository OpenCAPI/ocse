# ocse4_4

OpenCAPI Simulation Engine 4.0

--- ATTENTION ATTENTION ATTENTION ---
This branch is for the development of OpenCAPI 4.0 features:
cache support

Copyright 2015,2020 International Business Machines

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This is a simulation environment that allows a programmer to use the opencapi reference user api (libocxl) in their 
software to communicate with an accelerator design that is running in a 3rd party event simulator.  This permits a 
degree of hardware/software co-verification.  The accelerator design must use the opencapi reference tlx hardware 
interface and protocol to communicate with ocse.  The OpenCAPI specification that we model is "OpenCAPI 4.0 Transaction 
Layer Version 1.0."  The reference tlx hardware interface supported is version 4.0.  

NOTE: we currently include common/misc/ocxl.h.  When the Linux Technical Center creates a "generic reference kernel 
driver," they will likely deliver the official version of ocxl.h.  At that time, due to differences in licensing 
terms, we will no longer be allowed to distribute ocxl.h.  Our Makefiles will be adjusted to obtain a copy of the 
linux ocxl.h from the linux repository to statisfy the various compile steps.

See QUICK_START for general instructions on how to start the evironment.  You will need to understand your specific
vendor simulator to perform some of the steps specific to your simulator.

Demo kit(s) (sample, toy designs) are being provided to allow you to build the environment, a design, and a
host application.  This should a) allow you to validate your installation, and b) provide some coding examples
of how to used various interfaces.  Please note that the demo kit designs are not exhaustively tested, best in class
designs.  While they may be used to start your own design, they are not intended to be the final answer to your
specific acceleration problem.

version 2.0 Known limitations:
	- we've simulated with Cadence NCSim, Xilinx Xsim, and Synopsys VCS
	- we allow up to 16 tlx event simulations (numbered tlx0 to tlxf in shim_host.dat)
	- ocse performs a subset of the discovery and configuration process.  
	      - we think it does enough to give you a good idea the configuration is working
	      - feedback is certainly welcome
	- the afu is required to send a complete response to a command from the host; that is, no partial responses
	- ocse always generates a complete response.

	- due to restrictions in the use of memprotect(), our LPC (Lowest Point of Coherency) support is implemented as
	  helper function ocxl_lpc_read and ocxl_lpc_write in libocxl_lpc.  LPC memory (also known as home agent memory)
	  is memory that exists in the AFU that has been mapped into the user effective address space.
	- ocxl_lpc_read and ocxl_lpc_write require offsets and sizes that are naturally aligned.

	- due to restrictions in the use of memprotect(), our cache management behavior may evict more than the referenced
	  cache line.  This may result in a "busier" force_evict/castout exchange than you will see in real hardware.
	
