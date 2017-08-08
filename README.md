# ocse
OpenCAPI Simulation Engine

This is a simulation environment that allows a programmer to use the opencapi reference user api (libocxl) in their software to communicate with an accelerator design that is running in a 3rd party event simulator.  This permits a degree of hardware/software co-verification.  The accelerator design must use the opencapi reference tlx hardware interface and protocol to communicate with ocse.

NOTE: we currently include common/misc/ocxl.h.  When the Linux Technical Center creates a "generic reference kernel driver," they will likely deliver the official version of ocxl.h.  At that time, we will no longer distribute ocxl.h.  Our Makefiles will be adjusted to obtain a copy of the linux ocxl.h to statisfy the various compile steps.

mention startup guides
mention demo kit(s)
mention apache 2.0 license

sprint g

