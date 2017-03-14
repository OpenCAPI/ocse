srcdir = $(PWD)
COMMON_DIR=../common
include Makefile.vars
include Makefile.rules

OBJS = libocxl.o debug.o utils.o

all: libocxl.so libocxl.a

CHECK_HEADER := $(shell echo \\\#include\ $(1) | $(CC) $(CFLAGS) -E - > /dev/null 2>&1 && echo y || echo n)

$(COMMON_DIR)/misc/ocxl.h:
ifeq ($(call CHECK_HEADER,"<misc/cxl.h>"),n)
	$(call Q,CURL $(COMMON_DIR)/misc/cxl.h, mkdir $(COMMON_DIR)/misc 2>/dev/null; curl -o $(COMMON_DIR)/misc/cxl.h -s https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
endif

libocxl.o: $(COMMON_DIR)/misc/ocxl.h

libocxl.so: $(OBJS)
	$(call Q,CC, $(CC) $(CFLAGS) -shared $^ -o $@, $@) -Wl,--version-script symver.map

libocxl.a: $(OBJS)
	$(call Q,AR, $(AR) rcs $@ $^, $@)

clean:
	rm -f *.[od] $(COMMON_DIR)/*.[od] gmon.out libocxl.so libocxl.a $(COMMON_DIR)/misc/cxl.h

.PHONY: clean all
