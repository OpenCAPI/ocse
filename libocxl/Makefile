srcdir = $(PWD)
include Makefile.vars

OBJS = libocxl.o libocxl_sysfs.o
CFLAGS += -I include

# change VERS_LIB if new git tag
VERS_LIB = 0.0
LIBNAME   = libocxl.so.$(VERS_LIB)
# change VERS_SONAME only if library breaks backward compatibility.
# refer to file symver.map
VERS_SONAME=1
LIBSONAME = libocxl.so.$(VERS_SONAME)
SONAMEOPT = -Wl,-soname,$(LIBSONAME)

all: check_cxl_header $(LIBSONAME) libocxl.so libocxl.a

HAS_WGET = $(shell /bin/which wget > /dev/null 2>&1 && echo y || echo n)
HAS_CURL = $(shell /bin/which curl > /dev/null 2>&1 && echo y || echo n)

# Update this to test a single feature from the most recent header we require:
CHECK_CXL_HEADER_IS_UP_TO_DATE = $(shell /bin/echo -e \\\#include $(1)\\\nvoid test\(struct cxl_afu_id test\)\; | \
                 $(CC) $(CFLAGS) -Werror -x c -S -o /dev/null - > /dev/null 2>&1 && echo y || echo n)

check_cxl_header:
ifeq ($(call CHECK_CXL_HEADER_IS_UP_TO_DATE,"<misc/cxl.h>"),n)
	mkdir -p include/misc
ifeq (${HAS_WGET},y)
	$(call Q,WGET include/misc/cxl.h, wget -O include/misc/cxl.h -q http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
else ifeq (${HAS_CURL},y)
	$(call Q,CURL include/misc/cxl.h, curl -o include/misc/cxl.h -s http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
else
	$(error 'cxl.h is non-existant or out of date, Download from http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h and place in ${PWD}/include/misc/cxl.h')
endif
endif

libocxl.o libocxl_sysfs.o : CFLAGS += -fPIC

libocxl.so: $(LIBNAME)
	ln -sf $(LIBNAME) libocxl.so

$(LIBSONAME): $(LIBNAME)
	ln -sf $(LIBNAME) $(LIBSONAME)

$(LIBNAME): libocxl.o libocxl_sysfs.o symver.map
	$(call Q,CC, $(CC) $(CFLAGS) $(LDFLAGS) -shared libocxl.o libocxl_sysfs.o -o $(LIBNAME), $(LIBNAME)) -Wl,--version-script symver.map $(SONAMEOPT)

libocxl.a: libocxl.o libocxl_sysfs.o
	$(call Q,AR, ar rcs libocxl.a libocxl.o libocxl_sysfs.o, libocxl.a)

include Makefile.rules

clean:
	rm -f *.o *.d libocxl.so* libocxl.a include/misc/cxl.h

install: all
	mkdir -p $(DESTDIR)$(libdir)
	mkdir -p $(DESTDIR)$(includedir)
	install -m 0755 $(LIBNAME) $(DESTDIR)$(libdir)/
	cp -d libocxl.so $(LIBSONAME) $(DESTDIR)$(libdir)/
	install -m 0644 libocxl.h  $(DESTDIR)$(includedir)/

.PHONY: clean all install
