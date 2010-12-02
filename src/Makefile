##
# $Id$
##

ifeq ($(SRCDIR), $(EMPTY))
SRCDIR=.
else
VPATH=.:$(SRCDIR)
endif


################################################################################
## implicit rule flags ##
SHELL = /bin/sh
CC = gcc
CPP = g++
CFLAGS = -Wall -g -fPIC
LDFLAGS =
RANLIB = ranlib
SHLIBLDFLAGS = -shared
SHLIBREQLIBS = -lc 

# gSOAP 2.7.10 has introduced a virtual destructor, which inserts
# a pointer to the VMT at the beginning of the 'soap' structure,
# making the C and C++ versions of the code binary incompatible,
# so we need to build C++ flavour of the libraries as well:
#WITH_CPP_LIBS = yes

################################################################################
## project flags ##

ifeq ($(GLOBUS_LOCATION), $(EMPTY))
GLOBUS_LOCATION=/opt/globus
endif

ifeq ($(GLOBUS_FLAVOUR), $(EMPTY))
GLOBUS_FLAVOUR = gcc32dbg
endif

GLOBUS_FLAVOUR_PTHR=$(GLOBUS_FLAVOUR)pthr

ifeq ($(GSOAP_LOCATION), $(EMPTY))
GSOAP_LOCATION=/usr/local
endif
GSOAP_INCLUDE=-I$(GSOAP_LOCATION)/include

ifeq ($(GLOBUS_LOCATION), /usr)
GLOBUS_INCLUDE = -I/usr/include/globus -I/usr/$(LIBDIR)/globus/include
GLOBUS_LIBS = -lglobus_gssapi_gsi -lglobus_gss_assist

GSOAP_VERSION =

LIBFILES =libcgsi_plugin.a 
SHLIBFILES =libcgsi_plugin.so
ifneq ($(WITH_CPP_LIBS), $(EMPTY))
LIBFILES +=libcgsi_plugin_cpp.a
SHLIBFILES +=libcgsi_plugin_cpp.so
endif
ifneq ($(USE_VOMS), $(EMPTY))
LIBFILES +=libcgsi_plugin_voms.a
SHLIBFILES +=libcgsi_plugin_voms.so
ifneq ($(WITH_CPP_LIBS), $(EMPTY))
LIBFILES +=libcgsi_plugin_voms_cpp.a
SHLIBFILES +=libcgsi_plugin_voms_cpp.so
endif
endif
else
GLOBUS_INCLUDE = -I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOUR)
GLOBUS_LIBS = -L$(GLOBUS_LOCATION)/lib -lglobus_gssapi_gsi_$(GLOBUS_FLAVOUR) \
	-lglobus_gss_assist_$(GLOBUS_FLAVOUR)

GLOBUS_INCLUDE_PTHR = -I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOUR_PTHR)
GLOBUS_LIBS_PTHR = -L$(GLOBUS_LOCATION)/lib -lglobus_gssapi_gsi_$(GLOBUS_FLAVOUR_PTHR) \
        -lglobus_gss_assist_$(GLOBUS_FLAVOUR_PTHR)

ifeq ($(GSOAP_VERSION), $(EMPTY))
GSOAP_VERSION=_gsoap_2.7
endif

LIBFILES =libcgsi_plugin$(GSOAP_VERSION).a 
SHLIBFILES =libcgsi_plugin$(GSOAP_VERSION).so

ifneq ($(WITH_CPP_LIBS), $(EMPTY))
LIBFILES +=libcgsi_plugin$(GSOAP_VERSION)_cpp.a
SHLIBFILES +=libcgsi_plugin$(GSOAP_VERSION)_cpp.so
endif

ifneq ($(USE_VOMS), $(EMPTY))
LIBFILES += libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).a
LIBFILES += libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).a
SHLIBFILES += libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).so 
SHLIBFILES += libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).so
ifneq ($(WITH_CPP_LIBS), $(EMPTY))
LIBFILES += libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR)_cpp.a
LIBFILES += libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR)_cpp.a
SHLIBFILES += libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR)_cpp.so 
SHLIBFILES += libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR)_cpp.so
endif
endif
endif

# major version number for shared library names
VMAJOR=$(shell echo $(VERSION) | cut -f1 -d.)


# initial settings
CFLAGS += -I. $(GSOAP_INCLUDE) -I$(SRCDIR)

ifeq ($(VOMS_LOCATION), $(EMPTY))
VOMS_LOCATION=/opt/glite
endif

ifeq ($(LIBDIR), $(EMPTY))
LIBDIR=lib
endif

ifneq ($(USE_VOMS), $(EMPTY))
ifeq ($(VOMS_LOCATION), /usr)
VOMS_FLAGS = -DUSE_VOMS -I/usr/include/voms
VOMS_LIBS = -lvomsapi
else
VOMS_FLAGS = -DUSE_VOMS -I$(VOMS_LOCATION)/include/glite/security/voms
VOMS_LIBS=-L$(VOMS_LOCATION)/$(LIBDIR) -lvomsapi_$(GLOBUS_FLAVOUR)

VOMS_FLAGS_PTHR = -DUSE_VOMS -I$(VOMS_LOCATION)/include/glite/security/voms
VOMS_LIBS_PTHR=-L$(VOMS_LOCATION)/$(LIBDIR) -lvomsapi_$(GLOBUS_FLAVOUR_PTHR)
endif
endif

#CFLAGS += $(VOMS_FLAGS)
#LDLIBS += $(VOMS_LIBS)

# NO ! the libs should not be added at link time so that the
#users of CGSI_GSOAP can choose the ones they need to use
#SHLIBREQLIBS += $(LDLIBS)

################################################################################
## compilation targets ##
.PHONY: all

all: $(LIBFILES) $(SHLIBFILES)

# dependencies
cgsi_plugin.o: cgsi_plugin.c cgsi_plugin.h cgsi_plugin_int.h
	$(CC) $(CFLAGS) $(GLOBUS_INCLUDE)  -c -o $@ $<

libcgsi_plugin$(GSOAP_VERSION).a: cgsi_plugin.o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin$(GSOAP_VERSION).so: cgsi_plugin.o
	$(CC) $(SHLIBLDFLAGS) -Wl,-soname,$@.$(VMAJOR) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS)


ifneq ($(WITH_CPP_LIBS), $(EMPTY))
cgsi_plugin_cpp.o: cgsi_plugin.c cgsi_plugin.h cgsi_plugin_int.h
	$(CPP) $(CFLAGS) $(GLOBUS_INCLUDE)  -c -o $@ $<

libcgsi_plugin$(GSOAP_VERSION)_cpp.a: cgsi_plugin_cpp.o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin$(GSOAP_VERSION)_cpp.so: cgsi_plugin_cpp.o
	$(CPP) $(SHLIBLDFLAGS) -Wl,-soname,$@.$(VMAJOR) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS)
endif

ifneq ($(USE_VOMS), $(EMPTY))
cgsi_plugin_voms.o: cgsi_plugin.c cgsi_plugin.h cgsi_plugin_int.h
	$(CC) $(CFLAGS) $(VOMS_FLAGS)  $(GLOBUS_INCLUDE) -c -o $@ $<

libcgsi_plugin_voms$(GSOAP_VERSION).a: cgsi_plugin_voms.o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin_voms$(GSOAP_VERSION).so: cgsi_plugin_voms.o
	$(CC) $(SHLIBLDFLAGS) -Wl,-soname,$@.$(VMAJOR) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS) $(VOMS_LIBS)

cgsi_plugin_voms_$(GLOBUS_FLAVOUR).o: cgsi_plugin.c cgsi_plugin.h cgsi_plugin_int.h
	$(CC) $(CFLAGS) $(VOMS_FLAGS)  $(GLOBUS_INCLUDE) -c -o $@ $<

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).a: cgsi_plugin_voms_$(GLOBUS_FLAVOUR).o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).so: cgsi_plugin_voms_$(GLOBUS_FLAVOUR).o
	$(CC) $(SHLIBLDFLAGS) -Wl,-soname,$@.$(VMAJOR) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS) $(VOMS_LIBS)

cgsi_plugin_voms_$(GLOBUS_FLAVOUR_PTHR).o: cgsi_plugin.c cgsi_plugin.h cgsi_plugin_int.h
	$(CC) $(CFLAGS) $(VOMS_FLAGS_PTHR)  $(GLOBUS_INCLUDE_PTHR) -c -o $@ $<

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).a: cgsi_plugin_voms_$(GLOBUS_FLAVOUR_PTHR).o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).so: cgsi_plugin_voms_$(GLOBUS_FLAVOUR_PTHR).o
	$(CC) $(SHLIBLDFLAGS) -Wl,-soname,$@.$(VMAJOR) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS_PTHR) $(VOMS_LIBS_PTHR)

ifneq ($(WITH_CPP_LIBS), $(EMPTY))
cgsi_plugin_voms_cpp.o: cgsi_plugin.c cgsi_plugin.h cgsi_plugin_int.h
	$(CPP) $(CFLAGS) $(VOMS_FLAGS)  $(GLOBUS_INCLUDE) -c -o $@ $<

libcgsi_plugin_voms$(GSOAP_VERSION)_cpp.a: cgsi_plugin_voms_cpp.o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin_voms$(GSOAP_VERSION)_cpp.so: cgsi_plugin_voms_cpp.o
	$(CPP) $(SHLIBLDFLAGS) -Wl,-soname,$@.$(VMAJOR) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS) $(VOMS_LIBS)

cgsi_plugin_voms_$(GLOBUS_FLAVOUR)_cpp.o: cgsi_plugin.c cgsi_plugin.h cgsi_plugin_int.h
	$(CPP) $(CFLAGS) $(VOMS_FLAGS)  $(GLOBUS_INCLUDE) -c -o $@ $<

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR)_cpp.a: cgsi_plugin_voms_$(GLOBUS_FLAVOUR)_cpp.o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR)_cpp.so: cgsi_plugin_voms_$(GLOBUS_FLAVOUR)_cpp.o
	$(CPP) $(SHLIBLDFLAGS) -Wl,-soname,$@.$(VMAJOR) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS) $(VOMS_LIBS)

cgsi_plugin_voms_$(GLOBUS_FLAVOUR_PTHR)_cpp.o: cgsi_plugin.c cgsi_plugin.h cgsi_plugin_int.h
	$(CPP) $(CFLAGS) $(VOMS_FLAGS_PTHR)  $(GLOBUS_INCLUDE_PTHR) -c -o $@ $<

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR)_cpp.a: cgsi_plugin_voms_$(GLOBUS_FLAVOUR_PTHR)_cpp.o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR)_cpp.so: cgsi_plugin_voms_$(GLOBUS_FLAVOUR_PTHR)_cpp.o
	$(CPP) $(SHLIBLDFLAGS) -Wl,-soname,$@.$(VMAJOR) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS_PTHR) $(VOMS_LIBS)
endif

endif

doc: doxygenConfig
	SRCDIR=$(SRCDIR) VERSION=$(VERSION) doxygen $<

###############################################
## THIS IS STANDARD Makefile BELOW THIS LINE ##
###############################################

################################################################################

# Usage example: make install PREFIX=/usr/local

# installation directories defaults are generic unix
PPREFIX=/usr
PREFIX =$(RPM_BUILD_ROOT)$(PPREFIX)# could be /usr/local but you may not have perms
INCDIR =include
BINDIR =bin
MANDIR =share
DOCDIR =share/doc/CGSI$(GSOAP_VERSION)

INCFILES =cgsi_plugin.h

INSTALL_FLAGS =

# install targets
ifneq ($(USE_VOMS), $(EMPTY))
installtargets = installinc installlib installbin installman installdoc installshlib installshlibvoms installshlibvomspthr
else
installtargets = installinc installlib installbin installman installdoc installshlib
endif

.PHONY: uninstall install $(installtargets)
install: $(INCFILES) $(LIBFILES) $(SHLIBFILES)
	install -d $(PREFIX)/$(INCDIR)
	for i in $(INCFILES); do cp $(SRCDIR)/$$i $(PREFIX)/$(INCDIR); done
	install -d $(PREFIX)/$(LIBDIR)
	for l in $(LIBFILES); do cp $$l $(PREFIX)/$(LIBDIR)/$$l; done
	for l in $(SHLIBFILES); do \
		cp $$l $(PREFIX)/$(LIBDIR)/$$l.$(VERSION); \
		(cd $(PREFIX)/$(LIBDIR); ln -sf $$l.$(VERSION) $$l); \
		(cd $(PREFIX)/$(LIBDIR); ln -sf $$l.$(VERSION) $$l.$(VMAJOR)); \
		done
install.man: doc
	mkdir -p $(PREFIX)/share
	cp -r man $(PREFIX)/share/
	mkdir -p $(PREFIX)/$(DOCDIR)
	cp -r html $(PREFIX)/$(DOCDIR)/


################################################################################
## clean up ##
.PHONY: clean
clean:
# files vars are specified in install
	-$(RM) *.o $(LIBFILES) $(SHLIBFILES)


################################################################################
## help ## OK now I am going really over the top here :)
.PHONY: help
help:
	@echo -e "\n" \
	"\ttarget\t| description \n" \
	"\t================================================================\n" \
	"\tall\t| Makes the gsoap binaries.\n" \
	"\t\t|\n" \

