##
# $id: $
##


################################################################################
## implicit rule flags ##
SHELL = /bin/sh -e
CC = gcc
CFLAGS = -Wall -g -fPIC
LDFLAGS =
RANLIB = ranlib
SHLIBLDFLAGS = -shared
SHLIBREQLIBS = -lc 

################################################################################
## project flags ##

ifeq ($(GLOBUS), $(EMPTY))
GLOBUS_LOCATION=/opt/globus
endif

ifeq ($(GLOBUS_FLAVOUR), $(EMPTY))
GLOBUS_FLAVOUR = gcc32dbg
endif

GLOBUS_FLAVOUR_PTHR=$(GLOBUS_FLAVOUR)pthr

GLOBUS_INCLUDE = -I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOUR)
GLOBUS_LIBS = -L$(GLOBUS_LOCATION)/lib -lglobus_gssapi_gsi_$(GLOBUS_FLAVOUR) \
	-lglobus_gss_assist_$(GLOBUS_FLAVOUR)

GLOBUS_INCLUDE_PTHR = -I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOUR_PTHR)
GLOBUS_LIBS_PTHR = -L$(GLOBUS_LOCATION)/lib -lglobus_gssapi_gsi_$(GLOBUS_FLAVOUR_PTHR) \
        -lglobus_gss_assist_$(GLOBUS_FLAVOUR_PTHR)

ifeq ($(GSOAP_LOCATION), $(EMPTY))
GSOAP_LOCATION=/usr/local
#GSOAP_LOCATION=/afs/cern.ch/user/b/bcouturi/w0/gsoap-slc3/2.3
endif
GSOAP_INCLUDE=-I$(GSOAP_LOCATION)/include

ifeq ($(GSOAP_VERSION), $(EMPTY))
GSOAP_VERSION=_gsoap_2.3
endif


# initial settings
CFLAGS += -I. $(GSOAP_INCLUDE)

ifeq ($(VOMS_LOCATION), $(EMPTY))
VOMS_LOCATION=/opt/edg
endif

ifneq ($(USE_VOMS), $(EMPTY))
VOMS_FLAGS = -DUSE_VOMS -I$(VOMS_LOCATION)/include
VOMS_LIBS=-L$(VOMS_LOCATION)/lib -lvomsc

VOMS_FLAGS_PTHR = -DUSE_VOMS -I$(VOMS_LOCATION)/include
VOMS_LIBS_PTHR=-L$(VOMS_LOCATION)/lib -lvomsc_$(GLOBUS_FLAVOUR_PTHR)
endif

#CFLAGS += $(VOMS_FLAGS)
#LDLIBS += $(VOMS_LIBS)

# NO ! the libs should not be added at link time so that the
#users of CGSI_GSOAP can choose the ones they need to use
#SHLIBREQLIBS += $(LDLIBS)

################################################################################
## compilation targets ##
.PHONY: all


ifneq ($(USE_VOMS), $(EMPTY))
all: libcgsi_plugin$(GSOAP_VERSION).a libcgsi_plugin$(GSOAP_VERSION).so  vomsall
else
all: libcgsi_plugin$(GSOAP_VERSION).a libcgsi_plugin$(GSOAP_VERSION).so 
endif

vomsall: libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).a libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).so libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).a libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).so



# dependencies
cgsi_plugin.o: cgsi_plugin.h cgsi_plugin_int.h
	$(CC) $(CFLAGS) $(GLOBUS_INCLUDE)  -c -o $@ cgsi_plugin.c

libcgsi_plugin$(GSOAP_VERSION).a: cgsi_plugin.o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin$(GSOAP_VERSION).so: cgsi_plugin.o
	ld $(SHLIBLDFLAGS) -o $@ $? $(SHLIBREQLIBS)

ifneq ($(USE_VOMS), $(EMPTY))
cgsi_plugin_voms_$(GLOBUS_FLAVOUR).o: cgsi_plugin.h cgsi_plugin_int.h cgsi_plugin.c
	$(CC) $(CFLAGS) $(VOMS_FLAGS)  $(GLOBUS_INCLUDE) -c -o $@ cgsi_plugin.c

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).a: cgsi_plugin_voms_$(GLOBUS_FLAVOUR).o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).so: cgsi_plugin_voms_$(GLOBUS_FLAVOUR).o
	ld $(SHLIBLDFLAGS) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS) $(VOMS_LIBS)

cgsi_plugin_voms_$(GLOBUS_FLAVOUR_PTHR).o: cgsi_plugin.h cgsi_plugin_int.h cgsi_plugin.c
	$(CC) $(CFLAGS) $(VOMS_FLAGS_PTHR)  $(GLOBUS_INCLUDE_PTHR) -c -o $@ cgsi_plugin.c

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).a: cgsi_plugin_voms_$(GLOBUS_FLAVOUR_PTHR).o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).so: cgsi_plugin_voms_$(GLOBUS_FLAVOUR_PTHR).o
	ld $(SHLIBLDFLAGS) -o $@ $? $(SHLIBREQLIBS) $(GLOBUS_LIBS_PTHR) $(VOMS_LIBS_PTHR)


endif

###############################################
## THIS IS STANDARD Makefile BELOW THIS LINE ##
###############################################

################################################################################

# Usage example: make install PREFIX=/usr/local BINDIR=my_executables

# installation directories defaults are generic unix
PPREFIX=/usr
PREFIX =$(RPM_BUILD_ROOT)$(PPREFIX)# could be /usr/local but you may not have perms
INCDIR =include
LIBDIR =lib
BINDIR =bin
MANDIR =man

# insert space separated files to install (used for cleaning too) here
BINFILES =
LIBFILES =libcgsi_plugin$(GSOAP_VERSION).a 
SHLIBFILES =libcgsi_plugin$(GSOAP_VERSION).so

ifneq ($(USE_VOMS), $(EMPTY))
LIBFILES +=libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).a libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).a
endif

ifneq ($(USE_VOMS), $(EMPTY))
SHLIBFILES +=libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).so libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).so
endif

INCFILES =cgsi_plugin.h
MANFILES =

INSTALL_FLAGS =

# install targets
ifneq ($(USE_VOMS), $(EMPTY))
installtargets = installinc installlib installbin installman installshlib installshlibvoms installshlibvomspthr
else
installtargets = installinc installlib installbin installman installshlib
endif

.PHONY: uninstall install $(installtargets)
install: $(installtargets)

installinc: $(INCFILES)
ifneq ($(INCFILES), $(EMPTY))
	-mkdir -p $(PREFIX)/$(INCDIR)
	install $(INSTALL_FLAGS) -m 644 $^ $(PREFIX)/$(INCDIR)
endif
installlib: $(LIBFILES)
ifneq ($(LIBFILES), $(EMPTY))
	-mkdir -p $(PREFIX)/$(LIBDIR)
	install $(INSTALL_FLAGS) -m 755 $^ $(PREFIX)/$(LIBDIR)
endif

installshlib: libcgsi_plugin$(GSOAP_VERSION).so
	-mkdir -p $(PREFIX)/$(LIBDIR)
ifneq ($(VERSION), $(EMPTY))
	-cp $^ $(PREFIX)/$(LIBDIR)/$^.$(VERSION)
	-chmod 755 $(PREFIX)/$(LIBDIR)/$^.$(VERSION)
	(pushd $(PREFIX)/$(LIBDIR);  pwd ; ln -s $^.$(VERSION) $^)
else
	install $(INSTALL_FLAGS) -m 755 $^ $(PREFIX)/$(LIBDIR)
endif

installshlibvoms: libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).so
	-mkdir -p $(PREFIX)/$(LIBDIR)
ifneq ($(VERSION), $(EMPTY))
	-cp $^ $(PREFIX)/$(LIBDIR)/$^.$(VERSION)
	-chmod 755 $(PREFIX)/$(LIBDIR)/$^.$(VERSION)
	(pushd $(PREFIX)/$(LIBDIR);  pwd ; ln -s $^.$(VERSION) $^)
else
	install $(INSTALL_FLAGS) -m 755 $^ $(PREFIX)/$(LIBDIR)
endif



installshlibvomspthr: libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR_PTHR).so 
	-mkdir -p $(PREFIX)/$(LIBDIR)
ifneq ($(VERSION), $(EMPTY))
	-cp $^ $(PREFIX)/$(LIBDIR)/$^.$(VERSION)
	-chmod 755 $(PREFIX)/$(LIBDIR)/$^.$(VERSION)
	(pushd $(PREFIX)/$(LIBDIR);  pwd ; ln -s $^.$(VERSION) $^)
else
	install $(INSTALL_FLAGS) -m 755 $^ $(PREFIX)/$(LIBDIR)
endif




installbin: $(BINFILES)
ifneq ($(BINFILES), $(EMPTY))
	-mkdir -p $(PREFIX)/$(BINDIR)
	install $(INSTALL_FLAGS) -m 755 $^ $(PREFIX)/$(BINDIR)
endif
installman: $(MANFILES)
# this creates 'man3/foo.3' from 'foo.3'
ifneq ($(MANFILES), $(EMPTY))
	$(foreach MANFILE, $^, \
	-mkdir -p $(PREFIX)/$(MANDIR)/$(subst .,man,$(suffix $(MANFILE))); \
	install $(INSTALL_FLAGS) -m 644 $(MANFILE) \
	$(PREFIX)/$(MANDIR)/$(subst .,man,$(suffix $(MANFILE)))/$(MANFILE); )
endif


uninstall:
# minor hack - the subst in rmdir avoids trying to remove current dir '.'
ifneq ($(INCFILES), $(EMPTY))
	$(RM) $(foreach file, $(INCFILES), $(PREFIX)/$(INCDIR)/$(file))
	-rmdir -p $(subst ./,,$(PREFIX)/$(INCDIR))
endif
ifneq ($(LIBFILES), $(EMPTY))
	$(RM) $(foreach file, $(LIBFILES), $(PREFIX)/$(LIBDIR)/$(file))
	-rmdir -p $(subst ./,,$(PREFIX)/$(LIBDIR))
endif
ifneq ($(BINFILES), $(EMPTY))
	$(RM) $(foreach file, $(BINFILES), $(PREFIX)/$(BINDIR)/$(file))
	-rmdir -p $(subst ./,,$(PREFIX)/$(BINDIR))
endif
ifneq ($(MANFILES), $(EMPTY))
	$(RM) $(foreach file, $(MANFILES), $(PREFIX)/$(MANDIR)/*/$(file))
	-rmdir -p $(subst ./,,$(PREFIX)/$(MANDIR)/*)
endif


################################################################################
## clean up ##
.PHONY: clean
clean:
# files vars are specified in install
	-$(RM) *.o $(LIBFILES) $(BINFILES) $(SHLIBFILES)


################################################################################
## help ## OK now I am going really over the top here :)
.PHONY: help
help:
	@echo -e "\n" \
	"\ttarget\t| description \n" \
	"\t================================================================\n" \
	"\tall\t| Makes the gsoap binaries.\n" \
	"\t\t|\n" \

