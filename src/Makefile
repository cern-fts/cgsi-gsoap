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
GLOBUS_FLAVOUR = gcc32dbg
GLOBUS_INCLUDE = -I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOUR)
GLOBUS_LIBS = -L$(GLOBUS_LOCATION)/lib -lglobus_gssapi_gsi_$(GLOBUS_FLAVOUR) \
	-lglobus_gss_assist_$(GLOBUS_FLAVOUR)

ifeq ($(GSOAP_LOCATION), $(EMPTY))
GSOAP_LOCATION=/usr/local
endif
GSOAP_INCLUDE=-I$(GSOAP_LOCATION)/include

# initial settings
CFLAGS += -I. 
CFLAGS += $(GLOBUS_INCLUDE) $(GSOAP_INCLUDE)
LDLIBS += $(GLOBUS_LIBS)


################################################################################
## compilation targets ##
.PHONY: all
all: libcgsi_plugin$(GSOAP_VERSION).a libcgsi_plugin$(GSOAP_VERSION).so 

# dependencies
cgsi_plugin.o: cgsi_plugin.h cgsi_plugin_int.h

libcgsi_plugin$(GSOAP_VERSION).a: cgsi_plugin.o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

libcgsi_plugin$(GSOAP_VERSION).so: cgsi_plugin.o
	ld $(SHLIBLDFLAGS) -o $@ *.o $(SHLIBREQLIBS)

###############################################
## THIS IS STANDARD Makefile BELOW THIS LINE ##
###############################################

################################################################################

# Usage example: make install PREFIX=/usr/local BINDIR=my_executables

# installation directories defaults are generic unix
PPREFIX=/usr/local
PREFIX =$(RPM_BUILD_ROOT)$(PPREFIX)# could be /usr/local but you may not have perms
INCDIR =include
LIBDIR =lib
BINDIR =bin
MANDIR =man

# insert space separated files to install (used for cleaning too) here
BINFILES =
LIBFILES =libcgsi_plugin$(GSOAP_VERSION).a
SHLIBFILES =libcgsi_plugin$(GSOAP_VERSION).so
INCFILES =cgsi_plugin.h
MANFILES =

INSTALL_FLAGS =

# install targets
installtargets = installinc installlib installbin installman installshlib
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
installshlib: $(SHLIBFILES)
ifneq ($(SHLIBFILES), $(EMPTY))
	-mkdir -p $(PREFIX)/$(LIBDIR)
ifneq ($(VERSION), $(EMPTY))
	-cp $^ $(PREFIX)/$(LIBDIR)/$^.$(VERSION)
	-chmod 755 $(PREFIX)/$(LIBDIR)/$^.$(VERSION)
	(pushd $(PREFIX)/$(LIBDIR);  pwd ; ln -s $^.$(VERSION) $^)
else
	install $(INSTALL_FLAGS) -m 755 $^ $(PREFIX)/$(LIBDIR)
endif
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

