##
# $id: $
##

ifeq ($(SRCDIR), $(EMPTY))
SRCDIR=.
else
VPATH=.:$(SRCDIR)
endif


################################################################################
## implicit rule flags ##
SHELL = /bin/sh -e
CC = gcc
CFLAGS = -Wall -g -fPIC
LDFLAGS =

################################################################################
## project flags ##

ifeq ($(GLOBUS_LOCATION), $(EMPTY))
GLOBUS_LOCATION=/opt/globus
endif

ifeq ($(GLOBUS_FLAVOUR), $(EMPTY))
GLOBUS_FLAVOUR = gcc32dbg
endif

GLOBUS_FLAVOUR_PTHR=$(GLOBUS_FLAVOUR)pthr

GLOBUS_INCLUDE = -I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOUR)
GLOBUS_LIBS = -L$(GLOBUS_LOCATION)/lib -lglobus_gssapi_gsi_$(GLOBUS_FLAVOUR) \
	-lglobus_gss_assist_$(GLOBUS_FLAVOUR)
# This is not nice: libtool by hand...
GLOBUS_LIBS += $(shell $(SRCDIR)/libtool $(GLOBUS_LOCATION)/lib/libglobus_gssapi_gsi_$(GLOBUS_FLAVOUR).la)
GLOBUS_LIBS += $(shell $(SRCDIR)/libtool $(GLOBUS_LOCATION)/lib/libglobus_gss_assist_$(GLOBUS_FLAVOUR).la)

GLOBUS_INCLUDE_PTHR = -I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOUR_PTHR)
GLOBUS_LIBS_PTHR = -L$(GLOBUS_LOCATION)/lib -lglobus_gssapi_gsi_$(GLOBUS_FLAVOUR_PTHR) \
        -lglobus_gss_assist_$(GLOBUS_FLAVOUR_PTHR)
# This is not nice: libtool by hand...
GLOBUS_LIBS_PTHR += $(shell $(SRCDIR)/libtool $(GLOBUS_LOCATION)/lib/libglobus_gssapi_gsi_$(GLOBUS_FLAVOUR_PTHR).la)
GLOBUS_LIBS_PTHR += $(shell $(SRCDIR)/libtool $(GLOBUS_LOCATION)/lib/libglobus_gss_assist_$(GLOBUS_FLAVOUR_PTHR).la)

LDLIBS += $(GLOBUS_LIBS) 

ifeq ($(GSOAP_LOCATION), $(EMPTY))
GSOAP_LOCATION=/usr/local
endif
CFLAGS += -I$(GSOAP_LOCATION)/include
LDLIBS += -L$(GSOAP_LOCATION)/lib -lgsoap

ifeq ($(GSOAP_VERSION), $(EMPTY))
GSOAP_VERSION=_gsoap_2.3
endif

# local references to CGSI-gSOAP
CFLAGS += -I. -I$(SRCDIR) -I$(SRCDIR)/../src

ifeq ($(VOMS_LOCATION), $(EMPTY))
VOMS_LOCATION=/opt/glite
endif

ifneq ($(USE_VOMS), $(EMPTY))
VOMS_FLAGS = -DUSE_VOMS -I$(VOMS_LOCATION)/include/glite/security/voms
VOMS_LIBS=-L$(VOMS_LOCATION)/lib -lvomsc

VOMS_FLAGS_PTHR = -DUSE_VOMS -I$(VOMS_LOCATION)/include/glite/security/voms
VOMS_LIBS_PTHR=-L$(VOMS_LOCATION)/lib -lvomsc_$(GLOBUS_FLAVOUR_PTHR)

CFLAGS += $(VOMS_FLAGS)
LDLIBS += $(VOMS_LIBS)
endif

################################################################################
## compilation targets ##
.PHONY: all

all: cgsi-gsoap-client cgsi-gsoap-server

cgsi_gsoap_test.h: cgsi-gsoap-test.wsdl typemap.dat
	$(GSOAP_LOCATION)/bin/wsdl2h -t $(SRCDIR)/typemap.dat -n cgsi_gsoap_test -c -s -o $@ $<

cgsi_gsoap_testH.h cgsi_gsoap_testClientLib.c cgsi_gsoap_testServerLib.c: cgsi_gsoap_test.h
	$(GSOAP_LOCATION)/bin/soapcpp2 -I$(GSOAP_LOCATION)/include -p cgsi_gsoap_test $<
	# gSOAP 2.6.2 vs 2.7.6b workaround:
	if [ -f cgsi_USCOREgsoap_USCOREtest.nsmap ] ; \
		then mv cgsi_USCOREgsoap_USCOREtest.nsmap cgsi_gsoap_test.nsmap ; \
	fi


cgsi_gsoap_testC.o: cgsi_gsoap_testC.c
	$(CC) -I$(GSOAP_LOCATION)/include -c -o $@ $< 
cgsi_gsoap_testClient.o: cgsi_gsoap_testClient.c
	$(CC) -I$(GSOAP_LOCATION)/include -c -o $@ $< 
cgsi_gsoap_testServer.o: cgsi_gsoap_testServer.c
	$(CC) -I$(GSOAP_LOCATION)/include -c -o $@ $< 

cgsi-gsoap-client.o: cgsi-gsoap-client.c cgsi_gsoap_testH.h
	$(CC) $(CFLAGS) -c -o $@ $<

cgsi-gsoap-client: cgsi-gsoap-client.o cgsi_gsoap_testClient.o cgsi_gsoap_testC.o ../src/libcgsi_plugin$(GSOAP_VERSION).so 
	$(CC) -o $@ $^ $(LDLIBS) 

cgsi-gsoap-server.o: cgsi-gsoap-server.c cgsi_gsoap_testH.h
	$(CC) $(CFLAGS) -c -o $@ $<

cgsi-gsoap-server: cgsi-gsoap-server.o cgsi_gsoap_testServer.o cgsi_gsoap_testC.o ../src/libcgsi_plugin_voms$(GSOAP_VERSION)_$(GLOBUS_FLAVOUR).so
	$(CC) -o $@ $^ $(LDLIBS) 

clean:
	rm -f *.o *.c *.h *.xml *.nsmap

################################################################################
## test targets ##

test: cgsi-gsoap-client cgsi-gsoap-server
	LD_LIBRARY_PATH=$(GLOBUS_LOCATION)/lib $(SRCDIR)/test-client-server.sh

################################################################################
## maintenance targets ##

test-utils:
	cp -u $(SRCDIR)/../../org.glite.data.test-utils/shunit .
	cp -u $(SRCDIR)/../../org.glite.data.test-utils/glite-test-certs .

