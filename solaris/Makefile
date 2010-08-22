#
# Copyright (c) Members of the EGEE Collaboration. 2006-2010.
# See http://public.eu-egee.org/partners/ for details on 
# the copyright holders.
# For license conditions see the license file or
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors: 
#      Jean-Philippe Baud <Jean-Philippe.Baud@cern.ch>
#

default: all

ifndef VERSION
include ../VERSION
endif

ifndef RELEASE_SUFFIX
RELEASE_SUFFIX=sol10-x86
endif

VPACKAGE=CGSI-gSOAP27-$(VERSION)
VPACKAGE_TAR=$(VPACKAGE).tar.gz

all: CGSI-gSOAP27
	mkdir -p ../RPMS
	cp build-*/RPMS/*-sol10-x86 ../RPMS/

CGSI-gSOAP27: build-pkg 
	cd build-pkg/BUILD; \
	rm -rf $(VPACKAGE); \
	gtar -xzf ../SOURCES/$(VPACKAGE_TAR)
	BUILD_ROOT=$(PWD)/build-pkg/BUILD/$(VPACKAGE)-root; \
	LD_LIBRARY_PATH=$(GLOBUS_LOCATION)/lib:$(LD_LIBRARY_PATH); export LD_LIBRARY_PATH; \
	(cd build-pkg/BUILD/$(VPACKAGE); \
	./configure ${EXTRA_CONFIGURE_OPTIONS}; \
	gmake; \
	gmake install PREFIX=$$BUILD_ROOT; \
	gmake install.man PREFIX=$$BUILD_ROOT); \
	pkgmk -o -b$$BUILD_ROOT -f prototype.dev -v $(VERSION); \
	pkgmk -o -b$$BUILD_ROOT -f prototype.nonvoms -v $(VERSION) VERSION=$(VERSION); \
	pkgmk -o -b$$BUILD_ROOT -f prototype.voms -v $(VERSION) VERSION=$(VERSION)
	pkgtrans -o -s /var/spool/pkg $(PWD)/build-pkg/RPMS/CGSI-gSOAP27-dev-$(VERSION)-$(RELEASE_SUFFIX) CGSI-gSOAP27-dev
	pkgtrans -o -s /var/spool/pkg $(PWD)/build-pkg/RPMS/CGSI-gSOAP27-$(VERSION)-$(RELEASE_SUFFIX) CGSI-gSOAP27
	pkgtrans -o -s /var/spool/pkg $(PWD)/build-pkg/RPMS/CGSI-gSOAP27-voms-$(VERSION)-$(RELEASE_SUFFIX) CGSI-gSOAP27-voms

build-pkg: $(VPACKAGE_TAR)
	mkdir -p build-pkg
	mkdir -p build-pkg/BUILD
	mkdir -p build-pkg/RPMS
	mkdir -p build-pkg/SOURCES
	cp $(VPACKAGE_TAR) build-pkg/SOURCES

$(VPACKAGE_TAR):
	cd ..; \
	rm -rf $(VPACKAGE); \
	mkdir -p $(VPACKAGE); \
	cp -rp configure RELEASE-NOTES VERSION src $(VPACKAGE)/; \
	find $(VPACKAGE)/ -name .svn -exec rm -rf {} \;; \
	gtar -czf $(VPACKAGE_TAR) $(VPACKAGE); \
	rm -rf $(VPACKAGE)
	mv ../$(VPACKAGE_TAR) .

clean:
	rm -rf $(VPACKAGE_TAR) build-pkg

distclean:
	rm -rf ../RPMS

