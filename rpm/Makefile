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
RELEASE_SUFFIX=.$(shell ../get-platform-os)
endif

VPACKAGE=CGSI_gSOAP_2.7-$(VERSION)
VPACKAGE_TAR=$(VPACKAGE).tar.gz
BUILD_CGSI=build-rpm/BUILD/$(VPACKAGE)

all: rpm
	mkdir -p ../RPMS
	cp build-*/RPMS/*/*.rpm ../RPMS/
	cp build-*/SRPMS/*.rpm ../RPMS/

install: $(BUILD_CGSI)
	if [ ! -d "$(prefix)" ]; then mkdir -p "$(prefix)"; fi
	cd $(BUILD_CGSI); $(MAKE) PREFIX=$(prefix) install install.man

rpm: build-rpm 
	cd build-rpm; rpmbuild --define "_topdir $(PWD)/build-rpm" -ba SPECS/cgsi-gsoap.spec

build-rpm: $(VPACKAGE_TAR)
	mkdir -p build-rpm
	mkdir -p build-rpm/BUILD
	mkdir -p build-rpm/RPMS
	mkdir -p build-rpm/SRPMS
	mkdir -p build-rpm/SOURCES
	mkdir -p build-rpm/SPECS
	cp $(VPACKAGE_TAR) build-rpm/SOURCES/
	sed -e 's/@VERSION@/$(VERSION)/g;' \
	    -e 's/@RELEASE@/$(RELEASE)/g; ' \
	    -e 's/@RELEASE.SUFFIX@/$(RELEASE_SUFFIX)/g;' \
		cgsi-gsoap.spec >build-rpm/SPECS/cgsi-gsoap.spec
	cat ../RELEASE-NOTES >>build-rpm/SPECS/cgsi-gsoap.spec

$(VPACKAGE_TAR):
	cd ..; \
	rm -rf $(VPACKAGE); \
	mkdir -p $(VPACKAGE); \
	cp -ur configure RELEASE-NOTES VERSION src $(VPACKAGE)/; \
	find $(VPACKAGE)/ -name .svn -print0 | xargs -r -0 rm -rf; \
	tar -czf $(VPACKAGE_TAR) $(VPACKAGE); \
	rm -rf $(VPACKAGE)
	mv ../$(VPACKAGE_TAR) .

clean:
	rm -rf $(VPACKAGE_TAR) build-rpm

distclean:
	rm -rf ../RPMS

