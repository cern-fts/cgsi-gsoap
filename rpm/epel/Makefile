default: all

VERSION=1.3.4.2
PACKAGE=CGSI-gSOAP-$(VERSION)

all: rpm

rpm: src
	mkdir -p build-rpm
	mkdir -p build-rpm/BUILD
	mkdir -p build-rpm/RPMS
	mkdir -p build-rpm/SRPMS
	mkdir -p build-rpm/SOURCES
	mkdir -p build-rpm/SPECS
	cp ../../$(PACKAGE).tar.gz build-rpm/SOURCES
	cp *.spec build-rpm/SPECS
	rpmbuild -bs --nodeps --define "_topdir $(PWD)/build-rpm" build-rpm/SPECS/CGSI-gSOAP.spec

src: 	
	cd ../..; \
	rm -rf $(PACKAGE); \
	mkdir $(PACKAGE); \
	ls | grep -v $(PACKAGE) | xargs -I {} cp -R {} $(PACKAGE); \
	tar --exclude .svn -czf $(PACKAGE).tar.gz $(PACKAGE); \
	rm -rf $(PACKAGE); \
	cd -

clean: 
	rm -rf build-rpm
