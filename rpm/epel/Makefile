default: all

VERSION=1.3.4.2
PACKAGE=CGSI-gSOAP-$(VERSION)

all: src-rpm

rpm: pre-rpmbuild
	rpmbuild -ba --define "_topdir $(PWD)/build-rpm" build-rpm/SPECS/CGSI-gSOAP.spec

src-rpm: pre-rpmbuild
	rpmbuild -bs --nodeps --define "_topdir $(PWD)/build-rpm" build-rpm/SPECS/CGSI-gSOAP.spec
# and then to use mock: mock --rebuild $(PACKAGE).src.rpm

pre-rpmbuild: src
	mkdir -p build-rpm/{BUILD,RPMS,SRPMS,SOURCES,SPECS}
	cp ../../$(PACKAGE).tar.gz build-rpm/SOURCES
	cp *.spec build-rpm/SPECS

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
