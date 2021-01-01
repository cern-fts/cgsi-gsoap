Name:		CGSI-gSOAP
Version:	1.3.11
Release:	1%{?dist}
Summary:	GSI plugin for gSOAP

License:	ASL 2.0
URL:		https://dmc-docs.web.cern.ch/dmc-docs/cgsi-gsoap.html
#		The source tarfile is created from a repository checkout:
#		git clone https://gitlab.cern.ch/dmc/cgsi-gsoap.git
#		cd cgsi-gsoap
#		git archive --prefix CGSI-gSOAP-1.3.11/ -o CGSI-gSOAP-1.3.11.tar.gz v1.3.11
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	gcc-c++
BuildRequires:	make
BuildRequires:	globus-gss-assist-devel
BuildRequires:	globus-gssapi-gsi-devel
BuildRequires:	gsoap-devel
BuildRequires:	voms-devel
BuildRequires:	doxygen

%description
This is a GSI plugin for gSOAP. It uses the globus GSI libraries to implement
GSI secure authentication and encryption on top of gSOAP.

%package devel
Summary:	GSI plugin for gSOAP - development files
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	gsoap-devel

%description devel
This package provides the header files for programming with the cgsi-gsoap
plugins.

%prep
%setup -q

%build
cd src
%make_build \
     USE_VOMS=yes WITH_CPP_LIBS=yes \
     CFLAGS="%{build_cflags} -fPIC -I. $(pkg-config --cflags gsoap)" \
     SHLIBLDFLAGS="%{build_ldflags} -shared" \
     LIBDIR=%{_lib} \
     all doc

%install
pushd src
%make_install \
     USE_VOMS=yes WITH_CPP_LIBS=yes \
     LIBDIR=%{_lib} \
     DOCDIR=$(sed 's!^%{_prefix}/!!' <<< %{_pkgdocdir}) \
     install.man
popd
install -p -m 644 RELEASE-NOTES %{buildroot}%{_pkgdocdir}
rm %{buildroot}%{_libdir}/*.a

%ldconfig_scriptlets

%files
%{_libdir}/libcgsi_plugin.so.*
%{_libdir}/libcgsi_plugin_cpp.so.*
%{_libdir}/libcgsi_plugin_voms.so.*
%{_libdir}/libcgsi_plugin_voms_cpp.so.*
%dir %{_pkgdocdir}
%doc %{_pkgdocdir}/RELEASE-NOTES
%license LICENSE

%files devel
%{_includedir}/cgsi_plugin.h
%{_libdir}/libcgsi_plugin.so
%{_libdir}/libcgsi_plugin_cpp.so
%{_libdir}/libcgsi_plugin_voms.so
%{_libdir}/libcgsi_plugin_voms_cpp.so
%doc %{_pkgdocdir}/html
%doc %{_mandir}/man*/*

%changelog
* Wed May 30 2018 Oliver Keeble <oliver.keeble@cern.ch> - 1.3.11-1
- New upstream release

* Thu Sep 22 2016 Alejandro Alvarez Ayllon <aalvarez@cern.ch> - 1.3.10-1
- Update for new upstream release

* Wed Aug 12 2015 Alejandro Alvarez Ayllon <aalvarez@cern.ch> - 1.3.8-1
- Update for new upstream release

* Thu Nov 06 2014 Alejandro Alvarez Ayllon <aalvarez@cern.ch> - 1.3.7-1
- Update for new upstream release

* Wed Jun 25 2014 Alejandro Alvarez <aalvarez@cern.ch> - 1.3.6-1
- Up for new upstream release

* Mon Apr 02 2012 Ricardo Rocha <ricardo.rocha@cern.ch> - 1.3.5-1
- Up for new upstream release

* Thu Sep 01 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.3.4.2-2
- Use gsoap cflags from pkg-config

* Mon Jun 20 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.3.4.2-1
- Update to version 1.3.4.2

* Mon Feb 07 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.3.4.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Mon Dec 20 2010 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.3.4.0-1
- Update to version 1.3.4.0

* Thu Nov 12 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.3.3.2-2.20090920cvs
- Use cvs checkout date in release tag
- Drop Provides/Obsoletes for the old package name since it was never in Fedora

* Wed Sep 23 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.3.3.2-1
- Update to version 1.3.3.2
- Drop the patch - all issues fixed upstream
- Change License tag to Apache 2.0

* Fri Aug 14 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.3.3.1-1
- Update to version 1.3.3.1

* Tue Jun 30 2009 Anders Wäänänen <waananen@nbi.dk> - 1.3.2.2-4
- Fix docdir handling

* Wed Jan 14 2009 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.3.2.2-3
- Rebuild against distribution Globus

* Wed Nov 19 2008 Anders Wäänänen <waananen@nbi.dk> - 1.3.2.2-2
- Update patch to use $(CPP) instead of ld (2 places)

* Sun Oct 26 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.3.2.2-1
- Update to version 1.3.2.2

* Fri Jan 11 2008 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.2.1.2-1
- Update to version 1.2.1.2

* Tue Jul 24 2007 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.1.17.2-2
- Rebuild against newer globus and voms

* Wed May  9 2007 Mattias Ellert <mattias.ellert@fysast.uu.se> - 1.1.17.2-1
- Initial build
