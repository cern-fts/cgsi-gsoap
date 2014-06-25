Name:		CGSI-gSOAP
Version:	1.3.6
Release:	1%{?dist}
Summary:	GSI plugin for gSOAP

Group:		System Environment/Libraries
License:	ASL 2.0
URL:		http://glite.web.cern.ch/glite/
#		The source tarfile is created from a subversion checkout:
#		svn co http://svnweb.cern.ch/guest/lcgutil/cgsi-gsoap/tags/cgsi-gsoap_R_1_3_4_2 CGSI-gSOAP-1.3.4.2
#		tar --exclude .svn -z -c -f CGSI-gSOAP-1.3.4.2.tar.gz CGSI-gSOAP-1.3.4.2
Source0:	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	globus-gss-assist-devel%{?_isa}
BuildRequires:	globus-gssapi-gsi-devel%{?_isa}
BuildRequires:	gsoap-devel%{?_isa}
BuildRequires:	voms-devel%{?_isa}
BuildRequires:	doxygen

%description
This is a GSI plugin for gSOAP. It uses the globus GSI libraries to implement
GSI secure authentication and encryption on top of gSOAP.

%package devel
Summary:	GSI plugin for gSOAP - development files
Group:		Development/Libraries
Requires:	%{name}%{?_isa} = %{version}-%{release}
Requires:	gsoap-devel

%description devel
This package provides the header files for programming with the cgsi-gsoap
plugins.

%prep
%setup -q

# Fix bad permissions (which otherwise end up in the debuginfo package)
find . '(' -name '*.h' -o -name '*.c' -o -name '*.cpp' -o -name '*.cc' ')' \
    -exec chmod 644 {} ';'
chmod 644 LICENSE RELEASE-NOTES

# Remove -L/usr/lib and -L/usr/lib64 since they may cause problems
sed -e 's!-L$([A-Z_]*)/lib!!' \
    -e 's!-L$([A-Z_]*)/$(LIBDIR)!!' -i src/Makefile

# Remove gsoap version from library names
sed -e 's!$(GSOAP_VERSION)!!g' -i src/Makefile

%build
. ./VERSION
cd src
make CFLAGS="%optflags -fPIC -I. `pkg-config --cflags gsoap`" \
     USE_VOMS=yes WITH_EMI=yes WITH_CPP_LIBS=yes \
     LIBDIR=%{_lib} VERSION=$VERSION all doc

%install
rm -rf $RPM_BUILD_ROOT

. ./VERSION
cd src
make CFLAGS="%optflags -fPIC -I. `pkg-config --cflags gsoap`" \
     USE_VOMS=yes WITH_EMI=yes WITH_CPP_LIBS=yes \
     LIBDIR=%{_lib} VERSION=$VERSION install install.man

mkdir -p $RPM_BUILD_ROOT%{_docdir}/%{name}-devel-%{version}
mv $RPM_BUILD_ROOT%{_datadir}/doc/CGSI \
   $RPM_BUILD_ROOT%{_docdir}/%{name}-devel-%{version}

rm $RPM_BUILD_ROOT%{_libdir}/*.a

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/libcgsi_plugin.so.*
%{_libdir}/libcgsi_plugin_cpp.so.*
%{_libdir}/libcgsi_plugin_voms.so.*
%{_libdir}/libcgsi_plugin_voms_cpp.so.*
%doc LICENSE RELEASE-NOTES

%files devel
%defattr(-,root,root,-)
%{_includedir}/cgsi_plugin.h
%{_libdir}/libcgsi_plugin.so
%{_libdir}/libcgsi_plugin_cpp.so
%{_libdir}/libcgsi_plugin_voms.so
%{_libdir}/libcgsi_plugin_voms_cpp.so
%doc %{_docdir}/%{name}-devel-%{version}
%doc %{_mandir}/man*/*

%changelog
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
