Summary: GSI plugin for gSOAP
Name: CGSI_gSOAP_2.7
Version: @VERSION@
Release: @RELEASE@@RELEASE_SUFFIX@
Source0: CGSI_gSOAP_2.7-%{version}.tar.gz
Group: grid/lcg
BuildRoot: %{_builddir}/%{name}-%{version}-root
License: Apache-2.0
Prefix: /usr
Requires: @REQUIRES.GLOBUS@

%define __spec_install_post %{nil}
%define debug_package %{nil}
%define _unpackaged_files_terminate_build  %{nil}

%description
CGSI allows writing gSOAP clients with GSI authentication.
This package contains the shared libraries for the client
side.

%package -n CGSI_gSOAP_2.7-devel
Summary: GSI plugin for gSOAP -- development files
Group: grid/lcg
Requires: @REQUIRES.VOMS@
AutoReqProv: no
Obsoletes: CGSI_gSOAP_2.7-dev
%description -n CGSI_gSOAP_2.7-devel
CGSI allows writing gSOAP clients with GSI authentication.
This package contains the header and static library for
development.

%package -n CGSI_gSOAP_2.7-voms
Summary: GSI plugin for gSOAP -- VOMSified libraries
Group: grid/lcg
Requires: @REQUIRES.VOMS@
AutoReqProv: no
%description -n CGSI_gSOAP_2.7-voms
CGSI allows writing gSOAP clients with GSI authentication.
This package contains the VOMS enabled shared libraries for
the servers side.

%prep
%setup -q

%build
./configure ${EXTRA_CONFIGURE_OPTIONS}
make

%install 
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
mkdir -p ${RPM_BUILD_ROOT}%{prefix}/%{_lib}

make prefix=${RPM_BUILD_ROOT}%{prefix} install
make prefix=${RPM_BUILD_ROOT}%{prefix} install.man

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
%{prefix}/%{_lib}/libcgsi_plugin_gsoap_2.7*.so
%{prefix}/%{_lib}/libcgsi_plugin_gsoap_2.7*.so.*

%files -n CGSI_gSOAP_2.7-devel
%defattr(644,root,root)
%{prefix}/include/cgsi_plugin.h
%{prefix}/%{_lib}/libcgsi_plugin*.a
%doc %{prefix}/share/doc
%{prefix}/share/man/man3/cgsi_plugin.h.3

%files -n CGSI_gSOAP_2.7-voms
%defattr(-,root,root)
%{prefix}/%{_lib}/libcgsi_plugin_voms_gsoap_2.7*.so
%{prefix}/%{_lib}/libcgsi_plugin_voms_gsoap_2.7*.so.*

%post -n CGSI_gSOAP_2.7
if [ `uname -m` != x86_64 -o \( `uname -m` = x86_64 -a "%{_lib}" = lib64 \) ]; then
   if [ `grep -c ^%{prefix}/%{_lib} /etc/ld.so.conf` = 0 ]; then
      echo "%{prefix}/%{_lib}" >> /etc/ld.so.conf
   fi
fi

[ -x "/sbin/ldconfig" ] && /sbin/ldconfig

%postun -n CGSI_gSOAP_2.7
[ -x "/sbin/ldconfig" ] && /sbin/ldconfig

%changelog

