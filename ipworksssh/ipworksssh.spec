Summary: IP*Works! SSH V9
Name: ipworksssh
Version: 9.0
Release: 5329
URL: www.nsoftware.com
Source: %{name}-%{version}.tar.gz
Packager: /n software inc. <support@nsoftware.com>
License: Copyright (c) 2014 /n software inc. - All rights reserved.
BuildRequires: gcc-c++ zlib-devel openssl openssl-devel
Prefix: %{_prefix}
Vendor: /n software inc.
%description
IP*Works! SSH V9

%prep
%setup -q
%build

cd src;make;

%install
mkdir -p $RPM_BUILD_ROOT/%{_prefix}/local/%{name}-%{version}/
cp -r -f * $RPM_BUILD_ROOT/%{_prefix}/local/%{name}-%{version}/


mkdir -p $RPM_BUILD_ROOT/usr/%{_lib}
cp lib/libipworksssh.so.9.0 $RPM_BUILD_ROOT/usr/%{_lib}
ln -f -s libipworksssh.so.9.0 $RPM_BUILD_ROOT/usr/%{_lib}/libipworksssh.so.9
ln -f -s libipworksssh.so.9.0 $RPM_BUILD_ROOT/usr/%{_lib}/libipworksssh.so


%files
%{_prefix}/local/%{name}-%{version}/
/usr/%{_lib}/libipworksssh.so.9.0
/usr/%{_lib}/libipworksssh.so.9
/usr/%{_lib}/libipworksssh.so

