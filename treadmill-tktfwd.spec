Name:           treadmill-tktfwd
Version:        %{_version} 
Release:        %{_release}%{?dist}
Summary:        Treadmill treadmill-tktfwd utility.

License:        Apache 2.0
URL:            https://github.com/Morgan-Stanley/treadmill-tktfwd
Source0:        %{name}-%{version}.tar.gz 


%description
Treadmill ticket forwarding utilities.


%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}/tkt-recv
%{_bindir}/tkt-send
%{_bindir}/kt-add
%{_bindir}/kt-split
%{_sbindir}/ipa-ticket
%doc


%changelog
* Tue Apr 17 2018 Andrei Keis andreikeis@noreply.github.com - 2.0-2
- Initial RPM release.

