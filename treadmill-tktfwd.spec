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

%files
%defattr(-,root,root,-)
%{_sbindir}/ipa-ticket
%{_bindir}/tkt-recv
%{_bindir}/tkt-send
%{_bindir}/kt-add
%{_bindir}/kt-split
%{_bindir}/k-realm
%doc


%changelog
* Tue Apr 17 2018 Andrei Keis andreikeis@noreply.github.com - 2.0-2
- Initial RPM release.

