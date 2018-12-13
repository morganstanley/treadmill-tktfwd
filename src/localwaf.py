#-*- mode: python -*-
# vi:syntax=python
#
# WAF and wscript pieces shared across scripts
#

from waflib import Build, Logs

import os, platform, shutil, sys, tarfile, tempfile

global variants
variants = {
    'release': {'BINSUFFIX': '', 'CXXFLAGS': {'linux': ['-O2'], 'win32': ['/Ox']}},
    'debug': {'BINSUFFIX': '-g', 'CXXFLAGS': {'linux': ['-O0', '-g'], 'win32': ['/Zi']}}
}


class PackageContext(Build.BuildContext):
    cmd = 'package'
    fun = 'package'

    def is_rpm_based(self):
        (distro, vers, id) = platform.linux_distribution() # TODO: Deprecated in 3.7...
        return any(distro.startswith(x) for x in ['Red Hat', 'Fedora', 'CentOS'])

    def rpmbuild_create_dir(self):
        tmp = tempfile.mkdtemp()
        Logs.info("Creating rpmbuild dir in {}...".format(tmp))
        rpmbuild = os.path.join(tmp, 'rpmbuild')
        for d in ['BUILD', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS']:
            os.makedirs(os.path.join(rpmbuild, d))
        return rpmbuild

    def rpmbuild_export_spec(self, targetdir):
        spec = str(RPM_SPEC)
        # FIXME: substitute in spec template

        fn = os.path.join(targetdir, 'treadmill-tktfwd.spec')
        with open(fn, 'w+') as fh:
            fh.write(spec)
        return fn


def package(ctx):
    '''Create a system specific package'''

    if sys.platform == 'linux':
        if not ctx.is_rpm_based():
            raise ctx.errors.WafError("No package support for distro '{}'".format(distro))

        rpmbuild = ctx.rpmbuild_create_dir()

        specfn = ctx.rpmbuild_export_spec(os.path.join(rpmbuild, 'SPECS'))
        # FIXME:
        # - create tar.gz of build/
        # - invoke rpmbuild itself
        # - profit
    elif sys.platform.startswith('win32'):
        raise ctx.errors.WafError('Windows package support unimplemented.')
    else:
        raise ctx.errors.WafError("Unknown platform '{}', no packaging available.".format(sys.platform))


RPM_SPEC = '''
Name:           treadmill-tktfwd
Version:        __PKG_VERSION__
Release:        __PKG_VERSION__
Summary:        Treadmill ticket forwarding utilities

License:        Apache 2.0
URL:            https://github.com/Morgan-Stanley/treadmill-tktfwd
Source:         %{name}-%{version}.tar.gz

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root

%description
Treadmill ticket forwarding utilities.


%prep
%setup -q

%build
# Empty build section

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_sbindir}/ipa-ticket
%{_bindir}/tkt-recv
%{_bindir}/tkt-send
%{_bindir}/kt-add
%{_bindir}/kt-split
%{_bindir}/k-realm
%doc

'''
