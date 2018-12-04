#-*- mode: python -*-
# vi:syntax=python
#
# WAF and wscript pieces shared across scripts
#

from waflib import Build

global variants
variants = {
    'release': {'BINSUFFIX': '', 'CXXFLAGS': {'linux': ['-O2'], 'win32': ['/Ox']}},
    'debug': {'BINSUFFIX': '-g', 'CXXFLAGS': {'linux': ['-O0', '-g'], 'win32': ['/Zi']}}
}


class PackageContext(Build.InstallContext):
    def __init__(self, **kw):
        super(PackageContext, self).__init__(**kw)

    cmd = 'rpmbuild'
    fun = 'rpmbuild'
