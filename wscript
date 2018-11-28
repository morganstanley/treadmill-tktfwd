#-*- mode: python -*-
# vi:syntax=python
#
# WAF script
#

variants = {
    'release': {'BINSUFFIX': '', 'CXXFLAGS': {'linux': ['-O2'], 'win32': ['/Ox']}},
    'debug': {'BINSUFFIX': '-g', 'CXXFLAGS': {'linux': ['-O0', '-g'], 'win32': ['/Zi']}}
}

def options(opt):
    opt.add_option('--variant', action='store', default='debug',
                   help='build one of {}'.format(list(variants.keys())))
    opt.load('compiler_cxx')

def configure(conf):
    conf.recurse('src')

def build(bld):
    bld.recurse('src')
