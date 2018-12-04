#-*- mode: python -*-
# vi:syntax=python
#
# WAF script
#

from src.localwaf import *

SRCDIR='src'

def options(opt):
    opt.add_option('--variant', action='store', default='prod',
                   help='build one of {}'.format(list(variants.keys())))
    opt.load('compiler_cxx')

def configure(conf):
    conf.recurse(SRCDIR)

def build(bld):
    bld.recurse(SRCDIR)

def rpmbuild(ctx):
    ctx.recurse(SRCDIR)
