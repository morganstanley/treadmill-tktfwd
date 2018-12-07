#-*- mode: python -*-
# vi:syntax=python
#
# WAF script
#

import platform
from datetime import datetime
from src.localwaf import *
from waflib import Context, Errors

SRCDIR='src'

def options(opt):
    opt.add_option('--variant', action='store', default='prod',
                   help='build one of {}'.format(list(variants.keys())))
    opt.load('compiler_cxx')

def configure(conf):
    if not conf.env.VERSION:
        ver = 'unknown@{}_{}'.format(platform.node(),
                                     datetime.strftime(datetime.now(), '%Y%m%d.%H%M%S'))
        conf.env.append_value('VERSION', ver)
        conf.msg('VERSION', conf.env.VERSION)

    conf.recurse(SRCDIR)

def build(bld):
    bld.recurse(SRCDIR)

def rpmbuild(ctx):
    tgz = 'build/treadmill-tktfwd-{}.tar.gz'.format(ctx.env.VERSION[0])

    try:
        cmd = ['rpmbuild',
               '-D VERSION={}'.format(ctx.env.VERSION[0]),
               '-v',
               '-bb',
               'treadmill-tktfwd.spec']
        (out, err) = ctx.cmd_and_log(cmd, shell=True, output=Context.BOTH)
        print('STDOUT: ', out)
        print('STDERR: ', err)
    except Errors.WafError as e:
        print(e.stdout, e.stderr)
