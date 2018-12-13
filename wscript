#-*- mode: python -*-
# vi:syntax=python
#
# WAF script
#

import platform
from datetime import datetime
from src.localwaf import *
from waflib import Context, Errors

#FIXME
#from IPython.core.debugger import Pdb
import pdb

SRCDIR='src'

def options(opt):
    opt.add_option('--variant', action='store', default='prod',
                   help='build one of {}'.format(list(variants.keys())))
    opt.load('compiler_cxx')

def configure(conf):
    if not conf.env.VERSION:
        ver = 'unknown_{}_{}'.format(platform.node(),
                                     datetime.strftime(datetime.now(), '%Y%m%d.%H%M%S'))
        conf.env.append_value('VERSION', ver)
    conf.msg('VERSION', conf.env.VERSION) #FIXME
    conf.recurse(SRCDIR)

def build(bld):
    bld.recurse(SRCDIR)
    
# def packageRPM(ctx):
#     pdb.set_trace()

#     try:
#         tgz = 'build/treadmill-tktfwd-{}.tar.gz'.format(ctx.env.VERSION[0])
#         #FIXME: create tar gz
#         cmd = ['rpmbuild',
#                '-D "_version {}"'.format(ctx.env.VERSION[0]),
#                '-v',
#                '-bb',
#                '{}/treadmill-tktfwd.spec'.format(ctx.install_path)]
#         (out, err) = ctx.cmd_and_log(cmd, shell=True, output=Context.BOTH)
#         print('DEBUG RPM STDOUT: ', out)
#         print('DEBUG RPM STDERR: ', err)
#     except Errors.WafError as e:
#         print(e.stdout, e.stderr)
