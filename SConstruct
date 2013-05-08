# -*- python -*-
#
# Copyright 2011-2012 Justin Erenkrantz and Greg Stein
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys
import os
import re

HEADER_FILES = ['serf.h',
                'serf_bucket_types.h',
                'serf_bucket_util.h',
                ]

# where we save the configuration variables
SAVED_CONFIG = '.saved_config'

opts = Variables(files=[SAVED_CONFIG])
opts.AddVariables(
  PathVariable('PREFIX',
               'Directory to install under',
               '/usr/local',
               PathVariable.PathIsDir),
  PathVariable('APR',
               "Path to apr-1-config, or to APR's install area",
               '/usr',
               PathVariable.PathAccept),
  PathVariable('APU',
               "Path to apu-1-config, or to APR's install area",
               '/usr',
               PathVariable.PathAccept),
  PathVariable('OPENSSL',
               "Path to OpenSSL's install area",
               '/usr',
               PathVariable.PathIsDir),
  PathVariable('GSSAPI',
               "Path to GSSAPI's install area",
               None,
               None),
  BoolVariable('DEBUG',
               "Enable debugging info and strict compile warnings",
               False),
  )

env = Environment(variables=opts,
                  tools=('default', 'textfile',),
                  CPPPATH=['.', ],
                  )

match = re.search('SERF_MAJOR_VERSION ([0-9]+).*'
                  'SERF_MINOR_VERSION ([0-9]+).*'
                  'SERF_PATCH_VERSION ([0-9]+)',
                  env.File('serf.h').get_contents(),
                  re.DOTALL)
MAJOR, MINOR, PATCH = [int(x) for x in match.groups()]
env.Append(MAJOR=str(MAJOR))


# HANDLING OF OPTION VARIABLES

unknown = opts.UnknownVariables()
if unknown:
  print 'Unknown variables:', ', '.join(unknown.keys())
  Exit(1)

apr = str(env['APR'])
if os.path.isdir(apr):
  apr = os.path.join(apr, 'bin', 'apr-1-config')
  env['APR'] = apr
apu = str(env['APU'])
if os.path.isdir(apu):
  apu = os.path.join(apu, 'bin', 'apu-1-config')
  env['APU'] = apu
gssapi = env.get('GSSAPI', None)
if gssapi and os.path.isdir(str(gssapi)):
  gssapi = os.path.join(gssapi, 'bin', 'krb5-config')
  env['GSSAPI'] = gssapi
debug = env.get('DEBUG', None)

Help(opts.GenerateHelpText(env))
opts.Save(SAVED_CONFIG, env)

env.Append(CPPPATH='$OPENSSL/include')
env.Append(LIBPATH='$OPENSSL/lib')


# PLATFORM-SPECIFIC BUILD TWEAKS

def link_rpath(d):
  if sys.platform == 'sunos5':
    return '-Wl,-R,%s' % (d,)
  return '-Wl,-rpath,%s' % (d,)


thisdir = os.getcwd()
libdir = '$PREFIX/lib'
incdir = '$PREFIX/include/serf-$MAJOR'

LIBNAME = 'libserf-${MAJOR}'

linkflags = [link_rpath(libdir,), ]
if sys.platform == 'darwin':
#  linkflags.append('-Wl,-install_name,@executable_path/%s.dylib' % (LIBNAME,))
  linkflags.append('-Wl,-install_name,%s/%s.dylib' % (thisdir, LIBNAME,))
  # 'man ld' says positive non-zero for the first number, so we add one.
  # Mac's interpretation of compatibility is the same as our MINOR version.
  linkflags.append('-Wl,-compatibility_version,%d' % (MINOR+1,))
  linkflags.append('-Wl,-current_version,%d.%d' % (MINOR+1, PATCH,))

if sys.platform == 'win32':
  ### we should create serf.def for Windows DLLs and add it into the link
  ### step somehow.
  pass

ccflags = [ ]
if 1:
  ### gcc only. figure out appropriate test / better way to check these
  ### flags, and check for gcc.
  ### -Wall is not available on Solaris
  ccflags = ['-std=c89', ]
  if sys.platform != 'sunos5':
    ccflags.append('-Wall')
  if debug:
    ccflags.append(['-g', '-Wmissing-prototypes'])
  else:
    ccflags.append('-O2')
libs = [ ]
if 1:
  ### works for Mac OS. probably needs to change
  libs = ['ssl', 'crypto', 'z', ]

  if sys.platform == 'sunos5':
    libs.append('m')

env.Replace(LINKFLAGS=linkflags,
            CCFLAGS=ccflags,
            LIBS=libs,
            )


# PLAN THE BUILD

SOURCES = Glob('*.c') + Glob('buckets/*.c') + Glob('auth/*.c')

lib_static = env.StaticLibrary(LIBNAME, SOURCES)
lib_shared = env.SharedLibrary(LIBNAME, SOURCES)

# Get apr/apu information into our build
### we should use --cc, but that is giving some scons error about an implict
### dependency upon gcc. probably ParseConfig doesn't know what to do with
### the apr-1-config output
env.ParseConfig('$APR --cflags --cppflags --ldflags --includes'
                ' --link-ld --libs')
env.ParseConfig('$APU --ldflags --includes --link-ld --libs')

# If build with gssapi, get its information and define SERF_HAVE_GSSAPI
if gssapi:
    env.ParseConfig('$GSSAPI --libs gssapi')
    env.Append(CFLAGS='-DSERF_HAVE_GSSAPI')

### there is probably a better way to run/capture output.
### env.ParseConfig() may be handy for getting this stuff into the build
apr_libs = os.popen(env.subst('$APR --link-libtool --libs')).read().strip()
apu_libs = os.popen(env.subst('$APU --link-libtool --libs')).read().strip()

# On Solaris, the -R values that APR describes never make it into actual
# RPATH flags. We'll manually map all directories in LIBPATH into new
# flags to set RPATH values.
if sys.platform == 'sunos5':
  for d in env['LIBPATH']:
    env.Append(LINKFLAGS=link_rpath(d))

# Set up the construction of serf-*.pc
# TODO: add gssapi libs
pkgconfig = env.Textfile('serf-%d.pc' % (MAJOR,),
                         env.File('build/serf.pc.in'),
                         SUBST_DICT = {
                           '@MAJOR@': str(MAJOR),
                           '@PREFIX@': '$PREFIX',
                           '@INCLUDE_SUBDIR@': 'serf-%d' % (MAJOR,),
                           '@VERSION@': '%d.%d.%d' % (MAJOR, MINOR, PATCH),
                           '@LIBS@': '%s %s -lz' % (apu_libs, apr_libs),
                           })

env.Default(lib_static, lib_shared, pkgconfig)

if not (env.GetOption('clean') or env.GetOption('help')):
  conf = Configure(env)

  ### some configuration stuffs

  env = conf.Finish()


# INSTALLATION STUFF

install_static = env.Install(libdir, lib_static)
install_shared = env.Install(libdir, lib_shared)

if sys.platform == 'darwin':
  install_shared_path = install_shared[0].abspath
  env.AddPostAction(install_shared, ('install_name_tool -id %s %s'
                                     % (install_shared_path,
                                        install_shared_path)))
  ### construct shared lib symlinks. this also means install the lib
  ### as libserf-2.1.0.0.dylib, then add the symlinks.
  ### note: see InstallAs

env.Alias('install-lib', [install_static, install_shared,
                          ])
env.Alias('install-inc', env.Install(incdir, HEADER_FILES))
env.Alias('install-pc', env.Install(os.path.join(libdir, 'pkgconfig'),
                                    pkgconfig))
env.Alias('install', ['install-lib', 'install-inc', 'install-pc', ])


# TESTS
### make move to a separate scons file in the test/ subdir?

tenv = env.Clone()

TEST_PROGRAMS = [
  'test/serf_get',
  'test/serf_response',
  'test/serf_request',
  'test/serf_spider',
  'test/test_all',
]

env.AlwaysBuild(env.Alias('check', TEST_PROGRAMS, 'build/check.sh'))

# Find the (dynamic) library in this directory
linkflags = [link_rpath(thisdir,), ]
tenv.Replace(LINKFLAGS=linkflags)
tenv.Prepend(LIBS=['libserf-2', ],
             LIBPATH=[thisdir, ])

for proggie in TEST_PROGRAMS:
  if proggie.endswith('test_all'):
    tenv.Program('test/test_all', [
        'test/test_all.c',
        'test/CuTest.c',
        'test/test_util.c',
        'test/test_context.c',
        'test/test_buckets.c',
        'test/mock_buckets.c',
        'test/test_ssl.c',
        'test/server/test_server.c',
        'test/server/test_sslserver.c',
        ])
  else:
    tenv.Program(proggie, [proggie + '.c'])


# HANDLE CLEANING

if env.GetOption('clean'):
  # When we're cleaning, we want the dependency tree to include "everything"
  # that could be built. Thus, include all of the tests.
  env.Default('check')
