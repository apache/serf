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

# Variable class that does no validation on the input
def _converter(val):
    """
    """
    if val == 'none':
      val = []
    else:
      val = val.split(',')
    return val

def RawListVariable(key, help, default):
    """
    The input parameters describe a 'raw string list' option. This class
    accepts a comma separated list and converts it to a space separated
    list.
    """
    return (key, '%s' % (help), default, None, lambda val: _converter(val))

# default directories
if sys.platform == 'win32':
  default_libdir='..'
  default_prefix='Debug'
else:
  default_libdir='/usr'
  default_prefix='/usr/local'

opts = Variables(files=[SAVED_CONFIG])
opts.AddVariables(
  PathVariable('PREFIX',
               'Directory to install under',
               default_prefix,
               PathVariable.PathIsDir),
  PathVariable('APR',
               "Path to apr-1-config, or to APR's install area",
               default_libdir,
               PathVariable.PathAccept),
  PathVariable('APU',
               "Path to apu-1-config, or to APR's install area",
               default_libdir,
               PathVariable.PathAccept),
  PathVariable('OPENSSL',
               "Path to OpenSSL's install area",
               default_libdir,
               PathVariable.PathIsDir),
  PathVariable('ZLIB',
               "Path to zlib's install area",
               default_libdir,
               PathVariable.PathIsDir),
  PathVariable('GSSAPI',
               "Path to GSSAPI's install area",
               None,
               None),
  BoolVariable('DEBUG',
               "Enable debugging info and strict compile warnings",
               False),
  BoolVariable('APR_STATIC',
               "Enable using a static compiled APR",
               False),
  RawListVariable('CC', "Command name or path of the C compiler", None),
  RawListVariable('CFLAGS', "Extra flags for the C compiler (comma separated)",
                  ''),
  RawListVariable('LINKFLAGS', "Extra flags for the linker (comma separated)",
                  ''),
  RawListVariable('LIBS', "Extra libraries passed to the linker, "
                  "e.g. -l<library> (comma separated)", ''),
  RawListVariable('CPPFLAGS', "Extra flags for the C preprocessor "
                  "(comma separated)", ''), 
  )

env = Environment(variables=opts,
                  tools=('default', 'textfile',),
                  CPPPATH=['.', ],
                  )

env.Append(BUILDERS = {
    'GenDef' : 
      Builder(action = sys.executable + ' build/gen_def.py $SOURCES > $TARGET',
              suffix='.def', src_suffix='.h')
  })

match = re.search('SERF_MAJOR_VERSION ([0-9]+).*'
                  'SERF_MINOR_VERSION ([0-9]+).*'
                  'SERF_PATCH_VERSION ([0-9]+)',
                  env.File('serf.h').get_contents(),
                  re.DOTALL)
MAJOR, MINOR, PATCH = [int(x) for x in match.groups()]
env.Append(MAJOR=str(MAJOR))

# Calling external programs is okay if we're not cleaning or printing help.
# (cleaning: no sense in fetching information; help: we may not know where
# they are)
CALLOUT_OKAY = not (env.GetOption('clean') or env.GetOption('help'))


# HANDLING OF OPTION VARIABLES

unknown = opts.UnknownVariables()
if unknown:
  print 'Unknown variables:', ', '.join(unknown.keys())
  Exit(1)

apr = str(env['APR'])
apu = str(env['APU'])
zlib = str(env['ZLIB'])
gssapi = env.get('GSSAPI', None)

if gssapi and os.path.isdir(gssapi):
  krb5_config = os.path.join(gssapi, 'bin', 'krb5-config')
  if os.path.isfile(krb5_config):
    gssapi = krb5_config
    env['GSSAPI'] = krb5_config

debug = env.get('DEBUG', None)
aprstatic = env.get('APR_STATIC', None)

Help(opts.GenerateHelpText(env))
opts.Save(SAVED_CONFIG, env)


# PLATFORM-SPECIFIC BUILD TWEAKS

thisdir = os.getcwd()
libdir = '$PREFIX/lib'
incdir = '$PREFIX/include/serf-$MAJOR'

LIBNAME = 'libserf-${MAJOR}'
if sys.platform != 'win32':
  LIBNAMESTATIC = LIBNAME
else:
  LIBNAMESTATIC = 'serf-${MAJOR}'

env.append(RPATH=libdir)

if sys.platform == 'darwin':
#  linkflags.append('-Wl,-install_name,@executable_path/%s.dylib' % (LIBNAME,))
  env.Append(LINKFLAGS='-Wl,-install_name,%s/%s.dylib' % (thisdir, LIBNAME,))
  # 'man ld' says positive non-zero for the first number, so we add one.
  # Mac's interpretation of compatibility is the same as our MINOR version.
  env.Append(LINKFLAGS='-Wl,-compatibility_version,%d' % (MINOR+1,))
  env.Append(LINKFLAGS='-Wl,-current_version,%d.%d' % (MINOR+1, PATCH,))

if sys.platform != 'win32':
  ### gcc only. figure out appropriate test / better way to check these
  ### flags, and check for gcc.
  env.Append(CCFLAGS=[
               '-std=c89',
               '-Wdeclaration-after-statement',
               '-Wmissing-prototypes',
             ])

  ### -Wall is not available on Solaris
  if sys.platform != 'sunos5': 
    env.Append(CCFLAGS='-Wall')

  if debug:
    env.Append(CCFLAGS='-g')
  else:
    env.Append(CCFLAGS='-O2')
else:
  # Warning level 4, no unused argument warnings
  env.Append(CCFLAGS=['/W4', '/wd4100'])
  if debug:
    # Disable optimizations for debugging, use debug DLL runtime
    env.Append(CCFLAGS=['/Od', '/MDd'])
  else:
    # Optimize for speed, use DLL runtime
    env.Append(CCFLAGS=['/O2', '/MD'])
  
if sys.platform != 'win32':
  ### works for Mac OS. probably needs to change
  env.Append(LIBS=['ssl', 'crypto', 'z', ])

  if sys.platform == 'sunos5':
    env.Append(LIBS='m')

# PLAN THE BUILD
SHARED_SOURCES = []
if sys.platform == 'win32':
  env.GenDef(['serf.h','serf_bucket_types.h', 'serf_bucket_util.h'])
  SHARED_SOURCES.append(['serf.def'])

SOURCES = Glob('*.c') + Glob('buckets/*.c') + Glob('auth/*.c')

lib_static = env.StaticLibrary(LIBNAMESTATIC, SOURCES)
lib_shared = env.SharedLibrary(LIBNAME, SOURCES + SHARED_SOURCES)

if aprstatic:
  env.Append(CPPDEFINES=['APR_DECLARE_STATIC', 'APU_DECLARE_STATIC'])

if sys.platform == 'win32':
  env.Append(LIBS=['user32.lib', 'advapi32.lib', 'gdi32.lib', 'ws2_32.lib',
                   'crypt32.lib', 'mswsock.lib', 'rpcrt4.lib', 'secur32.lib'])

  # Get apr/apu information into our build
  
  env.Append(CPPPATH=['$APR/include','$APU/include'])
  env.Append(CPPDEFINES=['WIN32','WIN32_LEAN_AND_MEAN','NOUSER',
                        'NOGDI','NONLS','NOCRYPT'])
  if aprstatic:
    env.Append(LIBPATH=['$APR/LibR','$APU/LibR'],
               LIBS=['apr-1.lib', 'aprutil-1.lib'])
  else:
    env.Append(LIBPATH=['$APR/Release','$APU/Release'],
               LIBS=['libapr-1.lib', 'libaprutil-1.lib'])
  apr_libs='libapr-1.lib'
  apu_libs='libaprutil-1.lib'

  # zlib
  env.Append(CPPPATH='$ZLIB',
             LIBPATH='$ZLIB',
             LIBS='zlib.lib')

  # openssl
  env.Append(CPPPATH='$OPENSSL/inc32')
  env.Append(LIBPATH='$OPENSSL/out32dll', LIBS=['libeay32.lib', 'ssleay32.lib'])

else:
  if os.path.isdir(apr):
    apr = os.path.join(apr, 'bin', 'apr-1-config')
    env['APR'] = apr
  if os.path.isdir(apu):
    apu = os.path.join(apu, 'bin', 'apu-1-config')
    env['APU'] = apu

  ### we should use --cc, but that is giving some scons error about an implict
  ### dependency upon gcc. probably ParseConfig doesn't know what to do with
  ### the apr-1-config output
  if CALLOUT_OKAY:
    env.ParseConfig('$APR --cflags --cppflags --ldflags --includes'
                    ' --link-ld --libs')
    env.ParseConfig('$APU --ldflags --includes --link-ld --libs')

  ### there is probably a better way to run/capture output.
  ### env.ParseConfig() may be handy for getting this stuff into the build
  if CALLOUT_OKAY:
    apr_libs = os.popen(env.subst('$APR --link-libtool --libs')).read().strip()
    apu_libs = os.popen(env.subst('$APU --link-libtool --libs')).read().strip()
  else:
    apr_libs = ''
    apu_libs = ''
  
  env.Append(CPPPATH='$OPENSSL/include')
  env.Append(LIBPATH='$OPENSSL/lib')


# If build with gssapi, get its information and define SERF_HAVE_GSSAPI
if gssapi and CALLOUT_OKAY:
    env.ParseConfig('$GSSAPI --libs gssapi')
    env.Append(CPPDEFINES='SERF_HAVE_GSSAPI')
if sys.platform == 'win32':
  env.Append(CPPDEFINES=['SERF_HAVE_SPNEGO', 'SERF_HAVE_SSPI'])

# On Solaris, the -R values that APR describes never make it into actual
# RPATH flags. We'll manually map all directories in LIBPATH into new
# flags to set RPATH values.
if sys.platform == 'sunos5':
  for d in env['LIBPATH']:
    env.Append(RPATH=d)

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

if CALLOUT_OKAY:
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

TEST_PROGRAMS = [ 'serf_get', 'serf_response', 'serf_request', 'serf_spider',
                  'test_all', 'serf_bwtp' ]
if sys.platform == 'win32':
  TEST_EXES = [ os.path.join('test', '%s.exe' % (prog)) for prog in TEST_PROGRAMS ]
else:
  TEST_EXES = [ os.path.join('test', '%s' % (prog)) for prog in TEST_PROGRAMS ]

env.AlwaysBuild(env.Alias('check', TEST_EXES, 'build/check.sh'))

# Find the (dynamic) library in this directory
tenv.Replace(RPATH=thisdir)
tenv.Prepend(LIBS=[LIBNAME, ],
             LIBPATH=[thisdir, ])

testall_files = [
        'test/test_all.c',
        'test/CuTest.c',
        'test/test_util.c',
        'test/test_context.c',
        'test/test_buckets.c',
        'test/test_auth.c',
        'test/mock_buckets.c',
        'test/test_ssl.c',
        'test/server/test_server.c',
        'test/server/test_sslserver.c',
        ]

# test_all uses some private functions. Rather then adding them to serf.def,
# include the files implementing these functions as dependencies for test_all.
# This only impacts the Windows build, on all other platforms these functions
# are public in the serf library.
if sys.platform == 'win32':
  testall_files += [
        env.Object('buckets/buckets.c'),
        env.Object('buckets/aggregate_buckets.c'),
        env.Object('buckets/response_buckets.c'),
        ]

for proggie in TEST_EXES:
  if 'test_all' in proggie:
    tenv.Program(proggie, testall_files )
  else:
    tenv.Program(target = proggie, source = [proggie.replace('.exe','') + '.c'])


# HANDLE CLEANING

if env.GetOption('clean'):
  # When we're cleaning, we want the dependency tree to include "everything"
  # that could be built. Thus, include all of the tests.
  env.Default('check')
