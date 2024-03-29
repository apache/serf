# -*- python -*-
#
# ====================================================================
#    Licensed to the Apache Software Foundation (ASF) under one
#    or more contributor license agreements.  See the NOTICE file
#    distributed with this work for additional information
#    regarding copyright ownership.  The ASF licenses this file
#    to you under the Apache License, Version 2.0 (the
#    "License"); you may not use this file except in compliance
#    with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing,
#    software distributed under the License is distributed on an
#    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#    KIND, either express or implied.  See the License for the
#    specific language governing permissions and limitations
#    under the License.
# ====================================================================
#

import sys
import os
import re

EnsureSConsVersion(2,3,0)

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
      val = val.split(' ')
    return val

def RawListVariable(key, help, default):
    """
    The input parameters describe a 'raw string list' option. This class
    accepts a space-separated string and converts it to a list.
    """
    return (key, '%s' % (help), default, None, lambda val: _converter(val))

# Custom path validator, creates directory when a specified option is set.
# To be used to ensure a PREFIX directory is only created when installing.
def createPathIsDirCreateWithTarget(target):
  def my_validator(key, val, env):
    build_targets = (map(str, BUILD_TARGETS))
    if target in build_targets:
      return PathVariable.PathIsDirCreate(key, val, env)
    else:
      return PathVariable.PathAccept(key, val, env)
  return my_validator

# default directories
if sys.platform == 'win32':
  default_incdir='..'
  default_libdir='..'
  default_prefix='Debug'
else:
  default_incdir='/usr'
  default_libdir='$PREFIX/lib'
  default_prefix='/usr/local'

opts = Variables(files=[SAVED_CONFIG])
opts.AddVariables(
  PathVariable('PREFIX',
               'Directory to install under',
               default_prefix,
               createPathIsDirCreateWithTarget('install')),
  PathVariable('LIBDIR',
               'Directory to install architecture dependent libraries under',
               default_libdir,
               createPathIsDirCreateWithTarget('install')),
  PathVariable('APR',
               "Path to apr-1-config, or to APR's install area",
               default_incdir,
               PathVariable.PathAccept),
  PathVariable('APU',
               "Path to apu-1-config, or to APR's install area",
               default_incdir,
               PathVariable.PathAccept),
  PathVariable('EXPAT',
               "Path to Expat's install area, used with APR_STATIC",
               None,
               PathVariable.PathIsDir),
  PathVariable('OPENSSL',
               "Path to OpenSSL's install area",
               default_incdir,
               PathVariable.PathIsDir),
  PathVariable('ZLIB',
               "Path to zlib's install area",
               default_incdir,
               PathVariable.PathIsDir),
  PathVariable('GSSAPI',
               "Path to GSSAPI's install area",
               None,
               None),
  PathVariable('BROTLI',
               "Path to Brotli's install area",
               None,
               PathVariable.PathIsDir),
  BoolVariable('DEBUG',
               "Enable debugging info and strict compile warnings",
               False),
  BoolVariable('APR_STATIC',
               "Enable using a static compiled APR on Windows",
               False),
  BoolVariable('DISABLE_LOGGING',
               "Disable the logging framework at compile time",
               False),
  BoolVariable('ENABLE_SLOW_TESTS',
               "Enable long-running unit tests",
               False),
  RawListVariable('CC', "Command name or path of the C compiler", None),
  RawListVariable('CFLAGS', "Extra flags for the C compiler (space-separated)",
                  None),
  RawListVariable('LIBS', "Extra libraries passed to the linker, "
                  "e.g. \"-l<library1> -l<library2>\" (space separated)", None),
  RawListVariable('LINKFLAGS', "Extra flags for the linker (space-separated)",
                  None),
  RawListVariable('CPPFLAGS', "Extra flags for the C preprocessor "
                  "(space separated)", None),
  )

if sys.platform == 'win32':
  opts.AddVariables(
    # By default SCons builds for the host platform on Windows, when using
    # a supported compiler (E.g. VS2010/VS2012). Allow overriding

    # Note that Scons 1.3 only supports this on Windows and only when
    # constructing Environment(). Later changes to TARGET_ARCH are ignored
    EnumVariable('TARGET_ARCH',
                 "Platform to build for",
                 'x86',
                 allowed_values=('x86', 'x86_64', 'ia64'),
                 map={'X86'  : 'x86',
                      'win32': 'x86',
                      'Win32': 'x86',
                      'x64'  : 'x86_64',
                      'X64'  : 'x86_64'
                     }),

    EnumVariable('MSVC_VERSION',
                 "Visual C++ to use for building",
                 None,
                 allowed_values=('14.3', '14.2', '14.1', '14.0', '12.0',
                                 '11.0', '10.0', '9.0', '8.0', '6.0'),
                 map={'2005' :  '8.0',
                      '2008' :  '9.0',
                      '2010' : '10.0',
                      '2012' : '11.0',
                      '2013' : '12.0',
                      '2015' : '14.0',
                      '2017' : '14.1',
                      '2019' : '14.2',
                      '2022' : '14.3',
                     }),

    # We always documented that we handle an install layout, but in fact we
    # hardcoded source layouts. Allow disabling this behavior.
    # ### Fix default?
    BoolVariable('SOURCE_LAYOUT',
                 "Assume a source layout instead of install layout",
                 True),
    )

env = Environment(variables=opts,
                  tools=('default', 'textfile',),
                  CPPPATH=['.', ],
                  )

gen_def_script = env.File('build/gen_def.py').rstr()

env.Append(BUILDERS = {
    'GenDef' :
      Builder(action = '"%s" "%s" $SOURCES > $TARGET' % (sys.executable, gen_def_script,),
              suffix='.def', src_suffix='.h')
  })

match = re.search('SERF_MAJOR_VERSION ([0-9]+).*'
                  'SERF_MINOR_VERSION ([0-9]+).*'
                  'SERF_PATCH_VERSION ([0-9]+)',
                  env.File('serf.h').get_contents().decode('utf-8'),
                  re.DOTALL)
MAJOR, MINOR, PATCH = [int(x) for x in match.groups()]
env.Append(MAJOR=str(MAJOR))
env.Append(MINOR=str(MINOR))
env.Append(PATCH=str(PATCH))

# Calling external programs is okay if we're not cleaning or printing help.
# (cleaning: no sense in fetching information; help: we may not know where
# they are)
CALLOUT_OKAY = not (env.GetOption('clean') or env.GetOption('help'))


# HANDLING OF OPTION VARIABLES

unknown = opts.UnknownVariables()
if unknown:
  print('Warning: Used unknown variables:', ', '.join(unknown.keys()))

apr = str(env['APR'])
apu = str(env['APU'])
zlib = str(env['ZLIB'])
expat = env.get('EXPAT', None)
gssapi = env.get('GSSAPI', None)
brotli = env.get('BROTLI', None)

if gssapi and os.path.isdir(gssapi):
  krb5_config = os.path.join(gssapi, 'bin', 'krb5-config')
  if os.path.isfile(krb5_config):
    gssapi = krb5_config
    env['GSSAPI'] = krb5_config

debug = env.get('DEBUG', None)
aprstatic = env.get('APR_STATIC', None)
disablelogging = env.get('DISABLE_LOGGING', None)

Help(opts.GenerateHelpText(env))
opts.Save(SAVED_CONFIG, env)


# PLATFORM-SPECIFIC BUILD TWEAKS

thisdir = os.getcwd()
libdir = '$LIBDIR'
incdir = '$PREFIX/include/serf-$MAJOR'

# This version string is used in the dynamic library name, and for Mac OS X also
# for the compatibility_version option in the .dylib.
soversion = '%d.%d.%d' % (MAJOR, MINOR, 0)
libversion = '%d.%d.%d' % (MAJOR, MINOR, PATCH)
if sys.platform != 'sunos5':
  env['SHLIBVERSION'] = soversion

# XXX Since SCons 2.4.1, the SHLIBVERSION variable is no longer used to set the
# shared library versions on Mac OS X, so we add explicit linker flags to set
# the current_version and compatibility_version options.
if sys.platform == 'darwin':
  env.Append(LINKFLAGS=['-Wl,-current_version,' + libversion,
                        '-Wl,-compatibility_version,' + soversion])

LIBNAME   = '%sserf-%d' % (env['LIBPREFIX'], MAJOR)
if sys.platform == 'win32':
  # On Win32 SHLIBPREFIX and LIBPREFIX are empty and both produce a .lib file.
  SHLIBNAME = 'libserf-%d' % (MAJOR, )
elif env['SHLIBPREFIX'] == '$LIBPREFIX':
  # Let's avoid constructing '$LIBPREFIXserf...' which evaluates to ''
  SHLIBNAME = LIBNAME
else:
  SHLIBNAME = '%sserf-%d' % (env['SHLIBPREFIX'], MAJOR)

env.Append(RPATH=[libdir],
           PDB='${TARGET.filebase}.pdb')

if sys.platform != 'win32':
  def CheckGnuCC(context):
    src = '''
    #ifndef __GNUC__
    oh noes!
    #endif
    '''
    context.Message('Checking for GNU-compatible C compiler...')
    result = context.TryCompile(src, '.c')
    context.Result(result)
    return result

  conf = Configure(env, custom_tests = dict(CheckGnuCC=CheckGnuCC))
  have_gcc = conf.CheckGnuCC()
  env = conf.Finish()

  if have_gcc:
    env.Append(CFLAGS=['-std=c89'])
    env.Append(CCFLAGS=['-Wdeclaration-after-statement',
                        '-Wmissing-prototypes',
                        '-Wall'])

  if debug:
    env.Append(CCFLAGS=['-g'])
    env.Append(CPPDEFINES=['DEBUG', '_DEBUG'])
  else:
    env.Append(CCFLAGS=['-O2'])
    env.Append(CPPDEFINES=['NDEBUG'])

  ### works for Mac OS. probably needs to change
  env.Append(LIBS=['ssl', 'crypto', 'z', ])

  if sys.platform == 'sunos5':
    env.Append(LIBS=['m'])
    env.Append(PLATFORM='posix')

  if brotli:
    env.Append(LIBS=['brotlicommon', 'brotlidec'])

else:
  # Warning level 4, no unused argument warnings
  env.Append(CCFLAGS=['/W4',
                      '/wd4100', # Unused argument
                      '/wd4127', # Conditional expression is constant
                      '/wd4706', # Assignment within conditional expression
                      '/we4013', # 'function' undefined; assuming extern returning int
                     ])

  # Choose runtime and optimization
  if debug:
    # Disable optimizations for debugging, use debug DLL runtime
    env.Append(CCFLAGS=['/Od', '/MDd'])
    env.Append(CPPDEFINES=['DEBUG', '_DEBUG'])
  else:
    # Optimize for speed, use DLL runtime
    env.Append(CCFLAGS=['/O2', '/MD'])
    env.Append(CPPDEFINES=['NDEBUG'])
    env.Append(LINKFLAGS=['/RELEASE'])

# PLAN THE BUILD
SHARED_SOURCES = []
if sys.platform == 'win32':
  env.GenDef(['serf.h','serf_bucket_types.h', 'serf_bucket_util.h'])
  SHARED_SOURCES.append(['serf.def'])
  dll_res = env.RES(['serf.rc'])
  SHARED_SOURCES.append(dll_res)

SOURCES = Glob('src/*.c') + Glob('buckets/*.c') + Glob('auth/*.c') + \
          Glob('protocols/*.c')

lib_static = env.StaticLibrary(LIBNAME, SOURCES)
lib_shared = env.SharedLibrary(SHLIBNAME, SOURCES + SHARED_SOURCES)

# Define OPENSSL_NO_STDIO to prevent using _fp() API.
env.Append(CPPDEFINES=['OPENSSL_NO_STDIO'])

if aprstatic:
  env.Append(CPPDEFINES=['APR_DECLARE_STATIC', 'APU_DECLARE_STATIC'])

if sys.platform == 'win32':
  env.Append(LIBS=['user32.lib', 'advapi32.lib', 'gdi32.lib', 'ws2_32.lib',
                   'crypt32.lib', 'mswsock.lib', 'rpcrt4.lib', 'secur32.lib'])

  # Get apr/apu information into our build
  env.Append(CPPDEFINES=['WIN32','WIN32_LEAN_AND_MEAN','NOUSER',
                         'NOGDI', 'NONLS','NOCRYPT',
                         '_CRT_SECURE_NO_WARNINGS',
                         '_CRT_NONSTDC_NO_WARNINGS'])

  if env.get('TARGET_ARCH', None) == 'x86_64':
    env.Append(CPPDEFINES=['WIN64'])

  # Get the APR-Util version number to check if we need an external Expat
  if expat:
    expat_lib_name = 'expat.lib'
  else:    
    expat_lib_name = 'xml.lib'
    apuversion = os.path.join(apu, 'include', 'apu_version.h')
    if not os.path.isfile(apuversion):
      apuversion = os.path.join(apu, 'include', 'apr-1', 'apu_version.h')
      
    if os.path.isfile(apuversion):
      apu_major = 0
      apu_minor = 0
      with open(apuversion, 'r') as vfd:
        major_rx = re.compile(r'^\s*#\s*define\s+APU_MAJOR_VERSION\s+(\d+)')
        minor_rx = re.compile(r'^\s*#\s*define\s+APU_MINOR_VERSION\s+(\d+)')
        for line in vfd:
          m = major_rx.match(line)
          if m:
            apu_major = int(m.group(1))
            continue
          m = minor_rx.match(line)
          if m:
            apu_minor = int(m.group(1))
      print('Found APR-Util version %d.%d' % (apu_major, apu_minor))
      if apu_major >= 2 or apu_major == 1 and apu_minor >= 6:
        expat_lib_name = 'expat.lib'
    else:
      print("Warning: Missing header " + apuversion)

  if aprstatic:
    apr_libs='apr-1.lib'
    apu_libs='aprutil-1.lib'
    env.Append(LIBS=['shell32.lib', expat_lib_name])
  else:
    apr_libs='libapr-1.lib'
    apu_libs='libaprutil-1.lib'

  env.Append(LIBS=[apr_libs, apu_libs])
  if expat and aprstatic:
    env.Append(LIBPATH=[expat])

  if not env.get('SOURCE_LAYOUT', None):
    env.Append(LIBPATH=['$APR/lib', '$APU/lib'],
               CPPPATH=['$APR/include', '$APR/include/apr-1',
                        '$APU/include', '$APU/include/apr-1'])
  elif aprstatic:
    env.Append(LIBPATH=['$APR/LibR','$APU/LibR'],
               CPPPATH=['$APR/include', '$APU/include'])
  else:
    env.Append(LIBPATH=['$APR/Release','$APU/Release'],
               CPPPATH=['$APR/include', '$APU/include'])

  # zlib
  env.Append(LIBS=['zlib.lib'])
  if not env.get('SOURCE_LAYOUT', None):
    env.Append(CPPPATH=['$ZLIB/include'],
               LIBPATH=['$ZLIB/lib'])
  else:
    env.Append(CPPPATH=['$ZLIB'],
               LIBPATH=['$ZLIB'])

  # openssl
  if not env.get('SOURCE_LAYOUT', None):
    env.Append(CPPPATH=['$OPENSSL/include'],
               LIBPATH=['$OPENSSL/lib'])
  else:
    env.Append(CPPPATH=['$OPENSSL/inc32'],
               LIBPATH=['$OPENSSL/out32dll'])
  conf = Configure(env)
  if conf.CheckLib('libcrypto'):
    # OpenSSL 1.1.0+
    env.Append(LIBS=['libcrypto.lib', 'libssl.lib'])
  else:
    # Legacy OpenSSL
    env.Append(LIBS=['libeay32.lib', 'ssleay32.lib'])
  conf.Finish()

  # brotli
  if brotli:
    brotli_libs = 'brotlicommon.lib brotlidec.lib'
    env.Append(LIBS=['brotlicommon.lib', 'brotlidec.lib'])
    if not env.get('SOURCE_LAYOUT', None):
      env.Append(CPPPATH=['$BROTLI/include'],
                 LIBPATH=['$BROTLI/lib'])
    else:
      env.Append(CPPPATH=['$BROTLI/include'],
                 LIBPATH=['$BROTLI/Release'])
  else:
    brotli_libs = ''

else:
  if CALLOUT_OKAY:
    if os.path.isdir(apr):
      possible_apr = os.path.join(apr, 'bin', 'apr-2-config')
      if os.path.isfile(possible_apr):
        apr = possible_apr
      else:
        apr = os.path.join(apr, 'bin', 'apr-1-config')
      env['APR'] = apr

    apr_version = os.popen(env.subst('$APR --version')).read().strip()
    apr_major, apr_minor, apr_patch = map(int, apr_version.split('.'))

    if os.path.isdir(apu):
      apu = os.path.join(apu, 'bin', 'apu-1-config')
      env['APU'] = apu

    ### we should use --cc, but that is giving some scons error about an implict
    ### dependency upon gcc. probably ParseConfig doesn't know what to do with
    ### the apr-1-config output
    env.ParseConfig('$APR --cflags --cppflags --ldflags --includes'
                    ' --link-ld --libs', unique=0)
    if apr_major < 2:
      env.ParseConfig('$APU --ldflags --includes --link-ld --libs',
                      unique=0)

    ### there is probably a better way to run/capture output.
    ### env.ParseConfig() may be handy for getting this stuff into the build
    apr_libs = os.popen(env.subst('$APR --link-libtool --libs')).read().strip()
    if apr_major < 2:
      apu_libs = os.popen(env.subst('$APU --link-libtool --libs')).read().strip()
    else:
      apu_libs = ''
  else:
    apr_libs = ''
    apu_libs = ''

  env.Append(CPPPATH=['$ZLIB/include'])
  env.Append(LIBPATH=['$ZLIB/lib'])

  # MacOS ships ancient OpenSSL libraries, but no headers, so we can
  # assume we're building with an OpenSSL installed outside the
  # default include and link paths. To prevent accidentally linking to
  # the old shared libraries, make sure that the OpenSSL paths are
  # first in the search lists.
  if sys.platform == 'darwin':
    env.Prepend(CPPPATH=['$OPENSSL/include'])
    env.Prepend(LIBPATH=['$OPENSSL/lib'])
  else:
    env.Append(CPPPATH=['$OPENSSL/include'])
    env.Append(LIBPATH=['$OPENSSL/lib'])

  if brotli:
    brotli_libs = '-lbrotlicommon -lbrotlienc'
    env.Append(CPPPATH=['$BROTLI/include'],
               LIBPATH=['$BROTLI/lib'])
  else:
    brotli_libs = ''

# Check for OpenSSL functions which are only available in some of
# the versions we support. Also handles forks like LibreSSL.
conf = Configure(env)
if not conf.CheckFunc('BIO_set_init', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_BIO_WRAPPERS'])
if not conf.CheckFunc('X509_STORE_get0_param', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_X509_STORE_WRAPPERS'])
if not conf.CheckFunc('X509_get0_notBefore', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_X509_GET0_NOTBEFORE'])
if not conf.CheckFunc('X509_get0_notAfter', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_X509_GET0_NOTAFTER'])
if not conf.CheckFunc('X509_STORE_CTX_get0_chain', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_X509_GET0_CHAIN'])
if not conf.CheckFunc('ASN1_STRING_get0_data', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_ASN1_STRING_GET0_DATA'])
if conf.CheckFunc('CRYPTO_set_locking_callback', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_HAVE_SSL_LOCKING_CALLBACKS'])
if conf.CheckFunc('OPENSSL_malloc_init', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_HAVE_OPENSSL_MALLOC_INIT'])
if conf.CheckFunc('SSL_library_init', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_HAVE_OPENSSL_SSL_LIBRARY_INIT'])
if conf.CheckFunc('OpenSSL_version_num', '#include <openssl/crypto.h>'):
  env.Append(CPPDEFINES=['SERF_HAVE_OPENSSL_VERSION_NUM'])
if conf.CheckFunc('SSL_set_alpn_protos'):
  env.Append(CPPDEFINES=['SERF_HAVE_OPENSSL_ALPN'])
if conf.CheckType('OSSL_HANDSHAKE_STATE', '#include <openssl/ssl.h>'):
  env.Append(CPPDEFINES=['SERF_HAVE_OSSL_HANDSHAKE_STATE'])
env = conf.Finish()

# If build with gssapi, get its information and define SERF_HAVE_GSSAPI
if gssapi and CALLOUT_OKAY:
    env.ParseConfig('$GSSAPI --cflags gssapi')
    def parse_libs(env, cmd, unique=1):
        env['GSSAPI_LIBS'] = cmd.strip()
        return env.MergeFlags(cmd, unique)
    env.ParseConfig('$GSSAPI --libs gssapi', parse_libs)
    env.Append(CPPDEFINES=['SERF_HAVE_GSSAPI'])
if sys.platform == 'win32':
  env.Append(CPPDEFINES=['SERF_HAVE_SSPI'])

if brotli and CALLOUT_OKAY:
  conf = Configure(env)
  if conf.CheckCHeader('brotli/decode.h') and \
     conf.CheckFunc('BrotliDecoderTakeOutput'):
    env.Append(CPPDEFINES=['SERF_HAVE_BROTLI'])
  else:
    print("Cannot find Brotli library >= 1.0.0 in '%s'." % env.get('BROTLI'))
    Exit(1)
  env = conf.Finish()

# Set preprocessor define to disable the logging framework
if disablelogging:
    env.Append(CPPDEFINES=['SERF_DISABLE_LOGGING'])

# On some systems, the -R values that APR describes never make it into actual
# RPATH flags. We'll manually map all directories in LIBPATH into new
# flags to set RPATH values.
for d in env['LIBPATH']:
  env.Append(RPATH=[':'+d])

# Set up the construction of serf-*.pc
pkgconfig = env.Textfile('serf-%d.pc' % (MAJOR,),
                         env.File('build/serf.pc.in'),
                         SUBST_DICT = {
                           '@MAJOR@': str(MAJOR),
                           '@PREFIX@': re.escape(str(env['PREFIX'])),
                           '@LIBDIR@': re.escape(str(env['LIBDIR'])),
                           '@INCLUDE_SUBDIR@': 'serf-%d' % (MAJOR,),
                           '@VERSION@': '%d.%d.%d' % (MAJOR, MINOR, PATCH),
                           '@LIBS@': '%s %s %s %s -lz' % (apu_libs, apr_libs,
                                                          env.get('GSSAPI_LIBS', ''),
                                                          brotli_libs),
                           })

env.Default(lib_static, lib_shared, pkgconfig)

if CALLOUT_OKAY:
  conf = Configure(env)

  ### some configuration stuffs
  if conf.CheckCHeader('stdbool.h'):
    env.Append(CPPDEFINES=['HAVE_STDBOOL_H'])

  env = conf.Finish()


# INSTALLATION STUFF

install_static = env.Install(libdir, lib_static)
install_shared = env.InstallVersionedLib(libdir, lib_shared)

if sys.platform == 'darwin':
  # Change the shared library install name (id) to its final name and location.
  # Notes:
  # If --install-sandbox=<path> is specified, install_shared_path will point
  # to a path in the sandbox. We can't use that path because the sandbox is
  # only a temporary location. The id should be the final target path.
  # Also, we shouldn't use the complete version number for id, as that'll
  # make applications depend on the exact major.minor.patch version of serf.

  install_shared_path = install_shared[0].abspath
  target_install_shared_path = os.path.join(libdir, '%s.dylib' % SHLIBNAME)
  env.AddPostAction(install_shared, ('install_name_tool -id %s %s'
                                     % (target_install_shared_path,
                                        install_shared_path)))

env.Alias('install-lib', [install_static, install_shared,
                          ])
env.Alias('install-inc', env.Install(incdir, HEADER_FILES))
env.Alias('install-pc', env.Install(os.path.join(libdir, 'pkgconfig'),
                                    pkgconfig))
env.Alias('install', ['install-lib', 'install-inc', 'install-pc', ])


# TESTS
### make move to a separate scons file in the test/ subdir?

tenv = env.Clone()

# Check if long-running tests should be enabled
if tenv.get('ENABLE_SLOW_TESTS', None):
    tenv.Append(CPPDEFINES=['SERF_TEST_DEFLATE_4GBPLUS_BUCKETS'])

# MockHTTP requires C99 standard, so use it for the test suite.
cflags = tenv['CFLAGS']
tenv.Replace(CFLAGS = [f.replace('-std=c89', '-std=c99') for f in cflags])

tenv.Append(CPPDEFINES=['MOCKHTTP_OPENSSL'])

TEST_PROGRAMS = [ 'serf_get', 'serf_response', 'serf_request', 'serf_spider',
                  'serf_httpd',
                  'test_all', 'serf_bwtp' ]
if sys.platform == 'win32':
  TEST_EXES = [ os.path.join('test', '%s.exe' % (prog)) for prog in TEST_PROGRAMS ]
else:
  TEST_EXES = [ os.path.join('test', '%s' % (prog)) for prog in TEST_PROGRAMS ]

check_script = env.File('build/check.py').rstr()
test_dir = env.File('test/test_all.c').rfile().get_dir()
src_dir = env.File('serf.h').rfile().get_dir()
test_app = ("%s %s %s %s") % (sys.executable, check_script, test_dir, 'test')

# Set the library search path for the test programs
test_env = {'PATH' : os.environ['PATH'],
            'srcdir' : src_dir}
if sys.platform != 'win32':
  test_env['LD_LIBRARY_PATH'] = ':'.join(tenv.get('LIBPATH', []))
env.AlwaysBuild(env.Alias('check', TEST_EXES, test_app, ENV=test_env))

testall_files = [
        'test/test_all.c',
        'test/CuTest.c',
        'test/test_util.c',
        'test/test_context.c',
        'test/test_buckets.c',
        'test/test_auth.c',
        'test/test_internal.c',
        'test/test_server.c',
        'test/mock_buckets.c',
        'test/mock_sock_buckets.c',
        'test/test_ssl.c',
        'test/MockHTTPinC/MockHTTP.c',
        'test/MockHTTPinC/MockHTTP_server.c',
        ]

# We link the programs explicitly against the static libraries, to allow
# access to private functions
for proggie in TEST_EXES:
  if 'test_all' in proggie:
    tenv.Program(proggie, testall_files + [LIBNAME + env['LIBSUFFIX']])
  else:
    tenv.Program(target = proggie, source = [proggie.replace('.exe','') + '.c',
                                             LIBNAME + env['LIBSUFFIX']])


# HANDLE CLEANING

if env.GetOption('clean'):
  # When we're cleaning, we want the dependency tree to include "everything"
  # that could be built. Thus, include all of the tests.
  env.Default('check')
