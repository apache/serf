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


# Compatibility with old versions of SCons
try:
  # Python 2 / SCons 2.3.0 etc.
  from cStringIO import StringIO
  print("warning: replaced StringIO() for Python version < 3.")
except ImportError:
  # Python 3
  from io import StringIO

# Set up our additional config tests.
src_dir = File('SConstruct').rfile().get_dir().abspath
sys.path.insert(0, src_dir)
import build.scons_extras
import build.exports

build.scons_extras.AddEnvironmentMethods()
custom_tests = {'CheckGnuCC': build.scons_extras.CheckGnuCC}

# SCons 4.7 introduced the function argument list parameter to CheckFunc.
try:
  import SCons.Conftest as _conftest
  _conftest.CheckFunc(None, 'clock', '#include <time.h>', 'C', '')
except AttributeError:
  # This comes from the 'None' context argument, above. It's fine, we just
  # proved that CheckFunc has the funcargs parameter, so we don't have to
  # replace it with our own implementation.
  pass
except TypeError:
  # We have version < 4.7 without funcargs, use our replacement CheckFunc.
  custom_tests['CheckFunc'] = build.scons_extras.CheckFunc
  print('warning: replaced Conftest.CheckFunc() for SCons version < 4.7.')

# By default, we silence all warnings when compiling MockHTTP.
# Set this to True to show them instead.
SHOW_MOCKHTTP_WARNINGS = False

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

def filter_cflags(env, cmd, unique=0):
  '''Filter all debugging, optimization and warning flags from 'cmd'.'''
  cmd = re.sub(r'(^|\s)-[gOW]\S*', '', cmd)
  return env.MergeFlags(cmd, unique)

def unsubstable(string):
  '''There are things that SCons just shouldn't Subst.'''
  return string.replace('$', '$$')

# default directories
if sys.platform == 'win32':
  default_incdir='$PREFIX'
  default_libdir='$PREFIX/lib'
  default_prefix='./install'
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
  PathVariable('UNBOUND',
               "Path to libunbound's install area",
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
                 allowed_values=('x86', 'x86_64', 'arm64', 'ia64'),
                 map={'X86'  : 'x86',
                      'win32': 'x86',
                      'Win32': 'x86',
                      'x64'  : 'x86_64',
                      'X64'  : 'x86_64',
                      'ARM64': 'arm64'
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

# Export symbol generator (for Windows DLL, Mach-O and ELF)
export_generator = build.exports.ExportGenerator()
if export_generator.target is None:
  # Detect if the build target is an ELF platform the the
  # generator doesn't know about.
  sys.stdout.write("Checking if the build target is ELF ...")
  conf = Configure(env)  # No custom tests, we want a clean environment.
  if (conf.TryLink('int main(void) { return 0; }', '.c')):
    header = conf.lastTarget.get_contents()[:4]
    if header == b'\x7fELF':    # This is the ELF magic number.
      print(" yes")
      elf = build.exports.TARGET_ELF
      export_generator = build.exports.ExportGenerator(elf)
    else:
      print(" no")
  else:
    print(" failed")
  conf.Finish()

# Now try again...
if export_generator.target is None:
  # Nothing to do on this platform
  export_generator = None
else:
  def generate_exports(target, source, env):
    for target_path in (str(t) for t in target):
      stream = open(target_path, 'wt')
      export_generator.generate(stream, *(str(s) for s in source))
      stream.close()
  env.Append(BUILDERS = {
    'GenExports': Builder(action=generate_exports,
                          suffix=export_generator.target.ext,
                          src_suffix='.h')
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
unbound = env.get('UNBOUND', None)

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
pkgdir = '$LIBDIR/pkgconfig'

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

if export_generator is None:
  export_filter = None
else:
  export_filter = '%s%s' % (SHLIBNAME, export_generator.target.ext)

env.Append(RPATH=[libdir],
           PDB='${TARGET.filebase}.pdb')

if sys.platform != 'win32':
  conf = Configure(env, custom_tests=custom_tests)
  have_gcc = conf.CheckGnuCC()
  env = conf.Finish()

  if have_gcc:
    # env.Append(CFLAGS=['-std=c89'])
    env.SerfAppendIf(['CFLAGS'], r'-(ansi|std=c\d+)', CFLAGS=['-std=c89'])
    env.Append(CCFLAGS=['-Wdeclaration-after-statement',
                        '-Wmissing-prototypes',
                        '-Wshadow',
                        '-Wall'])

  if debug:
    # env.Append(CCFLAGS=['-g'])
    env.SerfAppendIf(['CFLAGS', 'CCFLAGS'], r'-g\S*', CCFLAGS=['-g'])
    env.Append(CPPDEFINES=['DEBUG', '_DEBUG'])
    for flag in ['-Werror=unknown-warning-option',
                 '-Wimplicit-function-declaration',
                 '-Wmissing-variable-declarations',
                 '-Wunreachable-code',
                 '-Wshorten-64-to-32',
                 '-Wno-system-headers',
                 '-Wextra-tokens',
                 '-Wnewline-eof']:
        if env.SerfCheckCFlag(flag):
          env.Append(CCFLAGS=[flag])
  else:
    # env.Append(CCFLAGS=['-O2'])
    env.SerfAppendIf(['CFLAGS', 'CCFLAGS'], r'-O\S*', CCFLAGS=['-O2'])
    env.Append(CPPDEFINES=['NDEBUG'])

  ### works for Mac OS. probably needs to change
  env.Append(LIBS=['ssl', 'crypto', 'z', ])

  if sys.platform == 'sunos5':
    env.Append(LIBS=['m'])
    env.Append(PLATFORM='posix')

  if brotli:
    env.Append(LIBS=['brotlicommon', 'brotlidec'])

  if unbound:
    env.Append(LIBS=['unbound'])

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
  SHARED_SOURCES.append(env.RES(['serf.rc']))

SOURCES = Glob('src/*.c') + Glob('buckets/*.c') + Glob('auth/*.c') + \
          Glob('protocols/*.c')

lib_static = env.StaticLibrary(LIBNAME, SOURCES)
lib_shared = env.SharedLibrary(SHLIBNAME, SOURCES + SHARED_SOURCES)
if export_filter is not None:
  env.GenExports(target=export_filter, source=HEADER_FILES)
  env.Depends(lib_shared, export_filter)

# We do not want or need OpenSSL's compatibility macros.
env.Append(CPPDEFINES=['OPENSSL_NO_DEPRECATED'])

# Define OPENSSL_NO_STDIO to prevent using _fp() API.
env.Append(CPPDEFINES=['OPENSSL_NO_STDIO'])

if aprstatic:
  env.Append(CPPDEFINES=['APR_DECLARE_STATIC', 'APU_DECLARE_STATIC'])

# Prepare lists for the pkg-config file
pc_requires = ['libssl', 'libcrypto']
pc_cppflags = []
pc_private_libs = []
win_std_libs = []

if sys.platform == 'win32':
  source_layout = env.get('SOURCE_LAYOUT', None)
  win_std_libs = ['crypt32.lib', 'mswsock.lib', 'rpcrt4.lib',
                  'secur32.lib', 'ws2_32.lib']

  # Get apr/apu information into our build
  env.Append(CPPDEFINES=['WIN32','WIN32_LEAN_AND_MEAN','NOUSER',
                         'NOGDI', 'NONLS','NOCRYPT',
                         '_CRT_SECURE_NO_WARNINGS',
                         '_CRT_NONSTDC_NO_WARNINGS'])

  if env.get('TARGET_ARCH', None) in ('x86_64', 'arm64', 'ia64'):
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
    win_std_libs.append('shell32.lib')
  else:
    apr_libs='libapr-1.lib'
    apu_libs='libaprutil-1.lib'

  if not source_layout:
    apr_libdir = '$APR/lib'
    apu_libdir = '$APU/lib'
    env.Append(CPPPATH=['$APR/include', '$APR/include/apr-1',
                        '$APU/include', '$APU/include/apr-1'])
  elif aprstatic:
    apr_libdir = '$APR/LibR'
    apu_libdir = '$APU/LibR'
    env.Append(CPPPATH=['$APR/include', '$APU/include'])
  else:
    apr_libdir = '$APR/Release'
    apu_libdir = '$APU/Release'
    env.Append(CPPPATH=['$APR/include', '$APU/include'])

  env.Append(LIBPATH=[apr_libdir, apu_libdir],
             LIBS=[apr_libs, apu_libs])
  pc_private_libs.append('/'.join([apr_libdir, apr_libs]))
  pc_private_libs.append('/'.join([apu_libdir, apu_libs]))

  if expat and aprstatic:
    env.Append(LIBPATH=[expat],
               LIBS=[expat_lib_name])
    pc_private_libs.append('/'.join([expat, expat_lib_name]))

  # zlib
  env.Append(LIBS=['zlib.lib'])
  if not source_layout:
    env.Append(CPPPATH=['$ZLIB/include'],
               LIBPATH=['$ZLIB/lib'])
    pc_private_libs.append('$ZLIB/lib/zlib.lib')
  else:
    env.Append(CPPPATH=['$ZLIB'],
               LIBPATH=['$ZLIB'])
    pc_private_libs.append('$ZLIB/zlib.lib')

  # openssl
  if not source_layout:
    env.Append(CPPPATH=['$OPENSSL/include'],
               LIBPATH=['$OPENSSL/lib'])
  else:
    env.Append(CPPPATH=['$OPENSSL/inc32'],
               LIBPATH=['$OPENSSL/out32dll'])
  conf = Configure(env, custom_tests=custom_tests)
  if conf.CheckLib('libcrypto'):
    # OpenSSL 1.1.0+
    env.Append(LIBS=['libcrypto.lib', 'libssl.lib'])
  else:
    # Legacy OpenSSL
    env.Append(LIBS=['libeay32.lib', 'ssleay32.lib'])
  conf.Finish()

  # brotli
  if brotli:
    env.Append(LIBS=['brotlicommon.lib', 'brotlidec.lib'])
    if not source_layout:
      env.Append(CPPPATH=['$BROTLI/include'],
                 LIBPATH=['$BROTLI/lib'])
      pc_private_libs.append('$BROTLI/lib/brotlicommon.lib')
      pc_private_libs.append('$BROTLI/lib/brotlidec.lib')
    else:
      env.Append(CPPPATH=['$BROTLI/include'],
                 LIBPATH=['$BROTLI/Release'])
      pc_private_libs.append('$BROTLI/Release/brotlicommon.lib')
      pc_private_libs.append('$BROTLI/Release/brotlidec.lib')

  # unbound
  if unbound:
    env.Append(CPPPATH=['$UNBOUND/include'],
               LIBPATH=['$UNBOUND/lib'],
               LIBS=['unbound.lib'])
    pc_private_libs.append('$UNBOUND/lib/unbound.lib')

  env.Append(LIBS=win_std_libs)

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

    ### we should use --cc, but that is giving some scons error about an implicit
    ### dependency upon gcc. probably ParseConfig doesn't know what to do with
    ### the apr-1-config output

    env.ParseConfig('$APR --cflags --cppflags --includes'
                    ' --ldflags --link-ld --libs',
                    filter_cflags)
    if apr_major < 2:
      env.ParseConfig('$APU --includes --ldflags --link-ld --libs',
                      filter_cflags)

    ### there is probably a better way to run/capture output.
    ### env.ParseConfig() may be handy for getting this stuff into the build
    apr_defs = os.popen(env.subst('$APR --cppflags')).read().strip()
    apr_libs = os.popen(env.subst('$APR --link-ld --libs')).read().strip()
    pc_cppflags.append(apr_defs)
    pc_private_libs.append(apr_libs)
    if apr_major < 2:
      apu_libs = os.popen(env.subst('$APU --link-ld --libs')).read().strip()
      pc_private_libs.append(apu_libs)

  env.Append(CPPPATH=['$ZLIB/include'])
  env.Append(LIBPATH=['$ZLIB/lib'])
  if env.subst('$ZLIB') not in ('', '/usr'):
    pc_private_libs.append('-L$ZLIB/lib')
  pc_private_libs.append('-lz')

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
    env.Append(CPPPATH=['$BROTLI/include'],
               LIBPATH=['$BROTLI/lib'])
    if env.subst('$BROTLI') not in ('', '/usr'):
      pc_private_libs.append('-L$BROTLI/lib')
    pc_private_libs.append('-lbrotlicommon -lbrotlidec')

  if unbound:
    env.Append(CPPPATH=['$UNBOUND/include'],
               LIBPATH=['$UNBOUND/lib'])
    if env.subst('$UNBOUND') not in ('', '/usr'):
      pc_private_libs.append('-L$UNBOUND/lib')
    pc_private_libs.append('-lunbound')

# Check for OpenSSL functions which are only available in some of
# the versions we support. Also handles forks like LibreSSL.
ssl_include_rx = re.compile(r'^\s*#\s*include\s+<openssl/[^>]+>')
ssl_include_list = []
stream = StringIO(env.File('buckets/ssl_buckets.c')
                  .rfile().get_text_contents())
for line in stream.readlines():
  if ssl_include_rx.match(line):
    ssl_include_list.append(line.rstrip())
ssl_includes = '\n'.join(ssl_include_list)

conf = Configure(env, custom_tests=custom_tests)
if not conf.CheckFunc('BIO_set_init', ssl_includes, 'C', 'NULL, 0'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_BIO_WRAPPERS'])
if not conf.CheckFunc('X509_STORE_get0_param', ssl_includes, 'C', 'NULL'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_X509_STORE_WRAPPERS'])
if not conf.CheckFunc('X509_get0_notBefore', ssl_includes, 'C', 'NULL'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_X509_GET0_NOTBEFORE'])
if not conf.CheckFunc('X509_get0_notAfter', ssl_includes, 'C', 'NULL'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_X509_GET0_NOTAFTER'])
if not conf.CheckFunc('X509_STORE_CTX_get0_chain', ssl_includes, 'C', 'NULL'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_X509_GET0_CHAIN'])
if not conf.CheckFunc('ASN1_STRING_get0_data', ssl_includes, 'C', 'NULL'):
  env.Append(CPPDEFINES=['SERF_NO_SSL_ASN1_STRING_GET0_DATA'])
if conf.CheckFunc('CRYPTO_set_locking_callback', ssl_includes, 'C', 'NULL'):
  env.Append(CPPDEFINES=['SERF_HAVE_SSL_LOCKING_CALLBACKS'])
if conf.CheckFunc('OPENSSL_malloc_init', ssl_includes):
  env.Append(CPPDEFINES=['SERF_HAVE_OPENSSL_MALLOC_INIT'])
if conf.CheckFunc('SSL_library_init', ssl_includes):
  env.Append(CPPDEFINES=['SERF_HAVE_OPENSSL_SSL_LIBRARY_INIT'])
if conf.CheckFunc('OpenSSL_version_num', ssl_includes):
  env.Append(CPPDEFINES=['SERF_HAVE_OPENSSL_VERSION_NUM'])
if conf.CheckFunc('SSL_set_alpn_protos', ssl_includes, 'C', 'NULL, NULL, 0'):
  env.Append(CPPDEFINES=['SERF_HAVE_OPENSSL_ALPN'])
if conf.CheckFunc('OSSL_STORE_open_ex', ssl_includes, 'C',
                  'NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL'):
  env.Append(CPPDEFINES=['SERF_HAVE_OSSL_STORE_OPEN_EX'])
if conf.CheckType('OSSL_HANDSHAKE_STATE', ssl_includes):
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
    pc_private_libs.append(env['GSSAPI_LIBS'])
if sys.platform == 'win32':
  env.Append(CPPDEFINES=['SERF_HAVE_SSPI'])

if brotli and CALLOUT_OKAY:
  conf = Configure(env, custom_tests=custom_tests)
  if (conf.CheckCHeader('brotli/decode.h')
      and conf.CheckFunc('BrotliDecoderTakeOutput',
                         '#include <brotli/decode.h>',
                         'C', 'NULL, NULL')):
    env.Append(CPPDEFINES=['SERF_HAVE_BROTLI'])
  else:
    print("Cannot find Brotli library >= 1.0.0 in '%s'." % env.get('BROTLI'))
    Exit(1)
  env = conf.Finish()

if unbound and CALLOUT_OKAY:
  print(custom_tests)
  conf = Configure(env, custom_tests=custom_tests)
  if (conf.CheckCHeader('unbound.h')
      and conf.CheckFunc('ub_ctx_create',
                         '#include <unbound.h>',
                         'C', '')
      and conf.CheckFunc('ub_resolve_async',
                         '#include <stddef.h>\n'
                         '#include <unbound.h>',
                         'C', 'NULL, NULL, 0, 0, NULL, NULL, NULL')):
    env.Append(CPPDEFINES=['SERF_HAVE_ASYNC_RESOLVER=1',
                           'SERF_HAVE_UNBOUND=1'])
  else:
    print("Cannot find Unbound library in '%s'." % env.get('UNBOUND'))
    Exit(1)
  env = conf.Finish()

if CALLOUT_OKAY:
  conf = Configure(env, custom_tests=custom_tests)

  ### some configuration stuffs
  if conf.CheckCHeader('stdbool.h'):
    env.Append(CPPDEFINES=['HAVE_STDBOOL_H'])

  env = conf.Finish()

# Tweak the link flags for selecting exported symbols. Must come after the
# config checks, because the symbols file doesn't exist yet.
if export_filter is not None:
  env.Append(LINKFLAGS=[export_generator.target.link_flag % export_filter])

# Set preprocessor define to disable the logging framework
if disablelogging:
    env.Append(CPPDEFINES=['SERF_DISABLE_LOGGING'])

# On some systems, the -R values that APR describes never make it into actual
# RPATH flags. We'll manually map all directories in LIBPATH into new
# flags to set RPATH values.
for d in env['LIBPATH']:
  env.Append(RPATH=[':'+d])

# Set up the construction of serf-*.pc
pkgprefix = os.path.relpath(env.subst('$PREFIX'), env.subst(pkgdir)
                            ).replace(os.path.sep, '/')
pkglibdir = os.path.relpath(env.subst('$LIBDIR'), env.subst('$PREFIX')
                            ).replace(os.path.sep, '/')
pkglibs = env.subst(' '.join(pc_private_libs + win_std_libs)
                    ).replace(os.path.sep, '/')
pkgconfig = env.Textfile('serf-%d.pc' % (MAJOR,),
                         env.File('build/serf.pc.in'),
                         SUBST_DICT = {
                           '@MAJOR@': str(MAJOR),
                           '@PREFIX@': unsubstable('${pcfiledir}/' + pkgprefix),
                           '@LIBDIR@': unsubstable('${prefix}/' + pkglibdir),
                           '@INCLUDE_SUBDIR@': 'serf-%d' % (MAJOR,),
                           '@REQUIRES@': ' '.join(pc_requires),
                           '@VERSION@': '%d.%d.%d' % (MAJOR, MINOR, PATCH),
                           '@CFLAGS@': unsubstable(' '.join(pc_cppflags)),
                           '@LIBS@': unsubstable(pkglibs),
                           })

env.Default(lib_static, lib_shared, pkgconfig)

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

env.Alias('install-lib', [install_static, install_shared])
env.Alias('install-inc', env.Install(incdir, HEADER_FILES))
env.Alias('install-pc', env.Install(pkgdir, pkgconfig))
env.Alias('install', ['install-lib', 'install-inc', 'install-pc', ])


# TESTS
### make move to a separate scons file in the test/ subdir?

tenv = env.Clone()
tenv.Append(CPPDEFINES=['MOCKHTTP_OPENSSL'])

# Build the MockHTTP static library. MockHTTP needs C99 and OpenSSL's
# deprecated APIs. Also silence all warnings from MockHTTP.
mockenv = tenv.Clone()
mockenv.Replace(CFLAGS = [f.replace('-std=c89', '-std=c99')
                          for f in mockenv['CFLAGS']])
mockenv.Replace(CCFLAGS = list(
  filter(lambda f: (SHOW_MOCKHTTP_WARNINGS
                    # NOTE: SCons flags are sometimes tuples, not strings.
                    #       In those cases, the first element is the flag
                    #       and the rest ar the flag's value(s).
                    or (# GCC-like warning flags
                        not re.match(r'^\s*-W[a-z][a-z-]+',
                                     f if type(f) == type('') else f[0])
                        # MSVC-like warning flags
                        and not re.match(r'^\s*/(W|w[de])\d+',
                                         f if type(f) == type('') else f[0]))),
         mockenv['CCFLAGS'])
))
if not SHOW_MOCKHTTP_WARNINGS:
  mockenv.Append(CCFLAGS = ['-w' if sys.platform != 'win32' else '/w'])
mockenv.Replace(CPPDEFINES = list(filter(lambda d: d != 'OPENSSL_NO_DEPRECATED',
                                         mockenv['CPPDEFINES'])))

mockhttpinc = mockenv.StaticLibrary('mockhttpinc',
                                    ['test/MockHTTPinC/MockHTTP.c',
                                     'test/MockHTTPinC/MockHTTP_server.c'])

# Check if long-running tests should be enabled
if tenv.get('ENABLE_SLOW_TESTS', None):
    tenv.Append(CPPDEFINES=['SERF_TEST_DEFLATE_4GBPLUS_BUCKETS'])

TEST_PROGRAMS = [ 'serf_get', 'serf_response', 'serf_request', 'serf_spider',
                  'serf_httpd',
                  'test_all', 'serf_bwtp' ]

_exe = '.exe' if sys.platform == 'win32' else ''
TEST_EXES = [os.path.join('test', '%s%s' % (prog, _exe)) for prog in TEST_PROGRAMS]

check_script = env.File('build/check.py').rstr()
test_dir = env.File('test/test_all.c').rfile().get_dir()
test_app = ("%s %s %s %s") % (sys.executable, check_script, test_dir, 'test')

# Set the library search path for the test programs
test_env = {'PATH' : os.environ['PATH'],
            'srcdir' : src_dir}
if sys.platform != 'win32':
  os_library_path = os.environ.get('LD_LIBRARY_PATH')
  os_library_path = [os_library_path] if os_library_path else []
  ld_library_path = [tenv.subst(p) for p in tenv.get('LIBPATH', [])]
  test_env['LD_LIBRARY_PATH'] = ':'.join(ld_library_path + os_library_path)
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
        ]

# We link the programs explicitly against the static libraries, to allow
# access to private functions
mocklib = mockhttpinc[0].rfile().abspath
serflib = lib_static[0].rfile().abspath
for proggie in TEST_EXES:
  if 'test_all' in proggie:
    tenv.Program(proggie, testall_files + [mocklib, serflib])
  else:
    tenv.Program(target=proggie,
                 source=[proggie.replace('.exe','') + '.c', serflib])


# HANDLE CLEANING

if env.GetOption('clean'):
  # When we're cleaning, we want the dependency tree to include "everything"
  # that could be built. Thus, include all of the tests.
  env.Default('check')
