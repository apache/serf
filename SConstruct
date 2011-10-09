# -*- python -*-

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
  )

match = re.search('SERF_MAJOR_VERSION ([0-9]+).*'
                  'SERF_MINOR_VERSION ([0-9]+).*'
                  'SERF_PATCH_VERSION ([0-9]+)',
                  open('serf.h').read(),
                  re.DOTALL)
MAJOR, MINOR, PATCH = [int(x) for x in match.groups()]


env = Environment(variables=opts,
                  tools=('default', 'textfile',),
                  CPPPATH=['.', ],
                  MAJOR=str(MAJOR),
                  )


# PLATFORM-SPECIFIC BUILD TWEAKS

thisdir = os.getcwd()
libdir = '$PREFIX/lib'
incdir = '$PREFIX/include/serf-$MAJOR'

LIBNAME = 'libserf-${MAJOR}'

linkflags = ['-Wl,-rpath,%s' % (libdir,), ]
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
  ### gcc only. figure out appropriate test
  ccflags = ['-g', '-O2', '-Wall', ]

libs = [ ]
if 1:
  ### works for Mac OS. probably needs to change
  libs = ['ssl', 'crypto', 'z', ]

env.Replace(LINKFLAGS=linkflags,
            CCFLAGS=ccflags,
            LIBS=libs,
            )


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
Help(opts.GenerateHelpText(env))
opts.Save(SAVED_CONFIG, env)


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

### there is probably a better way to run/capture output.
### env.ParseConfig() may be handy for getting this stuff into the build
apr_libs = os.popen(env.subst('$APR --link-libtool --libs')).read().strip()
apu_libs = os.popen(env.subst('$APU --link-libtool --libs')).read().strip()

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

TEST_PROGRAMS = [
]

#env.Prepend(LIBS=['libserf-2', ],
#            LIBPATH=['.', ])

for proggie in TEST_PROGRAMS:
  env.Program(proggie)
