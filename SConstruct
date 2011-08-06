# -*- python -*-

import sys
import os
import re

HEADER_FILES = ['serf.h',
                'serf_bucket_types.h',
                'serf_bucket_util.h',
                ]

opts = Variables()
opts.Add(PathVariable('PREFIX',
                      'Directory to install under',
                      '/usr/local',
                      PathVariable.PathIsDir))

match = re.search('SERF_MAJOR_VERSION ([0-9]+).*'
                  'SERF_MINOR_VERSION ([0-9]+).*'
                  'SERF_PATCH_VERSION ([0-9]+)',
                  open('serf.h').read(),
                  re.DOTALL)
MAJOR, MINOR, PATCH = [int(x) for x in match.groups()]

APR_INCLUDE = '/usr/include/apr-1'
APU_INCLUDE = '/usr/include/apr-1'

env = Environment(variables=opts,
                  tools=('default', 'textfile',),
                  CCFLAGS=['-g', '-O2', '-Wall', ],
                  CPPPATH=['.', APR_INCLUDE, APU_INCLUDE, ],
                  LIBS=['apr-1', 'aprutil-1', 'ssl', 'crypto', 'z', ],
                  )

thisdir = os.getcwd()
prefix = env['PREFIX']
libdir = prefix + '/lib'
incdir = '%s/include/serf-%d' % (prefix, MAJOR)

LIBNAME = 'libserf-' + str(MAJOR)

linkflags = ['-Wl,-rpath,%s' % (libdir,), ]
if sys.platform == 'darwin':
#  linkflags.append('-Wl,-install_name,@executable_path/%s.dylib' % (LIBNAME,))
  linkflags.append('-Wl,-install_name,%s/%s.dylib' % (thisdir, LIBNAME,))
  # 'man ld' says positive non-zero for the first number, so we add one.
  # The interpretation is same as our MINOR version.
  linkflags.append('-Wl,-compatibility_version,%d' % (MINOR+1,))
  linkflags.append('-Wl,-current_version,%d.%d' % (MINOR+1, PATCH,))

env.Replace(LINKFLAGS=linkflags,
            )

Help(opts.GenerateHelpText(env))

SOURCES = Glob('*.c') + Glob('buckets/*.c') + Glob('auth/*.c')

lib_static = env.StaticLibrary(LIBNAME, SOURCES)
lib_shared = env.SharedLibrary(LIBNAME, SOURCES)

### we need to find the right apu/apr config. maybe based on switch for now.
### there is probably a better way to run/capture output.
### env.ParseConfig() may be handy for getting this stuff into the build
DEPENDENT_LIBS = os.popen(env.subst('$PREFIX/bin/apu-1-config --link-libtool --libs')).read().strip()
DEPENDENT_LIBS += os.popen(env.subst('$PREFIX/bin/apr-1-config --link-libtool --libs')).read().strip()
DEPENDENT_LIBS += ' -lz'

pkgconfig = env.Textfile('serf-%d.pc' % (MAJOR,),
                         env.File('build/serf.pc.in'),
                         SUBST_DICT = {
                           '@MAJOR@': str(MAJOR),
                           '@PREFIX@': prefix,
                           '@INCLUDE_SUBDIR@': 'serf-%d' % (MAJOR,),
                           '@VERSION@': '%d.%d.%d' % (MAJOR, MINOR, PATCH),
                           '@LIBS@': DEPENDENT_LIBS,
                           })

env.Default(lib_static, lib_shared, pkgconfig)

if not (env.GetOption('clean') or env.GetOption('help')):
  conf = Configure(env)

  ### some configuration stuffs

  env = conf.Finish()


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


TEST_PROGRAMS = [
]

#env.Prepend(LIBS=['libserf-2', ],
#            LIBPATH=['.', ])

for proggie in TEST_PROGRAMS:
  env.Program(proggie)
