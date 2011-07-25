# -*- python -*-

import sys
import os

INCLUDE_FILES = ['serf.h',
                 'serf_bucket_types.h',
                 'serf_bucket_util.h',
                 ]

opts = Variables()
opts.Add(PathVariable('PREFIX',
                      'Directory to install under',
                      '/usr/local',
                      PathVariable.PathIsDir))

### fetch from serf.h
MAJOR = 2

APR_INCLUDE = '/usr/include/apr-1'
APU_INCLUDE = '/usr/include/apr-1'

env = Environment(variables=opts,
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

env.Replace(LINKFLAGS=linkflags,
            )

Help(opts.GenerateHelpText(env))

SOURCES = Glob('*.c') + Glob('buckets/*.c') + Glob('auth/*.c')

lib_static = env.StaticLibrary(LIBNAME, SOURCES)
lib_shared = env.SharedLibrary(LIBNAME, SOURCES)
env.Default(lib_static, lib_shared)

if not (env.GetOption('clean') or env.GetOption('help')):
  conf = Configure(env)

  ### some configuration stuffs

  env = conf.Finish()


env.Alias('install-lib', [env.Install(libdir, lib_static),
                          env.Install(libdir, lib_shared),
                          ### use 'install_name_tool' on mac
                          ])
env.Alias('install-inc', env.Install(incdir, INCLUDE_FILES))
env.Alias('install', ['install-lib', 'install-inc', ])


TEST_PROGRAMS = [
]

#env.Prepend(LIBS=['libserf-2', ],
#            LIBPATH=['.', ])

for proggie in TEST_PROGRAMS:
  env.Program(proggie)
