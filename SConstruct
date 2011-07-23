# -*- python -*-

import sys
import os

opts = Variables()
opts.Add(PathVariable('PREFIX',
                      'Directory to install under',
                      '/usr/local',
                      PathVariable.PathIsDir))

APR_INCLUDE = '/usr/include/apr-1'
APU_INCLUDE = '/usr/include/apr-1'

env = Environment(variables=opts,
                  CCFLAGS=['-g', '-O2', '-Wall', ],
                  CPPPATH=['.', APR_INCLUDE, APU_INCLUDE, ],
                  LIBS=['apr-1', 'aprutil-1', 'ssl', 'crypto', 'z', ],
                  )

Help(opts.GenerateHelpText(env))

SOURCES = Glob('*.c') + Glob('buckets/*.c') + Glob('auth/*.c')

lib_static = env.StaticLibrary('libserf-2', SOURCES)
lib_shared = env.SharedLibrary('libserf-2', SOURCES)
env.Default(lib_static, lib_shared)

if not (env.GetOption('clean') or env.GetOption('help')):
  conf = Configure(env)

  ### some configuration stuffs

  env = conf.Finish()


TEST_PROGRAMS = [
]

env.Prepend(LIBS=['libserf-2', ],
            LIBPATH=['.', ])

for proggie in TEST_PROGRAMS:
  env.Program(proggie)
