# scons_extras.py :  SCons extensions and compatibility functinos.
#
# ===================================================================
#   Licensed to the Apache Software Foundation (ASF) under one
#   or more contributor license agreements.  See the NOTICE file
#   distributed with this work for additional information
#   regarding copyright ownership.  The ASF licenses this file
#   to you under the Apache License, Version 2.0 (the
#   "License"); you may not use this file except in compliance
#   with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing,
#   software distributed under the License is distributed on an
#   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#   KIND, either express or implied.  See the License for the
#   specific language governing permissions and limitations
#   under the License.
# ===================================================================

import re

import SCons.Environment
import SCons.SConf
import SCons.Util


def CheckGnuCC(context):
  '''Check if the compiler is compatible with gcc.'''

  src = '''
#ifndef __GNUC__
oh noes!
#endif
'''

  context.Display('Checking for GNU-compatible C compiler... ')
  result = context.TryCompile(src, '.c')
  context.Result(result)
  return result


def __env_munge_if(env, method, variables, pattern, **kwargs):
  '''Invoke `env`.`method`(**`kwargs`), unless `pattern` matches the
   values in `variables` that are also in `env`.
  '''

  rx = re.compile(pattern)
  for var in variables:
    values = env.get(var, [])
    for value in values:
      if rx.search(value):
        return
  getattr(env, method)(**kwargs)


def __env_check_c_flag(env, flag):
  '''Check if the C compiler accepts the `flag`'''

  xenv = env.Clone()
  xenv.Append(CCFLAGS=[flag])
  xonf = SCons.SConf.SConf(xenv)
  xmsg = SCons.SConf.CheckContext(xonf)
  xmsg.Display('Checking if the C compiler accepts %s... ' % (flag,))
  result = xonf.TryCompile('int main(void) { return 0; }', '.c')
  xmsg.Result(result)
  xonf.Finish()
  return result


def AddEnvironmentMethods():
  SCons.Util.AddMethod(
    SCons.Environment.Environment,
    lambda env, variables, pattern, **kwargs:
    __env_munge_if(env, 'Append', variables, pattern, **kwargs),
    'SerfAppendIf')
  SCons.Util.AddMethod(
    SCons.Environment.Environment,
    lambda env, variables, pattern, **kwargs:
    __env_munge_if(env, 'Prepend', variables, pattern, **kwargs),
    'SerfPrependIf')
  SCons.Util.AddMethod(
    SCons.Environment.Environment,
    __env_check_c_flag, 'SerfCheckCFlag')


#
# The following code is derived from SCons, version 4.7.0.
#
# ===================================================================
#
# MIT License
#
# Copyright The SCons Foundation
# Copyright (c) 2003 Stichting NLnet Labs
# Copyright (c) 2001, 2002, 2003 Steven Knight
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
# KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ===================================================================


from SCons.Conftest import _YesNoResult, _lang2suffix


def CheckFunc(context, function_name, header=None, language=None, funcargs=''):
  if context.headerfilename:
    includetext = '#include "%s"' % context.headerfilename
  else:
    includetext = ''
  if not header:
    header = '''
#ifdef __cplusplus
extern "C"
#endif
char %s(void);''' % function_name

  lang, suffix, msg = _lang2suffix(language)
  if msg:
    context.Display('Cannot check for %s(): %s\n' % (function_name, msg))
    return msg

  text = '''
%(include)s
#include <assert.h>
%(hdr)s

#if _MSC_VER && !__INTEL_COMPILER
  #pragma function(%(name)s)
#endif

int main(void) {
#if defined (__stub_%(name)s) || defined (__stub___%(name)s)
  #error "%(name)s has a GNU stub, cannot check"
#else
  %(name)s(%(args)s);
#endif

  return 0;
}
''' % { 'name': function_name,
        'include': includetext,
        'hdr': header,
        'args': funcargs }

  context.Display('Checking for %s function %s()... ' % (lang, function_name))
  ret = context.BuildProg(text, suffix)
  comment = "Define to 1 if the system has the function `%s'." % function_name
  _YesNoResult(context, ret, 'HAVE_' + function_name, text, comment)

  # This is different than in SCons.Conftest -- it's how SCons.SConf
  # tweaks the result int its wrappers.
  context.did_show_result = 1
  return not ret
