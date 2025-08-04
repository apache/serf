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
# Generator for lists of public symbols to export from shared libraries.
# Supports:
#     - Windows DLL definitions files (.def)
#     - Mach-O dylib exported symbols list (.exp -- for macOS and suchlike)
#     - ELF version scripts (.map -- Linux, FreeBSD, OpenBSD, etc.)
#

import re
import sys
import collections

# This regex parses function declarations that look like:
#
#    return_type serf_func1(...
#    return_type *serf_func2(...
#
# Where return_type is a combination of words and "*" each separated by a
# SINGLE space. If the function returns a pointer type (like serf_func2),
# then a space may exist between the "*" and the function name. Thus,
# a more complicated example might be:
#    const type * const * serf_func3(...
#
_funcs = re.compile(r'^(?:(?:\w+|\*) )+\*?(serf_[a-z][a-zA-Z_0-9]*)\(',
                    re.MULTILINE)

# This regex parses the bucket type definitions which look like:
#
#    extern const serf_bucket_type_t serf_bucket_type_FOO;
#
_types = re.compile(r'^extern const serf_bucket_type_t (serf_[a-z_]*);',
                    re.MULTILINE)


# Blacklist the serf v2 API for now.
BLACKLIST = frozenset(['serf_connection_switch_protocol',
                       'serf_http_protocol_create',
                       'serf_https_protocol_create',
                       'serf_http_request_queue',
                       ])


# These are the types of export symbols formats that we know about.
ExportTarget = collections.namedtuple('ExportTarget',
                                      ('ext', 'link_flag', 'description'))
TARGET_WINDLL = ExportTarget('.def',
                             '/DEF:%s',
                             'Windows dynamic link library definitions')
TARGET_MACHO = ExportTarget('.exp',
                            '-Wl,-exported_symbols_list,%s',
                            'Mach-O dynamic library exported symbols')
TARGET_ELF = ExportTarget('.map',
                          '-Wl,--version-script,%s',
                          'ELF shared library symbol map')


class ExportGenerator(object):
  '''Generic exports generator, can guess the file format.'''

  def __init__(self, target=None):
    if target is None:
      target = self._guess_target()

    self._target = target
    self._dispatch = {
      TARGET_WINDLL: self._gen_win_def,
      TARGET_MACHO: self._gen_macho_exp,
      TARGET_ELF: self._gen_elf_map,
    }

  @property
  def target(self):
    return self._target

  def generate(self, stream, *headers):
    exports = set()
    for fname in headers:
      content = open(fname).read()
      for name in _funcs.findall(content):
        exports.add(name)
      for name in _types.findall(content):
        exports.add(name)

    write = self._dispatch.get(self._target, self._gen_error)
    return write(stream, sorted(exports - BLACKLIST))

  def _guess_target(self):
    if sys.platform == 'win32':
      return TARGET_WINDLL
    if sys.platform == 'darwin':
      return TARGET_MACHO
    return None

  def _gen_win_def(self, stream, symbols):
    stream.write('EXPORTS\n')
    for symbol in symbols:
      stream.write('%s\n' % symbol)
    return True

  def _gen_macho_exp(self, stream, symbols):
    stream.write('# Exported symbols\n')
    for symbol in symbols:
      stream.write('_%s\n' % symbol)
    return True

  def _gen_elf_map(self, stream, symbols):
    stream.write('{\n'
                 '  global:\n')
    for symbol in symbols:
      stream.write('    %s;\n' % symbol)
    stream.write('  local:\n'
                 '    *;\n'
                 '};\n')
    return True

  def _gen_error(self, *_):
    sys.stderr.write('error: unknown exports format: %s\n'
                     % repr(self._target))
    return False
