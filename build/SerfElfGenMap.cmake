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

# Generate Serf's .map file for Elf shared libraries.

include(SerfFindExports)

separate_arguments(SERF_EXPORT_BLACKLIST)
separate_arguments(SERF_EXPORT_HEADERS)

SerfFindExports("${SERF_EXPORT_BLACKLIST}" exports_ ${SERF_EXPORT_HEADERS})
file(WRITE "${SERF_EXPORT_SYMBOLS}"
     "{\n"
     "  global:\n")
foreach(symbol_ ${exports_})
  file(APPEND "${SERF_EXPORT_SYMBOLS}" "    ${symbol_};\n")
endforeach()
file(APPEND "${SERF_EXPORT_SYMBOLS}"
     "  local:\n"
     "    *;\n"
     "};\n")
