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

# This function defines:
# SERF_OPENSSL_STATIC, if we're linking with a static libraries.
# SERF_OPENSSL_EXTRA_LIBS, if we need additional libraries to link.
# SERF_OPENSSL_RUNTIME_LIBS, when it finds OpenSSL DLL libraries.
function(SerfWindowsProcessOpenSSL)
  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  endif()
endfunction(SerfWindowsProcessOpenSSL)

# This function defines:
# SERF_ZLIB_STATIC, if we're linking with a static libraries.
# SERF_ZLIB_EXTRA_LIBS, if we need additional libraries to link.
# SERF_ZLIB_RUNTIME_LIBS, when it finds OpenSSL DLL libraries.
function(SerfWindowsProcessZLIB)
  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  endif()
endfunction(SerfWindowsProcessZLIB)

# Generate a Windows DLL .def file from a list of headers.
function(SerfWindowsGenDef blacklist_ target_)
  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(func_search_rx_ "^(([a-zA-Z_0-9]+|\\*) )+\\*?(serf_[a-z][a-zA-Z_0-9]*)\\(")
    set(type_search_rx_ "^extern const serf_bucket_type_t (serf_[a-z_]*);")
    set(func_rx_ "^(([a-zA-Z_0-9]+|\\*) )+\\*?(serf_[a-z][a-zA-Z_0-9]*).*$")
    set(type_rx_ "^extern const serf_bucket_type_t (serf_[a-z_]*).*$")

    foreach(file_ ${ARGN})
      message(STATUS "Looking for exports in ${file_}")
      file(STRINGS ${file_} funcs_ REGEX "${func_search_rx_}")
      file(STRINGS ${file_} types_ REGEX "${type_search_rx_}")
      foreach(sym_ ${funcs_})
        string(REGEX REPLACE "${func_rx_}" "\\3" def_ ${sym_})
        list(APPEND defs_ ${def_})
      endforeach()
      foreach(sym_ ${types_})
        string(REGEX REPLACE "${type_rx_}" "\\1" def_ ${sym_})
        list(APPEND defs_ ${def_})
      endforeach()
    endforeach()

    list(SORT defs_)
    list(REMOVE_DUPLICATES defs_)
    file(WRITE ${target_} "EXPORTS\n")
    foreach(def_ ${defs_})
      list(FIND blacklist_ "${def_}" skip_)
      if(skip_ LESS 0)
        file(APPEND ${target_} "${def_}\n")
      endif()
    endforeach()
  endif()
endfunction(SerfWindowsGenDef)
