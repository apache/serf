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

cmake_minimum_required(VERSION 3.12)

include(GNUInstallDirs)
set(Brotli_FOUND FALSE)

function(_get_brotli_version)
  find_program(brotli NAMES "brotli"
               PATH_SUFFIXES "bin" "${CMAKE_INSTALL_BINDIR}")

  if(NOT "${brotli}" MATCHES "-NOTFOUND")
    execute_process(COMMAND "${brotli}" "--version"
                    OUTPUT_VARIABLE output
                    RESULT_VARIABLE failed)
   if(failed)
     message(STATUS "Failed: ${brotli} --version")
   else()
     string(REPLACE "brotli" "" output "${output}")
     string(STRIP "${output}" output)
     set(BROTLI_VERSION "${output}" PARENT_SCOPE)
   endif()
 endif()
endfunction(_get_brotli_version)

function(_get_brotli_includes_libs)
  find_path(includes "decode.h"
            PATH_SUFFIXES
            "include/brotli"
            "${CMAKE_INSTALL_INCLUDEDIR}/brotli}")
  get_filename_component(includes "${includes}" DIRECTORY)
  find_library(common_lib NAMES "brotlicommon"
               PATH_SUFFIXES "lib" "${CMAKE_INSTALL_LIBDIR}")
  find_library(decode_lib NAMES "brotlidec"
               PATH_SUFFIXES "lib" "${CMAKE_INSTALL_LIBDIR}")
  find_library(encode_lib NAMES "brotlienc"
               PATH_SUFFIXES "lib" "${CMAKE_INSTALL_LIBDIR}")

  set(BROTLI_INCLUDES "${includes}" PARENT_SCOPE)
  set(BROTLI_COMMON_LIBRARY "${common_lib}" PARENT_SCOPE)
  set(BROTLI_DECODE_LIBRARY "${decode_lib}" PARENT_SCOPE)
  set(BROTLI_ENCODE_LIBRARY "${encode_lib}" PARENT_SCOPE)
endfunction(_get_brotli_includes_libs)

if(DEFINED Brotli_ROOT)
  get_filename_component(Brotli_ROOT "${Brotli_ROOT}" REALPATH)
endif()

_get_brotli_version()
_get_brotli_includes_libs()
if(NOT EXISTS "${BROTLI_INCLUDES}/brotli/decode.h"
   OR NOT EXISTS "${BROTLI_INCLUDES}/brotli/encode.h"
   OR NOT EXISTS "${BROTLI_INCLUDES}/brotli/types.h")
  message(STATUS "Could NOT find Brotli (missing headers)")
else()
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Brotli
    REQUIRED_VARS BROTLI_COMMON_LIBRARY
                  BROTLI_DECODE_LIBRARY
                  BROTLI_ENCODE_LIBRARY
                  BROTLI_INCLUDES
    VERSION_VAR BROTLI_VERSION)
  if(Brotli_FOUND)
    add_library(Brotli::Common UNKNOWN IMPORTED)
    set_target_properties(Brotli::Common PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${BROTLI_INCLUDES}"
      IMPORTED_LOCATION "${BROTLI_COMMON_LIBRARY}")

    add_library(Brotli::Decode UNKNOWN IMPORTED)
    set_target_properties(Brotli::Decode PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${BROTLI_INCLUDES}"
      INTERFACE_LINK_LIBRARIES Brotli::Common
      IMPORTED_LOCATION "${BROTLI_DECODE_LIBRARY}")

    add_library(Brotli::Encode UNKNOWN IMPORTED)
    set_target_properties(Brotli::Encode PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${BROTLI_INCLUDES}"
      INTERFACE_LINK_LIBRARIES Brotli::Common
      IMPORTED_LOCATION "${BROTLI_ENCODE_LIBRARY}")
  endif()
endif()
