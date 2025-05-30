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
set(BROTLI_FOUND FALSE)

function(_get_brotli_version)
  if(DEFINED BROTLI_ROOT)
    get_filename_component(BROTLI_ROOT "${BROTLI_ROOT}" REALPATH)
    find_program(brotli NAMES "brotli"
                 PATHS
                 "${BROTLI_ROOT}/bin"
                 "${BROTLI_ROOT}/${CMAKE_INSTALL_BINDIR}"
                 NO_DEFAULT_PATH)
  else()
    find_program(brotli NAMES "brotli")
  endif()

  if(NOT "${brotli}" STREQUAL "brotli-NOTFOUND")
    execute_process(COMMAND "${brotli}" "--version"
                    OUTPUT_VARIABLE output
                    RESULT_VARIABLE failed)
   if(failed)
     message(STATUS "failed: ${brotli} --version")
     set(BROTLI_VERSION "unknown" PARENT_SCOPE)
   else()
     string(REPLACE "brotli" "" output "${output}")
     string(STRIP "${output}" output)
     set(BROTLI_VERSION "${output}" PARENT_SCOPE)
   endif()
 else()
   set(BROTLI_VERSION "unknown" PARENT_SCOPE)
 endif()
endfunction(_get_brotli_version)

function(_get_brotli_includes_libs)
  if(DEFINED BROTLI_ROOT)
    find_path(includes "decode.h"
              PATHS "${BROTLI_ROOT}"
              PATH_SUFFIXES
              "include/brotli"
              "${CMAKE_INSTALL_INCLUDEDIR}/brotli}"
              NO_DEFAULT_PATH)
    get_filename_component(includes "${includes}" DIRECTORY)
    find_library(common_lib "brotlicommon"
                 PATHS "${BROTLI_ROOT}"
                 PATH_SUFFIXES "lib" "${CMAKE_INSTALL_LIBDIR}"
                 NO_DEFAULT_PATH)
    find_library(decode_lib "brotlidec"
                 PATHS "${BROTLI_ROOT}"
                 PATH_SUFFIXES "lib" "${CMAKE_INSTALL_LIBDIR}"
                 NO_DEFAULT_PATH)
    find_library(encode_lib "brotlienc"
                 PATHS "${BROTLI_ROOT}"
                 PATH_SUFFIXES "lib" "${CMAKE_INSTALL_LIBDIR}"
                 NO_DEFAULT_PATH)
  else()
    find_path(includes "decode.h"
              PATH_SUFFIXES
              "include/brotli"
              "${CMAKE_INSTALL_INCLUDEDIR}/brotli}")
    get_filename_component(includes "${includes}" DIRECTORY)
    find_library(common_lib "brotlicommon")
    find_library(decode_lib "brotlidec")
    find_library(encode_lib "brotlienc")
  endif()
  set(BROTLI_INCLUDES "${includes}" PARENT_SCOPE)
  set(BROTLI_COMMON_LIBRARY "${common_lib}" PARENT_SCOPE)
  set(BROTLI_DECODE_LIBRARY "${decode_lib}" PARENT_SCOPE)
  set(BROTLI_ENCODE_LIBRARY "${encode_lib}" PARENT_SCOPE)
endfunction(_get_brotli_includes_libs)

_get_brotli_version()
_get_brotli_includes_libs()
if(NOT EXISTS "${BROTLI_INCLUDES}/brotli/decode.h"
   OR NOT EXISTS "${BROTLI_INCLUDES}/brotli/encode.h"
   OR NOT EXISTS "${BROTLI_INCLUDES}/brotli/types.h")
  message(STATUS "Could NOT find Brotli (missing headers)")
else()
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(BROTLI
    REQUIRED_VARS BROTLI_COMMON_LIBRARY
                  BROTLI_DECODE_LIBRARY
                  BROTLI_ENCODE_LIBRARY
                  BROTLI_INCLUDES
    VERSION_VAR BROTLI_VERSION)
  if(BROTLI_FOUND)
    add_library(BROTLI::COMMON UNKNOWN IMPORTED)
    set_target_properties(BROTLI::COMMON PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${BROTLI_INCLUDES}"
      IMPORTED_LOCATION "${BROTLI_COMMON_LIBRARY}")

    add_library(BROTLI::DECODE UNKNOWN IMPORTED)
    set_target_properties(BROTLI::DECODE PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${BROTLI_INCLUDES}"
      INTERFACE_LINK_LIBRARIES BROTLI::COMMON
      IMPORTED_LOCATION "${BROTLI_DECODE_LIBRARY}")

    add_library(BROTLI::ENCODE UNKNOWN IMPORTED)
    set_target_properties(BROTLI::ENCODE PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${BROTLI_INCLUDES}"
      INTERFACE_LINK_LIBRARIES BROTLI::COMMON
      IMPORTED_LOCATION "${BROTLI_ENCODE_LIBRARY}")
  endif()
endif()
