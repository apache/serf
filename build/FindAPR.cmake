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

cmake_minimum_required(VERSION 3.0)

# This module uses:
#   APR_ROOT, the (optional) root of the APR install area.
# This module defines:
#   APR_FOUND, set to TRUE if found, FALSE otherwise.
#   APR_VERSION, the version of APR that was found.
#   APR_CONTAINS_APRUTIL, set to TRUE if the APR major version is 2 or greater.
#   APR_INCLUDES, where to find apr.h, etc.
#   APR_LIBRARIES, linker switches to use with ld to link against APR
#   APR_EXTRALIBS, additional libraries to link against.
#   APR_CFLAGS, the flags to use to compile.
#   APR_STATIC_LIBS, on Windows: list of static libraries.
#   APR_RUNTIME_LIBS, on Windows: list of DLLs that will be loaded at runtime.


# -------------------------------------------------------------------
# Common utility functions for FindAPR.cmaks and FindAPRtil.cmake
# -------------------------------------------------------------------

function(_apru_config _program _varname _regexp)
  execute_process(COMMAND ${_program} ${ARGN}
                  OUTPUT_VARIABLE _apru_output
                  RESULT_VARIABLE _apru_failed)

  if(_apru_failed)
    message(FATAL_ERROR "${_program} ${ARGN} failed")
  else()
    # Join multi-line outupt
    string(REGEX REPLACE "[\r\n]"       ""  _apru_output "${_apru_output}")

    # Optionally apply the regular expression filter
    if(NOT ${_regexp} STREQUAL "")
      string(REGEX REPLACE "${_regexp}" " " _apru_output "${_apru_output}")
    endif()

    # Remove leading and trailing spaces
    string(REGEX REPLACE "^ +"          ""  _apru_output "${_apru_output}")
    string(REGEX REPLACE " +$"          ""  _apru_output "${_apru_output}")

    separate_arguments(_apru_output)
    set(${_varname} ${_apru_output} PARENT_SCOPE)
  endif()
endfunction(_apru_config)

function(_apru_version _version_varname _major_varname _minor_varname _header _prefix)
  file(STRINGS ${_header} _apru_major
       REGEX "^ *# *define +${_prefix}_MAJOR_VERSION +[0-9]+.*$")
  file(STRINGS ${_header} _apru_minor
       REGEX "^ *# *define +${_prefix}_MINOR_VERSION +[0-9]+.*$")
  file(STRINGS ${_header} _apru_patch
       REGEX "^ *# *define +${_prefix}_PATCH_VERSION +[0-9]+.*$")
  string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _apru_major ${_apru_major})
  string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _apru_minor ${_apru_minor})
  string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _apru_patch ${_apru_patch})
  set(${_version_varname} "${_apru_major}.${_apru_minor}.${_apru_patch}" PARENT_SCOPE)
  set(${_major_varname} ${_apru_major} PARENT_SCOPE)
  set(${_minor_varname} ${_apru_minor} PARENT_SCOPE)
endfunction(_apru_version)

function(_apru_find_dll _varname _dllname)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".dll")
  find_library(${_varname} NAMES ${_dllname}
               PATHS ${ARGN} NO_DEFAULT_PATH PATH_SUFFIXES "bin" "lib")
endfunction(_apru_find_dll)

# -------------------------------------------------------------------

if(NOT _apru_include_only_utilities)

  set(APR_FOUND FALSE)

  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

    if(NOT DEFINED APR_ROOT)
      message(FATAL_ERROR "APR_ROOT must be defined on Windows")
    endif()

    include(CheckIncludeFile)

    set(APR_INCLUDES "${APR_ROOT}/include")
    if(NOT EXISTS "${APR_INCLUDES}/apr.h")
      message(FATAL_ERROR "apr.h was not found in ${APR_INCLUDES}")
    endif()
    if(NOT EXISTS "${APR_INCLUDES}/apr_version.h")
      message(FATAL_ERROR "apr_version.h was not found in ${APR_INCLUDES}")
    endif()

    _apru_version(APR_VERSION _apr_major _apr_minor "${APR_INCLUDES}/apr_version.h" "APR")
    set(_apr_name "apr-${_apr_major}")

    find_library(APR_LIBRARIES NAMES "lib${_apr_name}.lib"
                 PATHS ${APR_ROOT} NO_DEFAULT_PATH PATH_SUFFIXES "lib")
    find_library(APR_STATIC_LIBS NAMES "${_apr_name}.lib"
                 PATHS ${APR_ROOT} NO_DEFAULT_PATH PATH_SUFFIXES "lib")
    _apru_find_dll(APR_RUNTIME_LIBS "lib${_apr_name}.dll" ${APR_ROOT})

  else()    #NOT Windows

    if(DEFINED APR_ROOT)
      find_program(APR_CONFIG_EXECUTABLE NAMES apr-2-config apr-1-config
                   PATHS "${APR_ROOT}/bin" NO_DEFAULT_PATH)
    else()
      find_program(APR_CONFIG_EXECUTABLE NAMES apr-2-config apr-1-config)
    endif()
    mark_as_advanced(APR_CONFIG_EXECUTABLE)

    macro(_apr_invoke _varname _regexp)
      _apru_config(${APR_CONFIG_EXECUTABLE} ${_varname} "${_regexp}" "${ARGN}")
    endmacro(_apr_invoke)

    _apr_invoke(APR_CFLAGS     "(^| )-(g|O)[^ ]*" --cppflags --cflags)
    _apr_invoke(APR_INCLUDES   "(^| )-I"          --includes)
    _apr_invoke(APR_LIBRARIES  ""                 --link-ld)
    _apr_invoke(APR_EXTRALIBS  ""                 --libs)
    _apr_invoke(APR_VERSION    ""                 --version)
    string(REGEX REPLACE "^([0-9]+)\\..*$" "\\1" _apr_major "${APR_VERSION}")

  endif()   # NOT Windows

  if(_apr_major GREATER 2)
    set(APR_CONTAINS_APRUTIL TRUE)
  else()
    set(APR_CONTAINS_APRUTIL FALSE)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(APR
                                    REQUIRED_VARS APR_LIBRARIES APR_INCLUDES
                                    VERSION_VAR APR_VERSION)

endif(NOT _apru_include_only_utilities)
