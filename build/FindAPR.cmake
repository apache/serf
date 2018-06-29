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

# This module defines:
# APR_FOUND, set to TRUE if found, FALSE otherwise.
# APR_VERSION, the version of APR that was found.
# APR_CONTAINS_APRUTIL, set to TRUE if the APR major version is 2 or greater.
# APR_INCLUDES, where to find apr.h, etc.
# APR_LIBRARIES, linker switches to use with ld to link against APR
# APR_EXTRALIBS, additional libraries to link against.
# APR_CFLAGS, the flags to use to compile.
# APR_STATIC_LIBS, on Windows: list of static libraries.
# APR_RUNTIME_LIBS, on Windows: list of DLLs that will be loaded at runtime.


set(APR_FOUND FALSE)
include(APRCommon)

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

  macro(_apr_invoke _varname _separate _regexp)
    _apru_config("${APR_CONFIG_EXECUTABLE}" "${_varname}" "${_separate}" "${_regexp}" ${ARGN})
  endmacro(_apr_invoke)

  _apr_invoke(APR_CFLAGS    FALSE "(^| )-(g|O)[^ ]*" --cppflags --cflags)
  _apr_invoke(APR_INCLUDES  TRUE  "(^| )-I"          --includes)
  _apr_invoke(APR_LIBRARIES TRUE  ""                 --link-ld)
  _apr_invoke(APR_EXTRALIBS TRUE  ""                 --libs)
  _apr_invoke(APR_VERSION   TRUE  ""                 --version)
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
