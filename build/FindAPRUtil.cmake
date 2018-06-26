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
# APRUTIL_FOUND, set to TRUE if found, FALSE otherwise.
# APRUTIL_VERSION, the version of APR that was found.
# APRUTIL_INCLUDES, where to find apr.h, etc.
# APRUTIL_LIBRARIES, linker switches to use with ld to link against APR
# APRUTIL_EXTRALIBS, additional libraries to link against.
# APRUTIL_DLLS, on Windows: list of DLLs that will be loaded at runtime.
# APRUTIL_STATICLIBS, on Windows: list of static libraries.


if(NOT APR_FOUND)
  find_package(APR)
endif()

if(APR_CONTAINS_APRUTIL)

  set(APRUTIL_FOUND TRUE)
  set(APRUTIL_VERSION ${APR_VERSION})

else(APR_CONTAINS_APRUTIL)

  set(APRUTIL_FOUND FALSE)
  include(APRCommon)

  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

    if(NOT DEFINED APRUTIL_ROOT)
      message(FATAL_ERROR "APRUTIL_ROOT must be defined on Windows")
    endif()

    include(CheckIncludeFile)

    set(APRUTIL_INCLUDES "${APRUTIL_ROOT}/include")
    if(NOT EXISTS "${APRUTIL_INCLUDES}/apu.h")
      message(FATAL_ERROR "apu.h was not found in ${APRUTIL_INCLUDES}")
    endif()
    if(NOT EXISTS "${APRUTIL_INCLUDES}/apu_version.h")
      message(FATAL_ERROR "apu_version.h was not found in ${APRUTIL_INCLUDES}")
    endif()

    _apru_version(APRUTIL_VERSION _apu_major "${APRUTIL_INCLUDES}/apu_version.h" "APU")

    find_library(APRUTIL_LIBRARIES NAMES "libaprutil-${_apu_major}.lib"
                 PATHS ${APRUTIL_ROOT} NO_DEFAULT_PATH PATH_SUFFIXES "lib")
    find_library(APRUTIL_STATICLIBS NAMES "aprutil-${_apu_major}.lib"
                 PATHS ${APRUTIL_ROOT} NO_DEFAULT_PATH PATH_SUFFIXES "lib")
    find_library(APRUTIL_DLLS NAMES "libaprutil-${_apu_major}.dll"
                 PATHS ${APRUTIL_ROOT} NO_DEFAULT_PATH PATH_SUFFIXES "bin")

  else()    # NOT Windows

    if(DEFINED APRUTIL_ROOT)
      find_program(APRUTIL_CONFIG_EXECUTABLE apu-1-config
                   PATHS "${APRUTIL_ROOT}/bin" NO_DEFAULT_PATH)
    else()
      find_program(APRUTIL_CONFIG_EXECUTABLE apu-1-config)
    endif()
    mark_as_advanced(APRUTIL_CONFIG_EXECUTABLE)

    macro(_apu_invoke _varname _separate _regexp)
      _apru_config("${APRUTIL_CONFIG_EXECUTABLE}" "${_varname}" "${_separate}" "${_regexp}" ${ARGN})
    endmacro(_apu_invoke)

    _apu_invoke(APRUTIL_INCLUDES  TRUE  "(^| )-I" --includes)
    _apu_invoke(APRUTIL_EXTRALIBS TRUE  ""        --libs)
    _apu_invoke(APRUTIL_LIBRARIES TRUE  ""        --link-ld)
    _apu_invoke(APRUTIL_LDFLAGS   FALSE ""        --ldflags)
    _apu_invoke(APRUTIL_VERSION   TRUE  ""        --version)

  endif()   # NOT Windows

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(APRUTIL
                                    REQUIRED_VARS APRUTIL_LIBRARIES APRUTIL_INCLUDES
                                    VERSION_VAR APRUTIL_VERSION)

endif(APR_CONTAINS_APRUTIL)
