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

#.rst:
# FindAPRUtil
# --------
#
# Find the native Apache Portable Runtime Utilities includes and library.
#
# IMPORTED Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines :prop_tgt:`IMPORTED` target ``APR::APRUTIL``, if
# APR-Util has been found. On Windows, it may define the :prop_tgt:`IMPORTED`
# target ``APR::APRUTIL_static`` if the static libraries are found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   APRUTIL_FOUND          - True if APR-Util was found
#   APRUTIL_VERSION        - The version of APR-Util found (x.y.z)
#   APRUTIL_INCLUDES       - Where to find apr.h, etc.
#   APRUTIL_LIBRARIES      - Linker switches to use with ld to link against APR
#
# ::
#
#   APRUTIL_EXTRALIBS      - Additional libraries to link against
#   APRUTIL_STATIC_LIBS    - On Windows: list of APR-Util static libraries
#   APRUTIL_RUNTIME_LIBS   - On Windows: list of APR-Util runtime DLLs
#
# Hints
# ^^^^^
#
# A user may set ``APRUtil_ROOT`` to an APR-Util installation root to tell
# this module where to look. This variable must be defined on Windows.


if(NOT APR_FOUND)
  find_package(APR REQUIRED)
endif()

set(APRUTIL_FOUND FALSE)

if(APR_CONTAINS_APRUTIL)

  set(APRUTIL_VERSION ${APR_VERSION})
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(APRUTIL
                                    REQUIRED_VARS APRUTIL_VERSION
                                    VERSION_VAR APRUTIL_VERSION)

else(APR_CONTAINS_APRUTIL)

  set(_apru_include_only_utilities TRUE)
  include(${CMAKE_CURRENT_LIST_DIR}/FindAPR.cmake)
  unset(_apru_include_only_utilities)

  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

    if(DEFINED APRUtil_ROOT)
      get_filename_component(APRUtil_ROOT "${APRUtil_ROOT}" REALPATH)
    else()
      message(FATAL_ERROR "APRUtil_ROOT must be defined on Windows")
    endif()

    include(CheckIncludeFile)

    set(APRUTIL_INCLUDES "${APRUtil_ROOT}/include")
    if(NOT EXISTS "${APRUTIL_INCLUDES}/apu.h")
      message(FATAL_ERROR "apu.h was not found in ${APRUTIL_INCLUDES}")
    endif()
    if(NOT EXISTS "${APRUTIL_INCLUDES}/apu_version.h")
      message(FATAL_ERROR "apu_version.h was not found in ${APRUTIL_INCLUDES}")
    endif()

    _apru_version(APRUTIL_VERSION _apu_major _apu_minor "${APRUTIL_INCLUDES}/apu_version.h" "APU")
    set(_apu_name "aprutil-${_apu_major}")

    if(${_apu_major} GREATER 1 OR (${_apu_major} EQUAL 1 AND ${_apu_minor} GREATER 5))
      set(_apu_expat_name "expat.lib")
    else()
      set(_apu_expat_name "xml.lib")
    endif()

    find_library(APRUTIL_LIBRARIES NAMES "lib${_apu_name}.lib"
                 PATHS ${APRUtil_ROOT} NO_DEFAULT_PATH PATH_SUFFIXES "lib")
    find_library(_apu_static NAMES "${_apu_name}.lib"
                 PATHS ${APRUtil_ROOT} NO_DEFAULT_PATH PATH_SUFFIXES "lib")
    find_library(_apu_expat NAMES ${_apu_expat_name}
                 PATHS ${APRUtil_ROOT} NO_DEFAULT_PATH PATH_SUFFIXES "lib")
    _apru_find_dll(APRUTIL_RUNTIME_LIBS "lib${_apu_name}.dll" ${APRUtil_ROOT})

    if(NOT _apu_expat AND (_apu_expat_name MATCHES "expat"))
      find_package(EXPAT QUIET)
      if(EXPAT_FOUND)
        set(_apu_expat ${EXPAT_LIBRARIES})
      endif()
    endif()
    if(NOT _apu_expat)
      message(WARNING "Could not find ${_apu_expat_name}"
                      " for APR-Util static linking.")
    endif()
    set(APRUTIL_STATIC_LIBS ${_apu_static} ${_apu_expat}
        CACHE STRING "APR-Util static libraies.")

  else()    # NOT Windows

    if(DEFINED APRUtil_ROOT)
      get_filename_component(APRUtil_ROOT "${APRUtil_ROOT}" REALPATH)
      find_program(APRUTIL_CONFIG_EXECUTABLE apu-1-config
                   PATHS "${APRUtil_ROOT}/bin" NO_DEFAULT_PATH)
    else()
      find_program(APRUTIL_CONFIG_EXECUTABLE apu-1-config)
    endif()
    mark_as_advanced(APRUTIL_CONFIG_EXECUTABLE)

    macro(_apu_invoke _varname _regexp)
      _apru_config(${APRUTIL_CONFIG_EXECUTABLE} ${_varname} "${_regexp}" "${ARGN}")
    endmacro(_apu_invoke)

    _apu_invoke(APRUTIL_INCLUDES  "(^| )-I" --includes)
    _apu_invoke(APRUTIL_EXTRALIBS ""        --libs)
    _apu_invoke(APRUTIL_LIBRARIES ""        --link-ld)
    _apu_invoke(APRUTIL_LDFLAGS   ""        --ldflags)
    _apu_invoke(APRUTIL_VERSION   ""        --version)

  endif()   # NOT Windows

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(APRUTIL
                                    REQUIRED_VARS APRUTIL_LIBRARIES APRUTIL_INCLUDES
                                    VERSION_VAR APRUTIL_VERSION)

  if(APRUTIL_FOUND)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

      if(APRUTIL_LIBRARIES AND APRUTIL_RUNTIME_LIBS)
        add_library(APR::APRUTIL SHARED IMPORTED)
        set_target_properties(APR::APRUTIL PROPERTIES
          INTERFACE_INCLUDE_DIRECTORIES "${APRUTIL_INCLUDES}"
          IMPORTED_LOCATION "${APRUTIL_RUNTIME_LIBS}"
          IMPORTED_IMPLIB "${APRUTIL_LIBRARIES}")
        if(TARGET APR::APR)
          set_target_properties(APR::APRUTIL PROPERTIES
            INTERFACE_LINK_LIBRARIES APR::APR)
        endif()
      endif()

      if(APRUTIL_STATIC_LIBS)
        _apru_extras(_apu_static _apu_extra ${APRUTIL_STATIC_LIBS})
        if(TARGET APR::APR_static)
          list(APPEND _apu_extra APR::APR_static)
        endif()
        add_library(APR::APRUTIL_static STATIC IMPORTED)
        set_target_properties(APR::APRUTIL_static PROPERTIES
          INTERFACE_INCLUDE_DIRECTORIES "${APRUTIL_INCLUDES}"
          INTERFACE_LINK_LIBRARIES "${_apu_extra}"
          IMPORTED_LOCATION "${_apu_static}")
      endif()

    else()    # NOT Windows

      _apru_location(_apu_library _apu_extra "${APRUTIL_LIBRARIES}")
      add_library(APR::APRUTIL UNKNOWN IMPORTED)
      set_target_properties(APR::APRUTIL PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${APRUTIL_INCLUDES}"
        INTERFACE_LINK_LIBRARIES "${APRUTIL_EXTRALIBS};${_apu_extra}"
        IMPORTED_LOCATION "${_apu_library}")

    endif()   # NOT Windows
  endif(APRUTIL_FOUND)

endif(APR_CONTAINS_APRUTIL)
