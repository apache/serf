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

#.rst:
# FindAPR
# --------
#
# Find the native Apache Portable Runtime includes and library.
#
# IMPORTED Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines :prop_tgt:`IMPORTED` target ``APR::APR``, if
# APR has been found. On Windows, it may define the :prop_tgt:`IMPORTED`
# target ``APR::APR_static`` if the static libraries are found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   APR_FOUND          - True if APR was found.
#   APR_VERSION        - The version of APR found (x.y.z)
#   APR_CONTAINS_APRUTIL - True if the APR major version is 2 or greater.
#   APR_INCLUDES       - Where to find apr.h, etc.
#   APR_LIBRARIES      - Linker switches to use with ld to link against APR
#
# ::
#
#   APR_EXTRALIBS      - Additional libraries to link against
#   APR_CFLAGS         - The flags to use to compile.
#   APR_STATIC_LIBS    - On Windows: list of APR static libraries
#   APR_RUNTIME_LIBS   - On Windows: list of APR runtime DLLs
#
# Hints
# ^^^^^
#
# A user may set ``APR_ROOT`` to an APR installation root to tell this
# module where to look. This variable must be defined on Windows.


# -------------------------------------------------------------------
# Common utility functions for FindAPR.cmake and FindAPRtil.cmake
# -------------------------------------------------------------------

include(GNUInstallDirs)

# Run the APR/Util configuration program
function(_apru_config _program _varname _regexp)
  execute_process(COMMAND ${_program} ${ARGN}
                  OUTPUT_VARIABLE _apru_output
                  RESULT_VARIABLE _apru_failed)

  if(_apru_failed)
    message(FATAL_ERROR "${_program} ${ARGN} failed")
  else()
    # Join multi-line output
    string(REGEX REPLACE "[\r\n]"       ""  _apru_output "${_apru_output}")

    # Optionally apply the regular expression filter
    if(NOT ${_regexp} STREQUAL "")
      string(REGEX REPLACE "${_regexp}" " " _apru_output "${_apru_output}")
    endif()

    # Remove leading and trailing spaces
    string(STRIP "${_apru_output}" _apru_output)
    separate_arguments(_apru_output)
    set(${_varname} ${_apru_output} PARENT_SCOPE)
  endif()
endfunction(_apru_config)

# Windows: Find the APR/Util include dir and version number.
function(_apru_find_win_version _header_basename
         _include_varname _version_varname _major_varname _minor_varname)
  find_path(${_include_varname} "${_header_basename}.h"
            PATH_SUFFIXES
            "include"
            "${CMAKE_INSTALL_INCLUDEDIR}"
            "include/apr-2"
            "${CMAKE_INSTALL_INCLUDEDIR}/apr-2"
            "include/apr-1"
            "${CMAKE_INSTALL_INCLUDEDIR}/apr-1")
  mark_as_advanced(${_include_varname})

  set(_header "${_header_basename}_version.h")
  if(NOT EXISTS "${${_include_varname}}/${_header}")
    message(FATAL_ERROR "${_header} was not found in ${${_include_varname}}")
  endif()

  string(TOUPPER "${_header_basename}" _prefix)
  set(_header "${${_include_varname}}/${_header}")
  file(STRINGS "${_header}" _apru_major
       REGEX "^ *# *define +${_prefix}_MAJOR_VERSION +[0-9]+.*$")
  file(STRINGS "${_header}" _apru_minor
       REGEX "^ *# *define +${_prefix}_MINOR_VERSION +[0-9]+.*$")
  file(STRINGS "${_header}" _apru_patch
       REGEX "^ *# *define +${_prefix}_PATCH_VERSION +[0-9]+.*$")
  string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _apru_major ${_apru_major})
  string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _apru_minor ${_apru_minor})
  string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _apru_patch ${_apru_patch})

  set(${_version_varname} "${_apru_major}.${_apru_minor}.${_apru_patch}" PARENT_SCOPE)
  set(${_major_varname} ${_apru_major} PARENT_SCOPE)
  set(${_minor_varname} ${_apru_minor} PARENT_SCOPE)
endfunction(_apru_find_win_version)

# Windows: Find the DLL (runtime) library
function(_apru_find_win_dll _varname _dllname)
  set(CMAKE_FIND_LIBRARY_PREFIXES "")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".dll")
  find_library(${_varname} NAMES "${_dllname}"
               PATH_SUFFIXES
               "bin" "${CMAKE_INSTALL_BINDIR}"
               "lib" "${CMAKE_INSTALL_LIBDIR}")
endfunction(_apru_find_win_dll)

# Windows: Find static and import libraries
function(_apru_find_win_lib _varname _libname)
  set(CMAKE_FIND_LIBRARY_PREFIXES "")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
  find_library(${_varname} NAMES "${_libname}"
               PATH_SUFFIXES "lib" "${CMAKE_INSTALL_LIBDIR}")
endfunction(_apru_find_win_lib)

# Extract the main and extra static libraries
function(_apru_extras _static_var _extra_var)
  # The first element in the list of static libraries will be the the main
  # APR/Util static library, anything else will be additional interface
  # libraries.
  set(_extra "${ARGN}")
  list(GET _extra 0 _static)
  list(REMOVE_AT _extra 0)
  set(${_static_var} ${_static} PARENT_SCOPE)
  set(${_extra_var} ${_extra} PARENT_SCOPE)
endfunction(_apru_extras)

# From the list of link libraries, extract the imported location
function(_apru_location _location_var _extralibs_var)
  unset(_dir)
  unset(_lib)
  unset(_extra)
  foreach(_part ${ARGN})
    string(SUBSTRING "${_part}" 0 2 _flag)
    if(_flag STREQUAL "-L")
      if(NOT _dir AND NOT _lib)
        string(SUBSTRING "${_part}" 2 -1 _rest)
        set(_dir "${_rest}")
      else()
        list(APPEND _extra "${_part}")
      endif()
    elseif(_flag STREQUAL "-l")
      if(NOT _lib)
        string(SUBSTRING "${_part}" 2 -1 _rest)
        set(_lib "${_rest}")
      else()
        list(APPEND _extra " ${_part}")
      endif()
    else()
      if(NOT _lib)
        set(_lib "${_rest}")
      else()
        list(APPEND _extra " ${_part}")
      endif()
    endif()
  endforeach()

  if(NOT _lib)
    message(FATAL_ERROR "did not find any libraries in '${ARGN}'")
  endif()

  if(NOT _dir)
    find_library(${_location_var} NAMES "${_lib}")
  else()
    find_library(${_location_var} NAMES "${_lib}"
                 PATHS "${_dir}" NO_DEFAULT_PATH)
  endif()
  set(${_extralibs_var} ${_extra} PARENT_SCOPE)
endfunction(_apru_location)


# -------------------------------------------------------------------
# The actual FindAPR implementation
# -------------------------------------------------------------------

if(NOT _apru_include_only_utilities)

  set(APR_FOUND FALSE)
  if(DEFINED APR_ROOT)
    get_filename_component(APR_ROOT "${APR_ROOT}" REALPATH)
  endif()

  if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

    _apru_find_win_version("apr" APR_INCLUDES
                           APR_VERSION _apr_major _apr_minor)
    set(_apr_name "apr-${_apr_major}")

    _apru_find_win_lib(APR_LIBRARIES "lib${_apr_name}")
    _apru_find_win_lib(APR_STATIC_LIBS "${_apr_name}")
    _apru_find_win_dll(APR_RUNTIME_LIBS "lib${_apr_name}")

  else()    # NOT Windows

    find_program(APR_CONFIG_EXECUTABLE NAMES apr-2-config apr-1-config
                 PATH_SUFFIXES "bin" "${CMAKE_INSTALL_BINDIR}")
    mark_as_advanced(APR_CONFIG_EXECUTABLE)

    macro(_apr_invoke _varname _regexp)
      _apru_config(${APR_CONFIG_EXECUTABLE} ${_varname} "${_regexp}" "${ARGN}")
    endmacro(_apr_invoke)

    _apr_invoke(APR_CFLAGS     "(^| )-(g|O)[^ ]*" --cppflags --cflags)
    _apr_invoke(APR_INCLUDES   "(^| )-I"          --includes)
    _apr_invoke(APR_LDFLAGS    ""                 --ldflags)
    _apr_invoke(APR_LIBRARIES  ""                 --link-ld)
    _apr_invoke(APR_EXTRALIBS  ""                 --libs)
    _apr_invoke(APR_VERSION    ""                 --version)
    string(REGEX REPLACE "^([0-9]+)\\..*$" "\\1" _apr_major "${APR_VERSION}")

  endif()   # NOT Windows

  if(${_apr_major} GREATER 1)
    set(APR_CONTAINS_APRUTIL TRUE)
  else()
    set(APR_CONTAINS_APRUTIL FALSE)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(
    APR
    REQUIRED_VARS APR_LIBRARIES APR_INCLUDES
    VERSION_VAR APR_VERSION)

  if(APR_FOUND)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

      if(APR_LIBRARIES AND APR_RUNTIME_LIBS)
        add_library(APR::APR SHARED IMPORTED)
        set_target_properties(APR::APR PROPERTIES
          INTERFACE_INCLUDE_DIRECTORIES "${APR_INCLUDES}"
          IMPORTED_LOCATION "${APR_RUNTIME_LIBS}"
          IMPORTED_IMPLIB "${APR_LIBRARIES}")
      endif()

      if(APR_STATIC_LIBS)
        _apru_extras(_apr_static _apr_extra ${APR_STATIC_LIBS})
        add_library(APR::APR_static STATIC IMPORTED)
        set_target_properties(APR::APR_static PROPERTIES
          INTERFACE_COMPILE_DEFINITIONS "APR_DECLARE_STATIC"
          INTERFACE_INCLUDE_DIRECTORIES "${APR_INCLUDES}"
          IMPORTED_INTERFACE_LINK_LIBRARIES "${_apr_extra}"
          IMPORTED_LOCATION "${_apr_static}")
      endif()

    else()    # NOT Windows

      _apru_location(_apr_library _apr_extra "${APR_LIBRARIES}")
      add_library(APR::APR UNKNOWN IMPORTED)
      set_target_properties(APR::APR PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${APR_INCLUDES}"
        INTERFACE_LINK_LIBRARIES "${APR_LDFLAGS};${APR_EXTRALIBS};${_apr_extra}"
        IMPORTED_LOCATION "${_apr_library}")

    endif()   # NOT Windows
  endif(APR_FOUND)

endif(NOT _apru_include_only_utilities)
