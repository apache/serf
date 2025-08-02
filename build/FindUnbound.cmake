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
# FindUnbound
# -----------
#
# Find the Unbound library and headers.
#
# IMPORTED Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines :prop_tgt:`IMPORTED` target ``Unbound::Unbound``, if
# libunbound has been found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   Unbound_FOUND        - True if libunbound was found.
#   UNBOUND_VERSION      - The version of libunbound found (x.y.z).
#   UNBOUND_INCLUDE_DIR  - Where to find unbound.h.
#   UNBOUND_LIBRARY      - Linker switches to use with ld to link the library.
#
# ::
#
#   UNBOUND_PC_REQUIRES  - The name of the pkg-config module for libunbound;
#                          empty if pkg-config was not used to find the library.
#   UNBOUND_PC_LIBS      - The link libraries for pkg-config, if
#                          UNBOUND_PC_REQUUIRES is not set.
#
# Hints
# ^^^^^
#
# A user may set ``Unbound_ROOT`` to tell this module where to look.

include(FindPackageHandleStandardArgs)
include(GNUInstallDirs)
find_package(PkgConfig QUIET)

# Save the PKG_CONFIG_PATH environment variable
if(PKG_CONFIG_FOUND)
  set(_pkg_config_path $ENV{PKG_CONFIG_PATH})
endif()

set(Unbound_FOUND FALSE)
if(DEFINED Unbound_ROOT)
  # Search in the provided root path
  set(_root_search PATHS ${Unbound_ROOT} NO_DEFAULT_PATH)
  list(APPEND _UNBOUND_SEARCHES _root_search)

  # Set the PKG_CONFIG_PATH environment variable
  if(PKG_CONFIG_FOUND)
    find_path(_pcfile NAMES "libunbound.pc"
              ${_root_search}
              PATH_SUFFIXES
              "lib/pkgconfig"
              "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
              "share/pkgconfig"
              "${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig")
    if(_pcfile AND EXISTS "${_pcfile}/libunbound.pc")
      set(ENV{PKG_CONFIG_PATH} ${_pcfile})
    endif()
  endif()
endif()

# Search in default paths
set(_default_search)
list(APPEND _UNBOUND_SEARCHES _default_search)

# Try pkg-config first
if(PKG_CONFIG_FOUND)
  pkg_search_module(UNBOUND QUIET IMPORTED_TARGET libunbound)
  if(UNBOUND_FOUND)
    find_package_handle_standard_args(Unbound
      REQUIRED_VARS UNBOUND_LINK_LIBRARIES UNBOUND_INCLUDEDIR
      VERSION_VAR UNBOUND_VERSION)
    if(Unbound_FOUND)
      add_library(Unbound::Unbound ALIAS PkgConfig::UNBOUND)
      set(UNBOUND_INCLUDE_DIR ${UNBOUND_INCLUDEDIR})
      set(UNBOUND_LIBRARY ${UNBOUND_LINK_LIBRARIES})
      set(UNBOUND_PC_REQUIRES libunbound)
      set(UNBOUND_PC_LIBS)
    endif()
  endif()
endif()

if(NOT Unbound_FOUND)
  # Try each search configuration
  foreach(search ${_UNBOUND_SEARCHES})
    find_path(UNBOUND_INCLUDE_DIR NAMES "unbound.h" ${${search}}
              PATH_SUFFIXES "include" "${CMAKE_INSTALL_INCLUDEDIR}")
    if(UNBOUND_INCLUDE_DIR AND EXISTS "${UNBOUND_INCLUDE_DIR}/unbound.h")
      # Use the first successful search to find the libraries
      if(NOT DEFINED libsearch)
        set(libsearch ${search})
      endif()
    endif()
  endforeach()

  find_library(UNBOUND_LIBRARY NAMES "unbound" NAMES_PER_DIR ${${libsearch}}
               PATH_SUFFIXES "lib" "${CMAKE_INSTALL_LIBDIR}")

  # Extract the version number from the header
  if(UNBOUND_INCLUDE_DIR AND EXISTS "${UNBOUND_INCLUDE_DIR}/unbound.h")
    file(STRINGS "${UNBOUND_INCLUDE_DIR}/unbound.h" _major
      REGEX "^ *# *define +UNBOUND_VERSION_MAJOR +[0-9]+.*$")
    file(STRINGS "${UNBOUND_INCLUDE_DIR}/unbound.h" _minor
      REGEX "^ *# *define +UNBOUND_VERSION_MINOR +[0-9]+.*$")
    file(STRINGS "${UNBOUND_INCLUDE_DIR}/unbound.h" _micro
      REGEX "^ *# *define +UNBOUND_VERSION_MICRO +[0-9]+.*$")
    string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _major ${_major})
    string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _minor ${_minor})
    string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _micro ${_micro})
    set(UNBOUND_VERSION "${_major}.${_minor}.${_micro}")
  endif()

  find_package_handle_standard_args(Unbound
    REQUIRED_VARS UNBOUND_LIBRARY UNBOUND_INCLUDE_DIR
    VERSION_VAR UNBOUND_VERSION)
  if(Unbound_FOUND)
    add_library(Unbound::Unbound UNKNOWN IMPORTED)
    set_target_properties(Unbound::Unbound PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${UNBOUND_INCLUDE_DIR}"
      IMPORTED_LOCATION "${UNBOUND_LIBRARY}")
    set(UNBOUND_PC_REQUIRES)
    set(UNBOUND_PC_LIBS "${UNBOUND_LIBRARY}")
  endif()
endif()

mark_as_advanced(UNBOUND_INCLUDE_DIR)
mark_as_advanced(UNBOUND_LIBRARY)

# Restore the PKG_CONFIG_PATH environment variable
if(PKG_CONFIG_FOUND)
  set(ENV{PKG_CONFIG_PATH} ${_pkg_config_path})
endif()
