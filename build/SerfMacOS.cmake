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

# macOS: Find packages installed in Homebrew or MacPorts.

macro(_serf_macos__check_package_manager)
  if(USE_HOMEBREW)
    _serf_macos__check_homebrew()
  endif()
  if(USE_MACPORTS)
    _serf_macos__check_macports()
  endif()
endmacro(_serf_macos__check_package_manager)

macro(_serf_macos__find_package package variable docstring)
  if(USE_HOMEBREW)
    _serf_macos__find_homebrew_package("${package}" "${variable}" "${docstring}")
  endif()
  if(USE_MACPORTS)
    _serf_macos__find_macports_package("${package}" "${variable}" "${docstring}")
  endif()
endmacro(_serf_macos__find_package)

function(serf_macos_find_packages)
  _serf_macos__check_package_manager()
  _serf_macos__find_package("apr" APR_ROOT "Path to APR's install area")
  _serf_macos__find_package("apr-util" APRUtil_ROOT "Path to APR-Util's install area")
  _serf_macos__find_package("openssl" OPENSSL_ROOT_DIR "Path to OpenSSL's install area")
  if(USE_MACPORTS)
    # NOTE: MacPorts uses its own version of zlib. Homebrew tends to use
    #       the system zlib, so we won't even look for the Homebrew version.
    #       The user can always override that on the command line.
    _serf_macos__find_package("zlib" ZLIB_ROOT "Path to zlib's install area")
  endif()
  _serf_macos__find_package("brotli" Brotli_ROOT "Path to Brotli's install area")
  _serf_macos__find_package("gssapi" GSSAPI_ROOT "Path to GSSAPI's install area")
endfunction()

#
# Homebrew
#
function(_serf_macos__check_homebrew)
  if(NOT DEFINED SERF_MACOS__HAS_HOMEBREW)
    execute_process(COMMAND "brew" "--version"
                    ERROR_VARIABLE shutup
                    OUTPUT_VARIABLE version
                    RESULT_VARIABLE failed)
    if(NOT failed)
      execute_process(COMMAND "brew" "--prefix"
                      ERROR_VARIABLE shutup
                      OUTPUT_VARIABLE prefix
                      RESULT_VARIABLE failed)
    endif()
    if(failed)
      set(SERF_MACOS__HAS_HOMEBREW FALSE PARENT_SCOPE)
      message(WARNING "Homebrew was not found")
    else()
      string(STRIP "${version}" version)
      string(STRIP "${prefix}" prefix)
      message(STATUS "Found ${version} at ${prefix}")
      set(SERF_MACOS__HAS_HOMEBREW TRUE PARENT_SCOPE)
    endif()
  endif()
endfunction(_serf_macos__check_homebrew)

function(_serf_macos__find_homebrew_package package variable docstring)
  # Don't override user's provided values.
  if("${${variable}}" STREQUAL "" AND ${SERF_MACOS__HAS_HOMEBREW})
    set(package_alias "${package}")
    if("${package_alias}" STREQUAL "gssapi")
      # The Homebrew package is called 'krb5'
      set(package "krb5")
    endif()

    execute_process(COMMAND "brew" "--prefix" "--installed" "${package}"
                    ERROR_VARIABLE shutup
                    OUTPUT_VARIABLE prefix
                    RESULT_VARIABLE failed)
    if(failed)
      message(STATUS "Homebrew: not found: ${package}")
    else()
      string(STRIP "${prefix}" prefix)
      if("${package_alias}" STREQUAL "${package}")
        message(STATUS "Homebrew: found ${package} at ${prefix}")
      else()
        message(STATUS "Homebrew: found ${package_alias} (${package}) at ${prefix}")
      endif()
      set(${variable} "${prefix}" CACHE PATH "${docstring}" FORCE)
    endif()
  endif()
endfunction(_serf_macos__find_homebrew_package)

#
# MacPorts
#
function(_serf_macos__check_macports)
  if(NOT DEFINED SERF_MACOS__HAS_MACPORTS)
    execute_process(COMMAND "port" "version"
                    ERROR_VARIABLE shutup
                    OUTPUT_VARIABLE version
                    RESULT_VARIABLE failed)
    if(NOT failed)
      find_program(port NAMES "port")
    endif()
    if(failed OR "${port}" STREQUAL "port-NOTFOUND")
      set(SERF_MACOS__HAS_MACPORTS FALSE PARENT_SCOPE)
      message(WARNING "MacPorts was not found")
    else()
      # 'port version' prints "Version: n.n.n"
      string(REPLACE "Version:" "" version "${version}")
      string(STRIP "${version}" version)

      # ${port} will be "/some/path/prefix/bin/port"
      get_filename_component(prefix ${port} DIRECTORY)
      get_filename_component(prefix ${prefix} DIRECTORY)
      message(STATUS "Found MacPorts ${version} at ${prefix}")
      set(SERF_MACOS__HAS_MACPORTS TRUE PARENT_SCOPE)
      set(SERF_MACOS__MACPORTS_DIR "${prefix}" PARENT_SCOPE)
    endif()
  endif()
endfunction(_serf_macos__check_macports)

function(_serf_macos__find_macports_package package variable docstring)
  # Don't override user's provided values.
  if("${${variable}}" STREQUAL "" AND ${SERF_MACOS__HAS_MACPORTS})
    set(package_alias "${package}")
    if("${package_alias}" STREQUAL "gssapi")
      # The MacPorts package is called 'kerberos5'
      set(package "kerberos5")
    endif()

    execute_process(COMMAND "port" "echo" "active" "and" "name:^${package}$"
                    ERROR_VARIABLE shutup
                    OUTPUT_VARIABLE output
                    RESULT_VARIABLE failed)
    if(failed OR "${output}" STREQUAL "")
      message(STATUS "MacPorts: not found: ${package_alias}")
    else()
      # TODO: Invoke "port contents ${package}" and calculate the common
      #       prefix of the installed files instead?
      if("${package_alias}" STREQUAL "${package}")
        message(STATUS "MacPorts: found ${package} at ${SERF_MACOS__MACPORTS_DIR}")
      else()
        message(STATUS "MacPorts: found ${package_alias} (${package}) at ${SERF_MACOS__MACPORTS_DIR}")
      endif()
      set(${variable} "${SERF_MACOS__MACPORTS_DIR}" CACHE PATH "${docstring}" FORCE)
    endif()
  endif()
endfunction(_serf_macos__find_macports_package)
