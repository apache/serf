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

macro(serf_macos__check_package_manager_)
  if(USE_HOMEBREW)
    serf_macos__check_homebrew_()
  endif()
  if(USE_MACPORTS)
    serf_macos__check_macports_()
  endif()
endmacro(serf_macos__check_package_manager_)

macro(serf_macos__find_package_ package variable docstring)
  if(USE_HOMEBREW)
    serf_macos__find_homebrew_package_("${package}" "${variable}" "${docstring}")
  endif()
  if(USE_MACPORTS)
    serf_macos__find_macports_package_("${package}" "${variable}" "${docstring}")
  endif()
endmacro(serf_macos__find_package_)

function(serf_macos_find_packages)
  serf_macos__check_package_manager_()
  serf_macos__find_package_("apr" APR_ROOT "Path to APR's install area")
  serf_macos__find_package_("apr-util" APRUtil_ROOT "Path to APR-Util's install area")
  serf_macos__find_package_("openssl" OPENSSL_ROOT_DIR "Path to OpenSSL's install area")
  if(USE_MACPORTS)
    # NOTE: MacPorts uses its own version of zlib. Homebrew tends to use
    #       the system zlib, so we won't even look for the Homebrew version.
    #       The user can always override that on the command line.
    serf_macos__find_package_("zlib" ZLIB_ROOT "Path to zlib's install area")
  endif()
  serf_macos__find_package_("brotli" BROTLI_ROOT "Path to GSSAPI's install area")
  serf_macos__find_package_("gssapi" GSSAPI_ROOT "Path to GSSAPI's install area")
endfunction()

#
# Homebrew
#
function(serf_macos__check_homebrew_)
  if(NOT DEFINED SERF_MACOS__HAS_HOMEBREW_)
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
      set(SERF_MACOS__HAS_HOMEBREW_ FALSE PARENT_SCOPE)
      message(WARNING "Homebrew was not found")
    else()
      string(STRIP "${version}" version)
      string(STRIP "${prefix}" prefix)
      message(STATUS "Found ${version} at ${prefix}")
      set(SERF_MACOS__HAS_HOMEBREW_ TRUE PARENT_SCOPE)
    endif()
  endif()
endfunction(serf_macos__check_homebrew_)

function(serf_macos__find_homebrew_package_ package variable docstring)
  # Don't override user's provided values.
  if("${${variable}}" STREQUAL "" AND ${SERF_MACOS__HAS_HOMEBREW_})
    execute_process(COMMAND "brew" "--prefix" "--installed" "${package}"
                    ERROR_VARIABLE shutup
                    OUTPUT_VARIABLE prefix
                    RESULT_VARIABLE failed)
    if(failed)
      message(STATUS "Homebrew: not found: ${package}")
    else()
      string(STRIP "${prefix}" prefix)
      message(STATUS "Homebrew: found ${package} at ${prefix}")
      set(${variable} "${prefix}" CACHE PATH "${docstring}" FORCE)
    endif()
  endif()
endfunction(serf_macos__find_homebrew_package_)

#
# MacPorts
#
function(serf_macos__check_macports_)
  if(NOT DEFINED SERF_MACOS__HAS_MACPORTS_)
    execute_process(COMMAND "port" "version"
                    ERROR_VARIABLE shutup
                    OUTPUT_VARIABLE version
                    RESULT_VARIABLE failed)
    if(NOT failed)
      execute_process(COMMAND "which" "port"
                      ERROR_VARIABLE shutup
                      OUTPUT_VARIABLE prefix
                      RESULT_VARIABLE failed)
    endif()
    if(failed)
      set(SERF_MACOS__HAS_MACPORTS_ FALSE PARENT_SCOPE)
      message(WARNING "MacPorts was not found")
    else()
      string(REPLACE "Version:" "" version "${version}")
      string(STRIP "${version}" version)
      cmake_path(SET prefix_path NORMALIZE ${prefix})
      cmake_path(GET prefix_path PARENT_PATH prefix_path)
      cmake_path(GET prefix_path PARENT_PATH prefix_path)
      cmake_path(NATIVE_PATH prefix_path prefix)
      message(STATUS "Found MacPorts ${version} at ${prefix}")
      set(SERF_MACOS__HAS_MACPORTS_ TRUE PARENT_SCOPE)
      set(SERF_MACOS__MACPORTS_ROOT_ "${prefix}" PARENT_SCOPE)
    endif()
  endif()
endfunction(serf_macos__check_macports_)

function(serf_macos__find_macports_package_ package variable docstring)
  # Don't override user's provided values.
  if("${${variable}}" STREQUAL "" AND ${SERF_MACOS__HAS_MACPORTS_})
    ##!message(WARNING "MacPorts dependencies are not implemented (${package})")
    execute_process(COMMAND "port" "echo" "active" "and" "name:^${package}$"
                    ERROR_VARIABLE shutup
                    OUTPUT_VARIABLE output
                    RESULT_VARIABLE failed)
    if(failed OR "${output}" STREQUAL "")
      message(STATUS "MacPorts: not found: ${package}")
    else()
      # TODO: Invoke "port contents ${package}" and calculate the common
      #       prefix of the installed files instead?
      message(STATUS "MacPorts: found ${package} at ${SERF_MACOS__MACPORTS_ROOT_}")
      set(${variable} "${SERF_MACOS__MACPORTS_ROOT_}" CACHE PATH "${docstring}" FORCE)
    endif()
  endif()
endfunction(serf_macos__find_macports_package_)
