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

if(${CMAKE_SYSTEM_NAME} MATCHES  "Darwin")
  set(SERF_UNIX TRUE)
  set(SERF_DARWIN TRUE)
  if(NOT RELATIVE_RPATH)
    set(CMAKE_MACOSX_RPATH FALSE)
  endif()
  if(APPLE)
    set(SERF_PLATFORM "Darwin (macOS)")
  else()
    set(SERF_PLATFORM "Darwin")
  endif()
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(SERF_UNIX TRUE)
  set(SERF_LINUX TRUE)
  set(SERF_ELF_TARGET TRUE)
  set(SERF_PLATFORM "Linux")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  set(SERF_UNIX TRUE)
  set(SERF_FREEBSD TRUE)
  set(SERF_ELF_TARGET TRUE)
  set(SERF_PLATFORM "FreeBSD")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  set(SERF_UNIX TRUE)
  set(SERF_OPENBSD TRUE)
  set(SERF_ELF_TARGET TRUE)
  set(SERF_PLATFORM "OpenBSD")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
  set(SERF_UNIX TRUE)
  set(SERF_NETBSD TRUE)
  set(SERF_ELF_TARGET TRUE)
  set(SERF_PLATFORM "NetBSD")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(SERF_WINDOWS TRUE)
  if(CMAKE_GENERATOR_PLATFORM MATCHES "(x64|ARM64|IA64)")
    set(SERF_WIN64 TRUE)
    set(SERF_PLATFORM "Windows (64-bit)")
  else()
    set(SERF_WIN32 TRUE)
    set(SERF_PLATFORM "Windows (32-bit)")
  endif()
else()
  set(SERF_UNIX TRUE)
  set(SERF_PLATFORM "generic Unix")
endif()

if(CMAKE_GENERATOR_PLATFORM)
  set(SERF_PLATFORM "${SERF_PLATFORM} [${CMAKE_GENERATOR_PLATFORM}]")
endif()
message(STATUS "Target platform is ${SERF_PLATFORM}")

string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} _arch)
string(TOLOWER ${CMAKE_SYSTEM_NAME} _system)
string(TOLOWER ${CMAKE_SYSTEM_VERSION} _version)
set(SERF_TARGET "${_arch}-${_system}${_version}")
