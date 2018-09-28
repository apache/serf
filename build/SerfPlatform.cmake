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
  set(SERF_DARWIN TRUE)
  if(NOT RELATIVE_RPATH)
    set(CMAKE_MACOSX_RPATH FALSE)
  endif()
  message(STATUS "Target platform is Darwin (macOS)")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(SERF_LINUX TRUE)
  message(STATUS "Target platform is Linux")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(SERF_WINDOWS TRUE)
  if(CMAKE_GENERATOR MATCHES "(Win64|IA64)")
    set(SERF_WIN64 TRUE)
    message(STATUS "Target platform is Windows (64-bit)")
  else()
    set(SERF_WIN32 TRUE)
    message(STATUS "Target platform is Windows (32-bit)")
  endif()
else()
  set(SERF_UNIX TRUE)
  message(STATUS "Assuming generic Unix target platform")
endif()
