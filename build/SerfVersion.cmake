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

# Find the version number in serf.h so that we don't keep it in two places.

set(SERF_HEADER "${SERF_SOURCE_DIR}/serf.h")

unset(SERF_VERSION)
unset(SERF_SOVERSION)
unset(SERF_MAJOR_VERSION)
unset(SERF_MINOR_VERSION)
unset(SERF_PATCH_VERSION)

file(STRINGS "${SERF_HEADER}" SERF_VERSION_BITS
     REGEX "^ *# *define +SERF_[A-Z]*_VERSION +[0-9]+ *$")
foreach(STR ${SERF_VERSION_BITS})
  if(STR MATCHES "^ *# *define +SERF_MAJOR_VERSION +([0-9])+ *$")
    string(REGEX REPLACE "^ *# *define +SERF_MAJOR_VERSION +([0-9])+ *$"
           "\\1" SERF_MAJOR_VERSION ${STR})
  endif()
  if(STR MATCHES "^ *# *define +SERF_MINOR_VERSION +([0-9])+ *$")
    string(REGEX REPLACE "^ *# *define +SERF_MINOR_VERSION +([0-9])+ *$"
           "\\1" SERF_MINOR_VERSION ${STR})
  endif()
  if(STR MATCHES "^ *# *define +SERF_PATCH_VERSION +([0-9])+ *$")
    string(REGEX REPLACE "^ *# *define +SERF_PATCH_VERSION +([0-9])+ *$"
           "\\1" SERF_PATCH_VERSION ${STR})
  endif()
endforeach()

if(NOT DEFINED SERF_MAJOR_VERSION
   OR NOT DEFINED SERF_MINOR_VERSION
   OR NOT DEFINED SERF_PATCH_VERSION)
  message(FATAL_ERROR "Could not find the version number in '${SERF_HEADER}'")
endif()

set(SERF_VERSION "${SERF_MAJOR_VERSION}.${SERF_MINOR_VERSION}.${SERF_PATCH_VERSION}")
set(SERF_SOVERSION "${SERF_MAJOR_VERSION}.${SERF_MINOR_VERSION}.0")
