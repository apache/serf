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

function(serf_parse_version_number_from_header)
  set(header_ "${SERF_SOURCE_DIR}/serf.h")
  file(STRINGS "${header_}" version_parts_
       REGEX "^ *# *define +SERF_[A-Z]+_VERSION +[0-9]+ *$")

  foreach(STR ${version_parts_})
    if(STR MATCHES "SERF_MAJOR_VERSION")
      string(REGEX REPLACE "^[^0-9]+([0-9])+ *$" "\\1" major_ ${STR})
    elseif(STR MATCHES "SERF_MINOR_VERSION")
      string(REGEX REPLACE "^[^0-9]+([0-9])+ *$" "\\1" minor_ ${STR})
    elseif(STR MATCHES "SERF_PATCH_VERSION")
      string(REGEX REPLACE "^[^0-9]+([0-9])+ *$" "\\1" patch_ ${STR})
    endif()
  endforeach()

  if(NOT DEFINED major_ OR NOT DEFINED minor_ OR NOT DEFINED patch_)
    message(FATAL_ERROR "Could not find the version number in '${header_}'")
  endif()

  set(SERF_VERSION "${major_}.${minor_}.${patch_}" PARENT_SCOPE)
  set(SERF_SOVERSION "${major_}.${minor_}.0" PARENT_SCOPE)
  set(SERF_MAJOR_VERSION "${major_}" PARENT_SCOPE)
  set(SERF_MINOR_VERSION "${minor_}" PARENT_SCOPE)
  set(SERF_PATCH_VERSION "${patch_}" PARENT_SCOPE)
endfunction()

unset(SERF_VERSION)
unset(SERF_SOVERSION)
unset(SERF_MAJOR_VERSION)
unset(SERF_MINOR_VERSION)
unset(SERF_PATCH_VERSION)
serf_parse_version_number_from_header()
