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

function(_apru_config _program _varname _separate _regexp)
  execute_process(COMMAND ${_program} ${ARGN}
                  OUTPUT_VARIABLE _apru_output
                  RESULT_VARIABLE _apru_failed)

  if(_apru_failed)
    message(FATAL_ERROR "${_program} ${ARGN} failed")
  else()

    # Join multi-line outupt
    string(REGEX REPLACE "[\r\n]"       ""  _apru_output "${_apru_output}")

    # Optionally apply the regular expression filter
    if(NOT ${_regexp} STREQUAL "")
      string(REGEX REPLACE "${_regexp}" " " _apru_output "${_apru_output}")
    endif()

    # Remove leading and trailing spaces
    string(REGEX REPLACE "^ +"          ""  _apru_output "${_apru_output}")
    string(REGEX REPLACE " +$"          ""  _apru_output "${_apru_output}")

    # Optionally split the result into an argument list
    if(${_separate})
      separate_arguments(_apru_output)
    endif()

    set(${_varname} "${_apru_output}" PARENT_SCOPE)
  endif()
endfunction(_apru_config)

function(_apru_version _version_varname _major_varname _header _prefix)
  file(STRINGS ${_header} _apru_major
       REGEX "^ *# *define +${_prefix}_MAJOR_VERSION +[0-9]+.*$")
  file(STRINGS ${_header} _apru_minor
       REGEX "^ *# *define +${_prefix}_MINOR_VERSION +[0-9]+.*$")
  file(STRINGS ${_header} _apru_patch
       REGEX "^ *# *define +${_prefix}_PATCH_VERSION +[0-9]+.*$")
  string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _apru_major ${_apru_major})
  string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _apru_minor ${_apru_minor})
  string(REGEX REPLACE "^[^0-9]+([0-9]+).*$" "\\1" _apru_patch ${_apru_patch})
  set(${_version_varname} "${_apru_major}.${_apru_minor}.${_apru_patch}" PARENT_SCOPE)
  set(${_major_varname} ${_apru_major} PARENT_SCOPE)
endfunction(_apru_version)

function(_apru_find_dll _varname _dllname)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".dll")
  find_library(${_varname} NAMES ${_dllname}
               PATHS ${ARGN} NO_DEFAULT_PATH PATH_SUFFIXES "bin" "lib")
endfunction(_apru_find_dll)
