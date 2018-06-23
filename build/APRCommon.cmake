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
