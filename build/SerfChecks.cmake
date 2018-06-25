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

include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckTypeSize)

function(_CheckFunction var_ name_ libraries_)
  if(libraries_)
    set(CMAKE_REQUIRED_LIBRARIES "${libraries_}")
  else()
    unset(CMAKE_REQUIRED_LIBRARIES)
  endif()

  check_function_exists("${name_}" "serf_foundit_${name_}_")
  if(${serf_foundit_${name_}_})
    set("${var_}" TRUE PARENT_SCOPE)
  else()
    set("${var_}" FALSE PARENT_SCOPE)
  endif()
  unset(CMAKE_REQUIRED_LIBRARIES)
endfunction(_CheckFunction)

macro(CheckFunction name_ symbol_)
  _CheckFunction("serf_feature_CheckFunction_${name}_" "${name_}" "${ARGN}")
  if("${serf_feature_CheckFunction_${name}_}")
    add_definitions("-D${symbol_}")
  endif()
endmacro(CheckFunction)

macro(CheckNotFunction name_ symbol_)
  _CheckFunction("serf_feature_CheckNotFunction_${name}_" "${name_}" "${ARGN}")
  if(NOT "${serf_feature_CheckNotFunction_${name}_}")
    add_definitions("-D${symbol_}")
  endif()
endmacro(CheckNotFunction)


function(_CheckHeader var_ name_ includes_)
  if(includes_)
    set(CMAKE_REQUIRED_INCLUDES "${includes_}")
  else()
    unset(CMAKE_REQUIRED_INCLUDES)
  endif()

  check_include_file("${name_}" "serf_foundit_${name_}_")
  if(${serf_foundit_${name_}_})
    set("${var_}" TRUE PARENT_SCOPE)
  else()
    set("${var_}" FALSE PARENT_SCOPE)
  endif()
  unset(CMAKE_REQUIRED_INCLUDES)
endfunction(_CheckHeader)

macro(CheckHeader name_ symbol_)
  _CheckHeader("serf_feature_CheckHeader_${name}_" "${name_}" "${ARGN}")
  if("${serf_feature_CheckHeader_${name}_}")
    add_definitions("-D${symbol_}")
  endif()
endmacro(CheckHeader)


function(_CheckType var_ name_ header_ includes_)
  if(includes_)
    set(CMAKE_REQUIRED_INCLUDES "${includes_}")
  else()
    unset(CMAKE_REQUIRED_INCLUDES)
  endif()

  if(header_)
    set(CMAKE_EXTRA_INCLUDE_FILES "${header_}")
  else()
    unset(CMAKE_EXTRA_INCLUDE_FILES)
  endif()

  check_type_size("${name_}" "serf_foundit_${name_}_")
  if(${HAVE_serf_foundit_${name_}_})
    set("${var_}" TRUE PARENT_SCOPE)
  else()
    set("${var_}" FALSE PARENT_SCOPE)
  endif()
  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_EXTRA_INCLUDE_FILES)
endfunction(_CheckType)

macro(CheckType name_ header_ symbol_)
  _CheckType("serf_feature_CheckType_${name}_" "${name_}" "${header_}" "${ARGN}")
  if("${serf_feature_CheckType_${name}_}")
    add_definitions("-D${symbol_}")
  endif()
endmacro(CheckType)
