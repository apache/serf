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

include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(CheckTypeSize)

list(TRANSFORM SERF_C_DEFINES PREPEND "-D" OUTPUT_VARIABLE cdef_)

function(_CheckFunction var_ name_ args_ header_ includes_ libraries_)
  set(CMAKE_REQUIRED_DEFINITIONS ${cdef_})
  if(libraries_)
    set(CMAKE_REQUIRED_LIBRARIES "${libraries_}")
  else()
    unset(CMAKE_REQUIRED_LIBRARIES)
  endif()

  if(includes_)
    set(CMAKE_REQUIRED_INCLUDES "${includes_}")
  else()
    unset(CMAKE_REQUIRED_INCLUDES)
  endif()

  set(source_
      "#include <${header_}>"
      ""
      "#if _MSC_VER && !__INTEL_COMPILER"
      "  #pragma function(${name_})"
      "#endif"
      ""
      "int main(void) {"
      "#if defined (__stub_${name_}) || defined (__stub___${name_})"
      "  #error \"${name_} has a GNU stub, cannot check\""
      "#else"
      "  ${name_}(${args_})\\;"
      "#endif"
      "  return 0\\;"
      "}"
      "")
  list(JOIN source_ "\n" source_)

  check_c_source_compiles("${source_}" "check_function_${name_}")
  if(${check_function_${name_}})
    set("${var_}" TRUE PARENT_SCOPE)
  else()
    set("${var_}" FALSE PARENT_SCOPE)
  endif()

  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_REQUIRED_LIBRARIES)
  unset(CMAKE_REQUIRED_DEFINITIONS)
endfunction(_CheckFunction)

macro(CheckFunction name_ args_ symbol_ header_ includes_)
  _CheckFunction("serf_feature_CheckFunction_${name_}_"
                 "${name_}" "${args_}" "${header_}" "${includes_}" "${ARGN}")
  if("${serf_feature_CheckFunction_${name_}_}")
    list(APPEND SERF_C_DEFINES "${symbol_}")
  endif()
endmacro(CheckFunction)

macro(CheckNotFunction name_ args_ symbol_ header_ includes_)
  _CheckFunction("serf_feature_CheckNotFunction_${name_}_"
                 "${name_}" "${args_}" "${header_}" "${includes_}" "${ARGN}")
  if(NOT "${serf_feature_CheckNotFunction_${name_}_}")
    list(APPEND SERF_C_DEFINES "${symbol_}")
  endif()
endmacro(CheckNotFunction)


function(_CheckHeader var_ name_ includes_)
  set(CMAKE_REQUIRED_DEFINITIONS ${cdef_})
  if(includes_)
    set(CMAKE_REQUIRED_INCLUDES "${includes_}")
  else()
    unset(CMAKE_REQUIRED_INCLUDES)
  endif()

  check_include_file("${name_}" "check_symbol_${name_}")
  if(${check_symbol_${name_}})
    set("${var_}" TRUE PARENT_SCOPE)
  else()
    set("${var_}" FALSE PARENT_SCOPE)
  endif()
  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_REQUIRED_DEFINITIONS)
endfunction(_CheckHeader)

macro(CheckHeader name_ symbol_)
  _CheckHeader("serf_feature_CheckHeader_${name_}_" "${name_}" "${ARGN}")
  if("${serf_feature_CheckHeader_${name_}_}")
    list(APPEND SERF_C_DEFINES "${symbol_}")
  endif()
endmacro(CheckHeader)


function(_CheckType var_ name_ header_ includes_)
  set(CMAKE_REQUIRED_DEFINITIONS ${cdef_})
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

  check_type_size("${name_}" "check_type_${name_}")
  if(${HAVE_check_type_${name_}})
    set("${var_}" TRUE PARENT_SCOPE)
  else()
    set("${var_}" FALSE PARENT_SCOPE)
  endif()
  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_EXTRA_INCLUDE_FILES)
  unset(CMAKE_REQUIRED_DEFINITIONS)
endfunction(_CheckType)

macro(CheckType name_ header_ symbol_)
  _CheckType("serf_feature_CheckType_${name_}_" "${name_}" "${header_}" "${ARGN}")
  if("${serf_feature_CheckType_${name_}_}")
    list(APPEND SERF_C_DEFINES "${symbol_}")
  endif()
endmacro(CheckType)
