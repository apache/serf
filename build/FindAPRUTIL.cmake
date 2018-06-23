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

# This module defines
# APRUTIL_INCLUDES, where to find apu.h, etc.
# APRUTIL_LIBRARIES, linker switches to use with ld to link against apr-util
# APRUTIL_EXTRALIBS, additional libraries to link against
# APRUTIL_LDFLAGS, additional linker flags that must be used
# APRUTIL_FOUND, set to TRUE if found, FALSE otherwise
# APRUTIL_VERSION, set to the version of apr-util found

if(NOT APR_FOUND)
  find_package(APR)
endif()

if(APR_CONTAINS_APRUTIL)

  set(APRUTIL_FOUND TRUE)
  set(APRUTIL_INCLUDES ${APR_INCLUDES})
  set(APRUTIL_LIBRARIES ${APR_LIBRARIES})
  set(APRUTIL_EXTRALIBS ${APR_EXTRALIBS})
  set(APRUTIL_VERSION ${APR_VERSION})

else(APR_CONTAINS_APRUTIL)

  set(APRUTIL_FOUND FALSE)

  if(DEFINED APRUTIL_ROOT)
    find_program(APRUTIL_CONFIG_EXECUTABLE apu-1-config
                 PATHS "${APRUTIL_ROOT}/bin" NO_DEFAULT_PATH)
  else()
    find_program(APRUTIL_CONFIG_EXECUTABLE apu-1-config)
  endif()
  mark_as_advanced(APRUTIL_CONFIG_EXECUTABLE)

  include(APRCommon)
  macro(_apu_invoke _varname _separate _regexp)
    _apru_config("${APRUTIL_CONFIG_EXECUTABLE}" "${_varname}" "${_separate}" "${_regexp}" ${ARGN})
  endmacro(_apu_invoke)

  _apu_invoke(APRUTIL_INCLUDES  TRUE  "(^| )-I" --includes)
  _apu_invoke(APRUTIL_EXTRALIBS TRUE  "(^| )-l" --libs)
  _apu_invoke(APRUTIL_LIBRARIES TRUE  ""        --link-ld)
  _apu_invoke(APRUTIL_LDFLAGS   FALSE ""        --ldflags)
  _apu_invoke(APRUTIL_VERSION   TRUE  ""        --version)

  INCLUDE(FindPackageHandleStandardArgs)
  FIND_PACKAGE_HANDLE_STANDARD_ARGS(APRUTIL
                                    REQUIRED_VARS APRUTIL_LIBRARIES APRUTIL_INCLUDES
                                    VERSION_VAR APRUTIL_VERSION)

endif(APR_CONTAINS_APRUTIL)
