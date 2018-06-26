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
# APR_INCLUDES, where to find apr.h, etc.
# APR_LIBRARIES, linker switches to use with ld to link against APR
# APR_EXTRALIBS, additional libraries to link against
# APR_CFLAGS, the flags to use to compile
# APR_FOUND, set to TRUE if found, FALSE otherwise
# APR_VERSION, the version of APR that was found
# APR_CONTAINS_APRUTIL, set to TRUE if the APR major version is 2 or greater.

set(APR_FOUND FALSE)

if(DEFINED APR_ROOT)
  find_program(APR_CONFIG_EXECUTABLE NAMES apr-2-config apr-1-config
               PATHS "${APR_ROOT}/bin" NO_DEFAULT_PATH)
else()
  find_program(APR_CONFIG_EXECUTABLE NAMES apr-2-config apr-1-config)
endif()
mark_as_advanced(APR_CONFIG_EXECUTABLE)

include(APRCommon)
macro(_apr_invoke _varname _separate _regexp)
  _apru_config("${APR_CONFIG_EXECUTABLE}" "${_varname}" "${_separate}" "${_regexp}" ${ARGN})
endmacro(_apr_invoke)

_apr_invoke(APR_CFLAGS    FALSE "(^| )-(g|O)[^ ]*" --cppflags --cflags)
_apr_invoke(APR_INCLUDES  TRUE  "(^| )-I"          --includes)
_apr_invoke(APR_LIBRARIES TRUE  ""                 --link-ld)
_apr_invoke(APR_EXTRALIBS TRUE  ""                 --libs)
_apr_invoke(APR_VERSION   TRUE  ""                 --version)

string(REGEX REPLACE "^([0-9]+)\\..*$" "\\1" _apr_major "${APR_VERSION}")
if(_apr_major GREATER 2)
  set(APR_CONTAINS_APRUTIL TRUE)
else()
  set(APR_CONTAINS_APRUTIL FALSE)
endif()
unset(_apr_major)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(APR
                                  REQUIRED_VARS APR_LIBRARIES APR_INCLUDES
                                  VERSION_VAR APR_VERSION)
