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

cmake_minimum_required(VERSION 3.12)

set(GSSAPI_FOUND FALSE)

if(DEFINED GSSAPI_ROOT)
  get_filename_component(GSSAPI_ROOT "${GSSAPI_ROOT}" REALPATH)
  find_program(KRB5_CONFIG_EXECUTABLE NAMES "krb5-config"
               PATHS "${GSSAPI_ROOT}/bin" NO_DEFAULT_PATH)
else()
  find_program(KRB5_CONFIG_EXECUTABLE NAMES "krb5-config")
endif()
mark_as_advanced(KRB5_CONFIG_EXECUTABLE)

if("${KRB5_CONFIG_EXECUTABLE}" STREQUAL "KRB5_CONFIG_EXECUTABLE-NOTFOUND")
  message(STATUS "Could NOT find GSSAPI (missing: krb5-config)")
else()
  function(_krb5_config _varname _dedup)
    execute_process(COMMAND "${KRB5_CONFIG_EXECUTABLE}" ${ARGN} "gssapi"
                    OUTPUT_VARIABLE output
                    RESULT_VARIABLE failed)
    if(failed)
      message(FATAL_ERROR "failed: ${KRB5_CONFIG_EXECUTABLE} ${ARGN} gssapi")
    endif()
    string(STRIP "${output}" output)
    separate_arguments(output)
    if(_dedup)
      list(REMOVE_DUPLICATES output)
    endif()
    set(${_varname} ${output} PARENT_SCOPE)
  endfunction(_krb5_config)

  _krb5_config(GSSAPI_VERSION   FALSE --version)
  _krb5_config(GSSAPI_INCLUDES  TRUE  --cflags)
  _krb5_config(GSSAPI_LIBRARIES TRUE  --libs)

  # The version "number" should look like "Kerberos N release X.Y.Z",
  # try to extract those numbers first.
  list(LENGTH GSSAPI_VERSION len)
  if(${len} EQUAL 4)
    # Use the second and fourth elements
    list(GET GSSAPI_VERSION 1 krb)
    list(GET GSSAPI_VERSION 3 rel)
    set(GSSAPI_VERSION "${krb}:${rel}")
  else()
    # It's some other format, join it back
    list(JOIN GSSAPI_VERSION " " GSSAPI_VERSION)
  endif()

  # Filter everything but include paths from --cflags
  list(FILTER GSSAPI_INCLUDES INCLUDE REGEX "^-I")

  # Figure out the import location. First, try with -L options in the libs.
  function(_find_location _variable _filter)
    set(tmp ${ARGN})
    list(FILTER tmp INCLUDE REGEX "${_filter}")
    list(LENGTH tmp len)
    if(${len} EQUAL 0)
      unset(${_variable} PARENT_SCOPE)
    else()
      list(GET tmp 0 first)
      string(REGEX REPLACE "${_filter}" "" first "${first}")
      set(${_variable} "${first}" PARENT_SCOPE)
    endif()
  endfunction(_find_location)

  _find_location(_location "^-L" ${GSSAPI_LIBRARIES})
  _find_location(_library "^-l" ${GSSAPI_LIBRARIES})
  if(DEFINED _location)
    find_library(_imported_location "${_library}"
                 PATHS "${_location}" NO_DEFAULT_PATH)
  else()
    find_library(_imported_location "${_library}")
  endif()

  include(FindPackageHandleStandardArgs)
  list(LENGTH GSSAPI_INCLUDES len)
  if(${len} EQUAL 0)
    # When using default include locations, GSSAPI_INCLUDES may be empty.
    find_package_handle_standard_args(GSSAPI
      REQUIRED_VARS GSSAPI_LIBRARIES
      VERSION_VAR GSSAPI_VERSION)
  else()
    # Remove option tags from the include paths.
    list(TRANSFORM GSSAPI_INCLUDES REPLACE "^-I" "")
    find_package_handle_standard_args(GSSAPI
      REQUIRED_VARS GSSAPI_LIBRARIES GSSAPI_INCLUDES
      VERSION_VAR GSSAPI_VERSION)
  endif()

  if(GSSAPI_FOUND)
    add_library(KRB5::GSSAPI UNKNOWN IMPORTED)
    set_target_properties(KRB5::GSSAPI PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${GSSAPI_INCLUDES}"
      INTERFACE_LINK_LIBRARIES "${GSSAPI_LIBRARIES}"
      IMPORTED_LOCATION "${_imported_location}")
  endif(GSSAPI_FOUND)
endif() # krb5-config not found
