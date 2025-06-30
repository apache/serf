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

set(MockHTTPinC_SOURCES
    "MockHTTP.c"
    "MockHTTP_server.c"
)

# Update compiler options for this library.
if(CC_LIKE_GNUC)
  # MockHTTP requires the C99 standard.
  string(REPLACE "-std=c89" "-std=c99" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
  # Also silence all warnings.
  if(NOT SHOW_MockHTTPinC_WARNINGS)
    string(REGEX REPLACE " *-W[a-z][a-z-]+" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
    string(APPEND CMAKE_C_FLAGS " -w")
  endif()
elseif(MSVC)
  # Silence warnings from Microsoft's compiler...
  #
  # ... of course, somewhere, somehow CMake adds the /W1 warning option
  # to the command line and then MSVC complains that we're overriding /W1
  # with /w. But it's more fun this way, or at least more #$@^&@%!
  # Or maybe that's just MSBuild doing its magic, and it depends on the
  # build generator. What would life be without its little mysteries?
  if(NOT SHOW_MockHTTPinC_WARNINGS)
    string(REGEX REPLACE " */(W|w[de])[0-9]+" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
    string(APPEND CMAKE_C_FLAGS " /w")
  endif()
endif()
mark_as_advanced(SHOW_MockHTTPinC_WARNINGS)

# MockHTTP needs deprecated OpenSSL APIs
get_directory_property(_cdef COMPILE_DEFINITIONS)
list(REMOVE_ITEM _cdef "OPENSSL_NO_DEPRECATED")
set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "${_cdef}")

add_library(mockhttpinc STATIC ${MockHTTPinC_SOURCES})
target_compile_definitions(mockhttpinc PUBLIC "MOCKHTTP_OPENSSL")
target_include_directories(mockhttpinc SYSTEM BEFORE
                           PRIVATE ${APR_INCLUDES} ${APRUTIL_INCLUDES})
