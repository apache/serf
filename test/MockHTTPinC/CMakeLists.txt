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

# MockHTTP requires the C99 standard.
set(CMAKE_C_STANDARD 99)

# Update compiler options for this library.
if(NOT SHOW_MockHTTPinC_WARNINGS)
  if(CC_LIKE_GNUC)
    set(MockHTTPinC_WARNINGS "-w")
  elseif(MSVC)
    # Silence warnings from Microsoft's compiler...
    #
    # ... of course, somewhere, somehow CMake adds the /W1 warning option
    # to the command line and then MSVC complains that we're overriding /W1
    # with /w. But it's more fun this way, or at least more #$@^&@%!
    # Or maybe that's just MSBuild doing its magic, and it depends on the
    # build generator. What would life be without its little mysteries?
    set(MockHTTPinC_WARNINGS "/w")
  endif()
else()
  set(MockHTTPinC_WARNINGS ${SERF_C_WARNINGS})
endif()
mark_as_advanced(SHOW_MockHTTPinC_WARNINGS)

# MockHTTP needs deprecated OpenSSL APIs
set(MockHTTPinC_DEFINES ${SERF_C_DEFINES})
list(REMOVE_ITEM MockHTTPinC_DEFINES "OPENSSL_NO_DEPRECATED")

add_library(mockhttpinc STATIC ${MockHTTPinC_SOURCES})
target_compile_options(mockhttpinc
                       PRIVATE
                       ${MockHTTPinC_WARNINGS}
                       ${APR_CFLAGS})
target_compile_definitions(mockhttpinc
                           PUBLIC "MOCKHTTP_OPENSSL"
                           PRIVATE ${MockHTTPinC_DEFINES})
target_link_libraries(mockhttpinc
                      ${SERF_PRIVATE_TARGETS}
                      ${SERF_PUBLIC_TARGETS}
                      ${SERF_STANDARD_LIBRARIES})
