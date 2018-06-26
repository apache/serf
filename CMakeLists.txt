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

cmake_minimum_required(VERSION 3.0.2)
enable_testing()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/build")
include(SerfVersion)

project("Serf" VERSION ${SERF_VERSION} LANGUAGES C)
message(WARNING
        "Serf's CMake build is considered EXPERIMENTAL. "
        "Some features are not supported and the build "
        "has not been tested on many supported platforms.")


# Build options
option(PREFIX "Installation root directory" OFF)
option(LIBDIR "Indstall directory for architecture-dependent libraries" OFF)
option(APR "Path to APR's install area" OFF)
option(APU "Path to APR-Util's install area" OFF)
option(OPENSSL "Path to OpenSSL's install area" OFF)
option(ZLIB "Path to zlib's install area" OFF)
option(GSSAPI "Path to GSSAPI's install area" OFF)
option(BROTLI "Path to Brotli's install area" OFF)
option(DEBUG "Enable debugging info and strict compile warnings" OFF)
option(DISABLE_LOGGING "Disable the logging framework at compile time" OFF)
option(ENABLE_SLOW_TESTS "Enable long-running unit tests" OFF)


# Public headers
set(HEADERS
    "serf.h"
    "serf_bucket_types.h"
    "serf_bucket_util.h"
)

# Serf library source files
set(SOURCES
    "src/config_store.c"
    "src/context.c"
    "src/deprecated.c"
    "src/incoming.c"
    "src/logging.c"
    "src/outgoing.c"
    "src/outgoing_request.c"
    "src/pump.c"
    "src/ssltunnel.c"
    "auth/auth.c"
    "auth/auth_basic.c"
    "auth/auth_digest.c"
    "auth/auth_spnego.c"
    "auth/auth_spnego_gss.c"
    "auth/auth_spnego_sspi.c"
    "buckets/aggregate_buckets.c"
    "buckets/allocator.c"
    "buckets/barrier_buckets.c"
    "buckets/brotli_buckets.c"
    "buckets/buckets.c"
    "buckets/bwtp_buckets.c"
    "buckets/chunk_buckets.c"
    "buckets/copy_buckets.c"
    "buckets/dechunk_buckets.c"
    "buckets/deflate_buckets.c"
    "buckets/event_buckets.c"
    "buckets/fcgi_buckets.c"
    "buckets/file_buckets.c"
    "buckets/headers_buckets.c"
    "buckets/hpack_buckets.c"
    "buckets/http2_frame_buckets.c"
    "buckets/iovec_buckets.c"
    "buckets/limit_buckets.c"
    "buckets/log_wrapper_buckets.c"
    "buckets/mmap_buckets.c"
    "buckets/prefix_buckets.c"
    "buckets/request_buckets.c"
    "buckets/response_body_buckets.c"
    "buckets/response_buckets.c"
    "buckets/simple_buckets.c"
    "buckets/socket_buckets.c"
    "buckets/split_buckets.c"
    "buckets/ssl_buckets.c"
    "protocols/fcgi_protocol.c"
    "protocols/fcgi_stream.c"
    "protocols/http2_protocol.c"
    "protocols/http2_stream.c"
)

if(WINDOWS)
  set(SHARED_SOURCES "serf.rc")
endif(WINDOWS)


# Process build options for dependency search
if(APR)
  set(APR_ROOT ${APR})
endif()

if(APU)
  set(APRUTIL_ROOT ${APU})
endif()

if(OPENSSL)
  set(OPENSSL_ROOT_DIR ${OPENSSL})
endif()

if(ZLIB)
  set(ZLIB_ROOT ${ZLIB})
endif()

if(GSSAPI)
  message(WARNING "option GSSAPI is not implemented yet")
endif()

if(BROTLI)
  message(WARNING "option BROTLI is not implemented yet")
endif()


# Find dependencies
find_package(OpenSSL)
find_package(ZLIB)
find_package(APR)
find_package(APRUtil)

set(DEPENDENCY_INCLUDES
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
    ${APR_INCLUDES}
    ${APRUTIL_INCLUDES}
)
list(REMOVE_DUPLICATES DEPENDENCY_INCLUDES)

set(DEPENDENCY_LIBRARIES
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${APR_LIBRARIES}
    ${APR_EXTRALIBS}
    ${APRUTIL_LIBRARIES}
    ${APRUTIL_EXTRALIBS}
)
list(REMOVE_DUPLICATES DEPENDENCY_LIBRARIES)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${APR_CFLAGS}")

include_directories(BEFORE SYSTEM ${DEPENDENCY_INCLUDES})
include_directories(${CMAKE_SOURCE_DIR})


# Feature tests
include(SerfChecks)
CheckNotFunction("BIO_set_init" "SERF_NO_SSL_BIO_WRAPPERS" ${OPENSSL_LIBRARIES})
CheckNotFunction("X509_STORE_get0_param" "SERF_NO_SSL_X509_STORE_WRAPPERS" ${OPENSSL_LIBRARIES})
CheckNotFunction("X509_get0_notBefore" "SERF_NO_SSL_X509_GET0_NOTBEFORE" ${OPENSSL_LIBRARIES})
CheckNotFunction("X509_get0_notAfter" "SERF_NO_SSL_X509_GET0_NOTAFTER" ${OPENSSL_LIBRARIES})
CheckNotFunction("X509_STORE_CTX_get0_chain" "SERF_NO_SSL_X509_GET0_CHAIN" ${OPENSSL_LIBRARIES})
CheckNotFunction("ASN1_STRING_get0_data" "SERF_NO_SSL_ASN1_STRING_GET0_DATA" ${OPENSSL_LIBRARIES})
CheckFunction("CRYPTO_set_locking_callback" "SERF_HAVE_SSL_LOCKING_CALLBACKS" ${OPENSSL_LIBRARIES})
CheckFunction("OPENSSL_malloc_init" "SERF_HAVE_OPENSSL_MALLOC_INIT" ${OPENSSL_LIBRARIES})
CheckFunction("SSL_library_init" "SERF_HAVE_OPENSSL_SSL_LIBRARY_INIT" ${OPENSSL_LIBRARIES})
CheckFunction("OpenSSL_version_num" "SERF_HAVE_OPENSSL_VERSION_NUM" ${OPENSSL_LIBRARIES})
CheckFunction("SSL_set_alpn_protos" "SERF_HAVE_OPENSSL_ALPN" ${OPENSSL_LIBRARIES})
CheckHeader("openssl/applink.c" "SERF_HAVE_OPENSSL_APPLINK_C" ${OPENSSL_INCLUDE_DIR})
CheckHeader("stdbool.h" "HAVE_STDBOOL_H=1")
CheckType("OSSL_HANDSHAKE_STATE" "openssl/ssl.h" "SERF_HAVE_OSSL_HANDSHAKE_STATE" ${OPENSSL_INCLUDE_DIR})

if(CMAKE_COMPILER_IS_GNUCC OR (CMAKE_C_COMPILER_ID MATCHES "Clang"))
  set(CC_LIKE_GNUC TRUE)
endif()

# Process other build options
if(PREFIX)
  set(CMAKE_INSTALL_PREFIX ${PREFIX})
else()
  set(PREFIX ${CMAKE_INSTALL_PREFIX})
endif()

if(LIBDIR)
  message(WARNING "option LIBDIR is not implemented yet")
else()
  set(LIBDIR "${PREFIX}/lib")
endif()

if(DEBUG)
  add_definitions("-DDEBUG" "-D_DEBUG")
endif()

if(DISABLE_LOGGING)
  add_definitions("-DSERF_DISABLE_LOGGING")
endif()

if(ENABLE_SLOW_TESTS)
  add_definitions("-DSERF_TEST_DEFLATE_4GBPLUS_BUCKETS")
endif()


# Set common compiler flags
if(NOT MSVC)
  if(CC_LIKE_GNUC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wdeclaration-after-statement")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c89")

    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
  endif()
else()
  # Warning level 4, no unused argument warnings
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /wd4100")
  # Conditional expression is constant
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4127")
  # Assignment within conditional expression
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4706")

  set(CMAKE_C_FLAGS_DEBUG "/Od /MDd")
  set(CMAKE_C_FLAGS_RELEASE "/O2 /MD")
  set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/RELEASE")
endif(NOT MSVC)


# This must come *AFTER* all the compiler flags and definitioins are set.
if(NOT CMAKE_BUILD_TYPE)
  if(DEBUG)
    set(CMAKE_BUILD_TYPE DEBUG)
  else()
    set(CMAKE_BUILD_TYPE RELEASE)
  endif()
endif()

if(NOT WINDOWS)
  # Use a separate variable scope for the substitutions in serf.pc.in.
  function(make_pkgconfig)
    set(VERSION ${SERF_VERSION})
    set(MAJOR ${SERF_MAJOR_VERSION})
    set(INCLUDE_SUBDIR "serf-${SERF_MAJOR_VERSION}")
    set(LIBS ${DEPENDENCY_LIBRARIES})
    configure_file("build/serf.pc.in" "serf.pc" @ONLY)
  endfunction()
  make_pkgconfig()
endif()

add_library(serf SHARED ${SOURCES} ${SHARED_SOURCES})
target_link_libraries(serf ${DEPENDENCY_LIBRARIES})

add_library(serf_static STATIC ${SOURCES})

set_target_properties(serf serf_static
                      PROPERTIES
                      OUTPUT_NAME "serf-${SERF_MAJOR_VERSION}"
                      VERSION ${SERF_VERSION}
                      SOVERSION ${SERF_SOVERSION})

add_subdirectory(test)
