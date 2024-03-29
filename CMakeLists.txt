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

# ===================================================================
# The following variables can be set to locate dependencies that
# are not installed in standard paths.  These variables are used
# by the find_package() modules.
#
# APR_ROOT          - Path to APR's install area
# APRUtil_ROOT      - Path to APR-Util's install area
# OPENSSL_ROOT_DIR  - Path to OpenSSL's install area
# ZLIB_ROOT         - Path to zlib's install area
# ===================================================================

cmake_minimum_required(VERSION 3.0)

# Silence warnings about ${<PackageName>_ROOT} in CMake 3.12+
if((${CMAKE_MAJOR_VERSION} GREATER 3) OR (${CMAKE_MINOR_VERSION} GREATER 11))
  cmake_policy(SET CMP0074 NEW)
endif()

# Enable CMP0092 if supported: MSVC warning flags are not in
# CMAKE_<LANG>_FLAGS by default.
if(POLICY CMP0092)
  cmake_policy(SET CMP0092 NEW)
endif()

set(SERF_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_MODULE_PATH "${SERF_SOURCE_DIR}/build")
include(SerfVersion)

project("Serf" VERSION ${SERF_VERSION} LANGUAGES C)
message(WARNING
        "Serf's CMake build is considered EXPERIMENTAL. "
        "Some features are not supported and the build "
        "has not been tested on many supported platforms.")


# Build options
option(DEBUG "Enable debugging info and strict compile warnings" OFF)
option(SKIP_SHARED "Disable building shared Serf libraries" OFF)
option(SKIP_STATIC "Disable building static Serf libraries" OFF)
option(LIBDIR "Install directory for architecture-dependent libraries" "")
option(GSSAPI "Path to GSSAPI's install area" "")
option(BROTLI "Path to Brotli's install area" "")
option(DISABLE_LOGGING "Disable the logging framework at compile time" OFF)
option(SKIP_TESTS "Disable building the unit tests and utilities" OFF)
option(ENABLE_SLOW_TESTS "Enable long-running unit tests" OFF)

# Platform-specific build options
option(APR_STATIC "Windows: Link with static APR/-Util libraries" OFF)
option(EXPAT "Windows: optional path to Expat's install area for APR_STATIC" "")
option(RELATIVE_RPATH "macOS: Use @rpath in installed shared library" OFF)

if(SKIP_SHARED AND SKIP_STATIC)
  message(FATAL_ERROR "You have disabled both shared and static library builds.")
endif()

# Initialize the build type if it was not set on the command line.
if(NOT CMAKE_BUILD_TYPE)
  if(DEBUG)
    set(CMAKE_BUILD_TYPE DEBUG CACHE STRING "Default to debug build.")
  else()
    set(CMAKE_BUILD_TYPE RELEASE CACHE STRING "Default to release build.")
  endif()
endif()

include(SerfPlatform)
include(SerfWindowsToolkit)


# Public headers
list(APPEND HEADERS
    "serf.h"
    "serf_bucket_types.h"
    "serf_bucket_util.h"
)

# List of symbols that should not be exported from the shared library.
list(APPEND EXPORTS_BLACKLIST
     "serf_connection_switch_protocol"
     "serf_http_protocol_create"
     "serf_https_protocol_create"
     "serf_http_request_queue"
)

# Serf library source files
list(APPEND SOURCES
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

if(SERF_WINDOWS)
  # Generate the .def file for the Windows DLL import library.
  set(SERF_DEF_FILE "${CMAKE_CURRENT_BINARY_DIR}/serf.def")
  add_custom_command(
    OUTPUT "${SERF_DEF_FILE}"
    DEPENDS ${HEADERS}
    COMMAND ${CMAKE_COMMAND}
            -DCMAKE_SYSTEM_NAME="${CMAKE_SYSTEM_NAME}"
            -DCMAKE_MODULE_PATH="${CMAKE_MODULE_PATH}"
            -DSERF_DEF_BLACKLIST="${EXPORTS_BLACKLIST}"
            -DSERF_DEF_HEADERS="${HEADERS}"
            -DSERF_DEF_FILE="${SERF_DEF_FILE}"
            -P "build/SerfWindowsGenDef.cmake"
    WORKING_DIRECTORY "${SERF_SOURCE_DIR}"
  )
  set(SHARED_SOURCES "serf.rc" "${SERF_DEF_FILE}")

  # Static OpenSSL, APR and APR-Util need additional libraries that are not
  # linked by default by CMake. These will be ignored by the linker if they're
  # not actually used.
  set(SERF_STANDARD_LIBRARIES
      "crypt32.lib"
      "mswsock.lib"
      "rpcrt4.lib"
      "secur32.lib"
      "ws2_32.lib"
  )
  add_definitions("-DSERF_HAVE_SSPI")
endif(SERF_WINDOWS)


# Process build options for dependency search
if(GSSAPI)
  message(WARNING "option GSSAPI is not implemented")
endif()

if(BROTLI)
  message(WARNING "option BROTLI is not implemented")
endif()

if(SERF_WINDOWS)
  if(EXPAT)
    set(PC_EXPAT_INCLUDE_DIRS "${EXPAT}/include")
    set(PC_EXPAT_LIBRARY_DIRS "${EXPAT}/lib")
  endif(EXPAT)
else(SERF_WINDOWS)
  if(EXPAT)
    message(WARNING "option EXPAT is not implemented on this platform")
  endif(EXPAT)
endif(SERF_WINDOWS)

# Find dependencies
find_package(OpenSSL)
find_package(ZLIB)
find_package(APR)
find_package(APRUtil)

# Calculate the set of private and public targets
set(SERF_PRIVATE_TARGETS OpenSSL::Crypto OpenSSL::SSL ZLIB::ZLIB)

if(APR_STATIC)
  if(SERF_WINDOWS)
    list(APPEND SERF_PUBLIC_TARGETS APR::APR_static)
    if(NOT APR_CONTAINS_APRUTIL)
      list(APPEND SERF_PUBLIC_TARGETS APR::APRUTIL_static)
    endif()
    add_definitions("/DAPR_DECLARE_STATIC" "/DAPU_DECLARE_STATIC")
  else(SERF_WINDOWS)
    message(WARNING "option APR_STATIC is not implemented on this platform")
  endif(SERF_WINDOWS)
else(APR_STATIC)
  list(APPEND SERF_PUBLIC_TARGETS APR::APR)
  if(NOT APR_CONTAINS_APRUTIL)
    list(APPEND SERF_PUBLIC_TARGETS APR::APRUTIL)
  endif()
endif(APR_STATIC)

# Feature tests
include(SerfChecks)
CheckNotFunction("BIO_set_init" "SERF_NO_SSL_BIO_WRAPPERS" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckNotFunction("X509_STORE_get0_param" "SERF_NO_SSL_X509_STORE_WRAPPERS" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckNotFunction("X509_get0_notBefore" "SERF_NO_SSL_X509_GET0_NOTBEFORE" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckNotFunction("X509_get0_notAfter" "SERF_NO_SSL_X509_GET0_NOTAFTER" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckNotFunction("X509_STORE_CTX_get0_chain" "SERF_NO_SSL_X509_GET0_CHAIN" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckNotFunction("ASN1_STRING_get0_data" "SERF_NO_SSL_ASN1_STRING_GET0_DATA" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckFunction("CRYPTO_set_locking_callback" "SERF_HAVE_SSL_LOCKING_CALLBACKS" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckFunction("OpenSSL_version_num" "SERF_HAVE_OPENSSL_VERSION_NUM" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckFunction("SSL_set_alpn_protos" "SERF_HAVE_OPENSSL_ALPN" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckFunctionMacro("OPENSSL_malloc_init" "SERF_HAVE_OPENSSL_MALLOC_INIT" "openssl/crypto.h"
                   "${OPENSSL_INCLUDE_DIR}" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckFunctionMacro("SSL_library_init" "SERF_HAVE_OPENSSL_SSL_LIBRARY_INIT" "openssl/ssl.h"
                   "${OPENSSL_INCLUDE_DIR}" ${OPENSSL_LIBRARIES} ${SERF_STANDARD_LIBRARIES})
CheckHeader("stdbool.h" "HAVE_STDBOOL_H=1")
CheckType("OSSL_HANDSHAKE_STATE" "openssl/ssl.h" "SERF_HAVE_OSSL_HANDSHAKE_STATE" ${OPENSSL_INCLUDE_DIR})

if(CMAKE_COMPILER_IS_GNUCC OR (CMAKE_C_COMPILER_ID MATCHES "Clang"))
  set(CC_LIKE_GNUC TRUE)
endif()

# Process other build options
if(LIBDIR)
  message(WARNING "option LIBDIR is not implemented yet")
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

# Define OPENSSL_NO_STDIO to prevent using _fp() API.
add_definitions("-DOPENSSL_NO_STDIO")

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

  # 'function' undefined; assuming extern returning int
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /we4013")

  add_definitions(
    "/DWIN32" "/DWIN32_LEAN_AND_MEAN"
    "/DNOUSER" "/DNOGDI" "/DNONLS" "/DNOCRYPT"
    "/D_CRT_SECURE_NO_WARNINGS"
    "/D_CRT_NONSTDC_NO_WARNINGS"
  )
  if(SERF_WIN64)
    add_definitions("/DWIN64")
  endif()

  set(CMAKE_IMPORT_LIBRARY_PREFIX "lib")
  set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
endif(NOT MSVC)

# Define all targets
if(NOT SKIP_SHARED)
  add_library(serf_shared SHARED ${SOURCES} ${SHARED_SOURCES})
  target_compile_options(serf_shared PUBLIC ${APR_CFLAGS})
  target_include_directories(serf_shared PUBLIC ${SERF_SOURCE_DIR})
  target_link_libraries(serf_shared
                        PRIVATE ${SERF_PRIVATE_TARGETS}
                                ${SERF_STANDARD_LIBRARIES}
                        PUBLIC ${SERF_PUBLIC_TARGETS})
  set_target_properties(serf_shared PROPERTIES
                        VERSION ${SERF_VERSION}
                        SOVERSION ${SERF_SOVERSION})
  if(SERF_DARWIN AND NOT RELATIVE_RPATH)
    set_target_properties(serf_shared PROPERTIES
                          INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib")
  endif()
  set(SERF_TARGETS "serf_shared")

  if(SERF_WINDOWS)
    install(FILES $<TARGET_PDB_FILE:serf_shared> DESTINATION "bin")
  endif()
endif()

if(NOT SKIP_STATIC)
  add_library(serf_static STATIC ${SOURCES})
  target_compile_options(serf_static PUBLIC ${APR_CFLAGS})
  target_include_directories(serf_static PUBLIC ${SERF_SOURCE_DIR})
  target_link_libraries(serf_static
                        ${SERF_PRIVATE_TARGETS}
                        ${SERF_PUBLIC_TARGETS}
                        ${SERF_STANDARD_LIBRARIES})
  list(APPEND SERF_TARGETS "serf_static")
endif()

set_target_properties(${SERF_TARGETS}
                      PROPERTIES
                      OUTPUT_NAME "serf-${SERF_MAJOR_VERSION}")

install(TARGETS ${SERF_TARGETS}
        ARCHIVE DESTINATION "lib"
        LIBRARY DESTINATION "lib"
        RUNTIME DESTINATION "bin")

if(NOT SERF_WINDOWS)
  set(SERF_INCLUDE_SUBDIR "serf-${SERF_MAJOR_VERSION}")
endif()
install(FILES ${HEADERS} DESTINATION "include/${SERF_INCLUDE_SUBDIR}")


# Generate the pkg-config module file.
if(NOT SERF_WINDOWS)
  # Use a separate variable scope for the substitutions in serf.pc.in.
  function(make_pkgconfig)
    set(PREFIX ${CMAKE_INSTALL_PREFIX})
    if(NOT LIBDIR)
      set(LIBDIR "\${prefix}/lib")
    endif()
    set(INCLUDE_SUBDIR ${SERF_INCLUDE_SUBDIR})
    set(VERSION ${SERF_VERSION})
    set(MAJOR ${SERF_MAJOR_VERSION})
    set(SERF_INTERFACE_LIBS
      ${APR_LIBRARIES}
      ${APR_EXTRALIBS}
      ${APRUTIL_LIBRARIES}
      ${APRUTIL_EXTRALIBS}
      )
    list(REMOVE_DUPLICATES SERF_INTERFACE_LIBS)
    unset(LIBS)
    foreach(DEPLIB ${SERF_INTERFACE_LIBS})
      string(APPEND LIBS " ${DEPLIB}")
    endforeach()
    configure_file("build/serf.pc.in" "serf.pc" @ONLY)
  endfunction()

  make_pkgconfig()
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/serf.pc"
          DESTINATION "share/pkgconfig")
endif()


if(NOT SKIP_TESTS)
  if(SKIP_STATIC)
    message(WARNING "The tests depend on the Serf static library")
    message(STATUS "Skipping tests; to silence this message, either remove")
    message(STATUS "the SKIP_STATIC option or add the SKIP_TESTS option.")
  else()
    enable_testing()
    add_subdirectory(test)
  endif()
endif()
