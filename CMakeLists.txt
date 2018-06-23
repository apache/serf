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

cmake_minimum_required(VERSION 3.0.2)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/build")
include(version)
include(feature)

project("Serf" VERSION ${SERF_VERSION} LANGUAGES C)
message(WARNING
        "Serf's CMake build is considered EXPERIMENTAL. "
        "Some features are not supported and the build "
        "has not been tested on many supported platforms.")


set(HEADERS
    "serf.h"
    "serf_bucket_types.h"
    "serf_bucket_util.h"
)

file(GLOB SOURCES "src/*.c" "auth/*.c" "buckets/*.c" "protocols/*.c")
if(WINDOWS)
  set(SHARED_SOURCES "serf.rc")
else(WINDOWS)
  set(SHARED_SOURCES)
endif(WINDOWS)


find_package(openssl)
find_package(zlib)
find_package(apr)
find_package(apu)

# Feature tests
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
CheckType("OSSL_HANDSHAKE_STATE" "openssl/ssl.h" "SERF_HAVE_OSSL_HANDSHAKE_STATE" ${OPENSSL_INCLUDE_DIR})

set(DEPENDENCY_INCLUDE_DIRS
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
    ${APR_INCLUDES}
    ${APU_INCLUDES}
)
list(REMOVE_DUPLICATES DEPENDENCY_INCLUDE_DIRS)

set(DEPENDENCY_LIBRARIES
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${APR_LIBS}
    ${APU_LIBS}
)
list(REMOVE_DUPLICATES DEPENDENCY_LIBRARIES)

include_directories(BEFORE SYSTEM ${DEPENDENCY_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR})
add_library(SerfStatic STATIC ${SOURCES})
add_library(SerfShared SHARED ${SOURCES} ${SHARED_SOURCES})
target_link_libraries(SerfShared ${DEPENDENCY_LIBRARIES})
set_target_properties(SerfStatic SerfShared
                      PROPERTIES
                      OUTPUT_NAME "serf-${SERF_MAJOR_VERSION}"
                      VERSION ${SERF_VERSION}
                      SOVERSION ${SERF_SOVERSION})
