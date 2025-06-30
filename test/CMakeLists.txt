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

add_subdirectory(MockHTTPinC)

set(TEST_ALL_SOURCES
    "test_all.c"
    "CuTest.c"
    "test_util.c"
    "test_context.c"
    "test_buckets.c"
    "test_auth.c"
    "test_internal.c"
    "test_server.c"
    "mock_buckets.c"
    "mock_sock_buckets.c"
    "test_ssl.c"
)

set(TEST_ALL_SUITES
    "auth"
    "buckets"
    "context"
    "server"
    "ssl"
    "internal"
)

set(SIMPLE_TEST_TARGETS
    "serf_get"
    "serf_response"
    "serf_request"
    "serf_spider"
    "serf_httpd"
    "serf_bwtp"
)

foreach(TEST_TARGET ${SIMPLE_TEST_TARGETS})
  add_executable(${TEST_TARGET} "${TEST_TARGET}.c")
  add_dependencies(${TEST_TARGET} serf_static)
  target_link_libraries(${TEST_TARGET} serf_static)
endforeach()

add_executable(test_all ${TEST_ALL_SOURCES})
add_dependencies(test_all serf_static mockhttpinc)
target_include_directories(test_all SYSTEM BEFORE PRIVATE ${SERF_DEPENDENCY_INCLUDES})
target_link_libraries(test_all serf_static mockhttpinc)

file(GLOB RESPONSE_TEST_CASES "${CMAKE_CURRENT_SOURCE_DIR}/testcases/*.response")
foreach(TEST_CASE ${RESPONSE_TEST_CASES})
  get_filename_component(TEST_CASE_NAME ${TEST_CASE} NAME)
  add_test(NAME "${TEST_CASE_NAME}" COMMAND serf_response "${TEST_CASE}")
  list(APPEND ALL_TESTS "${TEST_CASE_NAME}")
endforeach()

foreach(TEST_CASE ${TEST_ALL_SUITES})
  add_test(NAME test_${TEST_CASE} COMMAND test_all ${TEST_CASE})
  list(APPEND ALL_TESTS test_${TEST_CASE})
endforeach()

set_tests_properties(${ALL_TESTS} PROPERTIES
                     ENVIRONMENT srcdir=${SERF_SOURCE_DIR})
