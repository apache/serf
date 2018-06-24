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
    "MockHTTPinC/MockHTTP.c"
    "MockHTTPinC/MockHTTP_server.c"
)

add_definitions("-DMOCKHTTP_OPENSSL")
add_executable(test_all ${TEST_ALL_SOURCES})
add_dependencies(test_all SerfStatic)
target_link_libraries(test_all SerfStatic ${DEPENDENCY_LIBRARIES})
add_test(NAME test_all COMMAND test_all)
