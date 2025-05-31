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

# Generate a .clangd file at the root of the source tree.

function(SerfGenClangd)
  set(target "${CMAKE_SOURCE_DIR}/.clangd")

  function(write_clangd is_path prefix)
    foreach(arg ${ARGN})
      if(arg)
        if(is_path)
          file(TO_CMAKE_PATH "${arg}" arg)
        endif()
        file(APPEND ${target} "    - ${prefix}${arg}\n")
      endif()
    endforeach()
  endfunction(write_clangd)

  function(write_includes)
    write_clangd(TRUE "-I" ${ARGN})
  endfunction(write_includes)

  function(write_defines)
    write_clangd(TRUE "-D" ${ARGN})
  endfunction(write_defines)

  function(write_flags)
    write_clangd(FALSE "" ${ARGN})
  endfunction(write_flags)

  file(WRITE ${target}
    "---\n"
    "If:\n"
    "  PathMatch: .*\\.[ch]\n"
    "\n"
    "CompileFlags:\n"
    "  Add:\n")
  write_flags("--language=c")
  write_includes("${CMAKE_SOURCE_DIR}")
  write_includes("${APR_INCLUDES}")
  if(NOT APR_CONTAINS_APRUTIL)
    write_includes("${APRUTIL_INCLUDES}")
  endif()
  write_includes("${OPENSSL_INCLUDE_DIR}")
  write_includes("${ZLIB_INCLUDE_DIR}")
  if(BROTLI_FOUND)
    write_includes("${BROTLI_INCLUDES}")
  endif()
  if(GSSAPI_FOUND)
    write_includes("${GSSAPI_INCLUDES}")
  endif()

  get_directory_property(cdef COMPILE_DEFINITIONS)
  write_defines(${cdef})

  set(flags ${CMAKE_C_FLAGS})
  separate_arguments(flags)
  write_flags(${flags})
endfunction(SerfGenClangd)
SerfGenClangd()
