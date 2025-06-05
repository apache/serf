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

# Generate list of symbols to export from shared libraries..
function(SerfFindExports blacklist_ output_)
  set(W "[a-zA-Z_0-9]") # Word characters pattern
  set(base_func_rx_     "^((${W}+|\\*) )+\\*?(serf_[a-z]${W}*)\\(")
  set(base_type_rx_     "^extern const serf_bucket_type_t (serf_[a-z_]*)")
  set(func_search_rx_   "${base_func_rx_}")
  set(type_search_rx_   "${base_type_rx_};")
  set(func_name_rx_     "${base_func_rx_}.*$")
  set(type_name_rx_     "${base_type_rx_}.*$")

  foreach(file_ ${ARGN})
    message(STATUS "Looking for exports in ${file_}")
    file(STRINGS ${file_} funcs_ REGEX "${func_search_rx_}")
    file(STRINGS ${file_} types_ REGEX "${type_search_rx_}")
    foreach(sym_ ${funcs_})
      string(REGEX REPLACE "${func_name_rx_}" "\\3" def_ ${sym_})
      list(APPEND symbols_ ${def_})
    endforeach()
    foreach(sym_ ${types_})
      string(REGEX REPLACE "${type_name_rx_}" "\\1" def_ ${sym_})
      list(APPEND symbols_ ${def_})
    endforeach()
  endforeach()

  list(SORT symbols_)
  list(REMOVE_DUPLICATES symbols_)
  list(JOIN blacklist_ "|" filter_)
  list(FILTER symbols_ EXCLUDE REGEX "${filter_}")
  set(${output_} "${symbols_}" PARENT_SCOPE)
endfunction(SerfFindExports)
