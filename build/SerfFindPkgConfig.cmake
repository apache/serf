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

include(FindPackageHandleStandardArgs)
include(GNUInstallDirs)
find_package(PkgConfig QUIET)

# Generate list of symbols to export from shared libraries..
function(SerfFindPkgConfig name root pkgname target_alias)
  set(${name}_FOUND FALSE PARENT_SCOPE)
  if(PKG_CONFIG_FOUND)
    # Save the PKG_CONFIG_PATH environment variable
    set(pkg_config_path $ENV{PKG_CONFIG_PATH})

    if(DEFINED ${root})
      # Set the PKG_CONFIG_PATH environment variable for the search
      find_path(_${name}_pcdir NAMES "${pkgname}.pc"
                PATHS ${${root}} NO_DEFAULT_PATH
                PATH_SUFFIXES
                "lib/pkgconfig"
                "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
                "share/pkgconfig"
                "${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig")
      if(_${name}_pcdir AND EXISTS "${_${name}_pcdir}/${pkgname}.pc")
        set(ENV{PKG_CONFIG_PATH} ${_${name}_pcdir})
      endif()
    endif()

    string(TOUPPER "${name}" NAME)
    pkg_search_module(${NAME} QUIET IMPORTED_TARGET ${pkgname})
    if(${NAME}_FOUND)
      find_package_handle_standard_args(${name}
        REQUIRED_VARS ${NAME}_LINK_LIBRARIES ${NAME}_INCLUDEDIR
        VERSION_VAR ${NAME}_VERSION)
      if(${name}_FOUND)
        add_library(${target_alias} ALIAS PkgConfig::${NAME})
        set(${name}_FOUND ${${name}_FOUND} PARENT_SCOPE)
        set(${NAME}_INCLUDE_DIR ${${NAME}_INCLUDEDIR} PARENT_SCOPE)
        set(${NAME}_LIBRARY ${${NAME}_LINK_LIBRARIES} PARENT_SCOPE)
        set(${NAME}_VERSION ${${NAME}_VERSION} PARENT_SCOPE)
        set(${NAME}_PC_REQUIRES ${pkgname} PARENT_SCOPE)
      endif()
    endif()

    # Restore the PKG_CONFIG_PATH environment variable
    set(ENV{PKG_CONFIG_PATH} ${pkg_config_path})
  endif()
endfunction(SerfFindPkgConfig)
