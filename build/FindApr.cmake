# Source: http://svn.trolocsis.com/repos/projects/templates/apr/build/FindAPR.cmake
# Locate APR include paths and libraries

# This module defines
# APR_INCLUDES, where to find apr.h, etc.
# APR_LIBS, linker switches to use with ld to link against APR
# APR_EXTRALIBS, additional libraries to link against
# APR_CFLAGS, the flags to use to compile
# APR_FOUND, set to TRUE if found, FALSE otherwise
# APR_VERSION, the version of APR that was found

set(APR_FOUND FALSE)

find_program(APR_CONFIG_EXECUTABLE apr-1-config)
mark_as_advanced(APR_CONFIG_EXECUTABLE)

macro(_apr_invoke _varname _separate _regexp)
    execute_process(
        COMMAND ${APR_CONFIG_EXECUTABLE} ${ARGN}
        OUTPUT_VARIABLE _apr_output
        RESULT_VARIABLE _apr_failed
    )

    if(_apr_failed)
        message(FATAL_ERROR "${APR_CONFIG_EXECUTABLE} ${ARGN} failed")
    else()
        string(REGEX REPLACE "[\r\n]"  "" _apr_output "${_apr_output}")
        string(REGEX REPLACE " +$"     "" _apr_output "${_apr_output}")

        if(NOT ${_regexp} STREQUAL "")
            string(REGEX REPLACE "${_regexp}" " " _apr_output "${_apr_output}")
        endif()

        # XXX: We don't want to invoke separate_arguments() for APR_CFLAGS;
        # just leave as-is
        if(${_separate})
            separate_arguments(_apr_output)
        endif()

        set(${_varname} "${_apr_output}")
    endif()
endmacro(_apr_invoke)

_apr_invoke(APR_CFLAGS    FALSE ""        --cppflags --cflags)
_apr_invoke(APR_INCLUDES  TRUE  "(^| )-I" --includes)
_apr_invoke(APR_LIBS      TRUE  ""        --link-ld)
_apr_invoke(APR_EXTRALIBS TRUE  "(^| )-l" --libs)
_apr_invoke(APR_VERSION   TRUE  ""        --version)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(APR DEFAULT_MSG APR_INCLUDES APR_LIBS APR_VERSION)
