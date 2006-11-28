#**** serf Win32 -*- Makefile -*- ********************************************
#
# Define DEBUG_BUILD to create a debug version of the library.

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE
NULL=nul
!ENDIF

CFLAGS = /Zi /W3 /EHsc /I "./"

!IF "$(DEBUG_BUILD)" == ""
INTDIR = Release
CFLAGS = /MD /O2 /D "NDEBUG" $(CFLAGS)
STATIC_LIB = $(INTDIR)\serf.lib
!ELSE
INTDIR = Debug
CFLAGS = /MDd /Od /W3 /Gm /D "_DEBUG" $(CFLAGS)
STATIC_LIB = $(INTDIR)\serf.lib
!ENDIF

########
# Support for OpenSSL integration
!IF "$(OPENSSL_SRC)" == ""
!ERROR OpenSSL is required. Please define OPENSSL_SRC.
!ELSE
OPENSSL_FLAGS = /I "$(OPENSSL_SRC)\inc32"
!ENDIF

!IF "$(HTTPD_SRC)" != ""
!IF "$(APR_SRC)" == ""
APR_SRC=$(HTTPD_SRC)\srclib\apr
!ENDIF

!IF "$(APRUTIL_SRC)" == ""
APRUTIL_SRC=$(HTTPD_SRC)\srclib\apr-util
!ENDIF

!ENDIF

########
# APR
!IF "$(APR_SRC)" == ""
!ERROR APR is required. Please define APR_SRC or HTTPD_SRC.
!ENDIF

APR_FLAGS = /I "$(APR_SRC)\include"
!IF [IF EXIST "$(APR_SRC)\$(INTDIR)\libapr-1.lib" exit 1] == 1
APR_LIBS = "$(APR_SRC)\$(INTDIR)\libapr-1.lib"
!ELSE
APR_LIBS = "$(APR_SRC)\$(INTDIR)\libapr.lib"
!ENDIF

########
# APR Util
!IF "$(APRUTIL_SRC)" == ""
!ERROR APR-Util is required. Please define APRUTIL_SRC or HTTPD_SRC.
!ENDIF

APRUTIL_FLAGS = /I "$(APRUTIL_SRC)\include"
!IF [IF EXIST "$(APRUTIL_SRC)\$(INTDIR)\libaprutil-1.lib" exit 1] == 1
APRUTIL_LIBS = "$(APRUTIL_SRC)\$(INTDIR)\libaprutil-1.lib"
!ELSE
APRUTIL_LIBS = "$(APRUTIL_SRC)\$(INTDIR)\libaprutil.lib"
!ENDIF

########
# Support for zlib integration
!IF "$(ZLIB_SRC)" == ""
!ERROR ZLib is required. Please define ZLIB_SRC.
!ELSE
ZLIB_FLAGS = /I "$(ZLIB_SRC)"
!IF "$(ZLIB_DLL)" == ""
!IF "$(ZLIB_LIBDIR)" == ""
!IF "$(DEBUG_BUILD)" == ""
ZLIB_LIBS = "$(ZLIB_SRC)\zlibstat.lib"
!ELSE
ZLIB_LIBS = "$(ZLIB_SRC)\zlibstatD.lib"
!ENDIF
!ELSE
ZLIB_LIBS = "$(ZLIB_LIBDIR)\x86\ZlibStat$(INTDIR)\zlibstat.lib"
ZLIB_FLAGS = $(ZLIB_FLAGS) /D ZLIB_WINAPI
!ENDIF
!ELSE
ZLIB_FLAGS = $(ZLIB_FLAGS) /D ZLIB_DLL
ZLIB_LIBS = "$(ZLIB_SRC)\zlibdll.lib"
!ENDIF
!ENDIF


# Exclude stuff we don't need from the Win32 headers
WIN32_DEFS = /D WIN32 /D WIN32_LEAN_AND_MEAN /D NOUSER /D NOGDI /D NONLS /D NOCRYPT

CPP=cl.exe
CPP_PROJ = /c /nologo $(CFLAGS) $(WIN32_DEFS) $(EXPAT_FLAGS) $(APR_FLAGS) $(APRUTIL_FLAGS) $(OPENSSL_FLAGS) $(ZLIB_FLAGS) /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\"
LIB32=link.exe
LIB32_FLAGS=/nologo

LIB32_OBJS= \
    "$(INTDIR)\aggregate_buckets.obj" \
    "$(INTDIR)\context.obj" \
    "$(INTDIR)\allocator.obj" \
    "$(INTDIR)\barrier_buckets.obj" \
    "$(INTDIR)\buckets.obj" \
    "$(INTDIR)\chunk_buckets.obj" \
    "$(INTDIR)\dechunk_buckets.obj" \
    "$(INTDIR)\deflate_buckets.obj" \
    "$(INTDIR)\file_buckets.obj" \
    "$(INTDIR)\headers_buckets.obj" \
    "$(INTDIR)\limit_buckets.obj" \
    "$(INTDIR)\mmap_buckets.obj" \
    "$(INTDIR)\request_buckets.obj" \
    "$(INTDIR)\response_buckets.obj" \
    "$(INTDIR)\simple_buckets.obj" \
    "$(INTDIR)\socket_buckets.obj" \
    "$(INTDIR)\ssl_buckets.obj" \

!IFDEF OPENSSL_STATIC
LIB32_OBJS = $(LIB32_OBJS) "$(OPENSSL_SRC)\out32\libeay32.lib" \
               "$(OPENSSL_SRC)\out32\ssleay32.lib"
!ELSE
LIB32_OBJS = $(LIB32_OBJS) "$(OPENSSL_SRC)\out32dll\libeay32.lib" \
               "$(OPENSSL_SRC)\out32dll\ssleay32.lib"
!ENDIF

LIB32_OBJS = $(LIB32_OBJS) $(APR_LIBS) $(APRUTIL_LIBS) $(ZLIB_LIBS) 

ALL: INTDIR $(STATIC_LIB)
 

CLEAN:
  -@erase "$(INTDIR)" >nul

INTDIR:
  -@if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

"$(STATIC_LIB)": INTDIR $(LIB32_OBJS)
  $(LIB32) -lib @<<
    $(LIB32_FLAGS) $(LIB32_OBJS) /OUT:"$(STATIC_LIB)"
<<


.c{$(INTDIR)}.obj:
  $(CPP) @<<
    $(CPP_PROJ) $<
<<

{buckets}.c{$(INTDIR)}.obj:
  $(CPP) @<<
    $(CPP_PROJ) $<
<<
