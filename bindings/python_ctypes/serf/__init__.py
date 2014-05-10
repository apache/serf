#
# ====================================================================
#   Copyright 2013 Justin Erenkrantz and Greg Stein
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ====================================================================
#

import types
import ctypes


### make this work on all platforms
def _loadlib(which):
  return ctypes.cdll.LoadLibrary(which)

_serf = _loadlib('../../libserf-2.dylib')
_apr = _loadlib('libapr-1.dylib')
#_apu = _loadlib('libaprutil-1.dylib')


def _make_incomplete_ptr(name):
  "Create an incomplete pointer type, referencing the given name."
  cls = types.ClassType(name, (ctypes.Structure,), { })
  return ctypes.POINTER(cls)

POOL_P = _make_incomplete_ptr('apr_pool_t')
CONTEXT_P = _make_incomplete_ptr('serf_context_t')
CONN_P = _make_incomplete_ptr('serf_connection_t')
REQUEST_P = _make_incomplete_ptr('serf_request_t')
BKTALLOC_P = _make_incomplete_ptr('serf_bucket_allocator_t')

STATUS = ctypes.c_int

BATON = ctypes.py_object  # standard baton type: pass any Python object

class BUCKET(ctypes.Structure):
  pass
BUCKET_P = ctypes.POINTER(BUCKET)

class BUCKET_TYPE(ctypes.Structure):
  pass
BUCKET_TYPE_P = ctypes.POINTER(BUCKET_TYPE)
               
BUCKET._fields_ = [
  ('type', BUCKET_TYPE_P),
  ('data', BATON),
  ('allocator', BKTALLOC_P),
  ]
BUCKET_TYPE._fields_ = [
  ('name', ctypes.c_char_p),
  ('read', ctypes.CFUNCTYPE(STATUS, BUCKET_P, ctypes.c_int,
                            ctypes.POINTER(ctypes.c_char_p),
                            ctypes.POINTER(ctypes.c_int))),
  ('readline', ctypes.CFUNCTYPE(STATUS, BUCKET_P, ctypes.c_int,
                                ctypes.POINTER(ctypes.c_int),
                                ctypes.POINTER(ctypes.c_char_p),
                                ctypes.POINTER(ctypes.c_int))),
  ### needs to be fixed for Python to call/implement
  ('read_iovec', ctypes.CFUNCTYPE(STATUS, BUCKET_P, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_void_p,  ### wrong. VECS
                                  ctypes.POINTER(ctypes.c_int))),
  ### needs to be fixed for Python to call/implement
  ('read_for_sendfile', ctypes.CFUNCTYPE(STATUS, BUCKET_P, ctypes.c_int,
                                         ctypes.c_void_p,  ### wrong. HDTR
                                         ctypes.c_void_p,  ### wrong. FILE
                                         ctypes.POINTER(ctypes.c_int),
                                         ctypes.POINTER(ctypes.c_int))),
  ('read_bucket', ctypes.CFUNCTYPE(BUCKET_P, BUCKET_P, BUCKET_TYPE_P)),
  ('peek', ctypes.CFUNCTYPE(STATUS, BUCKET_P,
                            ctypes.POINTER(ctypes.c_char_p),
                            ctypes.POINTER(ctypes.c_int))),
  ('destroy', ctypes.CFUNCTYPE(None, BUCKET_P)),
  ]

class SOCKADDR(ctypes.Structure):
  pass
SOCKADDR_P = ctypes.POINTER(SOCKADDR)
SOCKADDR._fields_ = [
  ('pool', POOL_P),
  ('hostname', ctypes.c_char_p),
  ('servname', ctypes.c_char_p),
  ('port', ctypes.c_int),
  ('family', ctypes.c_int),
  ('salen', ctypes.c_int),
  ('ipaddr_len', ctypes.c_int),
  ('addr_str_len', ctypes.c_int),
  ('ipaddr_ptr', ctypes.c_void_p),  ### wrong.
  ('next', ctypes.POINTER(SOCKADDR)),
  ('sa', ctypes.c_byte * 128),
  ]


def _define(name, restype, *argtypes):
  if name.startswith('serf_'):
    f = getattr(_serf, name)
  else:
    f = getattr(_apr, name)
  f.restype = restype
  f.argtypes = argtypes
  globals()[name] = f
  return f

_define('apr_initialize', STATUS)
_define('apr_terminate', None)
_define('apr_pool_destroy', None, POOL_P)


ABORTFUNC_F = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
_ALLOCATOR_P = _make_incomplete_ptr('apr_allocator_t')
_NULL_ABORTFUNC = ABORTFUNC_F()
_NULL_ALLOCATOR = _ALLOCATOR_P()
apr_pool_create_ex = _define('apr_pool_create_ex', STATUS,
                             ctypes.POINTER(POOL_P), POOL_P,
                             ABORTFUNC_F, _ALLOCATOR_P)
def apr_pool_create(parent):
  pool = POOL_P()  # NULL pointer
  status = apr_pool_create_ex(ctypes.byref(pool), parent,
                              _NULL_ABORTFUNC, _NULL_ALLOCATOR)
  return status, pool

_apr_strerror = _define('apr_strerror', ctypes.c_char_p,
                        STATUS, ctypes.c_char_p, ctypes.c_int)
def apr_strerror(status):
  buf = ctypes.create_string_buffer(200)
  return _apr_strerror(status, buf, len(buf))

_apr_sockaddr_info_get = _define('apr_sockaddr_info_get', STATUS,
                                 ctypes.POINTER(SOCKADDR_P),
                                 ctypes.c_char_p,
                                 ctypes.c_int,
                                 ctypes.c_int,
                                 ctypes.c_int,
                                 POOL_P)
def apr_sockaddr_info_get(hostname, family, port, flags, pool):
  psa = SOCKADDR_P()  # NULL pointer
  status = _apr_sockaddr_info_get(ctypes.byref(psa),
                                  hostname, family, port, flags, pool)
  return status, psa


_define('serf_context_create', CONTEXT_P, POOL_P)
_define('serf_config_proxy', None, SOCKADDR_P)
_define('serf_config_authn_types', None, ctypes.c_int)
_define('serf_context_run', STATUS, CONTEXT_P, ctypes.c_int, POOL_P)
_define('serf_error_string', ctypes.c_char_p, STATUS)
_define('serf_debug__closed_conn', None, CONN_P)
_define('serf_connection_close', STATUS, CONN_P)
_define('serf_connection_set_max_outstanding_requests', None,
        CONN_P, ctypes.c_uint)
_define('serf_bucket_socket_create', BUCKET_P, ctypes.c_void_p, BKTALLOC_P)
_define('serf_request_bucket_request_create', BUCKET_P,
        REQUEST_P, ctypes.c_char_p, ctypes.c_char_p, BUCKET_P, BKTALLOC_P)
_define('serf_request_get_alloc', BKTALLOC_P, REQUEST_P)
_define('serf_bucket_barrier_create', BUCKET_P, BUCKET_P, BKTALLOC_P)
_define('serf_bucket_response_create', BUCKET_P, BUCKET_P, BKTALLOC_P)
_define('serf_bucket_socket_create', BUCKET_P, ctypes.c_void_p, BKTALLOC_P)

CREDENTIALS_F = ctypes.CFUNCTYPE(STATUS,
                                 ctypes.POINTER(ctypes.c_char_p),
                                 ctypes.POINTER(ctypes.c_char_p),
                                 REQUEST_P, BATON,
                                 ctypes.c_int, ctypes.c_char_p,
                                 ctypes.c_char_p,
                                 POOL_P)
_define('serf_config_credentials_callback', CONTEXT_P, CREDENTIALS_F)

UNFREED_FUNC_F = ctypes.CFUNCTYPE(None, BATON, ctypes.c_void_p)
_define('serf_bucket_allocator_create', BKTALLOC_P,
        POOL_P, UNFREED_FUNC_F, BATON)

### serf takes an apr_uri_t struct rather than the two fields it needs :-(
class URI(ctypes.Structure):
  _fields_ = [ ('scheme', ctypes.c_char_p),
               ('hostinfo', ctypes.c_char_p),
               ('user', ctypes.c_char_p),
               ('password', ctypes.c_char_p),
               ('hostname', ctypes.c_char_p),
               ('port_str', ctypes.c_char_p),
               ('path', ctypes.c_char_p),
               ('query', ctypes.c_char_p),
               ('fragment', ctypes.c_char_p),
               ('hostent', ctypes.c_void_p),  ### wrong. struct hostent *
               ('port', ctypes.c_int),
               ('bitfield', ctypes.c_int),  ### ctypes can't do bitfields.
               ]
CONN_SETUP_F = ctypes.CFUNCTYPE(STATUS,
                                ctypes.c_void_p,  ### wrong. SKT.
                                ctypes.POINTER(BUCKET_P),
                                ctypes.POINTER(BUCKET_P),
                                BATON,
                                POOL_P)
CONN_CLOSED_F = ctypes.CFUNCTYPE(None, CONN_P, BATON, STATUS, POOL_P)
_define('serf_connection_create2', STATUS,
        ctypes.POINTER(CONN_P),
        CONTEXT_P, URI,
        CONN_SETUP_F, BATON,
        CONN_CLOSED_F, BATON,
        POOL_P)

ACCEPTOR_F = ctypes.CFUNCTYPE(BUCKET_P, REQUEST_P, BUCKET_P, BATON, POOL_P)
HANDLER_F = ctypes.CFUNCTYPE(STATUS, REQUEST_P, BUCKET_P, BATON, POOL_P)
REQ_SETUP_F = ctypes.CFUNCTYPE(STATUS,
                               REQUEST_P, BATON,
                               ctypes.POINTER(BUCKET_P),
                               ctypes.POINTER(ACCEPTOR_F),
                               ctypes.POINTER(BATON),
                               ctypes.POINTER(HANDLER_F),
                               ctypes.POINTER(BATON),
                               POOL_P)
_define('serf_connection_request_create', REQUEST_P,
        CONN_P, REQ_SETUP_F, BATON)
