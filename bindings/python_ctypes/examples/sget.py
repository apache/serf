#!/usr/bin/python
#
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
# 

import sys
import argparse

import serf

ONE_SECOND = 1000000


def main():
  fetch('serf.googlecode.com', 80, '/svn/trunk/NOTICE')


def fetch(hostname, port, path):
  serf.apr_initialize()
  status, pool = serf.apr_pool_create(None)
  assert status == 0

  ### need to fill ALL fields
  uri_struct = serf.URI()
  uri_struct.hostname = hostname
  uri_struct.port_str = str(port)
  uri_struct.port = port
  uri_struct.path = path

  ctx = serf.serf_context_create(pool)

  bktalloc = serf.serf_bucket_allocator_create(pool,
                                               serf.UNFREED_FUNC_F(), None)
  conn = serf.CONN_P()
  status = serf.serf_connection_create2(serf.ctypes.byref(conn),
                                        ctx, uri_struct,
                                        serf.CONN_SETUP_F(conn_setup), None,
                                        serf.CONN_CLOSED_F(conn_closed), None,
                                        pool)
  assert status == 0

  baton = [ 1 ]
  req = serf.serf_connection_request_create(conn,
                                            serf.REQ_SETUP_F(setup_req), baton)

  while True:
    status = serf.serf_context_run(ctx, ONE_SECOND, pool)
    if status:
      print 'STATUS:', status, serf.serf_error_string(status)
      continue
    if not baton[0]:
      # the request was completed
      break

  serf.serf_connection_close(conn)
  serf.apr_pool_destroy(pool)
  serf.apr_terminate()


def conn_setup(skt, pp_readbkt, pp_write_bkt, baton, pool):
  sbkt = serf.serf_bucket_socket_create(skt, bktalloc)

  ### deal with SSL

  pp_readbkt.contents = sbkt

  return 0  ### APR_SUCCESS


def conn_closed(conn, baton, why, pool):
  # Nothing to do.
  pass


def setup_req(req, baton, pp_reqbkt,
              acceptor, a_baton, handler, h_baton, pool):

  pp_reqbkt = serf.serf_request_bucket_request_create(req, 'GET', path,
                                                      None,
                                                      bktalloc)
  #hdrs_bkt = serf_bucket_request_get_headers(pp_reqbkt.contents)

  acceptor.contents = req_accept
  handler.contents = req_handler

  return 0  ### APR_SUCCESS


def req_accept(req, bkt, a_baton, pool):
  bktalloc = serf.serf_request_get_alloc(req)
  bkt = serf.serf_bucket_barrier_create(bkt, bktalloc)
  bkt = serf.serf_bucket_response_create(bkt, bktalloc)
  return bkt


def req_handler(req, resp_bkt, h_baton, pool):
  assert resp_bkt is not None

  buf = serf.ctypes.create_string_buffer(8000)

  while True:
    status = resp_bkt.type.read(resp_bkt, 8000, buf, len(buf))
    print status
    if status:
      return status


if __name__ == '__main__':
  main()
