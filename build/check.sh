#!/bin/sh
#
# Run the test suite
#

if test -z "$1"; then
  TESTDIR="test"
else
  TESTDIR="$1"
fi

for case in "${TESTDIR}/testcases/"*.response; do
  echo "== Testing ${case} =="
  if "${TESTDIR}/serf_response" "${case}"; then :; else
    echo "ERROR: test case failed"
    exit 1
  fi
done

# Run the CuTest-based tests
if "${TESTDIR}/test_all"; then :; else
  echo "ERROR: some test(s) failed in test_all"
  exit 1
fi

exit 0
