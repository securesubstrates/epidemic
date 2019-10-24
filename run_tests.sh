#!/bin/bash
set -x

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
# PYTHONPATH="$SCRIPTPATH" python3 -m unittest pysgx.tests.sgx_tests
PYTHONPATH="$SCRIPTPATH" python3 -m unittest pysgx.tests.ias_tlv_tests
