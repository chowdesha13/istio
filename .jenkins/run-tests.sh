#!/bin/bash

set -e
set -x
set -o pipefail

#
# This is a replica of .circleci.yaml test target
#

mkdir -p out/tests
make localTestEnv
make test T=-v | tee -a out/tests/go-test-report.out
