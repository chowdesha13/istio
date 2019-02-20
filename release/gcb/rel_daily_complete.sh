#!/bin/bash
# Copyright 2018 Istio Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

set -o errexit
set -o nounset
set -o pipefail
set -x

# shellcheck disable=SC1091
source "/workspace/gcb_env.sh"

gsutil -q stat "gs://${CB_GCS_STAGING_BUCKET}/daily-build/${CB_VERSION}/*"

return_value=$?

if [ $return_value = 0 ]; then
    echo "Remove gs://${CB_GCS_STAGING_BUCKET}/daily-build/${CB_BRANCH}-latest-daily"
    # Remove the old folder in case there is any stale file.
    gsutil -q rm -rf "gs://${CB_GCS_STAGING_BUCKET}/daily-build/${CB_BRANCH}-latest-daily/" || echo "No old build"
    echo "Copy from ${CB_VERSION} to ${CB_BRANCH}-latest-daily"
    # Copy to the stable folder
    gsutil -q cp -r "gs://${CB_GCS_STAGING_BUCKET}/daily-build/${CB_VERSION}/*" "gs://${CB_GCS_STAGING_BUCKET}/daily-build/${CB_BRANCH}-latest-daily/"
else
    echo "gs://${CB_GCS_STAGING_BUCKET}/daily-build/${CB_VERSION} does not exist"
    exit 1
fi
