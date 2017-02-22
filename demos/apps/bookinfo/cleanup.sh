#!/bin/bash
#
# Copyright 2017 Istio Authors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

SCRIPTDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

kubectl delete -f $SCRIPTDIR/route-rule-reviews-v1.yaml
kubectl delete -f $SCRIPTDIR/route-rule-reviews-tester-v2.yaml
kubectl delete -f $SCRIPTDIR/route-rule-ratings-tester-delay.yaml
kubectl delete -f $SCRIPTDIR/route-rule-reviews-25-v3.yaml
kubectl delete -f $SCRIPTDIR/route-rule-reviews-50-v3.yaml
kubectl delete -f $SCRIPTDIR/route-rule-reviews-v3.yaml

kubectl delete -f $SCRIPTDIR/bookinfo-istio.yaml
kubectl delete -f $SCRIPTDIR/../controlplane.yaml
