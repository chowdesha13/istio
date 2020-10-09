//  Copyright Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package echo

import (
	"flag"
	"time"
)

var (
	callTimeout = 20 * time.Second
	callDelay   = 100 * time.Millisecond
)

// init registers the command-line flags that we can exposed for "go test".
func init() {
	flag.DurationVar(&callTimeout, "istio.test.echo.callTimeout", callTimeout,
		"Specifies the default timeout used when retrying calls to the Echo service")
	flag.DurationVar(&callDelay, "istio.test.echo.callDelay", callDelay,
		"Specifies the default delay between successive retry attempts when calling the Echo service")
}
