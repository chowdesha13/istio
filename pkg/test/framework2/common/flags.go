//  Copyright 2019 Istio Authors
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

package common

import (
	"flag"
	"fmt"
	"os"
)

var (
	settingsFromCommandLine = DefaultSettings()
)

// SettingsFromCommandLine returns settings obtained from command-line flags. flag.Parse must be called before
// calling this function.
func SettingsFromCommandLine(testID string) *Settings {
	if !flag.Parsed() {
		panic("flag.Parse must be called before this function")
	}

	s := settingsFromCommandLine.Clone()
	s.TestID = testID

	return s
}

// init registers the command-line flags that we can exposed for "go test".
func init() {
	flag.StringVar(&settingsFromCommandLine.BaseDir, "istio.test.work_dir", os.TempDir(),
		"Local working directory for creating logs/temp files. If left empty, os.TempDir() is used.")

	flag.StringVar((*string)(&settingsFromCommandLine.Environment), "istio.test.env", string(settingsFromCommandLine.Environment),
		fmt.Sprintf("Specify the environment to run the tests against. Allowed values are: %v", EnvironmentNames()))

	flag.BoolVar(&settingsFromCommandLine.NoCleanup, "istio.test.noCleanup", settingsFromCommandLine.NoCleanup,
		"Do not cleanup resources after test completion")

	flag.BoolVar(&settingsFromCommandLine.CIMode, "istio.test.ci", settingsFromCommandLine.CIMode,
		"Enable CI Mode. Additional logging and state dumping will be enabled.")
}
