// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package file

import (
	"io/ioutil"
	"os"

	"istio.io/istio/pkg/test"
)

// Copy the source file to the destination file. Creates the destination file if it doesn't exist,
// otherwise overwrites it.
func Copy(src string, dest string) error {
	// Copy the mode from the source file.
	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	input, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(dest, input, info.Mode())
}

// AsBytes is a simple wrapper around ioutil.ReadFile provided for completeness.
func AsBytes(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// AsBytesOrFail calls AsBytes and fails the test if any errors occurred.
func AsBytesOrFail(t test.Failer, filename string) []byte {
	t.Helper()
	content, err := AsBytes(filename)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// AsBytesOrPanic calls AsBytes and panics if any errors occurred.
func AsBytesOrPanic(filename string) []byte {
	content, err := AsBytes(filename)
	if err != nil {
		panic(err)
	}
	return content
}

// AsString is a convenience wrapper around ioutil.ReadFile that converts the content to a string.
func AsString(filename string) (string, error) {
	bytes, err := AsBytes(filename)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// AsStringOrFail calls AsBytesOrFail and then converts to string.
func AsStringOrFail(t test.Failer, filename string) string {
	t.Helper()
	return string(AsBytesOrFail(t, filename))
}
