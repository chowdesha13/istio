// Copyright 2017 Istio Authors
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

package modelgen

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/protoc-gen-gogo/descriptor"
)

func TestErrorInTemplate(t *testing.T) {
	tests := []struct {
		src           string
		expectedError string
	}{
		{"testdata/missing_package_name.descriptor_set", "package name missing"},
		{"testdata/missing_template_name.descriptor_set", "Contains only one of the following two options"},
		{"testdata/missing_template_variety.descriptor_set", "Contains only one of the following two options"},
		{"testdata/missing_both_required.descriptor_set", "one proto file that has both extensions"},
		{"testdata/missing_type_message.descriptor_set", "message 'Type' not defined"},
		{"testdata/missing_constructor_message.descriptor_set", "message 'Constructor' not defined"},
		{"testdata/reserved_field_in_constructor.descriptor_set", "proto:15: Constructor message must not contain the reserved filed name 'Name'"},
		{"testdata/proto2_bad_syntax.descriptor_set", "Proto2BadSyntax.proto:3: Only proto3 template files are allowed."},
	}

	for idx, tt := range tests {
		t.Run(fmt.Sprintf("[%d] %s", idx, tt.src), func(t *testing.T) {
			_, err := createTestModel(t, tt.src)

			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Errorf("CreateModel(%s) caused error '%v', \n wanted err that contains string `%v`", tt.src, err, fmt.Errorf(tt.expectedError))
			}
		})
	}
}

func TestBasicTopLevelFields(t *testing.T) {
	testFilename := "testdata/basic_top_level_fields.descriptor_set"
	model, _ := createTestModel(t,
		testFilename)
	if model.PackageName != "foo_bar" {
		t.Fatalf("CreateModel(%s).PackageName = %v, wanted %s", testFilename, model.PackageName, "foo_bar")
	}
	if model.Name != "List" {
		t.Fatalf("CreateModel(%s).Name = %v, wanted %s", testFilename, model.Name, "List")
	}
	if model.VarietyName != "TEMPLATE_VARIETY_CHECK" {
		t.Fatalf("CreateModel(%s).VarietyName = %v, wanted %s", testFilename, model.VarietyName, "TEMPLATE_VARIETY_CHECK")
	}
}

func TestConstructorDirRefAndImports(t *testing.T) {
	testFilename := "testdata/constructor_and_imports.descriptor_set"
	model, _ := createTestModel(t,
		testFilename)

	expectedTxt := "istio_mixer_v1_config_descriptor \"mixer/v1/config/descriptor\""
	if !contains(model.Imports, expectedTxt) {
		t.Fatalf("CreateModel(%s).Imports = %v, wanted to contain %s", testFilename, model.Imports, expectedTxt)
	}
	expectedTxt = "_ \"pkg/adapter/template\""
	if !contains(model.Imports, expectedTxt) {
		t.Fatalf("CreateModel(%s).Imports = %v, wanted to contain %s", testFilename, model.Imports, expectedTxt)
	}

	if len(model.ConstructorFields) != 5 {
		t.Fatalf("len(CreateModel(%s).ConstructorFields) = %v, wanted %d", testFilename, len(model.ConstructorFields), 5)
	}
	testField(t, testFilename, model, "Blacklist", "bool")
	testField(t, testFilename, model, "CheckExpression", "interface{}")
	testField(t, testFilename, model, "Om", "*OtherMessage")
	testField(t, testFilename, model, "Val", "istio_mixer_v1_config_descriptor.ValueType")
	testField(t, testFilename, model, "Submsgfield", "*ConstructorSubmessage")
}

func testField(t *testing.T, testFilename string, model *Model, fldName string, expectedFldType string) {
	found := false
	for _, cf := range model.ConstructorFields {
		if cf.Name == fldName {
			found = true
			if cf.Type.Name != expectedFldType {
				t.Fatalf("CreateModel(%s).ConstructorFields[%s] = %s, wanted %s", testFilename, fldName, cf.Type.Name, expectedFldType)
			}
		}
	}
	if !found {
		t.Fatalf("CreateModel(%s).ConstructorFields = %v, wanted to contain field with name '%s'", testFilename, model.ConstructorFields, fldName)
	}
}

func createTestModel(t *testing.T, inputFDS string) (*Model, error) {
	fds, err := getFileDescSet(inputFDS)
	if err != nil {
		t.Fatalf("Unable to parse file descriptor set file %v", err)

	}

	parser, _ := CreateFileDescriptorSetParser(fds, map[string]string{})
	return Create(parser)
}

func getFileDescSet(path string) (*descriptor.FileDescriptorSet, error) {
	byts, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	fds := &descriptor.FileDescriptorSet{}
	err = proto.Unmarshal(byts, fds)

	return fds, err
}
