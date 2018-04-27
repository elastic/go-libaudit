// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package aucoalesce

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestNormInit(t *testing.T) {
	assert.NotEmpty(t, syscallNorms)
	assert.NotEmpty(t, recordTypeNorms)
}

func TestLoadNormalizationConfig(t *testing.T) {
	b, err := ioutil.ReadFile("normalizations.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := LoadNormalizationConfig(b); err != nil {
		t.Fatal(err)
	}
}

var stringsYAML = `
---
plain_string: plain string
list_strings: [x, y, z]
`

func TestStrings_UnmarshalYAML(t *testing.T) {
	var data map[string]Strings
	if err := yaml.Unmarshal([]byte(stringsYAML), &data); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []string{"plain string"}, data["plain_string"].Values)
	assert.Equal(t, []string{"x", "y", "z"}, data["list_strings"].Values)
}
