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
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestNormInit(t *testing.T) {
	assert.NotEmpty(t, syscallNorms)
	assert.NotEmpty(t, recordTypeNorms)
}

func TestLoadNormalizationConfig(t *testing.T) {
	_, recordTypes, err := LoadNormalizationConfig(normalizationDataYAML)
	if err != nil {
		t.Fatal(err)
	}

	if len(recordTypes["USER_ROLE_CHANGE"]) != 1 {
		t.Fatal("expected single normalization")
	}
	n := recordTypes["USER_ROLE_CHANGE"][0]

	assert.Equal(t, n.SubjectPrimaryFieldName.Values, []string{"auid"})
	assert.Equal(t, n.SubjectSecondaryFieldName.Values, []string{"acct", "id", "uid"})

	assert.Equal(t, n.ObjectPrimaryFieldName.Values, []string{"selected-context"})
	assert.Equal(t, n.ObjectSecondaryFieldName.Values, []string{"addr", "hostname"})
	assert.Equal(t, n.ObjectWhat, "user-session")

	assert.Equal(t, n.How.Values, []string{"exe", "terminal"})
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
