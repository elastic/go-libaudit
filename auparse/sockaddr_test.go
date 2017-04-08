// Copyright 2017 Elasticsearch Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSockaddr(t *testing.T) {
	tests := []struct {
		saddr string
		data  map[string]string
	}{
		{
			"02000050080808080000000000000000",
			map[string]string{"address_family": "ipv4", "addr": "8.8.8.8", "port": "80"},
		},
		{
			"0A000050000000002607F8B0400C0C06000000000000006700000000",
			map[string]string{"address_family": "ipv6", "addr": "2607:f8b0:400c:c06::67", "port": "80"},
		},
		{
			"01007075626C69632F7069636B75700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			map[string]string{"address_family": "unix", "path": "public/pickup"},
		},
		{
			// bind
			"0A00084300000000000000000000000000000000000000000000000000000000281E7423FD7F0000C05034088F7F000007000000000000001E2D440000000000000000000000000060D758078F7F00000300000000000000C00F020000000000000000000000000005202302000000000200000000000000FFFFFFFFFFFFFFFF",
			map[string]string{"address_family": "ipv6", "addr": "::", "port": "2115"},
		},
	}

	for _, tc := range tests {
		data, err := parseSockaddr(tc.saddr)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, tc.data, data)
	}
}
