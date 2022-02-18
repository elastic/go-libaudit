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
	"os"
	"os/user"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUIDLookup(t *testing.T) {
	uid := os.Getuid()
	assert.NotPanics(t, func() { userLookup.LookupID(strconv.Itoa(uid)) })
	user := userLookup.LookupID(strconv.Itoa(uid))
	gid := os.Getgid()
	assert.NotPanics(t, func() { groupLookup.LookupID(strconv.Itoa(gid)) })
	group := groupLookup.LookupID(strconv.Itoa(gid))

	t.Log(user, group)
}

func TestResolveIDs(t *testing.T) {
	usr, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(usr.Gid)
	if err != nil {
		t.Fatal(err)
	}
	event := &Event{
		User: User{
			IDs: map[string]string{
				"auid": usr.Uid,
				"gid":  usr.Gid,
			},
		},
		Summary: Summary{
			Actor: Actor{
				Primary: usr.Uid,
			},
		},
		ECS: ECSFields{
			User: ECSEntity{
				ECSEntityData: ECSEntityData{
					ID: usr.Uid,
				},
				Effective: ECSEntityData{
					Name: usr.Username,
				},
			},
		},
	}

	ResolveIDs(event)
	t.Logf("%+v", event)
	assert.Equal(t, usr.Username, event.User.Names["auid"])
	assert.Equal(t, group.Name, event.User.Names["gid"])
	assert.Equal(t, usr.Username, event.Summary.Actor.Primary)
	assert.Equal(t, usr.Uid, event.ECS.User.ID)
	assert.Equal(t, usr.Username, event.ECS.User.Name)
	assert.Equal(t, usr.Uid, event.ECS.User.Effective.ID)
	assert.Equal(t, usr.Username, event.ECS.User.Effective.Name)
}

func TestNameLookup(t *testing.T) {
	usr, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(usr.Gid)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, usr.Uid, userLookup.LookupName(usr.Username))
	assert.Equal(t, group.Gid, groupLookup.LookupName(group.Name))
}

func TestHardcoded(t *testing.T) {
	usr := user.User{Uid: "42", Username: "auditbeat_user"}
	grp := user.Group{Gid: "43", Name: "auditbeat_group"}
	HardcodeUsers(usr)
	HardcodeGroups(grp)
	assert.Equal(t, usr.Username, userLookup.LookupID(usr.Uid))
	assert.Equal(t, usr.Uid, userLookup.LookupName(usr.Username))
	assert.Equal(t, grp.Name, groupLookup.LookupID(grp.Gid))
	assert.Equal(t, grp.Gid, groupLookup.LookupName(grp.Name))
}
