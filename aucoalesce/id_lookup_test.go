package aucoalesce

import (
	"os"
	"strconv"
	"testing"
)

func TestUIDLookup(t *testing.T) {
	uid := os.Getuid()
	user := userLookup.LookupUID(strconv.Itoa(uid))
	gid := os.Getgid()
	group := groupLookup.LookupGID(strconv.Itoa(gid))

	t.Log(user, group)
}

func TestResolveIDs(t *testing.T) {
	auid := strconv.Itoa(os.Getuid())
	event := &Event{
		Subject: Subject{
			Primary:   auid,
			Secondary: "0",
		},
		Data: map[string]string{
			"auid": auid,
			"gid":  strconv.Itoa(os.Getgid()),
		},
	}
	ResolveIDs(event)
	t.Logf("%+v", event)
}
