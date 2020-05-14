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

// Code generated by mknormalize_data.go - DO NOT EDIT.

package aucoalesce

import (
	"encoding/base64"
	"fmt"
)

var assets map[string][]byte

func asset(key string) ([]byte, error) {
	if assets == nil {
		assets = map[string][]byte{}

		var value []byte
		value, _ = base64.StdEncoding.DecodeString("LS0tCiMgTWFjcm9zIGRlY2xhcmVzIHNvbWUgWUFNTCBhbmNob3JzIHRoYXQgY2FuIGJlIHJlZmVyZW5jZWQgZm9yIHNvbWUgY29tbW9uCiMgb2JqZWN0IHR5cGUgbm9ybWFsaXphdGlvbnMgbGlrZSB1c2VyLXNlc3Npb24sIHNvY2tldCwgb3IgcHJvY2Vzcy4KbWFjcm9zOgogIC0gJmRlZmF1bHRzCiAgICBzdWJqZWN0OgogICAgICBwcmltYXJ5OiBhdWlkCiAgICAgIHNlY29uZGFyeTogdWlkCiAgICBob3c6IFtleGUsIGNvbW1dCgogIC0gJm1hY3JvLXVzZXItc2Vzc2lvbgogICAgc3ViamVjdDoKICAgICAgcHJpbWFyeTogYXVpZAogICAgICBzZWNvbmRhcnk6IFthY2N0LCBpZCwgdWlkXQogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiB0ZXJtaW5hbAogICAgICBzZWNvbmRhcnk6IFthZGRyLCBob3N0bmFtZV0KICAgICAgd2hhdDogdXNlci1zZXNzaW9uCiAgICBob3c6IFtleGUsIHRlcm1pbmFsXQoKICAtICZtYWNyby1zb2NrZXQKICAgIDw8OiAqZGVmYXVsdHMKICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogW2FkZHIsIHBhdGhdCiAgICAgIHNlY29uZGFyeTogcG9ydAogICAgICB3aGF0OiBzb2NrZXQKCiAgLSAmbWFjcm8tcHJvY2VzcwogICAgPDw6ICpkZWZhdWx0cwogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiBbY21kLCBleGUsIGNvbW1dCiAgICAgIHNlY29uZGFyeTogcGlkCiAgICAgIHdoYXQ6IHByb2Nlc3MKICAgIGhvdzogdGVybWluYWwKCiAgLSAmZWNzLWlhbQogICAgY2F0ZWdvcnk6IGlhbQogICAgdHlwZTogaW5mbwoKICAtICZlY3MtYXV0aAogICAgY2F0ZWdvcnk6IGF1dGhlbnRpY2F0aW9uCiAgICB0eXBlOiBpbmZvCgogIC0gJmVjcy1ob3N0CiAgICBjYXRlZ29yeTogaG9zdAogICAgdHlwZTogaW5mbwoKICAtICZlY3MtcHJvY2VzcwogICAgY2F0ZWdvcnk6IHByb2Nlc3MKICAgIHR5cGU6IGluZm8KCiAgLSAmZWNzLWZpbGUKICAgIGNhdGVnb3J5OiBmaWxlCiAgICB0eXBlOiBpbmZvCgogIC0gJmVjcy1uZXR3b3JrCiAgICBjYXRlZ29yeTogbmV0d29yawogICAgdHlwZToKICAgICAgLSBjb25uZWN0aW9uCiAgICAgIC0gaW5mbwoKIyBOb3JtYWxpemF0aW9ucyBpcyBhIGxpc3Qgb2YgZGVjbGFyYXRpb25zIHNwZWNpZnlpbmcgaG93IHRvIG5vcm1hbGl6ZSB0aGUgZGF0YQojIGNvbnRhaW5lZCBpbiBhbiBldmVudC4gVGhlIG5vcm1hbGl6YXRpb24gY2FuIGJlIGFwcGxpZWQgYmFzZWQgb24gdGhlIHN5c2NhbGwKIyBuYW1lIChlLmcuIGNvbm5lY3QsIG9wZW4pIG9yIGJhc2VkIG9uIHRoZSByZWNvcmQgdHlwZSAoZS5nLiBVU0VSX0xPR0lOKS4KIyBObyB0d28gbm9ybWFsaXphdGlvbnMgY2FuIGFwcGx5IHRvIHRoZSBzYW1lIHN5c2NhbGwgb3IgcmVjb3JkIHR5cGUuIFRoaXMKIyB3aWxsIHJlc3VsdCBpbiBhIGZhaWx1cmUgYXQgbG9hZCB0aW1lLgojCiMgRWFjaCBub3JtYWxpemF0aW9uIHNob3VsZCBzcGVjaWZ5OgojICAgYWN0aW9uIC0gd2hhdCBoYXBwZW5lZAojICAgYWN0b3IgIC0gd2hvIGRpZCB0aGlzIG9yIHdobyB0cmlnZ2VyZWQgdGhlIGV2ZW50CiMgICBvYmplY3QgLSB3aGF0IHdhcyB0aGUgInRoaW5nIiBpbnZvbHZlZCBpbiB0aGUgYWN0aW9uIChlLmcuIHByb2Nlc3MsIHNvY2tldCkKIyAgIGhvdyAgICAtIGhvdyB3YXMgdGhlIGFjdGlvbiBwZXJmb3JtZWQgKGUuZy4gZXhlIG9yIHRlcm1pbmFsKQpub3JtYWxpemF0aW9uczoKICAtIGVjczogKmVjcy1wcm9jZXNzCiAgICBzeXNjYWxsczoKICAgICAgLSAnKicgIyB0aGlzIGlzIGEgY2F0Y2ggYWxsCiAgLSBhY3Rpb246IG9wZW5lZC1maWxlCiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IGZpbGUKICAgIHN5c2NhbGxzOgogICAgICAtIGNyZWF0CiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWZpbGUKICAgICAgdHlwZTogY3JlYXRpb24KICAtIGFjdGlvbjogb3BlbmVkLWZpbGUKICAgIG9iamVjdDoKICAgICAgd2hhdDogZmlsZQogICAgc3lzY2FsbHM6CiAgICAgIC0gZmFsbG9jYXRlCiAgICAgIC0gdHJ1bmNhdGUKICAgICAgLSBmdHJ1bmNhdGUKICAgIGVjczoKICAgICAgPDw6ICplY3MtZmlsZQogICAgICAjIHRlY2huaWNhbGx5IHlvdSBjYW4gdHJ1bmNhdGUgYSBmaWxlIHRvIHRoZSBzYW1lIGxlbmd0aAogICAgICAjIGJ1dCByZWdhcmRsZXNzLCB3ZSBjb25zaWRlciB0aGlzIGEgY2hhbmdlCiAgICAgIHR5cGU6IGNoYW5nZQogIC0gYWN0aW9uOiBvcGVuZWQtZmlsZQogICAgb2JqZWN0OgogICAgICB3aGF0OiBmaWxlCiAgICBzeXNjYWxsczoKICAgICAgLSBvcGVuCiAgICAgIC0gb3BlbmF0CiAgICAgIC0gcmVhZGxpbmsKICAgICAgLSByZWFkbGlua2F0CiAgICBlY3M6ICplY3MtZmlsZQogIC0gYWN0aW9uOiByZWFkLWZpbGUKICAgIG9iamVjdDoKICAgICAgd2hhdDogZmlsZQogICAgc3lzY2FsbHM6CiAgICAgIC0gcmVhZAogICAgZWNzOiAqZWNzLWZpbGUKICAtIGFjdGlvbjogY2hhbmdlZC1maWxlLWF0dHJpYnV0ZXMtb2YKICAgIG9iamVjdDoKICAgICAgd2hhdDogZmlsZQogICAgc3lzY2FsbHM6CiAgICAgIC0gc2V0eGF0dHIKICAgICAgLSBmc2V0eGF0dHIKICAgICAgLSBsc2V0eGF0dHIKICAgICAgLSByZW1vdmV4YXR0cgogICAgICAtIGZyZW1vdmV4YXR0cgogICAgICAtIGxyZW1vdmV4YXR0cgogICAgZWNzOgogICAgICA8PDogKmVjcy1maWxlCiAgICAgIHR5cGU6IGNoYW5nZQogIC0gYWN0aW9uOiBjaGFuZ2VkLWZpbGUtcGVybWlzc2lvbnMtb2YKICAgIG9iamVjdDoKICAgICAgd2hhdDogZmlsZQogICAgc3lzY2FsbHM6CiAgICAgIC0gY2htb2QKICAgICAgLSBmY2htb2QKICAgICAgLSBmY2htb2RhdAogICAgZWNzOgogICAgICA8PDogKmVjcy1maWxlCiAgICAgIHR5cGU6IGNoYW5nZQogIC0gYWN0aW9uOiBjaGFuZ2VkLWZpbGUtb3duZXJzaGlwLW9mCiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IGZpbGUKICAgIHN5c2NhbGxzOgogICAgICAtIGNob3duCiAgICAgIC0gZmNob3duCiAgICAgIC0gZmNob3duYXQKICAgICAgLSBsY2hvd24KICAgIGVjczoKICAgICAgPDw6ICplY3MtZmlsZQogICAgICB0eXBlOiBjaGFuZ2UKICAtIGFjdGlvbjogbG9hZGVkLWtlcm5lbC1tb2R1bGUKICAgIG9iamVjdDoKICAgICAgd2hhdDogZmlsZQogICAgICBwcmltYXJ5OiBuYW1lCiAgICByZWNvcmRfdHlwZXM6CiAgICAgIC0gS0VSTl9NT0RVTEUKICAgIHN5c2NhbGxzOgogICAgICAtIGZpbml0X21vZHVsZQogICAgICAtIGluaXRfbW9kdWxlCiAgICBlY3M6CiAgICAgIGNhdGVnb3J5OiBkcml2ZXIKICAgICAgdHlwZTogc3RhcnQKICAtIGFjdGlvbjogdW5sb2FkZWQta2VybmVsLW1vZHVsZQogICAgb2JqZWN0OgogICAgICB3aGF0OiBmaWxlCiAgICBzeXNjYWxsczoKICAgICAgLSBkZWxldGVfbW9kdWxlCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWZpbGUKICAgICAgdHlwZTogZW5kCiAgLSBhY3Rpb246IGNyZWF0ZWQtZGlyZWN0b3J5CiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IGZpbGUKICAgICAgcGF0aF9pbmRleDogMQogICAgc3lzY2FsbHM6CiAgICAgIC0gbWtkaXIKICAgICAgLSBta2RpcmF0CiAgICBlY3M6CiAgICAgIGNhdGVnb3J5OiBmaWxlCiAgICAgIHR5cGU6IGNyZWF0ZQogIC0gYWN0aW9uOiBtb3VudGVkCiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IGZpbGVzeXN0ZW0KICAgICAgcGF0aF9pbmRleDogMQogICAgc3lzY2FsbHM6CiAgICAgIC0gbW91bnQKICAgIGVjczoKICAgICAgPDw6ICplY3MtZmlsZQogICAgICAjIHNpbmNlIGEgbmV3IG1vdW50IGFwcGVhcnMgb24gdGhlIHN5c3RlbQogICAgICAjIHdlIGNvbnNpZGVyIHRoaXMgYSBoaWdoLWxldmVsICJjcmVhdGlvbiIgZXZlbnQKICAgICAgdHlwZTogY3JlYXRpb24KICAtIGFjdGlvbjogcmVuYW1lZAogICAgb2JqZWN0OgogICAgICB3aGF0OiBmaWxlCiAgICAgIHBhdGhfaW5kZXg6IDIKICAgIHN5c2NhbGxzOgogICAgICAtIHJlbmFtZQogICAgICAtIHJlbmFtZWF0CiAgICAgIC0gcmVuYW1lYXQyCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWZpbGUKICAgICAgdHlwZTogY2hhbmdlCiAgLSBhY3Rpb246IGNoZWNrZWQtbWV0YWRhdGEtb2YKICAgIG9iamVjdDoKICAgICAgd2hhdDogZmlsZQogICAgc3lzY2FsbHM6CiAgICAgIC0gYWNjZXNzCiAgICAgIC0gZmFjY2Vzc2F0CiAgICAgIC0gbmV3ZnN0YXRhdAogICAgICAtIHN0YXQKICAgICAgLSBmc3RhdAogICAgICAtIGxzdGF0CiAgICAgIC0gc3RhdDY0CiAgICAgIC0gZ2V0eGF0dHIKICAgICAgLSBsZ2V0eGF0dHIKICAgICAgLSBmZ2V0eGF0dHIKICAgIGVjczogKmVjcy1maWxlCiAgLSBhY3Rpb246IGNoZWNrZWQtZmlsZXN5c3RlbS1tZXRhZGF0YS1vZgogICAgb2JqZWN0OgogICAgICB3aGF0OiBmaWxlc3lzdGVtCiAgICBzeXNjYWxsczoKICAgICAgLSBzdGF0ZnMKICAgICAgLSBmc3RhdGZzCiAgICBlY3M6ICplY3MtZmlsZQogIC0gYWN0aW9uOiBzeW1saW5rZWQKICAgIG9iamVjdDoKICAgICAgd2hhdDogZmlsZQogICAgc3lzY2FsbHM6CiAgICAgIC0gc3ltbGluawogICAgICAtIHN5bWxpbmthdAogICAgZWNzOgogICAgICA8PDogKmVjcy1maWxlCiAgICAgICMgImNyZWF0aW9uIiBzaW5jZSB3ZSdyZSBjcmVhdGluZyBhIG5ldyBmaWxlIHN5c3RlbQogICAgICAjIGVudHJ5IGZvciB0aGUgc3ltbGluawogICAgICB0eXBlOiBjcmVhdGlvbgogIC0gYWN0aW9uOiB1bm1vdW50ZWQKICAgIG9iamVjdDoKICAgICAgd2hhdDogZmlsZXN5c3RlbQogICAgc3lzY2FsbHM6CiAgICAgIC0gdW1vdW50MgogICAgZWNzOgogICAgICA8PDogKmVjcy1maWxlCiAgICAgICMgImRlbGV0aW9uIiB0byBtaXJyb3IgdGhlICJjcmVhdGlvbiIgb2YgdGhlIG1vdW50CiAgICAgIHR5cGU6IGRlbGV0aW9uCiAgLSBhY3Rpb246IGRlbGV0ZWQKICAgIG9iamVjdDoKICAgICAgd2hhdDogZmlsZQogICAgc3lzY2FsbHM6CiAgICAgIC0gcm1kaXIKICAgICAgLSB1bmxpbmsKICAgICAgLSB1bmxpbmthdAogICAgZWNzOgogICAgICA8PDogKmVjcy1maWxlCiAgICAgIHR5cGU6IGRlbGV0aW9uCiAgLSBhY3Rpb246IGNoYW5nZWQtdGltZXN0YW1wLW9mCiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IGZpbGUKICAgIHN5c2NhbGxzOgogICAgICAtIHV0aW1lCiAgICAgIC0gdXRpbWVzCiAgICAgIC0gZnV0aW1lc2F0CiAgICAgIC0gZnV0aW1lbnMKICAgICAgLSB1dGltZW5zYXQKICAgIGVjczogKmVjcy1maWxlCiAgLSBhY3Rpb246IGV4ZWN1dGVkCiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IGZpbGUKICAgIHN5c2NhbGxzOgogICAgICAtIGV4ZWN2ZQogICAgICAtIGV4ZWN2ZWF0CiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLXByb2Nlc3MKICAgICAgdHlwZTogY3JlYXRpb24KICAtIGFjdGlvbjogbGlzdGVuLWZvci1jb25uZWN0aW9ucwogICAgb2JqZWN0OgogICAgICB3aGF0OiBzb2NrZXQKICAgIHN5c2NhbGxzOgogICAgICAtIGxpc3RlbgogICAgZWNzOgogICAgICA8PDogKmVjcy1uZXR3b3JrCiAgICAgIHR5cGU6IHN0YXJ0CiAgLSBhY3Rpb246IGFjY2VwdGVkLWNvbm5lY3Rpb24tZnJvbQogICAgb2JqZWN0OgogICAgICB3aGF0OiBzb2NrZXQKICAgIHN5c2NhbGxzOgogICAgICAtIGFjY2VwdAogICAgICAtIGFjY2VwdDQKICAgIGVjczoKICAgICAgPDw6ICplY3MtbmV0d29yawogICAgICB0eXBlOgogICAgICAgIC0gY29ubmVjdGlvbgogICAgICAgIC0gc3RhcnQKICAtIGFjdGlvbjogYm91bmQtc29ja2V0CiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IHNvY2tldAogICAgc3lzY2FsbHM6CiAgICAgIC0gYmluZAogICAgZWNzOgogICAgICA8PDogKmVjcy1uZXR3b3JrCiAgICAgIHR5cGU6IHN0YXJ0CiAgLSBhY3Rpb246IGNvbm5lY3RlZC10bwogICAgb2JqZWN0OgogICAgICB3aGF0OiBzb2NrZXQKICAgIHN5c2NhbGxzOgogICAgICAtIGNvbm5lY3QKICAgIGVjczoKICAgICAgPDw6ICplY3MtbmV0d29yawogICAgICB0eXBlOgogICAgICAgIC0gY29ubmVjdGlvbgogICAgICAgIC0gc3RhcnQKICAtIGFjdGlvbjogcmVjZWl2ZWQtZnJvbQogICAgb2JqZWN0OgogICAgICB3aGF0OiBzb2NrZXQKICAgIHN5c2NhbGxzOgogICAgICAtIHJlY3Zmcm9tCiAgICAgIC0gcmVjdm1zZwogICAgZWNzOgogICAgICA8PDogKmVjcy1uZXR3b3JrCiAgLSBhY3Rpb246IHNlbnQtdG8KICAgIG9iamVjdDoKICAgICAgd2hhdDogc29ja2V0CiAgICBzeXNjYWxsczoKICAgICAgLSBzZW5kdG8KICAgICAgLSBzZW5kbXNnCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLW5ldHdvcmsKICAtIGFjdGlvbjoga2lsbGVkLXBpZAogICAgb2JqZWN0OgogICAgICB3aGF0OiBwcm9jZXNzCiAgICBzeXNjYWxsczoKICAgICAgLSBraWxsCiAgICAgIC0gdGtpbGwKICAgICAgLSB0Z2tpbGwKICAgIGVjczoKICAgICAgPDw6ICplY3MtcHJvY2VzcwogICAgICB0eXBlOiBlbmQKICAtIGFjdGlvbjogY2hhbmdlZC1pZGVudGl0eS1vZgogICAgb2JqZWN0OgogICAgICB3aGF0OiBwcm9jZXNzCiAgICBob3c6IHN5c2NhbGwKICAgIHN5c2NhbGxzOgogICAgICAtIHNldHVpZAogICAgICAtIHNldGV1aWQKICAgICAgLSBzZXRmc3VpZAogICAgICAtIHNldHJldWlkCiAgICAgIC0gc2V0cmVzdWlkCiAgICAgIC0gc2V0Z2lkCiAgICAgIC0gc2V0ZWdpZAogICAgICAtIHNldGZzZ2lkCiAgICAgIC0gc2V0cmVnaWQKICAgICAgLSBzZXRyZXNnaWQKICAgIGVjczoKICAgICAgPDw6ICplY3MtcHJvY2VzcwogICAgICB0eXBlOiBjaGFuZ2UKICAtIGFjdGlvbjogY2hhbmdlZC1zeXN0ZW0tdGltZQogICAgb2JqZWN0OgogICAgICB3aGF0OiBzeXN0ZW0KICAgIHN5c2NhbGxzOgogICAgICAtIHNldHRpbWVvZmRheQogICAgICAtIGNsb2NrX3NldHRpbWUKICAgICAgLSBzdGltZQogICAgICAtIGFkanRpbWV4CiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWhvc3QKICAgICAgdHlwZTogY2hhbmdlCiAgLSBhY3Rpb246IG1ha2UtZGV2aWNlCiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IGZpbGUKICAgIHN5c2NhbGxzOgogICAgICAtIG1rbm9kCiAgICAgIC0gbWtub2RhdAogICAgZWNzOgogICAgICA8PDogKmVjcy1maWxlCiAgICAgIHR5cGU6IGNyZWF0aW9uCiAgLSBhY3Rpb246IGNoYW5nZWQtc3lzdGVtLW5hbWUKICAgIG9iamVjdDoKICAgICAgd2hhdDogc3lzdGVtCiAgICBzeXNjYWxsczoKICAgICAgLSBzZXRob3N0bmFtZQogICAgICAtIHNldGRvbWFpbm5hbWUKICAgIGVjczoKICAgICAgPDw6ICplY3MtaG9zdAogICAgICB0eXBlOiBjaGFuZ2UKICAtIGFjdGlvbjogYWxsb2NhdGVkLW1lbW9yeQogICAgb2JqZWN0OgogICAgICB3aGF0OiBtZW1vcnkKICAgIHN5c2NhbGxzOgogICAgICAtIG1tYXAKICAgICAgLSBicmsKICAgIGVjczogKmVjcy1wcm9jZXNzCiAgLSBhY3Rpb246IGFkanVzdGVkLXNjaGVkdWxpbmctcG9saWN5LW9mCiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IHByb2Nlc3MKICAgIGhvdzogc3lzY2FsbAogICAgc3lzY2FsbHM6CiAgICAgIC0gc2NoZWRfc2V0cGFyYW0KICAgICAgLSBzY2hlZF9zZXRzY2hlZHVsZXIKICAgICAgLSBzY2hlZF9zZXRhdHRyCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLXByb2Nlc3MKICAgICAgdHlwZTogY2hhbmdlCgogICMgUmVjb3JkIHR5cGUgbm9ybWFsaXphdGlvbnMKICAjIFVzZWZ1bCBsaW5rczoKICAjIGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS90b3J2YWxkcy9saW51eC92NC4xNi9pbmNsdWRlL3VhcGkvbGludXgvYXVkaXQuaAogICMgaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2xpbnV4LWF1ZGl0L2F1ZGl0LXVzZXJzcGFjZS80ZDkzMzMwMWIxODM1Y2FmYTA4YjllOWVmNzA1YzhmYjZjOTZjYjYyL2xpYi9saWJhdWRpdC5oCiAgIyBodHRwczovL3d3dy5lbGFzdGljLmNvL2d1aWRlL2VuL2Vjcy9jdXJyZW50L2Vjcy1hbGxvd2VkLXZhbHVlcy1ldmVudC1jYXRlZ29yeS5odG1sCgogICMgSUFNIHJlbGF0ZWQgZXZlbnRzCgogICMgQVVESVRfQUNDVF9MT0NLIC0gVXNlcidzIGFjY291bnQgbG9ja2VkIGJ5IGFkbWluCiAgLSByZWNvcmRfdHlwZXM6IEFDQ1RfTE9DSwogICAgYWN0aW9uOiBsb2NrZWQtYWNjb3VudAogICAgZWNzOgogICAgICA8PDogKmVjcy1pYW0KICAgICAgdHlwZToKICAgICAgICAtIHVzZXIKICAgICAgICAtIGluZm8KICAjIEFVRElUX0FDQ1RfVU5MT0NLIC0gVXNlcidzIGFjY291bnQgdW5sb2NrZWQgYnkgYWRtaW4KICAtIHJlY29yZF90eXBlczogQUNDVF9VTkxPQ0sKICAgIGFjdGlvbjogdW5sb2NrZWQtYWNjb3VudAogICAgZWNzOgogICAgICA8PDogKmVjcy1pYW0KICAgICAgdHlwZToKICAgICAgICAtIHVzZXIKICAgICAgICAtIGluZm8KICAjIEFVRElUX0FERF9HUk9VUCAtIEdyb3VwIGFjY291bnQgYWRkZWQKICAtIHJlY29yZF90eXBlczogQUREX0dST1VQCiAgICBhY3Rpb246IGFkZGVkLWdyb3VwLWFjY291bnQtdG8KICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogW2lkLCBhY2N0XQogICAgICB3aGF0OiBhY2NvdW50CiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWlhbQogICAgICB0eXBlOgogICAgICAgIC0gZ3JvdXAKICAgICAgICAtIGNyZWF0aW9uCiAgIyBBVURJVF9BRERfVVNFUiAtIFVzZXIgYWNjb3VudCBhZGRlZAogIC0gcmVjb3JkX3R5cGVzOiBBRERfVVNFUgogICAgYWN0aW9uOiBhZGRlZC11c2VyLWFjY291bnQKICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogW2lkLCBhY2N0XQogICAgICB3aGF0OiBhY2NvdW50CiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWlhbQogICAgICB0eXBlOgogICAgICAgIC0gdXNlcgogICAgICAgIC0gY3JlYXRpb24KICAjIEFVRElUX0RFTF9HUk9VUCAtIEdyb3VwIGFjY291bnQgZGVsZXRlZAogIC0gcmVjb3JkX3R5cGVzOiBERUxfR1JPVVAKICAgIGFjdGlvbjogZGVsZXRlZC1ncm91cC1hY2NvdW50LWZyb20KICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogW2lkLCBhY2N0XQogICAgICB3aGF0OiBhY2NvdW50CiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWlhbQogICAgICB0eXBlOgogICAgICAgIC0gZ3JvdXAKICAgICAgICAtIGRlbGV0aW9uCiAgIyBBVURJVF9ERUxfVVNFUiAtIFVzZXIgYWNjb3VudCBkZWxldGVkCiAgLSByZWNvcmRfdHlwZXM6IERFTF9VU0VSCiAgICBhY3Rpb246IGRlbGV0ZWQtdXNlci1hY2NvdW50CiAgICBvYmplY3Q6CiAgICAgIHByaW1hcnk6IFtpZCwgYWNjdF0KICAgICAgd2hhdDogYWNjb3VudAogICAgZWNzOgogICAgICA8PDogKmVjcy1pYW0KICAgICAgdHlwZToKICAgICAgICAtIHVzZXIKICAgICAgICAtIGRlbGV0aW9uCiAgIyBBVURJVF9HUlBfTUdNVCAtIEdyb3VwIGFjY291bnQgYXR0ciB3YXMgbW9kaWZpZWQKICAtIHJlY29yZF90eXBlczogR1JQX01HTVQKICAgIGFjdGlvbjogbW9kaWZpZWQtZ3JvdXAtYWNjb3VudAogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiBbaWQsIGFjY3RdCiAgICAgIHdoYXQ6IGFjY291bnQKICAgIGVjczoKICAgICAgPDw6ICplY3MtaWFtCiAgICAgIHR5cGU6CiAgICAgICAgLSBncm91cAogICAgICAgIC0gY2hhbmdlCiAgIyBBVURJVF9ST0xFX0FTU0lHTiAtIEFkbWluIGFzc2lnbmVkIHVzZXIgdG8gcm9sZQogIC0gcmVjb3JkX3R5cGVzOiBST0xFX0FTU0lHTgogICAgYWN0aW9uOiBhc3NpZ25lZC11c2VyLXJvbGUtdG8KICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogW2lkLCBhY2N0XQogICAgICB3aGF0OiBhY2NvdW50CiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWlhbQogICAgICB0eXBlOgogICAgICAgIC0gdXNlcgogICAgICAgIC0gY2hhbmdlCiAgIyBBVURJVF9ST0xFX01PRElGWSAtIEFkbWluIG1vZGlmaWVkIGEgcm9sZQogIC0gcmVjb3JkX3R5cGVzOiBST0xFX01PRElGWQogICAgYWN0aW9uOiBtb2RpZmllZC1yb2xlCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWlhbQogICAgICB0eXBlOgogICAgICAgIC0gY2hhbmdlCiAgIyBBVURJVF9ST0xFX1JFTU9WRSAtIEFkbWluIHJlbW92ZWQgdXNlciBmcm9tIHJvbGUKICAtIHJlY29yZF90eXBlczogUk9MRV9SRU1PVkUKICAgIGFjdGlvbjogcmVtb3ZlZC11c2Utcm9sZS1mcm9tCiAgICBvYmplY3Q6CiAgICAgIHByaW1hcnk6IFtpZCwgYWNjdF0KICAgICAgd2hhdDogYWNjb3VudAogICAgZWNzOgogICAgICA8PDogKmVjcy1pYW0KICAgICAgdHlwZToKICAgICAgICAtIHVzZXIKICAgICAgICAtIGNoYW5nZQogICMgQVVESVRfVVNFUl9NR01UIC0gVXNlciBhY2N0IGF0dHJpYnV0ZSBjaGFuZ2UKICAtIDw8OiAqbWFjcm8tdXNlci1zZXNzaW9uCiAgICByZWNvcmRfdHlwZXM6IFVTRVJfTUdNVAogICAgYWN0aW9uOiBtb2RpZmllZC11c2VyLWFjY291bnQKICAgIGVjczoKICAgICAgPDw6ICplY3MtaWFtCiAgICAgIHR5cGU6CiAgICAgICAgLSB1c2VyCiAgICAgICAgLSBjaGFuZ2UKICAjIEFVRElUX1VTRVJfQ0hBVVRIVE9LIC0gVXNlciBhY2N0IHBhc3N3b3JkIG9yIHBpbiBjaGFuZ2VkCiAgLSA8PDogKm1hY3JvLXVzZXItc2Vzc2lvbgogICAgcmVjb3JkX3R5cGVzOiBVU0VSX0NIQVVUSFRPSwogICAgYWN0aW9uOiBjaGFuZ2VkLXBhc3N3b3JkCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWlhbQogICAgICB0eXBlOgogICAgICAgIC0gdXNlcgogICAgICAgIC0gY2hhbmdlCiAgIyBBVURJVF9HUlBfQ0hBVVRIVE9LIC0gR3JvdXAgYWNjdCBwYXNzd29yZCBvciBwaW4gY2hhbmdlZAogIC0gPDw6ICptYWNyby11c2VyLXNlc3Npb24KICAgIHJlY29yZF90eXBlczogR1JQX0NIQVVUSFRPSwogICAgYWN0aW9uOiBjaGFuZ2VkLWdyb3VwLXBhc3N3b3JkCiAgICBvYmplY3Q6CiAgICAgIHByaW1hcnk6IGFjY3QKICAgICAgd2hhdDogdXNlci1zZXNzaW9uCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWlhbQogICAgICB0eXBlOgogICAgICAgIC0gZ3JvdXAKICAgICAgICAtIGNoYW5nZQoKICAjIEF1dGhlbnRpY2F0aW9uIHJlbGF0ZWQgZXZlbnRzCgogICMgQVVESVRfQ1JFRF9BQ1EgLSBVc2VyIGNyZWRlbnRpYWwgYWNxdWlyZWQKICAtIDw8OiAqbWFjcm8tdXNlci1zZXNzaW9uCiAgICByZWNvcmRfdHlwZXM6IENSRURfQUNRCiAgICBhY3Rpb246IGFjcXVpcmVkLWNyZWRlbnRpYWxzCiAgICBlY3M6ICplY3MtYXV0aAogICMgQVVESVRfQ1JFRF9ESVNQIC0gVXNlciBjcmVkZW50aWFsIGRpc3Bvc2VkCiAgLSA8PDogKm1hY3JvLXVzZXItc2Vzc2lvbgogICAgcmVjb3JkX3R5cGVzOiBDUkVEX0RJU1AKICAgIGFjdGlvbjogZGlzcG9zZWQtY3JlZGVudGlhbHMKICAgIGVjczogKmVjcy1hdXRoCiAgIyBBVURJVF9DUkVEX1JFRlIgLSBVc2VyIGNyZWRlbnRpYWwgcmVmcmVzaGVkCiAgLSA8PDogKm1hY3JvLXVzZXItc2Vzc2lvbgogICAgcmVjb3JkX3R5cGVzOiBDUkVEX1JFRlIKICAgIGFjdGlvbjogcmVmcmVzaGVkLWNyZWRlbnRpYWxzCiAgICBlY3M6ICplY3MtYXV0aAogICMgQVVESVRfR1JQX0FVVEggLSBBdXRoZW50aWNhdGlvbiBmb3IgZ3JvdXAgcGFzc3dvcmQKICAtIHJlY29yZF90eXBlczogR1JQX0FVVEgKICAgIGFjdGlvbjogYXV0aGVudGljYXRlZC10by1ncm91cAogICAgZWNzOiAqZWNzLWF1dGgKICAjIEFVRElUX0xPR0lOIC0gRGVmaW5lIHRoZSBsb2dpbiBpZCBhbmQgaW5mb3JtYXRpb24KICAtIHJlY29yZF90eXBlczogTE9HSU4KICAgIGFjdGlvbjogY2hhbmdlZC1sb2dpbi1pZC10bwogICAgc3ViamVjdDoKICAgICAgcHJpbWFyeTogW29sZF9hdWlkLCBvbGQtYXVpZF0KICAgICAgc2Vjb25kYXJ5OiB1aWQKICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogYXVpZAogICAgICB3aGF0OiB1c2VyLXNlc3Npb24KICAgIGVjczoKICAgICAgPDw6ICplY3MtYXV0aAogICAgICB0eXBlOiBzdGFydAogICMgQVVESVRfVVNFUl9BQ0NUIC0gVXNlciBzeXN0ZW0gYWNjZXNzIGF1dGhvcml6YXRpb24KICAtIDw8OiAqbWFjcm8tdXNlci1zZXNzaW9uCiAgICByZWNvcmRfdHlwZXM6IFVTRVJfQUNDVAogICAgYWN0aW9uOiB3YXMtYXV0aG9yaXplZAogICAgZWNzOiAqZWNzLWF1dGgKICAjIEFVRElUX1VTRVJfQVVUSCAtIFVzZXIgc3lzdGVtIGFjY2VzcyBhdXRoZW50aWNhdGlvbgogIC0gPDw6ICptYWNyby11c2VyLXNlc3Npb24KICAgIHJlY29yZF90eXBlczogVVNFUl9BVVRICiAgICBhY3Rpb246IGF1dGhlbnRpY2F0ZWQKICAgIGVjczogKmVjcy1hdXRoCiAgIyBBVURJVF9VU0VSX0VORCAtIFVzZXIgc2Vzc2lvbiBlbmQKICAtIDw8OiAqbWFjcm8tdXNlci1zZXNzaW9uCiAgICByZWNvcmRfdHlwZXM6IFVTRVJfRU5ECiAgICBhY3Rpb246IGVuZGVkLXNlc3Npb24KICAgIGVjczogKmVjcy1hdXRoCiAgIyBBVURJVF9VU0VSX0VSUiAtIFVzZXIgYWNjdCBzdGF0ZSBlcnJvcgogIC0gPDw6ICptYWNyby11c2VyLXNlc3Npb24KICAgIHJlY29yZF90eXBlczogVVNFUl9FUlIKICAgIGFjdGlvbjogZXJyb3IKICAgIHNvdXJjZV9pcDogW2FkZHJdCiAgICBlY3M6ICplY3MtYXV0aAogICMgQVVESVRfVVNFUl9MT0dJTiAtIFVzZXIgaGFzIGxvZ2dlZCBpbgogIC0gPDw6ICptYWNyby11c2VyLXNlc3Npb24KICAgIHJlY29yZF90eXBlczogVVNFUl9MT0dJTgogICAgYWN0aW9uOiBsb2dnZWQtaW4KICAgIHNvdXJjZV9pcDogW2FkZHJdCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWF1dGgKICAgICAgdHlwZTogc3RhcnQKICAjIEFVRElUX1VTRVJfTE9HT1VUIC0gVXNlciBoYXMgbG9nZ2VkIG91dAogIC0gPDw6ICptYWNyby11c2VyLXNlc3Npb24KICAgIHJlY29yZF90eXBlczogVVNFUl9MT0dPVVQKICAgIGFjdGlvbjogbG9nZ2VkLW91dAogICAgZWNzOgogICAgICA8PDogKmVjcy1hdXRoCiAgICAgIHR5cGU6IGVuZAogICMgQVVESVRfVVNFUl9ST0xFX0NIQU5HRSAtIFVzZXIgY2hhbmdlZCB0byBhIG5ldyByb2xlCiAgLSA8PDogKm1hY3JvLXVzZXItc2Vzc2lvbgogICAgcmVjb3JkX3R5cGVzOiBVU0VSX1JPTEVfQ0hBTkdFCiAgICBhY3Rpb246IGNoYW5nZWQtcm9sZS10bwogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiBzZWxlY3RlZC1jb250ZXh0CiAgICAgIHdoYXQ6IHVzZXItc2Vzc2lvbgogICMgQVVESVRfVVNFUl9TVEFSVCAtIFVzZXIgc2Vzc2lvbiBzdGFydAogIC0gPDw6ICptYWNyby11c2VyLXNlc3Npb24KICAgIHJlY29yZF90eXBlczogVVNFUl9TVEFSVAogICAgYWN0aW9uOiBzdGFydGVkLXNlc3Npb24KICAgIHNvdXJjZV9pcDogW2FkZHJdCiAgICBlY3M6ICplY3MtYXV0aAoKICAjIEhvc3QgdmlydHVhbGl6YXRpb24gZXZlbnRzCgogICMgQVVESVRfVklSVF9DT05UUk9MIC0gU3RhcnQsIFBhdXNlLCBTdG9wIFZNCiAgLSByZWNvcmRfdHlwZXM6IFZJUlRfQ09OVFJPTAogICAgYWN0aW9uOiBpc3N1ZWQtdm0tY29udHJvbAogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiBvcAogICAgICBzZWNvbmRhcnk6IHZtCiAgICAgIHdoYXQ6IHZpcnR1YWwtbWFjaGluZQogICAgZWNzOiAqZWNzLWhvc3QKICAjIEFVRElUX1ZJUlRfQ1JFQVRFIC0gQ3JlYXRpb24gb2YgZ3Vlc3QgaW1hZ2UKICAtIHJlY29yZF90eXBlczogVklSVF9DUkVBVEUKICAgIGFjdGlvbjogY3JlYXRlZC12bS1pbWFnZQogICAgZWNzOiAqZWNzLWhvc3QKICAjIEFVRElUX1ZJUlRfREVTVFJPWSAtIERlc3RydWN0aW9uIG9mIGd1ZXN0IGltYWdlCiAgLSByZWNvcmRfdHlwZXM6IFZJUlRfREVTVFJPWQogICAgYWN0aW9uOiBkZWxldGVkLXZtLWltYWdlCiAgICBlY3M6ICplY3MtaG9zdAogICMgQVVESVRfVklSVF9JTlRFR1JJVFlfQ0hFQ0sgLSBHdWVzdCBpbnRlZ3JpdHkgcmVzdWx0cwogIC0gcmVjb3JkX3R5cGVzOiBWSVJUX0lOVEVHUklUWV9DSEVDSwogICAgYWN0aW9uOiBjaGVja2VkLWludGVncml0eS1vZgogICAgZWNzOiAqZWNzLWhvc3QKICAjIEFVRElUX1ZJUlRfTUFDSElORV9JRCAtIEJpbmRpbmcgb2YgbGFiZWwgdG8gVk0KICAtIHJlY29yZF90eXBlczogVklSVF9NQUNISU5FX0lECiAgICBhY3Rpb246IGFzc2lnbmVkLXZtLWlkCiAgICBvYmplY3Q6CiAgICAgIHByaW1hcnk6IHZtCiAgICAgIHdoYXQ6IHZpcnR1YWwtbWFjaGluZQogICAgZWNzOiAqZWNzLWhvc3QKICAjIEFVRElUX1ZJUlRfTUlHUkFURV9JTiAtIEluYm91bmQgZ3Vlc3QgbWlncmF0aW9uIGluZm8KICAtIHJlY29yZF90eXBlczogVklSVF9NSUdSQVRFX0lOCiAgICBhY3Rpb246IG1pZ3JhdGVkLXZtLWZyb20KICAgIGVjczogKmVjcy1ob3N0CiAgIyBBVURJVF9WSVJUX01JR1JBVEVfT1VUIC0gT3V0Ym91bmQgZ3Vlc3QgbWlncmF0aW9uIGluZm8KICAtIHJlY29yZF90eXBlczogVklSVF9NSUdSQVRFX09VVAogICAgYWN0aW9uOiBtaWdyYXRlZC12bS10bwogICAgZWNzOiAqZWNzLWhvc3QKICAjIEFVRElUX1ZJUlRfUkVTT1VSQ0UgLSBSZXNvdXJjZSBhc3NpZ25tZW50CiAgLSByZWNvcmRfdHlwZXM6IFZJUlRfUkVTT1VSQ0UKICAgIGFjdGlvbjogYXNzaWduZWQtdm0tcmVzb3VyY2UKICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogcmVzcmMKICAgICAgc2Vjb25kYXJ5OiB2bQogICAgICB3aGF0OiB2aXJ0dWFsLW1hY2hpbmUKICAgIGVjczogKmVjcy1ob3N0CgogICMgVXNlcnNwYWNlIHByb2Nlc3MgZXZlbnRzCgogICMgQVVESVRfQ0hHUlBfSUQgLSBVc2VyIHNwYWNlIGdyb3VwIElEIGNoYW5nZWQKICAtIHJlY29yZF90eXBlczogQ0hHUlBfSUQKICAgIGFjdGlvbjogY2hhbmdlZC1ncm91cAogICAgZWNzOgogICAgICA8PDogKmVjcy1wcm9jZXNzCiAgICAgIHR5cGU6IGNoYW5nZQogICMgQVVESVRfQ0hVU0VSX0lEIC0gQ2hhbmdlZCB1c2VyIElEIHN1cHBsZW1lbnRhbCBkYXRhCiAgLSByZWNvcmRfdHlwZXM6IENIVVNFUl9JRAogICAgYWN0aW9uOiBjaGFuZ2VkLXVzZXItaWQKICAgIGVjczoKICAgICAgPDw6ICplY3MtcHJvY2VzcwogICAgICB0eXBlOiBjaGFuZ2UKICAjIEFVRElUX1RFU1QgLSBVc2VkIGZvciB0ZXN0IHN1Y2Nlc3MgbWVzc2FnZXMKICAtIHJlY29yZF90eXBlczogVEVTVAogICAgYWN0aW9uOiBzZW50LXRlc3QKICAgIGVjczogKmVjcy1wcm9jZXNzCiAgIyBBVURJVF9UUlVTVEVEX0FQUCAtIFRydXN0ZWQgYXBwIG1zZyAtIGZyZWVzdHlsZSB0ZXh0CiAgLSByZWNvcmRfdHlwZXM6IFRSVVNURURfQVBQCiAgICBhY3Rpb246IHVua25vd24KICAgIGVjczogKmVjcy1wcm9jZXNzCiAgIyBBVURJVF9VU0VSX0NNRCAtIFVzZXIgc2hlbGwgY29tbWFuZCBhbmQgYXJncwogIC0gcmVjb3JkX3R5cGVzOiBVU0VSX0NNRAogICAgYWN0aW9uOiByYW4tY29tbWFuZAogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiBjbWQKICAgICAgd2hhdDogcHJvY2VzcwogICAgZGVzY3JpcHRpb246ID4KICAgICAgVGhlc2UgbWVzc2FnZXMgYXJlIGZyb20gdXNlci1zcGFjZSBhcHBzLCBsaWtlIHN1ZG8sIHRoYXQgbG9nIGNvbW1hbmRzCiAgICAgIGJlaW5nIHJ1biBieSBhIHVzZXIuIFRoZSB1aWQgY29udGFpbmVkIGluIHRoZXNlIG1lc3NhZ2VzIGlzIHVzZXIncyBVSUQgYXQKICAgICAgdGhlIHRpbWUgdGhlIGNvbW1hbmQgd2FzIHJ1bi4gSXQgaXMgbm90IHRoZSAidGFyZ2V0IiBVSUQgdXNlZCB0byBydW4gdGhlCiAgICAgIGNvbW1hbmQsIHdoaWNoIGlzIG5vcm1hbGx5IHJvb3QuCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLXByb2Nlc3MKICAgICAgdHlwZTogc3RhcnQKCiAgIyBIb3N0LWxldmVsIGV2ZW50cwoKICAjIEFVRElUX1NZU1RFTV9CT09UIC0gU3lzdGVtIGJvb3QKICAtIHJlY29yZF90eXBlczogU1lTVEVNX0JPT1QKICAgIGFjdGlvbjogYm9vdGVkLXN5c3RlbQogICAgb2JqZWN0OgogICAgICB3aGF0OiBzeXN0ZW0KICAgIGVjczoKICAgICAgPDw6ICplY3MtaG9zdAogICAgICB0eXBlOiBzdGFydAogICMgQVVESVRfU1lTVEVNX1JVTkxFVkVMIC0gU3lzdGVtIHJ1bmxldmVsIGNoYW5nZQogIC0gcmVjb3JkX3R5cGVzOiBTWVNURU1fUlVOTEVWRUwKICAgIGFjdGlvbjogY2hhbmdlZC10by1ydW5sZXZlbAogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiBuZXctbGV2ZWwKICAgICAgd2hhdDogc3lzdGVtCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLWhvc3QKICAgICAgdHlwZTogY2hhbmdlCiAgIyBBVURJVF9TWVNURU1fU0hVVERPV04gLSBTeXN0ZW0gc2h1dGRvd24KICAtIHJlY29yZF90eXBlczogU1lTVEVNX1NIVVRET1dOCiAgICBhY3Rpb246IHNodXRkb3duLXN5c3RlbQogICAgb2JqZWN0OgogICAgICB3aGF0OiBzeXN0ZW0KICAgIGVjczoKICAgICAgPDw6ICplY3MtaG9zdAogICAgICB0eXBlOiBlbmQKCiAgIyBTZXJ2aWNlLWxldmVsIGV2ZW50cwoKICAjIEFVRElUX1NFUlZJQ0VfU1RBUlQgLSBTZXJ2aWNlIChkYWVtb24pIHN0YXJ0CiAgLSByZWNvcmRfdHlwZXM6IFNFUlZJQ0VfU1RBUlQKICAgIGFjdGlvbjogc3RhcnRlZC1zZXJ2aWNlCiAgICBvYmplY3Q6CiAgICAgIHByaW1hcnk6IHVuaXQKICAgICAgd2hhdDogc2VydmljZQogICAgZWNzOgogICAgICA8PDogKmVjcy1wcm9jZXNzCiAgICAgIHR5cGU6IHN0YXJ0CiAgIyBBVURJVF9TRVJWSUNFX1NUT1AgLSBTZXJ2aWNlIChkYWVtb24pIHN0b3AKICAtIHJlY29yZF90eXBlczogU0VSVklDRV9TVE9QCiAgICBhY3Rpb246IHN0b3BwZWQtc2VydmljZQogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiB1bml0CiAgICAgIHdoYXQ6IHNlcnZpY2UKICAgIGVjczoKICAgICAgPDw6ICplY3MtcHJvY2VzcwogICAgICB0eXBlOiBzdG9wCgogICMgQXVkaXRkIGludGVybmFsIGV2ZW50cwoKICAjIEFVRElUX0NPTkZJR19DSEFOR0UgLSBBdWRpdCBzeXN0ZW0gY29uZmlndXJhdGlvbiBjaGFuZ2UKICAtIHJlY29yZF90eXBlczogQ09ORklHX0NIQU5HRQogICAgYWN0aW9uOiBjaGFuZ2VkLWF1ZGl0LWNvbmZpZ3VyYXRpb24KICAgIG9iamVjdDoKICAgICAgcHJpbWFyeToKICAgICAgICBbb3AsIGtleSwgYXVkaXRfZW5hYmxlZCwgYXVkaXRfcGlkLCBhdWRpdF9iYWNrbG9nX2xpbWl0LCBhdWRpdF9mYWlsdXJlXQogICAgICB3aGF0OiBhdWRpdC1jb25maWcKICAgIGVjczoKICAgICAgPDw6ICplY3MtcHJvY2VzcwogICAgICB0eXBlOiBjaGFuZ2UKICAjIEFVRElUX0RBRU1PTl9BQk9SVCAtIERhZW1vbiBlcnJvciBzdG9wIHJlY29yZAogIC0gcmVjb3JkX3R5cGVzOiBEQUVNT05fQUJPUlQKICAgIGFjdGlvbjogYWJvcnRlZC1hdWRpdGQtc3RhcnR1cAogICAgb2JqZWN0OgogICAgICB3aGF0OiBzZXJ2aWNlCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLXByb2Nlc3MKICAgICAgdHlwZTogc3RvcAogICMgQVVESVRfREFFTU9OX0FDQ0VQVCAtIEF1ZGl0ZCBhY2NlcHRlZCByZW1vdGUgY29ubmVjdGlvbgogIC0gcmVjb3JkX3R5cGVzOiBEQUVNT05fQUNDRVBUCiAgICBhY3Rpb246IHJlbW90ZS1hdWRpdC1jb25uZWN0ZWQKICAgIG9iamVjdDoKICAgICAgd2hhdDogc2VydmljZQogICAgZWNzOgogICAgICA8PDogKmVjcy1uZXR3b3JrCiAgICAgIHR5cGU6CiAgICAgICAgLSBjb25uZWN0aW9uCiAgICAgICAgLSBzdGFydAogICMgQVVESVRfREFFTU9OX0NMT1NFIC0gQXVkaXRkIGNsb3NlZCByZW1vdGUgY29ubmVjdGlvbgogIC0gcmVjb3JkX3R5cGVzOiBEQUVNT05fQ0xPU0UKICAgIGFjdGlvbjogcmVtb3RlLWF1ZGl0LWRpc2Nvbm5lY3RlZAogICAgb2JqZWN0OgogICAgICB3aGF0OiBzZXJ2aWNlCiAgICBlY3M6CiAgICAgIDw8OiAqZWNzLW5ldHdvcmsKICAgICAgdHlwZToKICAgICAgICAtIGNvbm5lY3Rpb24KICAgICAgICAtIHN0YXJ0CiAgIyBBVURJVF9EQUVNT05fQ09ORklHIC0gRGFlbW9uIGNvbmZpZyBjaGFuZ2UKICAtIHJlY29yZF90eXBlczogREFFTU9OX0NPTkZJRwogICAgYWN0aW9uOiBjaGFuZ2VkLWF1ZGl0ZC1jb25maWd1cmF0aW9uCiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IHNlcnZpY2UKICAgIGVjczoKICAgICAgPDw6ICplY3MtcHJvY2VzcwogICAgICB0eXBlOiBzdG9wCiAgIyBBVURJVF9EQUVNT05fRU5EIC0gRGFlbW9uIG5vcm1hbCBzdG9wIHJlY29yZAogIC0gcmVjb3JkX3R5cGVzOiBEQUVNT05fRU5ECiAgICBhY3Rpb246IHNodXRkb3duLWF1ZGl0CiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IHNlcnZpY2UKICAgIGVjczoKICAgICAgPDw6ICplY3MtcHJvY2VzcwogICAgICB0eXBlOiBzdG9wCiAgIyBBVURJVF9EQUVNT05fRVJSIC0gQXVkaXRkIGludGVybmFsIGVycm9yCiAgLSByZWNvcmRfdHlwZXM6IERBRU1PTl9FUlIKICAgIGFjdGlvbjogYXVkaXQtZXJyb3IKICAgIG9iamVjdDoKICAgICAgd2hhdDogc2VydmljZQogICAgZWNzOiAqZWNzLXByb2Nlc3MKICAjIEFVRElUX0RBRU1PTl9SRUNPTkZJRyAtIEF1ZGl0ZCBzaG91bGQgcmVjb25maWd1cmUKICAtIHJlY29yZF90eXBlczogREFFTU9OX1JFQ09ORklHCiAgICBhY3Rpb246IHJlY29uZmlndXJlZC1hdWRpdGQKICAgIG9iamVjdDoKICAgICAgd2hhdDogc2VydmljZQogICAgZWNzOgogICAgICA8PDogKmVjcy1wcm9jZXNzCiAgICAgIHR5cGU6IGNoYW5nZQogICMgQVVESVRfREFFTU9OX1JFU1VNRSAtIEF1ZGl0ZCBzaG91bGQgcmVzdW1lIGxvZ2dpbmcKICAtIHJlY29yZF90eXBlczogREFFTU9OX1JFU1VNRQogICAgYWN0aW9uOiByZXN1bWVkLWF1ZGl0LWxvZ2dpbmcKICAgIG9iamVjdDoKICAgICAgd2hhdDogc2VydmljZQogICAgZWNzOgogICAgICA8PDogKmVjcy1wcm9jZXNzCiAgICAgIHR5cGU6IGNoYW5nZQogICMgQVVESVRfREFFTU9OX1JPVEFURSAtIEF1ZGl0ZCBzaG91bGQgcm90YXRlIGxvZ3MKICAtIHJlY29yZF90eXBlczogREFFTU9OX1JPVEFURQogICAgYWN0aW9uOiByb3RhdGVkLWF1ZGl0LWxvZ3MKICAgIG9iamVjdDoKICAgICAgd2hhdDogc2VydmljZQogICAgZWNzOgogICAgICA8PDogKmVjcy1wcm9jZXNzCiAgICAgIHR5cGU6IGNoYW5nZQogICMgQVVESVRfREFFTU9OX1NUQVJUIC0gRGFlbW9uIHN0YXJ0dXAgcmVjb3JkCiAgLSByZWNvcmRfdHlwZXM6IERBRU1PTl9TVEFSVAogICAgYWN0aW9uOiBzdGFydGVkLWF1ZGl0CiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IHNlcnZpY2UKICAgIGVjczoKICAgICAgPDw6ICplY3MtcHJvY2VzcwogICAgICB0eXBlOiBzdGFydAogICMgQVVESVRfS0VSTkVMIC0gQXN5bmNocm9ub3VzIGF1ZGl0IHJlY29yZC4gTk9UIEEgUkVRVUVTVC4KICAtIHJlY29yZF90eXBlczogS0VSTkVMCiAgICBhY3Rpb246IGluaXRpYWxpemVkLWF1ZGl0LXN1YnN5c3RlbQogICAgZWNzOiAqZWNzLXByb2Nlc3MKCiAgIyBDb25maWd1cmF0aW9uIGNoYW5nZSBldmVudHMKCiAgIyBBVURJVF9VU1lTX0NPTkZJRyAtIFVzZXIgc3BhY2Ugc3lzdGVtIGNvbmZpZyBjaGFuZ2UKICAtIHJlY29yZF90eXBlczogVVNZU19DT05GSUcKICAgIGFjdGlvbjogY2hhbmdlZC1jb25maWd1cmF0aW9uCiAgICBvYmplY3Q6CiAgICAgIHByaW1hcnk6IG9wCiAgICAgIHdoYXQ6IHN5c3RlbQogICMgQVVESVRfTkVURklMVEVSX0NGRyAtIE5ldGZpbHRlciBjaGFpbiBtb2RpZmljYXRpb25zCiAgLSByZWNvcmRfdHlwZXM6IE5FVEZJTFRFUl9DRkcKICAgIGFjdGlvbjogbG9hZGVkLWZpcmV3YWxsLXJ1bGUtdG8KICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogdGFibGUKICAgICAgd2hhdDogZmlyZXdhbGwKICAjIEFVRElUX0ZFQVRVUkVfQ0hBTkdFIC0gYXVkaXQgbG9nIGxpc3RpbmcgZmVhdHVyZSBjaGFuZ2VzCiAgLSByZWNvcmRfdHlwZXM6IEZFQVRVUkVfQ0hBTkdFCiAgICBhY3Rpb246IGNoYW5nZWQtYXVkaXQtZmVhdHVyZQogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiBmZWF0dXJlCiAgICAgIHdoYXQ6IHN5c3RlbQogICMgQVVESVRfUkVQTEFDRSAtIFJlcGxhY2UgYXVkaXRkIGlmIHRoaXMgcGFja2V0IHVuYW5zd2VyZAoKICAjIFRUWSBldmVudHMKCiAgLSByZWNvcmRfdHlwZXM6CiAgICAgICMgQVVESVRfVFRZIC0gSW5wdXQgb24gYW4gYWRtaW5pc3RyYXRpdmUgVFRZCiAgICAgIC0gVFRZCiAgICAgICMgQVVESVRfVVNFUl9UVFkgLSBOb24tSUNBTk9OIFRUWSBpbnB1dCBtZWFuaW5nCiAgICAgIC0gVVNFUl9UVFkKICAgIGFjdGlvbjogdHlwZWQKICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogZGF0YQogICAgICB3aGF0OiBrZXlzdHJva2VzCiAgICBob3c6IFtjb21tLCBleGVdCgogICMgUG9saWN5IGV2ZW50cwoKICAjIEFVRElUX0FWQyAtIFNFIExpbnV4IGF2YyBkZW5pYWwgb3IgZ3JhbnQgKHNlbGludXgpCiAgLSByZWNvcmRfdHlwZXM6IEFWQwogICAgYWN0aW9uOiB2aW9sYXRlZC1zZWxpbnV4LXBvbGljeQogICAgc3ViamVjdDoKICAgICAgcHJpbWFyeTogc2NvbnRleHQKICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogdGNvbnRleHQKICAgICAgc2Vjb25kYXJ5OiB0Y2xhc3MKICAgIGhhc19maWVsZHM6CiAgICAgIC0gc2VyZXN1bHQKICAjIEFVRElUX0FWQyAtIFNFIExpbnV4IGF2YyBkZW5pYWwgb3IgZ3JhbnQgKGFwcGFybW9yKQogIC0gcmVjb3JkX3R5cGVzOiBBVkMKICAgIGFjdGlvbjogdmlvbGF0ZWQtYXBwYXJtb3ItcG9saWN5CiAgICBvYmplY3Q6CiAgICAgIHByaW1hcnk6IG9wZXJhdGlvbgogICAgICBzZWNvbmRhcnk6IFtyZXF1ZXN0ZWRfbWFzaywgZGVuaWVkX21hc2ssIGNhcG5hbWVdCiAgICAgIHdoYXQ6IHBvbGljeQogICAgaGFzX2ZpZWxkczoKICAgICAgLSBhcHBhcm1vcgogICMgQVVESVRfRlNfUkVMQUJFTCAtIEZpbGVzeXN0ZW0gcmVsYWJlbGVkCiAgLSByZWNvcmRfdHlwZXM6IEZTX1JFTEFCRUwKICAgIGFjdGlvbjogcmVsYWJlbGVkLWZpbGVzeXN0ZW0KICAgIG9iamVjdDoKICAgICAgd2hhdDogbWFjLWNvbmZpZwogICMgQVVESVRfTEFCRUxfTEVWRUxfQ0hBTkdFIC0gT2JqZWN0J3MgbGV2ZWwgd2FzIGNoYW5nZWQKICAtIHJlY29yZF90eXBlczogTEFCRUxfTEVWRUxfQ0hBTkdFCiAgICBhY3Rpb246IG1vZGlmaWVkLWxldmVsLW9mCiAgICBvYmplY3Q6CiAgICAgIHByaW1hcnk6IHByaW50ZXIKICAgICAgd2hhdDogcHJpbnRlcgogICMgQVVESVRfTEFCRUxfT1ZFUlJJREUgLSBBZG1pbiBpcyBvdmVycmlkaW5nIGEgbGFiZWwKICAtIHJlY29yZF90eXBlczogTEFCRUxfT1ZFUlJJREUKICAgIGFjdGlvbjogb3ZlcnJvZGUtbGFiZWwtb2YKICAgIG9iamVjdDoKICAgICAgd2hhdDogbWFjLWNvbmZpZwogICMgQVVESVRfTUFDX0NIRUNLIC0gVXNlciBzcGFjZSBNQUMgZGVjaXNpb24gcmVzdWx0cwogIC0gcmVjb3JkX3R5cGVzOiBNQUNfQ0hFQ0sKICAgIGFjdGlvbjogbWFjLXBlcm1pc3Npb24KICAjIEFVRElUX01BQ19DT05GSUdfQ0hBTkdFIC0gQ2hhbmdlcyB0byBib29sZWFucwogIC0gcmVjb3JkX3R5cGVzOiBNQUNfQ09ORklHX0NIQU5HRQogICAgYWN0aW9uOiBjaGFuZ2VkLXNlbGludXgtYm9vbGVhbgogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiBib29sCiAgICAgIHdoYXQ6IG1hYy1jb25maWcKICAjIEFVRElUX01BQ19QT0xJQ1lfTE9BRCAtIFBvbGljeSBmaWxlIGxvYWQKICAtIHJlY29yZF90eXBlczogTUFDX1BPTElDWV9MT0FECiAgICBhY3Rpb246IGxvYWRlZC1zZWxpbnV4LXBvbGljeQogICAgb2JqZWN0OgogICAgICB3aGF0OiBtYWMtY29uZmlnCiAgIyBBVURJVF9NQUNfU1RBVFVTIC0gQ2hhbmdlZCBlbmZvcmNpbmcscGVybWlzc2l2ZSxvZmYKICAtIHJlY29yZF90eXBlczogTUFDX1NUQVRVUwogICAgYWN0aW9uOiBjaGFuZ2VkLXNlbGludXgtZW5mb3JjZW1lbnQKICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogZW5mb3JjaW5nCiAgICAgIHdoYXQ6IG1hYy1jb25maWcKICAjIEFVRElUX1VTRVJfQVZDIC0gVXNlciBzcGFjZSBhdmMgbWVzc2FnZQogIC0gcmVjb3JkX3R5cGVzOiBVU0VSX0FWQwogICAgYWN0aW9uOiBhY2Nlc3MtcGVybWlzc2lvbgogICMgQVVESVRfVVNFUl9NQUNfQ09ORklHX0NIQU5HRSAtIENoYW5nZSBtYWRlIHRvIE1BQyBwb2xpY3kKICAtIHJlY29yZF90eXBlczogVVNFUl9NQUNfQ09ORklHX0NIQU5HRQogICAgYWN0aW9uOiBjaGFuZ2VkLW1hYy1jb25maWd1cmF0aW9uCiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IG1hYy1jb25maWcKICAjIEFVRElUX1VTRVJfTUFDX1BPTElDWV9MT0FEIC0gVXNlcnNwYyBkYWVtb24gbG9hZGVkIHBvbGljCiAgLSByZWNvcmRfdHlwZXM6IFVTRVJfTUFDX1BPTElDWV9MT0FECiAgICBhY3Rpb246IGxvYWRlZC1tYWMtcG9saWN5CiAgICBvYmplY3Q6CiAgICAgIHdoYXQ6IG1hYy1jb25maWcKICAjIEFVRElUX1VTRVJfU0VMSU5VWF9FUlIgLSBTRSBMaW51eCB1c2VyIHNwYWNlIGVycm9yCiAgLSByZWNvcmRfdHlwZXM6IFVTRVJfU0VMSU5VWF9FUlIKICAgIGFjdGlvbjogYWNjZXNzLWVycm9yCiAgIyBBVURJVF9TRUNDT01QIC0gU2VjdXJlIENvbXB1dGluZyBldmVudAogIC0gcmVjb3JkX3R5cGVzOiBTRUNDT01QCiAgICBhY3Rpb246IHZpb2xhdGVkLXNlY2NvbXAtcG9saWN5CiAgICBvYmplY3Q6CiAgICAgIHByaW1hcnk6IHN5c2NhbGwKICAgICAgd2hhdDogcHJvY2VzcwogICMgQVVESVRfU0VMSU5VWF9FUlIgLSBJbnRlcm5hbCBTRSBMaW51eCBFcnJvcnMKICAtIGFjdGlvbjogY2F1c2VkLW1hYy1wb2xpY3ktZXJyb3IKICAgIG9iamVjdDoKICAgICAgd2hhdDogc3lzdGVtCiAgICByZWNvcmRfdHlwZXM6IFNFTElOVVhfRVJSCiAgIyBBVURJVF9BUFBBUk1PUl9BTExPV0VECiAgIyBBVURJVF9BUFBBUk1PUl9ERU5JRUQKICAjIEFVRElUX0FQUEFSTU9SX0VSUk9SCiAgIyBBVURJVF9BVkNfUEFUSCAtIGRlbnRyeSwgdmZzbW91bnQgcGFpciBmcm9tIGF2YwogICMgQVVESVRfQVBQQVJNT1JfQVVESVQKICAjIEFVRElUX0FQUEFSTU9SX0hJTlQKICAjIEFVRElUX0FQUEFSTU9SX1NUQVRVUwogICMgQVVESVRfQVBQQVJNT1JfRVJST1IKICAjIEFVRElUX0RFVl9BTExPQyAtIERldmljZSB3YXMgYWxsb2NhdGVkCiAgIyBBVURJVF9ERVZfREVBTExPQyAtIERldmljZSB3YXMgZGVhbGxvY2F0ZWQKICAjIEFVRElUX01BQ19VTkxCTF9BTExPVyAtIE5ldExhYmVsOiBhbGxvdyB1bmxhYmVsZWQgdHJhZmZpYwogICMgQVVESVRfTUFDX0NJUFNPVjRfQUREIC0gTmV0TGFiZWw6IGFkZCBDSVBTT3Y0IERPSSBlbnRyeQogICMgQVVESVRfTUFDX0NJUFNPVjRfREVMIC0gTmV0TGFiZWw6IGRlbCBDSVBTT3Y0IERPSSBlbnRyeQogICMgQVVESVRfTUFDX01BUF9BREQgLSBOZXRMYWJlbDogYWRkIExTTSBkb21haW4gbWFwcGluZwogICMgQVVESVRfTUFDX01BUF9ERUwgLSBOZXRMYWJlbDogZGVsIExTTSBkb21haW4gbWFwcGluZwogICMgQVVESVRfTUFDX0lQU0VDX0VWRU5UIC0gQXVkaXQgYW4gSVBTZWMgZXZlbnQKICAjIEFVRElUX01BQ19VTkxCTF9TVENBREQgLSBOZXRMYWJlbDogYWRkIGEgc3RhdGljIGxhYmVsCiAgIyBBVURJVF9NQUNfVU5MQkxfU1RDREVMIC0gTmV0TGFiZWw6IGRlbCBhIHN0YXRpYyBsYWJlbAogICMgQVVESVRfTUFDX0NBTElQU09fQUREIC0gTmV0TGFiZWw6IGFkZCBDQUxJUFNPIERPSSBlbnRyeQogICMgQVVESVRfTUFDX0NBTElQU09fREVMIC0gTmV0TGFiZWw6IGRlbCBDQUxJUFNPIERPSSBlbnRyeQogICMgQVVESVRfVVNFUl9MQUJFTEVEX0VYUE9SVCAtIE9iamVjdCBleHBvcnRlZCB3aXRoIGxhYmVsCiAgIyBBVURJVF9VU0VSX1VOTEFCRUxFRF9FWFBPUlQgLSBPYmplY3QgZXhwb3J0ZWQgd2l0aG91dCBsYWJlbAoKICAjIENyeXB0byBldmVudHMKCiAgLSA8PDogKm1hY3JvLXVzZXItc2Vzc2lvbgogICAgYWN0aW9uOiBuZWdvdGlhdGVkLWNyeXB0by1rZXkKICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogZnAKICAgICAgc2Vjb25kYXJ5OiBbYWRkciwgaG9zdG5hbWVdCiAgICAgIHdoYXQ6IHVzZXItc2Vzc2lvbgogICAgcmVjb3JkX3R5cGVzOiBDUllQVE9fS0VZX1VTRVIKICAgIHNvdXJjZV9pcDogW2FkZHJdCiAgICBlY3M6ICplY3MtcHJvY2VzcwogIC0gYWN0aW9uOiBjcnlwdG8tb2ZmaWNlci1sb2dnZWQtaW4KICAgIHJlY29yZF90eXBlczogQ1JZUFRPX0xPR0lOCiAgLSBhY3Rpb246IGNyeXB0by1vZmZpY2VyLWxvZ2dlZC1vdXQKICAgIHJlY29yZF90eXBlczogQ1JZUFRPX0xPR09VVAogICAgZWNzOiAqZWNzLXByb2Nlc3MKICAtIDw8OiAqbWFjcm8tdXNlci1zZXNzaW9uCiAgICBhY3Rpb246IHN0YXJ0ZWQtY3J5cHRvLXNlc3Npb24KICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogYWRkcgogICAgICBzZWNvbmRhcnk6IFtycG9ydF0KICAgIHJlY29yZF90eXBlczogQ1JZUFRPX1NFU1NJT04KICAgIHNvdXJjZV9pcDogW2FkZHJdCiAgICBlY3M6ICplY3MtcHJvY2VzcwogIC0gYWN0aW9uOiBhY2Nlc3MtcmVzdWx0CiAgICByZWNvcmRfdHlwZXM6IERBQ19DSEVDSwoKICAjIEFub21hbGllcwoKICAjIEFVRElUX0FOT01fQUJFTkQgLSBQcm9jZXNzIGVuZGVkIGFibm9ybWFsbHkKICAtIHJlY29yZF90eXBlczogQU5PTV9BQkVORAogICAgYWN0aW9uOiBjcmFzaGVkLXByb2dyYW0KICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogW2NvbW0sIGV4ZV0KICAgICAgc2Vjb25kYXJ5OiBwaWQKICAgICAgd2hhdDogcHJvY2VzcwogICAgaG93OiBzaWcKICAgIGVjczoKICAgICAgIyBjb25zaWRlciBhZGRpbmcgYW4gYW5vbWFseSBjYXRlZ29yeSB3aGVuIHdlIGludHJvZHVjZQogICAgICAjIHRvIEVDUwogICAgICA8PDogKmVjcy1wcm9jZXNzCiAgICAgIHR5cGU6IGVuZAogICMgQVVESVRfQU5PTV9FWEVDIC0gRXhlY3V0aW9uIG9mIGZpbGUKICAtIHJlY29yZF90eXBlczogQU5PTV9FWEVDCiAgICBhY3Rpb246IGF0dGVtcHRlZC1leGVjdXRpb24tb2YtZm9yYmlkZGVuLXByb2dyYW0KICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogY21kCiAgICAgIHdoYXQ6IHByb2Nlc3MKICAgIGhvdzogdGVybWluYWwKICAgIGVjczoKICAgICAgIyBjb25zaWRlciBhZGRpbmcgYW4gYW5vbWFseSBjYXRlZ29yeSB3aGVuIHdlIGludHJvZHVjZQogICAgICAjIHRvIEVDUwogICAgICA8PDogKmVjcy1wcm9jZXNzCiAgICAgIHR5cGU6IHN0YXJ0CiAgIyBBVURJVF9BTk9NX0xJTksgLSBTdXNwaWNpb3VzIHVzZSBvZiBmaWxlIGxpbmtzCiAgLSByZWNvcmRfdHlwZXM6IEFOT01fTElOSwogICAgYWN0aW9uOiB1c2VkLXN1c3BjaW91cy1saW5rCiAgIyBBVURJVF9BTk9NX0xPR0lOX0ZBSUxVUkVTIC0gRmFpbGVkIGxvZ2luIGxpbWl0IHJlYWNoZWQKICAtIDw8OiAqbWFjcm8tdXNlci1zZXNzaW9uCiAgICByZWNvcmRfdHlwZXM6IEFOT01fTE9HSU5fRkFJTFVSRVMKICAgIGFjdGlvbjogZmFpbGVkLWxvZy1pbi10b28tbWFueS10aW1lcy10bwogICMgQVVESVRfQU5PTV9MT0dJTl9MT0NBVElPTiAtIExvZ2luIGZyb20gZm9yYmlkZGVuIGxvY2F0aW9uCiAgLSA8PDogKm1hY3JvLXVzZXItc2Vzc2lvbgogICAgcmVjb3JkX3R5cGVzOiBBTk9NX0xPR0lOX0xPQ0FUSU9OCiAgICBhY3Rpb246IGF0dGVtcHRlZC1sb2ctaW4tZnJvbS11bnVzdWFsLXBsYWNlLXRvCiAgIyBBVURJVF9BTk9NX0xPR0lOX1NFU1NJT05TIC0gTWF4IGNvbmN1cnJlbnQgc2Vzc2lvbnMgcmVhY2hlZAogIC0gPDw6ICptYWNyby11c2VyLXNlc3Npb24KICAgIHJlY29yZF90eXBlczogQU5PTV9MT0dJTl9TRVNTSU9OUwogICAgYWN0aW9uOiBvcGVuZWQtdG9vLW1hbnktc2Vzc2lvbnMtdG8KICAjIEFVRElUX0FOT01fTE9HSU5fVElNRSAtIExvZ2luIGF0dGVtcHRlZCBhdCBiYWQgdGltZQogIC0gPDw6ICptYWNyby11c2VyLXNlc3Npb24KICAgIHJlY29yZF90eXBlczogQU5PTV9MT0dJTl9USU1FCiAgICBhY3Rpb246IGF0dGVtcHRlZC1sb2ctaW4tZHVyaW5nLXVudXN1YWwtaG91ci10bwogICMgQVVESVRfQU5PTV9QUk9NSVNDVU9VUyAtIERldmljZSBjaGFuZ2VkIHByb21pc2N1b3VzIG1vZGUKICAtIHJlY29yZF90eXBlczogQU5PTV9QUk9NSVNDVU9VUwogICAgYWN0aW9uOiBjaGFuZ2VkLXByb21pc2N1b3VzLW1vZGUtb24tZGV2aWNlICMgQ291bGQgYmUgZW50ZXJlZCBvciBleGl0ZWQgYmFzZWQgb24gcHJvbSBmaWVsZC4KICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogZGV2CiAgICAgIHdoYXQ6IG5ldHdvcmstZGV2aWNlCiAgIyBBVURJVF9BTk9NX1JCQUNfSU5URUdSSVRZX0ZBSUwgLSBSQkFDIGZpbGUgaW50ZWdyaXR5IGZhaWx1cmUKICAtIHJlY29yZF90eXBlczogQU5PTV9SQkFDX0lOVEVHUklUWV9GQUlMCiAgICBhY3Rpb246IHRlc3RlZC1maWxlLXN5c3RlbS1pbnRlZ3JpdHktb2YKICAgIG9iamVjdDoKICAgICAgcHJpbWFyeTogaG9zdG5hbWUKICAgICAgd2hhdDogZmlsZXN5c3RlbQogICMgQVVESVRfQU5PTV9MT0dJTl9BQ0NUIC0gTG9naW4gYXR0ZW1wdGVkIHRvIHdhdGNoZWQgYWNjdAogICMgQVVESVRfQU5PTV9NQVhfREFDIC0gTWF4IERBQyBmYWlsdXJlcyByZWFjaGVkCiAgIyBBVURJVF9BTk9NX01BWF9NQUMgLSBNYXggTUFDIGZhaWx1cmVzIHJlYWNoZWQKICAjIEFVRElUX0FOT01fQU1UVV9GQUlMIC0gQU1UVSBmYWlsdXJlCiAgIyBBVURJVF9BTk9NX1JCQUNfRkFJTCAtIFJCQUMgc2VsZiB0ZXN0IGZhaWx1cmUKICAjIEFVRElUX0FOT01fQ1JZUFRPX0ZBSUwgLSBDcnlwdG8gc3lzdGVtIHRlc3QgZmFpbHVyZQogICMgQVVESVRfQU5PTV9NS19FWEUgLSBNYWtlIGFuIGV4ZWN1dGFibGUKICAjIEFVRElUX0FOT01fQUNDRVNTX0ZTIC0gQWNjZXNzIG9mIGZpbGUgb3IgZGlyCiAgIyBBVURJVF9BTk9NX0FERF9BQ0NUIC0gQWRkaW5nIGFuIGFjY3QKICAjIEFVRElUX0FOT01fREVMX0FDQ1QgLSBEZWxldGluZyBhbiBhY2N0CiAgIyBBVURJVF9BTk9NX01PRF9BQ0NUIC0gQ2hhbmdpbmcgYW4gYWNjdAogICMgQVVESVRfQU5PTV9ST09UX1RSQU5TIC0gVXNlciBiZWNhbWUgcm9vdAogICMgQVVESVRfQU5PTV9MT0dJTl9TRVJWSUNFIC0gU2VydmljZSBhY2N0IGF0dGVtcHRlZCBsb2dpbgoKICAjIEFub21hbHkgcmVzcG9uc2VzCgogICMgQVVESVRfUkVTUF9BTk9NQUxZIC0gQW5vbWFseSBub3QgcmVhY3RlZCB0bwogICMgQVVESVRfUkVTUF9BTEVSVCAtIEFsZXJ0IGVtYWlsIHdhcyBzZW50CiAgIyBBVURJVF9SRVNQX0tJTExfUFJPQyAtIEtpbGwgcHJvZ3JhbQogICMgQVVESVRfUkVTUF9URVJNX0FDQ0VTUyAtIFRlcm1pbmF0ZSBzZXNzaW9uCiAgIyBBVURJVF9SRVNQX0FDQ1RfUkVNT1RFIC0gQWNjdCBsb2NrZWQgZnJvbSByZW1vdGUgYWNjZXNzCiAgIyBBVURJVF9SRVNQX0FDQ1RfTE9DS19USU1FRCAtIFVzZXIgYWNjdCBsb2NrZWQgZm9yIHRpbWUKICAjIEFVRElUX1JFU1BfQUNDVF9VTkxPQ0tfVElNRUQgLSBVc2VyIGFjY3QgdW5sb2NrZWQgZnJvbSB0aW1lCiAgIyBBVURJVF9SRVNQX0FDQ1RfTE9DSyAtIFVzZXIgYWNjdCB3YXMgbG9ja2VkCiAgIyBBVURJVF9SRVNQX1RFUk1fTE9DSyAtIFRlcm1pbmFsIHdhcyBsb2NrZWQKICAjIEFVRElUX1JFU1BfU0VCT09MIC0gU2V0IGFuIFNFIExpbnV4IGJvb2xlYW4KICAjIEFVRElUX1JFU1BfRVhFQyAtIEV4ZWN1dGUgYSBzY3JpcHQKICAjIEFVRElUX1JFU1BfU0lOR0xFIC0gR28gdG8gc2luZ2xlIHVzZXIgbW9kZQogICMgQVVESVRfUkVTUF9IQUxUIC0gdGFrZSB0aGUgc3lzdGVtIGRvd24KICAjIEFVRElUX1JFU1BfT1JJR0lOX0JMT0NLIC0gQWRkcmVzcyBibG9ja2VkIGJ5IGlwdGFibGVzCiAgIyBBVURJVF9SRVNQX09SSUdJTl9CTE9DS19USU1FRCAtIEFkZHJlc3MgYmxvY2tlZCBmb3IgdGltZQoKICAjIEF1ZGl0IHJ1bGUgZXZlbnRzCgogICMgQVVESVRfU1lTQ0FMTCAtIFN5c2NhbGwgZXZlbnQKICAjIEFVRElUX1BBVEggLSBGaWxlbmFtZSBwYXRoIGluZm9ybWF0aW9uCiAgIyBBVURJVF9JUEMgLSBJUEMgcmVjb3JkCiAgIyBBVURJVF9TT0NLRVRDQUxMIC0gc3lzX3NvY2tldGNhbGwgYXJndW1lbnRzCiAgIyBBVURJVF9TT0NLQUREUiAtIHNvY2thZGRyIGNvcGllZCBhcyBzeXNjYWxsIGFyZwogICMgQVVESVRfQ1dEIC0gQ3VycmVudCB3b3JraW5nIGRpcmVjdG9yeQogICMgQVVESVRfRVhFQ1ZFIC0gZXhlY3ZlIGFyZ3VtZW50cwogICMgQVVESVRfSVBDX1NFVF9QRVJNIC0gSVBDIG5ldyBwZXJtaXNzaW9ucyByZWNvcmQgdHlwZQogICMgQVVESVRfTVFfT1BFTiAtIFBPU0lYIE1RIG9wZW4gcmVjb3JkIHR5cGUKICAjIEFVRElUX01RX1NFTkRSRUNWLSBQT1NJWCBNUSBzZW5kL3JlY2VpdmUgcmVjb3JkIHR5cGUKICAjIEFVRElUX01RX05PVElGWSAtIFBPU0lYIE1RIG5vdGlmeSByZWNvcmQgdHlwZQogICMgQVVESVRfTVFfR0VUU0VUQVRUUiAtIFBPU0lYIE1RIGdldC9zZXQgYXR0cmlidXRlIHJlY29yZCB0eXBlCiAgIyBBVURJVF9GRF9QQUlSIC0gYXVkaXQgcmVjb3JkIGZvciBwaXBlL3NvY2tldHBhaXIKICAjIEFVRElUX09CSl9QSUQgLSBwdHJhY2UgdGFyZ2V0CiAgIyBBVURJVF9CUFJNX0ZDQVBTIC0gSW5mb3JtYXRpb24gYWJvdXQgZmNhcHMgaW5jcmVhc2luZyBwZXJtcwogICMgQVVESVRfQ0FQU0VUIC0gUmVjb3JkIHNob3dpbmcgYXJndW1lbnQgdG8gc3lzX2NhcHNldAogICMgQVVESVRfTU1BUCAtIFJlY29yZCBzaG93aW5nIGRlc2NyaXB0b3IgYW5kIGZsYWdzIGluIG1tYXAKICAjIEFVRElUX05FVEZJTFRFUl9QS1QgLSBQYWNrZXRzIHRyYXZlcnNpbmcgbmV0ZmlsdGVyIGNoYWlucwoKICAjIEludGVncml0eSBjaGVja3MKCiAgIyBBVURJVF9JTlRFR1JJVFlfREFUQSAtIERhdGEgaW50ZWdyaXR5IHZlcmlmaWNhdGlvbgogICMgQVVESVRfSU5URUdSSVRZX01FVEFEQVRBIC0gTWV0YWRhdGEgaW50ZWdyaXR5IHZlcmlmaWNhdGlvbgogICMgQVVESVRfSU5URUdSSVRZX1NUQVRVUyAtIEludGVncml0eSBlbmFibGUgc3RhdHVzCiAgIyBBVURJVF9JTlRFR1JJVFlfSEFTSCAtIEludGVncml0eSBIQVNIIHR5cGUKICAjIEFVRElUX0lOVEVHUklUWV9QQ1IgLSBQQ1IgaW52YWxpZGF0aW9uIG1zZ3MKICAjIEFVRElUX0lOVEVHUklUWV9SVUxFIC0gUG9saWN5IHJ1bGUKCiAgIyBWYXJpb3VzCgogICMgQVVESVRfVVNFUiAtIE1lc3NhZ2UgZnJvbSB1c2Vyc3BhY2UgLS0gZGVwcmVjYXRlZAogIC0gcmVjb3JkX3R5cGVzOiBVU0VSCiAgICBhY3Rpb246IHNlbnQtbWVzc2FnZQogICAgb2JqZWN0OgogICAgICBwcmltYXJ5OiBhZGRyCg==")
		assets["normalizationData"] = value
	}

	if value, found := assets[key]; found {
		return value, nil
	}
	return nil, fmt.Errorf("asset not found for key=%v", key)
}
