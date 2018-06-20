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

// +build linux,amd64

package rule_test

import (
	"bufio"
	"bytes"
	"flag"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/elastic/go-libaudit"
)

var update = flag.Bool("update", false, "update .golden.yml files")

// TestUpdateGoldenData generates new X.rules.golden.yml files the given
// X.rules files. The .rules files contain rules that are installed to the
// kernel using auditctl (auditd package must be installed). Then the binary
// representation of the rule from the kernel is requested and stored. Each
// rules and blob is stored in the YAML file as a test case.
//
// The kernel version and auditctl version used to generate the golden data
// are stored as comments in the YAML file header.
func TestUpdateGoldenData(t *testing.T) {
	if !*update {
		t.SkipNow()
	}

	rulesFiles, err := filepath.Glob("testdata/*.rules")
	if err != nil {
		t.Fatal(err)
	}

	for _, rulesFile := range rulesFiles {
		makeGoldenFile(t, rulesFile)
	}
}

func makeGoldenFile(t testing.TB, rulesFile string) {
	rules, err := ioutil.ReadFile(rulesFile)
	if err != nil {
		t.Fatal(err)
	}

	var testData GoldenData
	s := bufio.NewScanner(bytes.NewReader(rules))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		rule, ruleData := auditctlExec(t, line)

		testData.Rules = append(testData.Rules, TestCase{
			Flags: rule,
			Bytes: string(ruleData),
		})
	}

	yamlData, err := yaml.Marshal(testData)
	if err != nil {
		t.Fatal(err)
	}

	outFile, err := os.Create(rulesFile + ".golden.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()

	versionInfo := uname(t)
	outFile.WriteString("# ")
	outFile.WriteString(versionInfo)

	versionInfo = auditctlVersion(t)
	outFile.WriteString("# ")
	outFile.WriteString(versionInfo)
	outFile.WriteString("")

	outFile.Write(yamlData)
}

func uname(t testing.TB) string {
	output, err := exec.Command("uname", "-a").Output()
	if err != nil {
		t.Fatal(err)
	}

	return string(output)
}

func auditctlVersion(t testing.TB) string {
	output, err := exec.Command("auditctl", "-v").Output()
	if err != nil {
		t.Fatal(err)
	}

	return string(output)
}

func auditctlExec(t testing.TB, command string) (string, []byte) {
	if err := os.MkdirAll(tempDir, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	client, err := libaudit.NewAuditClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.DeleteRules()

	// Replace paths with ones in a temp dir for test environment consistency.
	command = makePaths(t, tempDir, command)

	args := strings.Fields(command)
	_, err = exec.Command("auditctl", args...).Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			t.Fatalf("command=auditctl %v, stderr=%v, err=%v", command, string(exitError.Stderr), err)
		}
		t.Fatal(err)
	}

	rules, err := client.GetRules()
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule but got %d", len(rules))
	}

	return command, rules[0]
}

// makePaths extracts any paths from the command, creates the path as either
// a regular file or directory, then updates the paths to point to the one
// created for the test. It returns the updated command that contains the test
// paths.
func makePaths(t testing.TB, tmpDir string, rule string) string {
	var re = regexp.MustCompile(`(-w |dir=|path=)/(\S+)`)
	matches := re.FindAllStringSubmatch(rule, -1)
	for _, match := range matches {
		path := match[2]
		realPath := filepath.Join(tmpDir, path)

		if strings.HasSuffix(path, "/") {
			// Treat paths with trailing slashes as a directory to monitor.
			if err := os.MkdirAll(realPath, 0700); err != nil {
				t.Fatal(err)
			}
		} else {
			// Touch a file.
			dir := filepath.Dir(realPath)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := ioutil.WriteFile(realPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}

	var substitution = "$1" + filepath.Join(tmpDir, "$2")
	return re.ReplaceAllString(rule, substitution)
}
