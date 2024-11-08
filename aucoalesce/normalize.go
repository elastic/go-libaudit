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
	"bytes"
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	//go:embed normalizations.yaml
	normalizationDataYAML []byte

	syscallNorms    map[string]*Normalization
	recordTypeNorms map[string][]*Normalization
)

func init() {
	var err error
	syscallNorms, recordTypeNorms, err = LoadNormalizationConfig(normalizationDataYAML)
	if err != nil {
		panic(fmt.Errorf("failed to parse built in normalization mappings: %w", err))
	}
}

// Strings is a custom type to enable YAML values that can be either a string
// or a list of strings.
type Strings struct {
	Values []string
}

var _ yaml.Unmarshaler = (*Strings)(nil)

func (s *Strings) UnmarshalYAML(n *yaml.Node) error {
	var singleValue string
	if err := n.Decode(&singleValue); err == nil {
		s.Values = []string{singleValue}
		return nil
	}

	return n.Decode(&s.Values)
}

type NormalizationConfig struct {
	Macros         []any           `yaml:"macros"`
	Normalizations []Normalization `yaml:"normalizations"`
}

type Normalization struct {
	SubjectPrimaryFieldName   Strings    `yaml:"subject_primary"`
	SubjectSecondaryFieldName Strings    `yaml:"subject_secondary"`
	Action                    string     `yaml:"action"`
	ObjectPrimaryFieldName    Strings    `yaml:"object_primary"`
	ObjectSecondaryFieldName  Strings    `yaml:"object_secondary"`
	ObjectWhat                string     `yaml:"object_what"`
	ObjectPathIndex           int        `yaml:"object_path_index"`
	How                       Strings    `yaml:"how"`
	RecordTypes               Strings    `yaml:"record_types"`
	Syscalls                  Strings    `yaml:"syscalls"`
	SourceIP                  Strings    `yaml:"source_ip"`
	HasFields                 Strings    `yaml:"has_fields"` // Apply the normalization if all fields are present.
	ECS                       ECSMapping `yaml:"ecs"`
	Description               string     `yaml:"description,omitempty"`
}

type ECSFieldMapping struct {
	From readReference  `yaml:"from" json:"from"`
	To   writeReference `yaml:"to" json:"to"`
}

type ECSMapping struct {
	Kind     string            `yaml:"kind"`
	Category Strings           `yaml:"category"`
	Type     Strings           `yaml:"type"`
	Mappings []ECSFieldMapping `yaml:"mappings"`
}

type (
	readReference  func(*Event) string
	writeReference func(*Event, string)
)

var (
	_ yaml.Unmarshaler = (*readReference)(nil)
	_ yaml.Unmarshaler = (*writeReference)(nil)
)

var (
	fromFieldReferences = map[string]readReference{
		"subject.primary": func(event *Event) string {
			return event.Summary.Actor.Primary
		},
		"subject.secondary": func(event *Event) string {
			return event.Summary.Actor.Secondary
		},
		"object.primary": func(event *Event) string {
			return event.Summary.Object.Primary
		},
		"object.secondary": func(event *Event) string {
			return event.Summary.Object.Secondary
		},
	}

	fromDictReferences = map[string]func(key string) readReference{
		"data": func(key string) readReference {
			return func(event *Event) string {
				return event.Data[key]
			}
		},
		"uid": func(key string) readReference {
			return func(event *Event) string {
				return event.User.IDs[key]
			}
		},
	}

	toFieldReferences = map[string]writeReference{
		"user": func(event *Event, s string) {
			event.ECS.User.set(s)
		},
		"user.effective": func(event *Event, s string) {
			event.ECS.User.Effective.set(s)
		},
		"user.target": func(event *Event, s string) {
			event.ECS.User.Target.set(s)
		},
		"user.changes": func(event *Event, s string) {
			event.ECS.User.Changes.set(s)
		},
		"group": func(event *Event, s string) {
			event.ECS.Group.set(s)
		},
	}
)

func resolveFieldReference(fieldRef string) (ref readReference) {
	if ref = fromFieldReferences[fieldRef]; ref != nil {
		return ref
	}
	if dot := strings.IndexByte(fieldRef, '.'); dot != -1 {
		dict := fieldRef[:dot]
		key := fieldRef[dot+1:]
		if accessor := fromDictReferences[dict]; accessor != nil {
			return accessor(key)
		}
	}
	return nil
}

func (ref *readReference) UnmarshalYAML(n *yaml.Node) error {
	var fieldRef string
	if err := n.Decode(&fieldRef); err != nil {
		return err
	}
	if *ref = resolveFieldReference(fieldRef); *ref == nil {
		return fmt.Errorf("field '%s' is not a valid from-reference for ECS mapping", fieldRef)
	}
	return nil
}

func (ref *writeReference) UnmarshalYAML(n *yaml.Node) error {
	var fieldRef string
	if err := n.Decode(&fieldRef); err != nil {
		return err
	}
	if *ref = toFieldReferences[fieldRef]; *ref == nil {
		return fmt.Errorf("field '%s' is not a valid to-reference for ECS mapping", fieldRef)
	}
	return nil
}

func LoadNormalizationConfig(b []byte) (syscalls map[string]*Normalization, recordTypes map[string][]*Normalization, err error) {
	c := &NormalizationConfig{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, nil, err
	}

	syscalls = map[string]*Normalization{}
	recordTypes = map[string][]*Normalization{}

	for i := range c.Normalizations {
		norm := c.Normalizations[i]
		for _, syscall := range norm.Syscalls.Values {
			if _, found := syscalls[syscall]; found {
				return nil, nil, fmt.Errorf("duplication mappings for syscall %v", syscall)
			}
			syscalls[syscall] = &norm
		}
		for _, recordType := range norm.RecordTypes.Values {
			norms, found := recordTypes[recordType]
			if found {
				for _, n := range norms {
					if len(n.HasFields.Values) == 0 {
						return nil, nil, fmt.Errorf("duplication mappings for record_type %v without has_fields qualifier", recordType)
					}
				}
			}
			recordTypes[recordType] = append(norms, &norm)
		}
	}

	return syscalls, recordTypes, nil
}
