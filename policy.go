package brewOPA

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

type AccessPolicy struct {
	SensitiveAttributes []string       `json:"sensitiveAttrs" yaml:"sensitiveAttrs"`
	Locations           []DataLocation `json:"locations" yaml:"locations"`
	Rules               []Rule         `json:"rules" yaml:"rules"`
	DefaultRule         Rule           `json:"defaultRule" yaml:"defaultRule"`
}

type DataLocation struct {
	Repo   string `json:"repo" yaml:"repo"`
	Schema string `json:"schema" yaml:"schema"`
	Table  string `json:"table" yaml:"table"`
}

type Rule struct {
	Identities []string      `json:"identities" yaml:"identities"`
	Reads      ContextedRule `json:"reads" yaml:"reads"`
	Updates    ContextedRule `json:"updates" yaml:"updates"`
	Deletes    ContextedRule `json:"deletes" yaml:"deletes"`
}

type ContextedRule struct {
	Allow      bool     `json:"allow" yaml:"allow"`
	Rows       int64    `json:"rows" yaml:"rows"`
	Attributes []string `json:"attributes" yaml:"attributes"`
}

func AccessPolicyFromYAML(policyYAML []byte) (AccessPolicy, error) {
	var a AccessPolicy
	if err := yaml.Unmarshal(policyYAML, &a); err != nil {
		msg := fmt.Errorf("failed to decode policy: %v", err)
		return a, msg
	}
	return a, nil
}
