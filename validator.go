package brewOPA

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

type Validator struct {
	regoModule    []byte
	policies      map[string]interface{}
	preparedQuery rego.PreparedEvalQuery
}

// NewValidatorFromRego returns a Validator initalized with the rego
// policy at the given file path as well as stored policy data.
// TODO: This should return an interface rather than a pointer to a struct.
//       Have it return QueryLogEvaluator for the moment...
func NewValidatorFromRego(regoModulePath string) (*Validator, error) {
	regoPolicy, err := ioutil.ReadFile(regoModulePath)
	if err != nil {
		msg := fmt.Errorf("failed to read rego file at '%s': %v",
			regoModulePath, err)
		return nil, msg
	}

	return NewValidator(regoPolicy)
}

func NewValidator(regoModule []byte) (*Validator, error) {
	v := &Validator{
		regoModule: regoModule,
		policies:   make(map[string]interface{}),
	}
	if err := v.loadPolicies(); err != nil {
		msg := fmt.Errorf("failed to load policies: %v", err)
		return nil, msg
	}

	return v, nil
}

func (v *Validator) Validate(ctx context.Context, a Access) (*Result, error) {
	parsedAccess, err := parseAccess(a)
	if err != nil {
		msg := fmt.Errorf("failed to parse access: %v", err)
		return nil, msg
	}

	regoResp, err := v.preparedQuery.Eval(
		ctx,
		rego.EvalParsedInput(parsedAccess),
	)
	if err != nil {
		msg := fmt.Errorf("failed to evaluate Rego with input: %v", err)
		return nil, msg
	}

	return resultFromRego(regoResp)
}

func (v *Validator) AddPolicy(policyID string, policy AccessPolicy) error {
	v.policies[policyID] = policy
	return v.loadPolicies()
}

func (v *Validator) loadPolicies() error {
	policies := map[string]interface{}{
		"policies": v.policies,
	}
	store := inmem.NewFromObject(policies)

	r := rego.New(
		// rego.Query("data.brewOPA.main"),
		rego.Query("data.brewOPA.main"),
		rego.Module("brewOPA.rego", string(v.regoModule)),
		rego.Store(store),
	)

	ctx := context.Background()
	preparedQuery, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare Rego: %v", err)
	}

	v.preparedQuery = preparedQuery
	return nil
}

type Access struct {
	Repository        string              `json:"repo"`
	User              string              `json:"user"`
	AccessType        AccessType          `json:"accessType"`
	RowsAffected      int64               `json:"rowsAffected"`
	TablesReferenced  []string            `json:"tablesReferenced,omitempty"`
	TablesUpdated     []string            `json:"tablesUpdated,omitempty"`
	TablesDeleted     []string            `json:"tablesDeleted,omitempty"`
	ColumnsReferenced map[string][]string `json:"columnsReferenced,omitempty"`
	ColumnsUpdated    map[string][]string `json:"columnsUpdated,omitempty"`
}

type AccessType int

const (
	AccessTypeRead AccessType = iota
	AccessTypeUpdate
	AccessTypeDelete
)

func (a AccessType) String() string {
	return []string{"reads", "updates", "deletes"}[a]
}

func NewAccess(repository, user string,
	rowsAffected int64,
	accessType AccessType,
	opts ...AccessOption) Access {
	a := Access{
		Repository:   repository,
		User:         user,
		AccessType:   accessType,
		RowsAffected: rowsAffected,
	}

	for _, opt := range opts {
		opt(&a)
	}

	return a
}

type AccessOption func(*Access)

func TablesReferenced(t []string) AccessOption {
	return func(a *Access) {
		a.TablesReferenced = t
	}
}

func TablesUpdated(t []string) AccessOption {
	return func(a *Access) {
		a.TablesUpdated = t
	}
}

func TablesDeleted(t []string) AccessOption {
	return func(a *Access) {
		a.TablesDeleted = t
	}
}

func ColumnsReferenced(c map[string][]string) AccessOption {
	return func(a *Access) {
		a.ColumnsReferenced = c
	}
}

func ColumnsUpdated(c map[string][]string) AccessOption {
	return func(a *Access) {
		a.ColumnsUpdated = c
	}
}

func parseAccess(a Access) (ast.Value, error) {
	b, err := json.Marshal(a)
	if err != nil {
		msg := fmt.Errorf("failed to encode access: %v", err)
		return nil, msg
	}
	return ast.ValueFromReader(bytes.NewReader(b))
}

// Result is the outcome of an access validation.
type Result struct {
	Pass   bool                  `json:"pass"`
	Tables map[string]*TableRule `json:"tables"`
}

// TableRule details the contexted rules applied for a table during validation of an access.
type TableRule struct {
	PolicyDefined bool                      `json:"policyDefined"`
	RulesApplied  map[string]*EvaluatedRule `json:"rulesApplied"`
}

// EvaluatedRule contains a contexted rule applied to a table and whether or not it was violated.
type EvaluatedRule struct {
	Violated      bool          `json:"violated"`
	ContextedRule ContextedRule `json:"contextedRule"`
}

func resultFromRego(resultSet rego.ResultSet) (*Result, error) {
	pass := true
	tables := make(map[string]*TableRule)

	unparsedResult, err := extractResultFromSet(resultSet)
	if err != nil {
		return nil, fmt.Errorf("failed to extract result from result set: %v", err)
	}

	unparsedResultMap, err := asMap(unparsedResult)
	if err != nil {
		return nil, err
	}
	for table, unparsedTableRule := range unparsedResultMap {
		tableRule, violation, err := parseTableRule(unparsedTableRule)
		if err != nil {
			return nil, fmt.Errorf("failed to parse table rule: %v", err)
		}
		if violation {
			pass = false
		}
		tables[table] = tableRule
	}

	result := &Result{
		Pass:   pass,
		Tables: tables,
	}

	return result, nil
}

func extractResultFromSet(resultSet rego.ResultSet) (interface{}, error) {
	if len(resultSet) == 0 {
		return nil, fmt.Errorf("undefined rego query")
	}
	regoResult := resultSet[0]
	if len(regoResult.Expressions) == 0 {
		return nil, fmt.Errorf("query returned no expressions")
	}
	return regoResult.Expressions[0].Value, nil
}

func parseTableRule(unparsed interface{}) (*TableRule, bool, error) {
	unparsedMap, err := asMap(unparsed)
	if err != nil {
		return nil, false, err
	}

	policyDefined, ok := unparsedMap["policyDefined"].(bool)
	if !ok {
		return nil, false, fmt.Errorf("expected policyDefined to be a bool, but got %T", unparsedMap["policyDefined"])
	}

	rulesApplied := make(map[string]*EvaluatedRule)
	ruleMap, err := asMap(unparsedMap["rule"])
	if err != nil {
		return nil, false, err
	}

	var violation bool
	for accessType, unparsedEvalRule := range ruleMap {
		evalRule, err := parseEvalRule(unparsedEvalRule)
		if err != nil {
			return nil, false, fmt.Errorf("failed to parse eval rule: %v", err)
		}
		if evalRule.Violated {
			violation = true
		}
		rulesApplied[accessType] = evalRule
	}

	tableRule := &TableRule{
		PolicyDefined: policyDefined,
		RulesApplied:  rulesApplied,
	}
	return tableRule, violation, nil
}

func parseEvalRule(unparsed interface{}) (*EvaluatedRule, error) {
	unparsedMap, err := asMap(unparsed)
	if err != nil {
		return nil, err
	}
	violation, ok := unparsedMap["violation"].(bool)
	if !ok {
		return nil, fmt.Errorf("expected a bool, but got %T", unparsedMap["violation"])
	}
	contextedRule, err := parseContextedRule(unparsedMap["contextedRule"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse contexted rule: %v", err)
	}

	evalRule := &EvaluatedRule{
		Violated:      violation,
		ContextedRule: contextedRule,
	}
	return evalRule, nil
}

func parseContextedRule(unparsed interface{}) (ContextedRule, error) {
	unparsedMap, err := asMap(unparsed)
	if err != nil {
		return ContextedRule{}, err
	}

	untypedAllow, ok := unparsedMap["allow"]
	if !ok {
		return ContextedRule{}, fmt.Errorf("field 'allow' not found")
	}
	allow, ok := untypedAllow.(bool)
	if !ok {
		return ContextedRule{}, fmt.Errorf("expected a bool, but got %T", untypedAllow)
	}

	untypedRows, ok := unparsedMap["rows"]
	if !ok {
		return ContextedRule{}, fmt.Errorf("field 'rows' not found")
	}
	rows, err := untypedRows.(json.Number).Int64()
	if err != nil {
		return ContextedRule{}, fmt.Errorf("expected an int64, but got %T", untypedRows)
	}

	untypedAttrs, ok := unparsedMap["attributes"]
	if !ok {
		return ContextedRule{}, fmt.Errorf("field 'attributes' not found")
	}
	attrs, err := asStringSlice(untypedAttrs)
	if err != nil {
		return ContextedRule{}, fmt.Errorf("failed to build []string from []interface{}")
	}

	c := ContextedRule{
		Allow:      allow,
		Rows:       rows,
		Attributes: attrs,
	}
	return c, nil
}

func asStringSlice(u interface{}) ([]string, error) {
	slice, ok := u.([]interface{})
	if !ok {
		return nil, fmt.Errorf("not a slice")
	}
	ret := make([]string, len(slice))
	for i, elem := range slice {
		s, ok := elem.(string)
		if !ok {
			return nil, fmt.Errorf("expected string, but got %T", elem)
		}
		ret[i] = s
	}
	return ret, nil
}

func asMap(i interface{}) (map[string]interface{}, error) {
	m, ok := i.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected map[string]interface{}, but got %T", i)
	}
	return m, nil
}
