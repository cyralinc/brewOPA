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

func (v *Validator) Validate(ctx context.Context, a Access) (Result, error) {
	parsedAccess, err := parseAccess(a)
	if err != nil {
		msg := fmt.Errorf("failed to parse access: %v", err)
		return Result{}, msg
	}

	regoResp, err := v.preparedQuery.Eval(
		ctx,
		rego.EvalParsedInput(parsedAccess),
	)
	if err != nil {
		msg := fmt.Errorf("failed to evaluate Rego with input: %v", err)
		return Result{}, msg
	}

	return parseRegoResp(regoResp)
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

func NewAccess(repository, user string, accessType AccessType, opts ...AccessOption) Access {
	a := Access{
		Repository: repository,
		User:       user,
		AccessType: accessType,
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

// func parseAccess(a Access) (ast.Value,error) {
// 	terms := [][2]*Term{
// 		Item(NewTerm("Repo"),NewTerm())
// 	}
// 	ast.NewObject(...terms)
// }

func parseAccess(a Access) (ast.Value, error) {
	b, err := json.Marshal(a)
	if err != nil {
		msg := fmt.Errorf("failed to encode access: %v", err)
		return nil, msg
	}
	fmt.Printf("\naccess JSON (%T):\n%s\n\n", b, b)
	return ast.ValueFromReader(bytes.NewReader(b))
}

type Result struct {
}

func parseRegoResp(resultSet rego.ResultSet) (Result, error) {
	b, err := json.Marshal(resultSet)
	if err != nil {
		msg := fmt.Errorf("failed to encode access: %v", err)
		return Result{}, msg
	}
	fmt.Printf("\nregoResp JSON (%T):\n%s\n\n", b, b)
	view("regoResp", resultSet)
	view("regoResp[0]", resultSet)
	view("regoResp[0].Expressions", resultSet[0].Expressions)
	view("regoResp[0].Expressions[0]", resultSet[0].Expressions[0])
	b, err = json.Marshal(resultSet[0].Expressions[0])
	if err != nil {
		return Result{}, fmt.Errorf("failed to encode access: %v", err)
	}
	fmt.Printf("\resultSet[0].Expressions[0] JSON (%T):\n%s\n\n", b, b)
	if len(resultSet) == 0 {
		return Result{}, fmt.Errorf("undefined rego query")
	}
	regoResult := resultSet[0]
	if len(regoResult.Expressions) == 0 {
		return Result{}, fmt.Errorf("query returned no expressions")
	}
	unparsedResult := regoResult.Expressions[0].Value
	fmt.Printf("\nunparsedResult (%T):\n%+v\n\n",
		unparsedResult, unparsedResult)

	return Result{}, nil
}

func view(label string, v interface{}) {
	fmt.Printf("\n%s (%T):\n%+v\n\n", label, v, v)
}

// // Read all existing policices and return in a map where each key is a policyID
// // and the corresponding value is the policy data associated with that policyID.
// func (v *Validator) getStoredPolicies(ctx context.Context) (map[string]interface{},error) {
// 	kvs,err := q.storage.GetPrefix(ctx,cyralKeys.PolicyKeyPrefix)
// 	if err != nil {
// 		msg := fmt.Errorf("failed to get values with key prefix '%s': %v",
// 			cyralKeys.PolicyKeyPrefix,err)
// 		return nil,msg
// 	}

// 	policies := make(map[string]interface{})
// 	for _,kv := range kvs {
// 		policyId := strings.TrimPrefix(kv.Key,cyralKeys.PolicyKeyPrefix)

// 		var policy map[string]interface{}
// 		policyBytes := []byte(kv.Value)
// 		err = json.Unmarshal(policyBytes,&policy)
// 		if err != nil {
// 			msg := fmt.Errorf("failed to decode policy '%s': %v",
// 				kv.Value,err)
// 			return nil,msg
// 		}

// 		policies[policyId] = policy
// 	}

// 	policyData := map[string]interface{}{
// 		"policies": policies,
// 	}

// 	return policyData,nil
// }

// type Result map[string]TableResult

// type TableResult struct {
// 	PolicyDefined bool      `json:"policyDefined"`
// 	Rule          TableRule `json:"rule"`
// }

// type TableRule map[string]*EvaluatedRule

// type EvaluatedRule struct {
// 	ContextedRule policyClient.ContextedRule `json:"contextedRule"`
// 	Violation     bool                       `json:"violation"`
// }
