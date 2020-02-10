package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/cyralinc/brewOPA"
)

func main() {
	// instantiate validator
	validator, err := brewOPA.NewValidatorFromRego("../rego/brewOPA.rego")
	if err != nil {
		fmt.Print("failed to create validator: %v", err)
	}

	// read and add data access policy (multiple policies can be added to a validator)
	data, err := ioutil.ReadFile("../rego/sample_data/policy.yaml")
	if err != nil {
		fmt.Printf("failed to decode yaml: %v", err)
		return
	}

	policy, err := brewOPA.AccessPolicyFromYAML(data)
	if err != nil {
		fmt.Print("failed to create access policy from YAML: %v", err)
		return
	}

	err = validator.AddPolicy("myPolicy", policy)
	if err != nil {
		fmt.Printf("failed to add policy")
		return
	}

	// this access reads from card_number, which is disallowed by the policy
	badAccess := brewOPA.NewAccess("invoices", "bob", 10, brewOPA.AccessTypeRead,
		brewOPA.TablesReferenced([]string{"finance.cards"}),
		brewOPA.ColumnsReferenced(map[string][]string{
			"finance.cards": []string{"card_number", "credit_limit"},
		}),
	)

	// validate access against stored policies
	result, err := validator.Validate(context.Background(), badAccess)
	if err != nil {
		fmt.Printf("failed to validate access: %v", err)
		return
	}

	b, err := json.Marshal(result)
	if err != nil {
		fmt.Printf("failed to encode result: %v", err)
		return
	}
	fmt.Printf("result:\n%s\n\n", b)

	// The access violates the policy!
	// {
	// 	"pass": false,
	// 	"tables": {
	// 		"finance.cards": {
	// 			"policyDefined": true,
	// 			"rulesApplied": {
	// 				"reads": {
	// 					"violated": true,
	// 					"contextedRule": {
	// 						"allow": true,
	// 						"rows": 10,
	// 						"attributes": ["credit_limit","card_family"]
	// 					}
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	// Let's try again with a good access (no longer reading "card_number")
	goodAccess := brewOPA.NewAccess("invoices", "bob", 10, brewOPA.AccessTypeRead,
		brewOPA.TablesReferenced([]string{"finance.cards"}),
		brewOPA.ColumnsReferenced(map[string][]string{
			"finance.cards": []string{"credit_limit"},
		}),
	)

	result, err = validator.Validate(context.Background(), goodAccess)
	if err != nil {
		fmt.Printf("failed to validate access: %v", err)
		return
	}

	b, err = json.Marshal(result)
	if err != nil {
		fmt.Printf("failed to encode result: %v", err)
		return
	}
	fmt.Printf("result:\n%s\n\n", b)

	// The access passes validation.
	// {
	// 	"pass": true,
	// 	"tables": {
	// 		"finance.cards": {
	// 			"policyDefined": true,
	// 			"rulesApplied": {
	// 				"reads": {
	// 					"violated": false,
	// 					"contextedRule": {
	// 						"allow": true,
	// 						"rows": 10,
	// 						"attributes": ["credit_limit", "card_family"]
	// 					}
	// 				}
	// 			}
	// 		}
	// 	}
	// }
}
