package main

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/cyralinc/brewOPA"
)

func main() {
	validator, err := brewOPA.NewValidatorFromRego("../rego/brewOPA.rego")
	if err != nil {
		fmt.Print("failed to create validator: %v", err)
	}

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

	ctx := context.Background()

	access := brewOPA.NewAccess("invoices", "bob", brewOPA.AccessTypeRead,
		brewOPA.TablesReferenced([]string{"finance.cards"}),
		brewOPA.ColumnsReferenced(map[string][]string{
			"finance.cards": []string{"card_number", "credit_limit"},
		}),
	)

	result, err := validator.Validate(ctx, access)
	if err != nil {
		fmt.Printf("failed to validate access: %v", err)
		return
	}
}
