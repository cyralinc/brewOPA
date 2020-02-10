![brewOPA logo](./assets/logo.png)

[brewopa.org](https://brewopa.org/)

**brewOPA** is an extensible open-source framework that enables developers to easily brew data access control policies for [Open Policy Agent (OPA)](www.openpolicyagent.org) by writing them in the human-friendly YAML.

## Usage

Instantiate the validator with the brewOPA rego module.

```
validator, err := brewOPA.NewValidatorFromRego("../rego/brewOPA.rego")
if err != nil {
        fmt.Print("failed to create validator: %v", err)
}
```

Configure the validator with one or more data access policies.

```
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
```

Create and validate accesses to data.

```
access := brewOPA.NewAccess("invoices", "bob", 10, brewOPA.AccessTypeRead,
        brewOPA.TablesReferenced([]string{"finance.cards"}),
        brewOPA.ColumnsReferenced(map[string][]string{
                "finance.cards": []string{"card_number", "credit_limit"},
        }),
)

result, err := validator.Validate(context.Background(), access)
if err != nil {
        fmt.Printf("failed to validate access: %v", err)
        return
}
```

## Access control via OPA REST APIs

Start OPA as a service (listening on port `8181` by default)

```
opa run -s
```

Create the access policy module

```
curl localhost:8181/v1/policies/brewOPA \
    -X PUT \
    -H "Content-Type: text/plain" \
    --data-binary @rego/brewOPA.rego
```

Deposit access policy to the namespace `policies/:policyID`
Here, we deposit JSON (generated from the YAML using [yq](https://mikefarah.gitbook.io/yq/usage/convert#yaml-to-json)) because OPA's REST API doesn't support YAML.

```
curl localhost:8181/v1/data/policies/myPolicy \
    -X PUT \
    -H "Content-Type: text/plain" \
    -d '{
        "sensitiveAttrs": ["card_number", "credit_limit", "card_family"],
        "locations": [
            {
                "repo": "invoices",
                "schema": "finance",
                "table": "cards"
            }
        ],
        "rules": [
            {
                "deletes": {
                    "allow": true,
                    "rows": 1
                },
                "identities": ["bob"],
                "reads": {
                    "allow": true,
                    "attributes": ["credit_limit", "card_family"],
                    "rows": 10
                },
                "updates": {
                    "allow": true,
                    "attributes": ["credit_limit"],
                    "rows": 1
                }
            }
        ],
        "defaultRule": {
            "deletes": {
                "allow": false
            },
            "reads": {
                "allow": true,
                "attributes": "any",
                "rows": 1
            },
            "updates": {
                "allow": false
            }
        }
    }'
```

Query the access policy module providing data access parameters as input

```
curl localhost:8181/v1/data/dbAccess/main\?pretty\=true \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{
        "input": {
            "user": "bob",
            "repo": "clinics",
            "accessType": "SELECT",
            "tablesReferenced": ["finance.cards"],
            "columnsReferenced": {
                "finance.cards": ["cust_id", "card_number", "credit_limit"]
            },
            "rowsAffected": 10
        }
    }'
```
