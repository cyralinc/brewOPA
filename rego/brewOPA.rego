package brewOPA

import data.policies

import input.repo as input_repo
import input.user as input_user
import input.accessType as input_access_type
import input.tablesReferenced as input_tables_referenced
import input.tablesUpdated as input_tables_updated
import input.tablesDeleted as input_tables_deleted
import input.columnsReferenced as input_columns_referenced
import input.columnsUpdated as input_columns_updated
import input.rowsAffected as input_rows_affected

# remove_obj_key removes a given key and corresponding value from a given object
# and returns to stripped object
remove_obj_key(obj, remove) = stripped_obj {
    stripped_obj := { key : val |
        val := obj[key]
        key != remove
    }
}

# rule_map is an object mapping from a dataset location to a policy containing
# that watch, wherein each policy contains a default rule as well as an
# "targeted_rules" object mapping from an identity to a specific rule set by
# the user to apply for that identity. This object contains policy data alone
# and doesn't require query data. Therefore, it can be completely generated
# through partial evaluation and can be leveraged for faster policy evaluation.
rule_map = { location_key : policy | 
    location := policies[policyID].locations[_]
    location_key := sprintf("%v.%v.%v", [location.repo, location.schema, location.table])
    specific_policy := policies[policyID]
    targeted_rules := { identity : rule | 
        identity := specific_policy.rules[i].identities[_]
        # we remove the identities field from the rule to avoid copying
        # unecessary data across the unrolled rules
        rule := remove_obj_key(specific_policy.rules[i], "identities")
    }
    policy := {
        "policy_ID": policyID,
        "targeted_rules": targeted_rules,
        "default_rule": specific_policy.defaultRule
    }
}

# is_subset returns true if each element in a is in b
is_subset(a, b) {
    set_a := cast_set(a)
    set_b := cast_set(b)
    # set_a - set_b gives the elements in set_a that are not in set_b
    # set_a is a subset of set_b when this is an empty set
    set_a - set_b = set()
}

access_types = ["reads", "updates", "deletes"]

contexted_input_tables[type] = input_tables_referenced {
    type := "reads"
    input_tables_referenced
}
contexted_input_tables[type] = [] {
    type := "reads"
    not input_tables_referenced
}
contexted_input_tables[type] = input_tables_updated {
    type := "updates"
    input_tables_updated
}
contexted_input_tables[type] = [] {
    type := "updates"
    not input_tables_updated
}
contexted_input_tables[type] = input_tables_deleted {
    type := "deletes"
    input_tables_deleted
}
contexted_input_tables[type] = [] {
    type := "deletes"
    not input_tables_deleted
}

# all_tables is the comprehensive set of tables involved in the input query
all_input_tables[table] {
    table := input_tables_referenced[_]
}
all_input_tables[table] {
    table := input_tables_deleted[_]
}
all_input_tables[table] {
    table := input_tables_updated[_]
}

single_table_access {
    count(all_input_tables) == 1
}

match(input_val, pattern_val) {
    input_val == pattern_val
}
match(input_val, pattern_val) {
    pattern_val == "*"
}

# select_rules returns an array of rules from a given policy, wherein each
# rule is defined (by the user) to apply for the given input host, enduser,
# and dbuser via the "identities" field of the rule.
select_rules(policy, user) = rules {
    rules := [ rule |
        rule := policy.targeted_rules[user]
    ]
    count(rules) > 0
}
# this second definition returns the default rule if no targeted rules match
# the input identity
select_rules(policy, user) = default_rule {
    rules := [ rule |
        rule := policy.targeted_rules[user]
    ]
    count(rules) == 0
    default_rule := [policy.default_rule]
}


# These functions implement the logic for the above "{case}_rule_violations"
# functions. Each function returns an array containing a string describing its
# corresponding violation or an empty array if no violation is found.
attrs_read_violation(table, rule) {
    rule.reads.attributes != ["*"]
    not is_subset(input_columns_referenced[table], rule.reads.attributes)
} 
attrs_read_violation(table, rule) {
    not rule.reads.attributes
}

attrs_updated_violation(table, rule) {
    rule.updates.attributes != ["*"]
    not is_subset(input_columns_updated[table], rule.updates.attributes)
} 
attrs_updated_violation(table, rule) {
    not rule.updates.attributes
}


rows_read_violation(rule) {
    single_table_access
    input_rows_affected > rule.reads.rows 
}
rows_read_violation(rule) {
    single_table_access
    not rule.reads.rows
}

rows_updated_violation(rule) {
    single_table_access
    input_rows_affected > rule.updates.rows 
}
rows_updated_violation(rule) {
    single_table_access
    not rule.updates.rows
}

rows_deleted_violation(rule) {
    single_table_access
    input_rows_affected > rule.deletes.rows
}
rows_deleted_violation(rule) {
    single_table_access
    not rule.deletes.rows
}

# read_rule_violations returns a list of violations occurring for a read
# access to a table based on constraints in the given rule. An empty array will
# be returned if there no violations are found. The set of possible violations
# for reads from a table is ["readDisallowed", "excessiveRowsRead", "disallowedAttrsRead"].
read_rule_violations(table, rule) = ["readDisallowed"] {
    not rule.reads.allow
}
read_rule_violations(table, rule) = ["disallowedAttrsRead","excessiveRowsRead"] {
    rule.reads.allow
    attrs_read_violation(table, rule)
    rows_read_violation(rule)
}
read_rule_violations(table, rule) = ["disallowedAttrsRead"] {
    rule.reads.allow
    attrs_read_violation(table, rule)
    not rows_read_violation(rule)
}
read_rule_violations(table, rule) = ["excessiveRowsRead"] {
    rule.reads.allow
    not attrs_read_violation(table, rule)
    rows_read_violation(rule)
}
read_rule_violations(table, rule) = [] {
    rule.reads.allow
    not attrs_read_violation(table, rule)
    not rows_read_violation(rule)
}

update_rule_violations(table, rule) = ["updateDisallowed"] {
    not rule.updates.allow
}
update_rule_violations(table, rule) = ["disallowedAttrsUpdated", "excessiveRowsUpdated"] {
    rule.updates.allow
    attrs_updated_violation(table, rule)
    rows_updated_violation(rule)
}
update_rule_violations(table, rule) = ["disallowedAttrsUpdated"] {
    rule.updates.allow
    attrs_updated_violation(table, rule)
    not rows_updated_violation(rule)
}
update_rule_violations(table, rule) = ["excessiveRowsUpdated"] {
    rule.updates.allow
    not attrs_updated_violation(table, rule)
    rows_updated_violation(rule)
}
update_rule_violations(table, rule) = [] {
    rule.updates.allow
    not attrs_updated_violation(table, rule)
    not rows_updated_violation(rule)
}

delete_rule_violations(table, rule) = ["deleteDisallowed"] {
    not rule.deletes.allow
}
delete_rule_violations(table, rule) = ["excessiveRowsDeleted"] {
    rule.deletes.allow
    rows_deleted_violation(rule)
}
delete_rule_violations(table, rule) = [] {
    rule.deletes.allow
    not rows_deleted_violation(rule)
}

rule_violations(access_type, rule, table) = read_rule_violations(table, rule) {
    access_type == "reads"
}
rule_violations(access_type, rule, table) = update_rule_violations(table, rule) {
    access_type == "updates"
}
rule_violations(access_type, rule, table) = delete_rule_violations(table, rule) {
    access_type == "deletes"
}

eval_table_contexted(access_type, rule, table) = retval {
    contexted_tables_set := cast_set(contexted_input_tables[access_type])
    contexted_tables_set[table]
    violations := rule_violations(access_type, rule, table)
    retval := {
        "violation": count(violations) > 0, 
        "contextedRule": rule[access_type]
    }
}

eval_table(repo, table) = retval {
    dataset_location := sprintf("%v.%v", [repo, table])
    relevant_policy := rule_map[dataset_location]
    rules := select_rules(relevant_policy, input_user)
    rule := rules[0]
    retval := {
        "policyDefined": true,
        "rule": {access_type:ret | access_type := access_types[_]; ret:=eval_table_contexted(access_type, rule, table)}
    }
}

eval_table(repo, table) = retval {
    dataset_location := sprintf("%v.%v", [repo, table])
    not rule_map[dataset_location]
    retval := {
        "policyDefined": false,
        "rule": {}
    }
}

main[table] = table_retval {
    all_input_tables[table]
    table_retval := eval_table(input_repo, table)
}