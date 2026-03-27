# Expects:
#   -v managed_rule="uid:<uid>:tcp:<port>"
#   -v root_uid="<uid>"

function trim(s) {
    sub(/^[[:space:]]+/, "", s)
    sub(/[[:space:]]+$/, "", s)
    return s
}

function normalize_rules(s,    n, i, arr, out) {
    s = trim(s)
    if (s == "") return ""
    n = split(s, arr, /,/)
    out = ""
    for (i = 1; i <= n; i++) {
        arr[i] = trim(arr[i])
        if (arr[i] == "") continue
        if (out != "") out = out "," arr[i]
        else out = arr[i]
    }
    return out
}

BEGIN {
    if (managed_rule == "" || root_uid == "") {
        print "portacl_merge.awk requires -v managed_rule and -v root_uid" > "/dev/stderr"
        exit 1
    }
    found = 0
    malformed = 0
}

/^security\.mac\.portacl\.rules=/ {
    found = 1
    value = substr($0, index($0, "=") + 1)
    comment = ""
    rules_part = value
    if (match(value, /[[:space:]]+#/)) {
        rules_part = substr(value, 1, RSTART - 1)
        comment = substr(value, RSTART)
    }
    rules = normalize_rules(rules_part)
    if (rules == "" && rules_part !~ /^[[:space:]]*$/) {
        malformed = 1
        print "Malformed security.mac.portacl.rules line: " $0 > "/dev/stderr"
        exit 1
    }
    n = split(rules, arr, /,/)
    out = ""
    managed_seen = 0
    for (i = 1; i <= n; i++) {
        rule = trim(arr[i])
        if (rule == "") continue
        if (rule ~ ("^uid:" root_uid ":tcp:[0-9]+$")) {
            if (!managed_seen) {
                if (out != "") out = out "," managed_rule
                else out = managed_rule
                managed_seen = 1
            }
            continue
        }
        if (out != "") out = out "," rule
        else out = rule
    }
    if (!managed_seen) {
        if (out != "") out = out "," managed_rule
        else out = managed_rule
    }
    print "security.mac.portacl.rules=" out comment
    next
}

{ print }

END {
    if (malformed) exit 1
    if (!found) print "security.mac.portacl.rules=" managed_rule
}
