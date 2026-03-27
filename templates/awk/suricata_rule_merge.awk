# Expects:
#   -v managed_rule="alert tcp ... sid:1000001; ..."

BEGIN {
    if (managed_rule == "") {
        print "suricata_rule_merge.awk requires -v managed_rule='alert tcp ...'" > "/dev/stderr"
        exit 1
    }
}

/sid:1000001;/ {
    if (!replaced) {
        print managed_rule
        replaced = 1
    }
    next
}

{ print }

END {
    if (!replaced) {
        print managed_rule
    }
}
