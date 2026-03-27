# Expects:
#   -v custom_include="/path/to/custom.yaml"

BEGIN {
    if (custom_include == "") {
        print "suricata_include_merge.awk requires -v custom_include=/path/to/custom.yaml" > "/dev/stderr"
        exit 1
    }
}

function print_include_block(    idx) {
    print "include:"
    for (idx = 1; idx <= include_count; idx++) {
        print "  - " include_entries[idx]
    }
    include_seen = 1
}

/^[[:space:]]*include:[[:space:]]*$/ {
    if (!include_seen) {
        include_seen = 1
        in_include_block = 1
        next
    }
}

in_include_block {
    if ($0 ~ /^[[:space:]]*-[[:space:]]*/) {
        include_entry = $0
        sub(/^[[:space:]]*-[[:space:]]*/, "", include_entry)
        if (!(include_entry in include_entry_seen)) {
            include_entries[++include_count] = include_entry
            include_entry_seen[include_entry] = 1
        }
        if (include_entry == custom_include) {
            custom_seen = 1
        }
        next
    }

    if (!custom_seen) {
        include_entries[++include_count] = custom_include
        include_entry_seen[custom_include] = 1
        custom_seen = 1
    }
    print_include_block()
    in_include_block = 0
}

/^[[:space:]]*include:[[:space:]]+/ {
    include_entry = $0
    sub(/^[[:space:]]*include:[[:space:]]*/, "", include_entry)
    if (!(include_entry in include_entry_seen)) {
        include_entries[++include_count] = include_entry
        include_entry_seen[include_entry] = 1
    }
    if (include_entry == custom_include) {
        custom_seen = 1
    }
    include_seen = 1
    next
}

{ print }

END {
    if (!custom_seen) {
        include_entries[++include_count] = custom_include
        include_entry_seen[custom_include] = 1
    }
    if (include_seen) {
        print_include_block()
    } else {
        include_seen = 1
        print_include_block()
    }
}
