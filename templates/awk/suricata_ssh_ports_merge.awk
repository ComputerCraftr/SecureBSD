# Expects:
#   -v ssh_ports_value='[22, 2222]'

BEGIN {
    if (ssh_ports_value == "") {
        print "suricata_ssh_ports_merge.awk requires -v ssh_ports_value='[22, 2222]'" > "/dev/stderr"
        exit 1
    }
}

/^[[:space:]]*SSH_PORTS:[[:space:]]*/ {
    match($0, /^[[:space:]]*/)
    indent = substr($0, RSTART, RLENGTH)
    $0 = indent "SSH_PORTS: " ssh_ports_value
    updated = 1
}

{ print }

END {
    if (!updated) {
        exit 1
    }
}
