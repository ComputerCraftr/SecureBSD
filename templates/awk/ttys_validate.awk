# Validates the hardened /etc/ttys structure for console and ttyv* entries.

function trim(s) {
    sub(/^[[:space:]]+/, "", s)
    sub(/[[:space:]]+$/, "", s)
    return s
}

function parse_line(line, arr, rest) {
    arr["name"] = arr["getty"] = arr["type"] = arr["status"] = arr["comment"] = ""
    if (match(line, /^[^[:space:]]+/)) {
        arr["name"] = substr(line, RSTART, RLENGTH)
        rest = substr(line, RSTART + RLENGTH)
    } else {
        return
    }
    rest = trim(rest)
    if (match(rest, /^"[^"]+"|^[^[:space:]]+/)) {
        arr["getty"] = substr(rest, RSTART, RLENGTH)
        rest = substr(rest, RSTART + RLENGTH)
    }
    rest = trim(rest)
    if (match(rest, /^[^[:space:]]+/)) {
        arr["type"] = substr(rest, RSTART, RLENGTH)
        rest = substr(rest, RSTART + RLENGTH)
    }
    rest = trim(rest)
    if (match(rest, /^[^[:space:]]+/)) {
        arr["status"] = substr(rest, RSTART, RLENGTH)
        rest = substr(rest, RSTART + RLENGTH)
    }
    rest = trim(rest)
    if (match(rest, /^[^[:space:]]+/)) {
        arr["comment"] = substr(rest, RSTART, RLENGTH)
    }
}

/^[[:space:]]*#/ || NF == 0 { next }

{
    parse_line($0, f)
    if (f["name"] ~ /^console$/) {
        if (f["getty"] == "" || f["type"] == "" || f["status"] == "" || f["comment"] == "") {
            print "Invalid console line: " $0 > "/dev/stderr"
            exit 1
        }
    } else if (f["name"] ~ /^ttyv[0-9]+$/) {
        if (f["getty"] == "" || f["type"] == "" || f["status"] == "" || f["comment"] == "") {
            print "Invalid tty line: " $0 > "/dev/stderr"
            exit 1
        }
    }
}
