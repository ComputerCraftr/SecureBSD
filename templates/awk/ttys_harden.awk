# Rewrites /etc/ttys to require a console password and disable extra VTs.

BEGIN {
    OFS = "\t"
}

function trim(s) {
    sub(/^[[:space:]]+/, "", s)
    sub(/[[:space:]]+$/, "", s)
    return s
}

function parse_line(line, arr, rest) {
    arr["name"] = arr["getty"] = arr["type"] = arr["status"] = arr["comment"] = arr["rest"] = ""
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
        rest = substr(rest, RSTART + RLENGTH)
    }
    arr["rest"] = trim(rest)
}

function print_with_rest(n, g, t, s, c, rest, line) {
    line = n OFS g OFS t OFS s OFS c
    if (rest != "") {
        line = line OFS rest
    }
    print line
}

/^[[:space:]]*#/ || NF == 0 { print; next }

{
    parse_line($0, f)
    if (f["name"] == "") {
        print
        next
    }
    if (f["name"] == "console") {
        print_with_rest("console", "none", "unknown", "off", "insecure", f["rest"])
        next
    }
    if (f["name"] ~ /^ttyv[0-1]$/) {
        g = (f["getty"] ? f["getty"] : "\"/usr/libexec/getty Pc\"")
        t = (f["type"] ? f["type"] : "xterm")
        print_with_rest(f["name"], g, t, "onifexists", "secure", f["rest"])
        next
    }
    if (f["name"] ~ /^ttyv[0-9]+$/) {
        g = (f["getty"] ? f["getty"] : "\"/usr/libexec/getty Pc\"")
        t = (f["type"] ? f["type"] : "xterm")
        print_with_rest(f["name"], g, t, "off", "secure", f["rest"])
        next
    }
    print
}
