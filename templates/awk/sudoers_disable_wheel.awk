/^%wheel[[:blank:]]+ALL=\(ALL(:ALL)?\)[[:blank:]]+(NOPASSWD:[[:blank:]]+)?ALL$/ {
    if (!disabled) {
        print "# " $0
        disabled = 1
        next
    }
}

{ print }
