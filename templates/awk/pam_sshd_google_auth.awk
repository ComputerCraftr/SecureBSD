# Expects:
#   -v ga_line="auth requisite pam_google_authenticator.so"

BEGIN {
    inserted = 0
}

/^auth/ {
    if (!inserted && $0 ~ /pam_unix\.so/) {
        print ga_line
        inserted = 1
        next
    }
    if (!inserted && $0 ~ /(sufficient|requisite|binding)/) {
        print ga_line
        inserted = 1
    }
}

/^(account|password|session)/ && !inserted {
    print ga_line
    inserted = 1
}

{ print }

END {
    if (!inserted) print ga_line
}
