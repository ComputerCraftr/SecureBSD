# Expects:
#   -v new_passwd_format="blf"
#   -v new_umask="027"
#   -v password_expiration="<days>d|none"

BEGIN {
    if (new_passwd_format == "" || new_umask == "" || password_expiration == "") {
        print "login_conf_defaults.awk requires -v new_passwd_format, -v new_umask, and -v password_expiration" > "/dev/stderr"
        exit 1
    }
    in_default = 0
    passwd_format_present = 0
    umask_present = 0
    passwordtime_present = 0
}

/^default:/ {
    in_default = 1
    passwd_format_present = 0
    umask_present = 0
    passwordtime_present = 0
}

in_default {
    if ($0 ~ /:passwd_format=/) {
        passwd_format_present = 1
        sub(/:passwd_format=[^:]+:/, ":passwd_format=" new_passwd_format ":")
    }
    if ($0 ~ /:umask=/) {
        umask_present = 1
        sub(/:umask=[0-9]+:/, ":umask=" new_umask ":")
    }
    if ($0 ~ /:passwordtime=/) {
        passwordtime_present = 1
        if (password_expiration != "none") sub(/:passwordtime=[^:]+:/, ":passwordtime=" password_expiration ":")
    }
    if ($0 !~ /:\\$/) {
        in_default = 0
        if (!passwd_format_present) {
            print "\t:passwd_format=" new_passwd_format ":\\"
        }
        if (!umask_present) {
            print "\t:umask=" new_umask ":\\"
        }
        if (!passwordtime_present && password_expiration != "none") {
            print "\t:passwordtime=" password_expiration ":\\"
        }
    }
}

{ print }

END {
    if (in_default) {
        if (!passwd_format_present) {
            print "\t:passwd_format=" new_passwd_format ":\\"
        }
        if (!umask_present) {
            print "\t:umask=" new_umask ":\\"
        }
        if (!passwordtime_present && password_expiration != "none") {
            print "\t:passwordtime=" password_expiration ":\\"
        }
    }
}
