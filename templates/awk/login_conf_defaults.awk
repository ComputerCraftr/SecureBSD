# Expects:
#   -v new_passwd_format="blf"
#   -v new_umask="027"
#   -v password_expiration="<days>d|none"

BEGIN {
    in_default = 0
    passwordtime_present = 0
}

/^default:/ { in_default = 1 }

in_default {
    if ($0 ~ /:passwd_format=/) sub(/:passwd_format=[^:]+:/, ":passwd_format=" new_passwd_format ":")
    if ($0 ~ /:umask=/) sub(/:umask=[0-9]+:/, ":umask=" new_umask ":")
    if ($0 ~ /:passwordtime=/) {
        passwordtime_present = 1
        if (password_expiration != "none") sub(/:passwordtime=[^:]+:/, ":passwordtime=" password_expiration ":")
    }
    if ($0 !~ /:\\$/) {
        in_default = 0
        if (!passwordtime_present && password_expiration != "none") {
            print "\t:passwordtime=" password_expiration ":\\"
        }
    }
}

{ print }
