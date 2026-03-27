# Expects:
#   -v settings_file="/path/to/settings"
#   -v append_missing="yes|no"

BEGIN {
    if (settings_file == "") {
        print "kv_settings_merge.awk requires -v settings_file=/path/to/settings" > "/dev/stderr"
        exit 1
    }
    while ((getline setting < settings_file) > 0) {
        if (setting == "") {
            continue
        }

        eq_index = index(setting, "=")
        if (eq_index <= 1) {
            continue
        }

        key = substr(setting, 1, eq_index - 1)
        setting_line[key] = setting
        if (!(key in setting_seen_order)) {
            setting_order[++setting_order_count] = key
            setting_seen_order[key] = 1
        }
    }
    close(settings_file)
}

{
    line = $0
    eq_index = index(line, "=")
    if (eq_index > 1) {
        key = substr(line, 1, eq_index - 1)
        if (key in setting_line) {
            print setting_line[key]
            seen_key[key] = 1
            next
        }
    }

    print line
}

END {
    if (append_missing != "yes") {
        exit
    }

    for (i = 1; i <= setting_order_count; i++) {
        key = setting_order[i]
        if (!(key in seen_key)) {
            print setting_line[key]
        }
    }
}
