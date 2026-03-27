# Expects:
#   -v settings_file="/path/to/settings"

function trim(text) {
    sub(/^[[:space:]]+/, "", text)
    sub(/[[:space:]]+$/, "", text)
    return text
}

function parse_setting_line(setting,    first_space, key, value) {
    setting = trim(setting)
    if (setting == "") {
        return 0
    }

    first_space = index(setting, " ")
    if (first_space == 0) {
        return 0
    }

    key = substr(setting, 1, first_space - 1)
    value = trim(substr(setting, first_space + 1))
    if (key == "" || value == "") {
        return 0
    }

    if (key == "Port") {
        port_setting[++port_setting_count] = setting
        port_setting_seen[value] = 1
    } else {
        setting_line[key] = setting
        setting_value[key] = value
    }
    if (!(key in setting_seen_order)) {
        setting_order[++setting_order_count] = key
        setting_seen_order[key] = 1
    }

    return 1
}

function extract_key(line,    stripped, key) {
    stripped = line
    sub(/^[[:space:]]*#?[[:space:]]*/, "", stripped)
    key = stripped
    sub(/[[:space:]].*$/, "", key)
    if (key == stripped && stripped ~ /[[:space:]]/) {
        return ""
    }
    return key
}

function extract_value(line,    stripped, first_space, value) {
    stripped = line
    sub(/^[[:space:]]*#?[[:space:]]*/, "", stripped)
    first_space = index(stripped, " ")
    if (first_space == 0) {
        return ""
    }
    value = substr(stripped, first_space + 1)
    return trim(value)
}

function print_port_settings(    idx) {
    for (idx = 1; idx <= port_setting_count; idx++) {
        print port_setting[idx]
    }
}

function allowusers_has_target(value, target,    count, i, parts) {
    if (value == "") {
        return 0
    }
    count = split(value, parts, /[[:space:]]+/)
    for (i = 1; i <= count; i++) {
        if (parts[i] == target) {
            return 1
        }
    }
    return 0
}

BEGIN {
    while ((getline setting < settings_file) > 0) {
        parse_setting_line(setting)
    }
    close(settings_file)
    allowusers_target = setting_value["AllowUsers"]
}

{
    lines[++line_count] = $0
    key = extract_key($0)
    if (key == "AllowUsers" && allowusers_has_target(extract_value($0), allowusers_target)) {
        allowusers_target_present = 1
    }
}

END {
    for (i = 1; i <= line_count; i++) {
        line = lines[i]
        key = extract_key(line)

        if (!(key in setting_line) && !(key == "Port" && port_setting_count > 0)) {
            print line
            continue
        }

        seen_key[key] = 1
        if (key == "Port") {
            if (!port_printed) {
                print_port_settings()
                port_printed = 1
            }
            continue
        }
        if (key == "AllowUsers") {
            if (allowusers_target_present) {
                print line
                continue
            }

            current_value = extract_value(line)
            if (current_value == "") {
                print setting_line[key]
            } else {
                print "AllowUsers " setting_value[key] " " current_value
            }
            continue
        }

        print setting_line[key]
    }

    for (i = 1; i <= setting_order_count; i++) {
        key = setting_order[i]
        if (!(key in seen_key)) {
            if (key == "Port") {
                if (!port_printed) {
                    print_port_settings()
                    port_printed = 1
                }
            } else {
                print setting_line[key]
            }
        }
    }
}
