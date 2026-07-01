// SPDX-License-Identifier: GPL-3.0-or-later

#include "common.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void config_defaults(struct config *config) {
    memset(config, 0, sizeof(*config));
    config->ipv6 = true;

    snprintf(config->pin_cidr_out4, sizeof(config->pin_cidr_out4), "%s", PIN_CIDR_OUT4);
    snprintf(config->pin_cidr_out6, sizeof(config->pin_cidr_out6), "%s", PIN_CIDR_OUT6);
    snprintf(config->pin_cidr_pre4, sizeof(config->pin_cidr_pre4), "%s", PIN_CIDR_PRE4);
    snprintf(config->pin_cidr_pre6, sizeof(config->pin_cidr_pre6), "%s", PIN_CIDR_PRE6);
    snprintf(config->pin_force_out4, sizeof(config->pin_force_out4), "%s", PIN_FORCE_OUT4);
    snprintf(config->pin_force_out6, sizeof(config->pin_force_out6), "%s", PIN_FORCE_OUT6);
    snprintf(config->pin_app_out4, sizeof(config->pin_app_out4), "%s", PIN_APP_OUT4);
    snprintf(config->pin_app_out6, sizeof(config->pin_app_out6), "%s", PIN_APP_OUT6);

    snprintf(config->map_cidr4, sizeof(config->map_cidr4), "%s", MAP_CIDR4);
    snprintf(config->map_cidr6, sizeof(config->map_cidr6), "%s", MAP_CIDR6);
    snprintf(config->map_force_uid, sizeof(config->map_force_uid), "%s", MAP_FORCE_UID);
    snprintf(config->map_app_uid, sizeof(config->map_app_uid), "%s", MAP_APP_UID);
}

static char *read_all(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    long len = ftell(file);
    if (len < 0) {
        fclose(file);
        return NULL;
    }
    rewind(file);

    char *text = calloc((size_t)len + 1U, 1U);
    if (!text) {
        fclose(file);
        return NULL;
    }
    if (fread(text, 1U, (size_t)len, file) != (size_t)len) {
        free(text);
        fclose(file);
        return NULL;
    }
    fclose(file);
    return text;
}

static const char *skip_ws(const char *p) {
    while (*p && isspace((unsigned char)*p)) ++p;
    return p;
}

static const char *find_json_key(const char *json, const char *key) {
    char quoted[96];
    snprintf(quoted, sizeof(quoted), "\"%s\"", key);
    const char *p = strstr(json, quoted);
    if (!p) return NULL;
    p = skip_ws(p + strlen(quoted));
    if (*p != ':') return NULL;
    return skip_ws(p + 1);
}

static bool read_json_string(const char *json, const char *key, char *out, size_t out_size) {
    const char *p = find_json_key(json, key);
    if (!p || *p != '"') return false;
    ++p;

    size_t len = 0;
    while (*p && *p != '"' && len + 1U < out_size) {
        if (*p == '\\' && p[1]) ++p;
        out[len++] = *p++;
    }
    out[len] = '\0';
    return *p == '"';
}

static bool read_json_bool(const char *json, const char *key, bool *out) {
    const char *p = find_json_key(json, key);
    if (!p) return false;
    if (strncmp(p, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if (strncmp(p, "false", 5) == 0) {
        *out = false;
        return true;
    }
    if (*p == '1' || *p == '0') {
        *out = *p == '1';
        return true;
    }
    return false;
}

bool read_config_json(const char *path, struct config *config) {
    config_defaults(config);
    char *json = read_all(path);
    if (!json) {
        fprintf(stderr, "read config failed: %s\n", path);
        return false;
    }

    read_json_bool(json, "ipv6", &config->ipv6);
    read_json_string(json, "cidr4", config->cidr4_file, sizeof(config->cidr4_file));
    read_json_string(json, "cidr6", config->cidr6_file, sizeof(config->cidr6_file));
    read_json_string(json, "forceUids", config->force_uid_file, sizeof(config->force_uid_file));
    read_json_string(json, "appUids", config->app_uid_file, sizeof(config->app_uid_file));

    read_json_string(json, "pinCidrOut4", config->pin_cidr_out4, sizeof(config->pin_cidr_out4));
    read_json_string(json, "pinCidrOut6", config->pin_cidr_out6, sizeof(config->pin_cidr_out6));
    read_json_string(json, "pinCidrPre4", config->pin_cidr_pre4, sizeof(config->pin_cidr_pre4));
    read_json_string(json, "pinCidrPre6", config->pin_cidr_pre6, sizeof(config->pin_cidr_pre6));
    read_json_string(json, "pinForceOut4", config->pin_force_out4, sizeof(config->pin_force_out4));
    read_json_string(json, "pinForceOut6", config->pin_force_out6, sizeof(config->pin_force_out6));
    read_json_string(json, "pinAppOut4", config->pin_app_out4, sizeof(config->pin_app_out4));
    read_json_string(json, "pinAppOut6", config->pin_app_out6, sizeof(config->pin_app_out6));

    read_json_string(json, "mapCidr4", config->map_cidr4, sizeof(config->map_cidr4));
    read_json_string(json, "mapCidr6", config->map_cidr6, sizeof(config->map_cidr6));
    read_json_string(json, "mapForceUid", config->map_force_uid, sizeof(config->map_force_uid));
    read_json_string(json, "mapAppUid", config->map_app_uid, sizeof(config->map_app_uid));

    free(json);

    if (config->cidr4_file[0] == '\0') {
        fprintf(stderr, "missing config field: cidr4\n");
        return false;
    }
    if (config->ipv6 && config->cidr6_file[0] == '\0') {
        fprintf(stderr, "missing config field: cidr6\n");
        return false;
    }
    return true;
}

static char *trim_line(char *line) {
    char *comment = strchr(line, '#');
    if (comment) *comment = '\0';

    while (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n') ++line;
    if (*line == '\0') return line;

    char *end = line + strlen(line) - 1;
    while (end > line && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        --end;
    }
    return line;
}

static bool parse_cidr(char *line, int *family, uint8_t *address, uint32_t *prefix_len) {
    char *value = trim_line(line);
    if (*value == '\0') return false;

    char *slash = strchr(value, '/');
    if (!slash) return false;
    *slash = '\0';

    char *end = NULL;
    unsigned long prefix = strtoul(slash + 1, &end, 10);
    if (end == slash + 1) return false;

    if (strchr(value, ':')) {
        if (prefix > 128UL || inet_pton(AF_INET6, value, address) != 1) return false;
        *family = AF_INET6;
    } else {
        if (prefix > 32UL || inet_pton(AF_INET, value, address) != 1) return false;
        *family = AF_INET;
    }
    *prefix_len = (uint32_t)prefix;
    return true;
}

int load_cidr_file(int map_fd, const char *path, bool ipv6) {
    FILE *file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "CIDR file unavailable, using empty map: %s\n", path);
        return 0;
    }

    int loaded = 0;
    int failed = 0;
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        uint8_t address[16] = {0};
        uint32_t prefix_len = 0;
        int family = 0;
        if (!parse_cidr(line, &family, address, &prefix_len)) continue;
        if (ipv6 && family != AF_INET6) continue;
        if (!ipv6 && family != AF_INET) continue;

        uint8_t value = 1;
        int rc;
        if (ipv6) {
            struct lpm6_key key;
            memset(&key, 0, sizeof(key));
            key.prefixlen = prefix_len;
            memcpy(key.addr, address, sizeof(key.addr));
            rc = update_elem(map_fd, &key, &value);
        } else {
            struct lpm4_key key;
            memset(&key, 0, sizeof(key));
            key.prefixlen = prefix_len;
            memcpy(key.addr, address, sizeof(key.addr));
            rc = update_elem(map_fd, &key, &value);
        }
        if (rc == 0) ++loaded; else ++failed;
    }

    fclose(file);
    if (failed > 0) {
        fprintf(stderr, "CIDR map dropped %d entries (map full or kernel error): %s\n", failed, path);
    }
    return loaded;
}

static bool parse_uid(char *line, uint32_t *uid) {
    char *value = trim_line(line);
    if (*value == '\0') return false;

    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (end == value || parsed > UINT32_MAX) return false;
    *uid = (uint32_t)parsed;
    return true;
}

int load_uid_file(int map_fd, const char *path) {
    if (!path || path[0] == '\0') return 0;

    FILE *file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "UID file unavailable, using empty map: %s\n", path);
        return 0;
    }

    uint8_t value = 1;
    int loaded = 0;
    int failed = 0;
    char line[128];
    while (fgets(line, sizeof(line), file)) {
        uint32_t uid = 0;
        if (!parse_uid(line, &uid)) continue;
        if (update_elem(map_fd, &uid, &value) == 0) ++loaded; else ++failed;
    }

    fclose(file);
    if (failed > 0) {
        fprintf(stderr, "UID map dropped %d entries (map full or kernel error): %s\n", failed, path);
    }
    return loaded;
}

bool uid_file_has_entries(const char *path) {
    if (!path || path[0] == '\0') return false;

    FILE *file = fopen(path, "r");
    if (!file) return false;

    char line[128];
    while (fgets(line, sizeof(line), file)) {
        uint32_t uid = 0;
        if (parse_uid(line, &uid)) {
            fclose(file);
            return true;
        }
    }

    fclose(file);
    return false;
}
