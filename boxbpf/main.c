// SPDX-License-Identifier: GPL-3.0-or-later

#include "common.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static void raise_memlock(void) {
    struct rlimit unlimited = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &unlimited);
}

struct fds {
    int cidr4;
    int cidr6;
    int force_uid;
    int app_uid;
};

static void init_fds(struct fds *fds) {
    fds->cidr4 = -1;
    fds->cidr6 = -1;
    fds->force_uid = -1;
    fds->app_uid = -1;
}

static void close_fds(struct fds *fds) {
    close_fd(fds->cidr4);
    close_fd(fds->cidr6);
    close_fd(fds->force_uid);
    close_fd(fds->app_uid);
    init_fds(fds);
}

static const char *arg_value(int argc, char **argv, const char *flag) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], flag) == 0) return argv[i + 1];
    }
    return NULL;
}

static bool has_arg(int argc, char **argv, const char *flag) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], flag) == 0) return true;
    }
    return false;
}

static void print_usage(const char *argv0) {
    fprintf(
        stderr,
        "Usage: %s --probe [--ipv6 1]\n"
        "       %s --init --config FILE\n"
        "       %s --apply --config FILE\n"
        "       %s --update --config FILE\n"
        "       %s --clear\n",
        argv0,
        argv0,
        argv0,
        argv0,
        argv0
    );
}

static int create_cidr_map(const char *source, const char *pin_path, bool ipv6, int *fd_out) {
    *fd_out = create_map(
        BPF_MAP_TYPE_LPM_TRIE,
        ipv6 ? sizeof(struct lpm6_key) : sizeof(struct lpm4_key),
        sizeof(uint8_t),
        MAX_CIDRS,
        COMPAT_MAP_NO_PREALLOC
    );
    if (*fd_out < 0) {
        fprintf(stderr, "create IPv%d CIDR map failed: errno=%d (%s)\n", ipv6 ? 6 : 4, errno, strerror(errno));
        return STATUS_CONFIG_ERROR;
    }

    load_cidr_file(*fd_out, source, ipv6);
    return pin_replace(*fd_out, pin_path) == 0 ? STATUS_OK : STATUS_CONFIG_ERROR;
}

static int create_uid_map(const char *source, const char *pin_path, bool required, int *fd_out) {
    *fd_out = create_map(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint8_t), MAX_UIDS, 0);
    if (*fd_out < 0) {
        fprintf(stderr, "create UID map failed: errno=%d (%s)\n", errno, strerror(errno));
        return STATUS_CONFIG_ERROR;
    }

    int loaded = load_uid_file(*fd_out, source);
    if (required && loaded <= 0) {
        fprintf(stderr, "required UID map is empty: %s\n", source ? source : "-");
        return STATUS_CONFIG_ERROR;
    }

    return pin_replace(*fd_out, pin_path) == 0 ? STATUS_OK : STATUS_CONFIG_ERROR;
}

static int pin_program(const char *section, const char *name, const char *pin_path, const struct fds *fds) {
    int fd = load_program(section, name, fds->cidr4, fds->cidr6, fds->force_uid, fds->app_uid);
    if (fd < 0) return STATUS_CONFIG_ERROR;

    int rc = pin_replace(fd, pin_path);
    close(fd);
    return rc == 0 ? STATUS_OK : STATUS_CONFIG_ERROR;
}

static int apply_config(const struct config *config) {
    remove_known_pins();

    int status = STATUS_CONFIG_ERROR;
    struct fds fds;
    init_fds(&fds);

    bool app_uid_required = uid_file_has_entries(config->app_uid_file);
    if (create_cidr_map(config->cidr4_file, config->map_cidr4, false, &fds.cidr4) != STATUS_OK) goto cleanup;
    if (create_cidr_map(config->cidr6_file, config->map_cidr6, true, &fds.cidr6) != STATUS_OK) goto cleanup;
    if (create_uid_map(config->force_uid_file, config->map_force_uid, false, &fds.force_uid) != STATUS_OK) goto cleanup;
    if (create_uid_map(config->app_uid_file, config->map_app_uid, app_uid_required, &fds.app_uid) != STATUS_OK) goto cleanup;

    if (pin_program("socket/cidr4", "cidr4", config->pin_cidr_out4, &fds) != STATUS_OK) goto cleanup;
    if (pin_program("socket/cidr4", "pre4", config->pin_cidr_pre4, &fds) != STATUS_OK) goto cleanup;
    if (pin_program("socket/force4", "force4", config->pin_force_out4, &fds) != STATUS_OK) goto cleanup;
    if (pin_program("socket/appuid", "app4", config->pin_app_out4, &fds) != STATUS_OK) goto cleanup;

    if (config->ipv6) {
        if (pin_program("socket/cidr6", "cidr6", config->pin_cidr_out6, &fds) != STATUS_OK) goto cleanup;
        if (pin_program("socket/cidr6", "pre6", config->pin_cidr_pre6, &fds) != STATUS_OK) goto cleanup;
        if (pin_program("socket/force6", "force6", config->pin_force_out6, &fds) != STATUS_OK) goto cleanup;
        if (pin_program("socket/appuid", "app6", config->pin_app_out6, &fds) != STATUS_OK) goto cleanup;
    }

    status = STATUS_OK;

cleanup:
    if (status != STATUS_OK) remove_known_pins();
    close_fds(&fds);
    return status;
}

static int update_config(const struct config *config) {
    int cidr4 = get_pinned(config->map_cidr4);
    int cidr6 = get_pinned(config->map_cidr6);
    int force_uid = get_pinned(config->map_force_uid);
    int app_uid = get_pinned(config->map_app_uid);

    if (cidr4 < 0 || (config->ipv6 && cidr6 < 0) || force_uid < 0 || app_uid < 0) {
        close_fd(cidr4);
        close_fd(cidr6);
        close_fd(force_uid);
        close_fd(app_uid);
        return apply_config(config);
    }

    int status = STATUS_OK;
    if (clear_map(cidr4, sizeof(struct lpm4_key)) < 0) status = STATUS_UPDATE_ERROR;
    load_cidr_file(cidr4, config->cidr4_file, false);
    if (config->ipv6) {
        if (clear_map(cidr6, sizeof(struct lpm6_key)) < 0) status = STATUS_UPDATE_ERROR;
        load_cidr_file(cidr6, config->cidr6_file, true);
    }
    if (clear_map(force_uid, sizeof(uint32_t)) < 0) status = STATUS_UPDATE_ERROR;
    load_uid_file(force_uid, config->force_uid_file);
    if (clear_map(app_uid, sizeof(uint32_t)) < 0) status = STATUS_UPDATE_ERROR;
    load_uid_file(app_uid, config->app_uid_file);

    close_fd(cidr4);
    close_fd(cidr6);
    close_fd(force_uid);
    close_fd(app_uid);
    return status;
}

static int run_with_config(const char *config_path, bool update_only) {
    struct config config;
    if (!read_config_json(config_path, &config)) return STATUS_CONFIG_ERROR;
    return update_only ? update_config(&config) : apply_config(&config);
}

static int probe_runtime(bool ipv6) {
    struct config config;
    config_defaults(&config);
    snprintf(config.map_cidr4, sizeof(config.map_cidr4), "%s", PROBE_MAP_CIDR4);
    snprintf(config.map_cidr6, sizeof(config.map_cidr6), "%s", PROBE_MAP_CIDR6);
    snprintf(config.map_force_uid, sizeof(config.map_force_uid), "%s", PROBE_MAP_FORCE_UID);
    snprintf(config.map_app_uid, sizeof(config.map_app_uid), "%s", PROBE_MAP_APP_UID);

    struct fds fds;
    init_fds(&fds);
    bool ok = false;

    if (create_cidr_map("/dev/null", config.map_cidr4, false, &fds.cidr4) != STATUS_OK) goto cleanup;
    if (create_cidr_map("/dev/null", config.map_cidr6, true, &fds.cidr6) != STATUS_OK) goto cleanup;
    if (create_uid_map("", config.map_force_uid, false, &fds.force_uid) != STATUS_OK) goto cleanup;
    if (create_uid_map("", config.map_app_uid, false, &fds.app_uid) != STATUS_OK) goto cleanup;

    ok = pin_program("socket/cidr4", "probe4", PROBE_PIN4, &fds) == STATUS_OK;
    if (ipv6) {
        ok = pin_program("socket/cidr6", "probe6", PROBE_PIN6, &fds) == STATUS_OK && ok;
    }

cleanup:
    close_fds(&fds);
    unlink(PROBE_PIN4);
    unlink(PROBE_PIN6);
    unlink(config.map_cidr4);
    unlink(config.map_cidr6);
    unlink(config.map_force_uid);
    unlink(config.map_app_uid);
    rmdir(PIN_DIR);

    printf("supported=%d\n", ok ? 1 : 0);
    printf("message=%s\n", ok ? "ok" : "eBPF xt_bpf unavailable");
    printf("lpm_ipv4=%d\n", ok ? 1 : 0);
    printf("program_ipv4=%d\n", ok ? 1 : 0);
    printf("pin_ipv4=%d\n", ok ? 1 : 0);
    if (ipv6) {
        printf("lpm_ipv6=%d\n", ok ? 1 : 0);
        printf("program_ipv6=%d\n", ok ? 1 : 0);
        printf("pin_ipv6=%d\n", ok ? 1 : 0);
    }
    return ok ? STATUS_OK : STATUS_UNSUPPORTED;
}

int main(int argc, char **argv) {
    raise_memlock();

    if (has_arg(argc, argv, "--clear")) {
        remove_known_pins();
        return STATUS_OK;
    }

    if (has_arg(argc, argv, "--probe")) {
        const char *ipv6 = arg_value(argc, argv, "--ipv6");
        return probe_runtime(ipv6 && strcmp(ipv6, "1") == 0);
    }

    const char *config = arg_value(argc, argv, "--config");
    if (has_arg(argc, argv, "--init") || has_arg(argc, argv, "--apply")) {
        if (!config) {
            fprintf(stderr, "--config is required\n");
            return STATUS_CONFIG_ERROR;
        }
        return run_with_config(config, false);
    }

    if (has_arg(argc, argv, "--update")) {
        if (!config) {
            fprintf(stderr, "--config is required\n");
            return STATUS_CONFIG_ERROR;
        }
        return run_with_config(config, true);
    }

    print_usage(argv[0]);
    return STATUS_CONFIG_ERROR;
}
