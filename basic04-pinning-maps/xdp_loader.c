/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
                             " - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "common_kern_user.h"

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

    {{"help", no_argument, NULL, 'h'},
     "Show help",
     false},

    {{"dev", required_argument, NULL, 'd'},
     "Operate on device <ifname>",
     "<ifname>",
     true},

    {{"skb-mode", no_argument, NULL, 'S'},
     "Install XDP program in SKB (AKA generic) mode"},

    {{"native-mode", no_argument, NULL, 'N'},
     "Install XDP program in native mode"},

    {{"auto-mode", no_argument, NULL, 'A'},
     "Auto-detect SKB or native mode"},

    {{"force", no_argument, NULL, 'F'},
     "Force install, replacing existing program on interface"},

    {{"unload", no_argument, NULL, 'U'},
     "Unload XDP program instead of loading"},

    {{"reuse-maps", no_argument, NULL, 'M'},
     "Reuse pinned maps"},

    {{"quiet", no_argument, NULL, 'q'},
     "Quiet mode (no output)"},

    {{"filename", required_argument, NULL, 1},
     "Load program from <file>",
     "<file>"},

    {{"progname", required_argument, NULL, 2},
     "Load program from function <name> in the ELF file",
     "<name>"},

    {{0, 0, NULL, 0}, NULL, false}};

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";
const char *map_name = "xdp_stats_map";

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
    char pin_dir[PATH_MAX], map_filename[PATH_MAX];
    int len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg->ifname);

    if (len < 0)
    {
        perror("Creating pin dirname");
        return EXIT_FAIL_OPTION;
    }

    len = snprintf(map_filename, PATH_MAX, "%s/%s/%s", pin_basedir, cfg->ifname, map_name);
    if (len < 0)
    {
        perror("Creating map_name");
        return EXIT_FAIL_OPTION;
    }

    /* Existing/previous XDP prog might not have cleaned up */
    if (access(map_filename, F_OK) != -1)
    {
        if (verbose)
            printf(" - Unpinning (remove) prev maps in %s/\n", pin_dir);

        if (bpf_object__unpin_maps(bpf_obj, pin_dir))
        {
            perror("UNpinning maps");
            return EXIT_FAIL_BPF;
        }
    }
    if (verbose)
        printf(" - Pinning maps in %s/\n", pin_dir);

    if (bpf_object__pin_maps(bpf_obj, pin_dir))
        return EXIT_FAIL_BPF;

    return 0;
}

int load_prog_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
    struct bpf_program *bpf_prog = bpf_object__find_program_by_name(bpf_obj, cfg->progname);

    if (!bpf_prog)
    {
        perror("bpf_object__find_program_by_name");
        return EXIT_FAIL_BPF;
    }

    int prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd < 0)
    {
        perror("bpf_program__fd");
        return EXIT_FAIL_BPF;
    }

    if (bpf_xdp_attach(cfg->ifindex, prog_fd, cfg->attach_mode, NULL) < 0)
    {
        perror("bpf_xdp_attach");
        return EXIT_FAIL_BPF;
    }

    return 0;
    return 0;
}

int reuse_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
    char map_filename[PATH_MAX];
    int len = snprintf(map_filename, PATH_MAX, "%s/%s/%s", pin_basedir, cfg->ifname, map_name);

    if (len < 0)
    {
        perror("Creating map_name");
        return EXIT_FAIL_OPTION;
    }

    int map_fd = bpf_obj_get(map_filename);
    if (map_fd < 0)
    {
        perror("bpf_obj_get");
        return EXIT_FAIL_BPF;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xdp_stats_map");
    if (!map)
    {
        perror("bpf_object__find_map_by_name");
        return EXIT_FAIL_BPF;
    }

    if (bpf_map__reuse_fd(map, map_fd))
    {
        perror("bpf_map__reuse_fd");
        return EXIT_FAIL_BPF;
    }

    if (bpf_object__load(bpf_obj))
    {
        perror("bpf_object__load");
        return EXIT_FAIL_BPF;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct xdp_program *program;
    char errmsg[1024];
    int err;

    struct config cfg = {
        .attach_mode = XDP_MODE_NATIVE,
        .ifindex = -1,
        .do_unload = false,
    };
    /* Set default BPF-ELF object file and BPF program name */
    strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
    /* Cmdline options can change progname */
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    /* Required option */
    if (cfg.ifindex == -1)
    {
        fprintf(stderr, "ERR: required option --dev missing\n\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.do_unload)
    {
        /* TODO: Miss unpin of maps on unload */
		err = do_unload(&cfg);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't unload XDP program %s: %s\n",
				cfg.progname, errmsg);
			return err;
		}

		printf("Success: Unloading XDP prog name: %s\n", cfg.progname);
		return EXIT_OK;
    }

    if (!cfg.reuse_maps)
    {
        program = load_bpf_and_xdp_attach(&cfg);
        if (!program)
            return EXIT_FAIL_BPF;

        if (verbose)
        {
            printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
                   cfg.filename, cfg.progname);
            printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
                   cfg.ifname, cfg.ifindex);
        }

        if (pin_maps_in_bpf_object(xdp_program__bpf_obj(program), &cfg))
        {
            perror("Pinning maps");
            return EXIT_FAIL_BPF;
        }
    }
    else
    {
        struct bpf_object *bpf_obj = bpf_object__open(cfg.filename);

        if (libbpf_get_error(bpf_obj))
        {
            perror("bpf_object__open");
            return EXIT_FAIL_BPF;
        }

        if (reuse_maps_in_bpf_object(bpf_obj, &cfg) || load_prog_in_bpf_object(bpf_obj, &cfg))
        {
            return EXIT_FAIL_BPF;
        }

        if (verbose)
        {
            printf("Success: Loaded BPF-object(%s) and used program(%s)\n", cfg.filename, cfg.progname);
            printf(" - XDP prog attached on device:%s(ifindex:%d)\n", cfg.ifname, cfg.ifindex);
        }
    }

    return EXIT_OK;
}