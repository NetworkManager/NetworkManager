#pragma once

/*
 * Test Helpers
 * Bunch of helpers to setup the environment for networking tests. This
 * includes net-namespace setups, veth setups, and more.
 */

#undef NDEBUG
#include <assert.h>
#include <c-stdaux.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "n-acd.h"

static inline void test_add_child_ip(const struct in_addr *addr) {
        char *p;
        int r;

        r = asprintf(&p, "ip addr add dev veth1 %s/8", inet_ntoa(*addr));
        c_assert(r >= 0);

        r = system(p);
        c_assert(r >= 0);

        free(p);
}

static inline void test_del_child_ip(const struct in_addr *addr) {
        char *p;
        int r;

        r = asprintf(&p, "ip addr del dev veth1 %s/8", inet_ntoa(*addr));
        c_assert(r >= 0);

        r = system(p);
        c_assert(r >= 0);

        free(p);
}

static inline void test_if_query(const char *name, int *indexp, struct ether_addr *macp) {
        struct ifreq ifr = {};
        size_t l;
        int r, s;

        l = strlen(name);
        c_assert(l <= IF_NAMESIZE);

        if (indexp) {
                *indexp = if_nametoindex(name);
                c_assert(*indexp > 0);
        }

        if (macp) {
                s = socket(AF_INET, SOCK_DGRAM, 0);
                c_assert(s >= 0);

                strncpy(ifr.ifr_name, name, l + 1);
                r = ioctl(s, SIOCGIFHWADDR, &ifr);
                c_assert(r >= 0);

                memcpy(macp->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

                close(s);
        }
}

static inline void test_veth_cmd(int ifindex, const char *cmd) {
        char *p, name[IF_NAMESIZE + 1] = {};
        int r;

        p = if_indextoname(ifindex, name);
        c_assert(p);

        r = asprintf(&p, "ip link set %s %s", name, cmd);
        c_assert(r >= 0);

        /* Again: Ewwww... */
        r = system(p);
        c_assert(r == 0);

        free(p);
}

static inline void test_veth_new(int *parent_indexp,
                                 struct ether_addr *parent_macp,
                                 int *child_indexp,
                                 struct ether_addr *child_macp) {
        int r;

        /* Eww... but it works. */
        r = system("ip link add type veth");
        c_assert(r == 0);
        r = system("ip link set veth0 up");
        c_assert(r == 0);
        r = system("ip link set veth1 up");
        c_assert(r == 0);

        test_if_query("veth0", parent_indexp, parent_macp);
        test_if_query("veth1", child_indexp, child_macp);
}

static inline void test_loopback_up(int *indexp, struct ether_addr *macp) {
        int r;

        r = system("ip link set lo up");
        c_assert(r == 0);

        test_if_query("lo", indexp, macp);
}

static inline void test_raise_memlock(void) {
        const size_t wanted = 64 * 1024 * 1024;
        struct rlimit get, set;
        int r;

        r = getrlimit(RLIMIT_MEMLOCK, &get);
        c_assert(!r);

        /* try raising limit to @wanted */
        set.rlim_cur = wanted;
        set.rlim_max = (wanted > get.rlim_max) ? wanted : get.rlim_max;
        r = setrlimit(RLIMIT_MEMLOCK, &set);
        if (r) {
                c_assert(errno == EPERM);

                /* not privileged to raise limit, so maximize soft limit */
                set.rlim_cur = get.rlim_max;
                set.rlim_max = get.rlim_max;
                r = setrlimit(RLIMIT_MEMLOCK, &set);
                c_assert(!r);
        }
}

static inline void test_unshare_user_namespace(void) {
        uid_t euid;
        gid_t egid;
        int r, fd;

        /*
         * Enter a new user namespace as root:root.
         */

        euid = geteuid();
        egid = getegid();

        r = unshare(CLONE_NEWUSER);
        c_assert(r >= 0);

        fd = open("/proc/self/uid_map", O_WRONLY);
        c_assert(fd >= 0);
        r = dprintf(fd, "0 %d 1\n", euid);
        c_assert(r >= 0);
        close(fd);

        fd = open("/proc/self/setgroups", O_WRONLY);
        c_assert(fd >= 0);
        r = dprintf(fd, "deny");
        c_assert(r >= 0);
        close(fd);

        fd = open("/proc/self/gid_map", O_WRONLY);
        c_assert(fd >= 0);
        r = dprintf(fd, "0 %d 1\n", egid);
        c_assert(r >= 0);
        close(fd);
}

static inline void test_setup(void) {
        int r;

        /*
         * Move into a new network and mount namespace both associated
         * with a new user namespace where the current eUID is mapped to
         * 0. Then create a a private instance of /run/netns. This ensures
         * that any network devices or network namespaces are private to
         * the test process.
         */

        test_raise_memlock();
        test_unshare_user_namespace();

        r = unshare(CLONE_NEWNET | CLONE_NEWNS);
        c_assert(r >= 0);

        r = mount(NULL, "/", "", MS_PRIVATE | MS_REC, NULL);
        c_assert(r >= 0);

        r = mount(NULL, "/run", "tmpfs", 0, NULL);
        c_assert(r >= 0);

        r = mkdir("/run/netns", 0755);
        c_assert(r >= 0);
}
