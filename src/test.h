#pragma once

/*
 * Test Helpers
 * Bunch of helpers to setup the environment for networking tests. This
 * includes net-namespace setups, veth setups, and more.
 */

#undef NDEBUG
#include <assert.h>
#include <c-stdaux.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

        r = mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL);
        c_assert(r >= 0);

        r = mount(NULL, "/run", "tmpfs", 0, NULL);
        c_assert(r >= 0);

        r = mkdir("/run/netns", 0755);
        c_assert(r >= 0);
}
