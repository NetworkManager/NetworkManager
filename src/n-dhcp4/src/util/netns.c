/*
 * Network Namespaces
 *
 * This is meant for testing-purposes only. It is not meant to be used outside
 * of our unit-tests!
 */

#include <assert.h>
#include <c-stdaux.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>
#include "netns.h"

/**
 * netns_new() - create a new network namespace
 * @netnsp:             output argument to store netns fd
 *
 * This creates a new network namespace and returns a netns fd that refers to
 * the new network namespace. Note that there is no native API to create an
 * anonymous network namespace, so this call has to temporarily switch to a new
 * network namespace (using unshare(2)). This temporary switch does not affect
 * any other threads or processes, however, it can be observed by other
 * processes.
 */
void netns_new(int *netnsp) {
        int r, oldns;

        netns_get(&oldns);

        r = unshare(CLONE_NEWNET);
        c_assert(r >= 0);

        netns_get(netnsp);
        netns_set(oldns);
}

/**
 * netns_new_dup() - duplicate network namespace descriptor
 * @newnsp:             output argument for duplicated descriptor
 * @netns:              netns descriptor to duplicate
 *
 * This duplicates the network namespace file descriptor. The duplicate still
 * refers to the same network namespace, but is an independent file descriptor.
 */
void netns_new_dup(int *newnsp, int netns) {
        *newnsp = fcntl(netns, F_DUPFD_CLOEXEC, 0);
        c_assert(*newnsp >= 0);
}

/**
 * netns_close() - destroy a network namespace descriptor
 * @netns:              netns to operate on, or <0
 *
 * This closes the given network namespace descriptor. If @netns is negative,
 * this is a no-op.
 *
 * Return: -1 is returned.
 */
int netns_close(int netns) {
        return c_close(netns);
}

/**
 * netns_get() - retrieve the current network namespace
 * @netnsp:             output argument to store netns fd
 *
 * This retrieves a file-descriptor to the current network namespace.
 */
void netns_get(int *netnsp) {
        *netnsp = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        c_assert(*netnsp >= 0);
}

/**
 * setns_set() - change the current network namespace
 * @netns:              netns to set
 *
 * This changes the current network namespace to the netns given by the
 * file-descriptor @netns.
 */
void netns_set(int netns) {
        int r;

        r = setns(netns, CLONE_NEWNET);
        c_assert(r >= 0);
}

/**
 * netns_set_anonymous() - enter an anonymous network namespace
 *
 * This is a helper that creates a new network namespace, enters it, and then
 * forgets about it.
 */
void netns_set_anonymous(void) {
        int r;

        r = unshare(CLONE_NEWNET);
        c_assert(r >= 0);
}

/**
 * netns_pin() - pin network namespace in file-system
 * @netns:              netns to pin
 * @name:               name to pin netns under
 *
 * This pins the network namespace given as @netns in the file-system as
 * `/run/netns/@name`. It is the responsibility of the caller to guarantee
 * @name is not used by anyone else in parallel. This function will abort if
 * @name is already in use.
 *
 * The namespace in `/run/netns/` is compatible with the namespace provided by
 * the ip(1) tool, and can be used to pass network namespaces to invocations of
 * ip(1).
 */
void netns_pin(int netns, const char *name) {
        char *fd_path, *netns_path;
        int r, fd;

        r = asprintf(&fd_path, "/proc/self/fd/%d", netns);
        c_assert(r >= 0);

        r = asprintf(&netns_path, "/run/netns/%s", name);
        c_assert(r >= 0);

        fd = open(netns_path, O_RDONLY|O_CLOEXEC|O_CREAT|O_EXCL, 0);
        c_assert(fd >= 0);
        close(fd);

        r = mount(fd_path, netns_path, "none", MS_BIND, NULL);
        c_assert(r >= 0);

        free(netns_path);
        free(fd_path);
}

/**
 * netns_unpin() - unpin network namespace from file-system
 * @name:               name to unpin
 *
 * This removes a network namespace pin from the file-system. It expects the
 * pin to be located at `/run/netns/@name`. This function aborts if the pin
 * does not exist.
 *
 * See netns_pin() for ways to create such pins.
 */
void netns_unpin(const char *name) {
        char *netns_path;
        int r;

        r = asprintf(&netns_path, "/run/netns/%s", name);
        c_assert(r >= 0);

        r = umount2(netns_path, MNT_DETACH);
        c_assert(r >= 0);

        r = unlink(netns_path);
        c_assert(r >= 0);

        free(netns_path);
}
