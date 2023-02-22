/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Copyright (C) 2021 Red Hat, Inc. */

#include "libnm-std-aux/nm-default-std.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
#if defined(__GLIBC__)
#include <nss.h>
#endif
#include <stdarg.h>

enum {
    RETURN_SUCCESS      = 0,
    RETURN_INVALID_CMD  = 1,
    RETURN_INVALID_ARGS = 2,
    RETURN_ERROR        = 3,
};

static char *
read_arg(void)
{
    nm_auto_free char *arg = NULL;
    size_t             len = 0;

    if (getdelim(&arg, &len, '\0', stdin) < 0)
        return NULL;

    return nm_steal_pointer(&arg);
}

static int
more_args(void)
{
    nm_auto_free char *arg = NULL;

    arg = read_arg();

    return !!arg;
}

static int
cmd_version(void)
{
    if (more_args())
        return RETURN_INVALID_ARGS;

    printf("1");
    return RETURN_SUCCESS;
}

static int
cmd_resolve_address(void)
{
    nm_auto_free char *address = NULL;
    union {
        struct sockaddr_in  in;
        struct sockaddr_in6 in6;
    } sockaddr;
    socklen_t sockaddr_size;
    char      name[NI_MAXHOST];
    int       ret;

    address = read_arg();
    if (!address)
        return RETURN_INVALID_ARGS;

    if (more_args())
        return RETURN_INVALID_ARGS;

    memset(&sockaddr, 0, sizeof(sockaddr));
#if defined(__GLIBC__)
    __nss_configure_lookup("hosts", "dns");
#endif

    if (inet_pton(AF_INET, address, &sockaddr.in.sin_addr) == 1) {
        sockaddr.in.sin_family = AF_INET;
        sockaddr_size          = sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, address, &sockaddr.in6.sin6_addr) == 1) {
        sockaddr.in6.sin6_family = AF_INET6;
        sockaddr_size            = sizeof(struct sockaddr_in6);
    } else
        return RETURN_INVALID_ARGS;

    ret = getnameinfo((struct sockaddr *) &sockaddr,
                      sockaddr_size,
                      name,
                      sizeof(name),
                      NULL,
                      0,
                      NI_NAMEREQD);
    if (ret != 0) {
        if (ret == EAI_SYSTEM) {
            fprintf(stderr,
                    "getnameinfo() failed: %d (%s), system error: %d (%s)\n",
                    ret,
                    gai_strerror(ret),
                    errno,
                    strerror(errno));
        } else {
            fprintf(stderr, "getnameinfo() failed: %d (%s)\n", ret, gai_strerror(ret));
        }
        return RETURN_ERROR;
    }

    printf("%s", name);

    return RETURN_SUCCESS;
}

int
main(int argc, char **argv)
{
    nm_auto_free char *cmd = NULL;

    cmd = read_arg();
    if (!cmd)
        return RETURN_INVALID_CMD;

    if (nm_streq(cmd, "version"))
        return cmd_version();
    if (nm_streq(cmd, "resolve-address"))
        return cmd_resolve_address();

    return RETURN_INVALID_CMD;
}
