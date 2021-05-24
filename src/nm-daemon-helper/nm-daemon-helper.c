/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Copyright (C) 2021 Red Hat, Inc. */

#include <stdio.h>
#include <stdlib.h>

#include "libnm-std-aux/nm-std-aux.h"

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

int
main(int argc, char **argv)
{
    nm_auto_free char *cmd = NULL;

    cmd = read_arg();
    if (!cmd)
        return RETURN_INVALID_CMD;

    if (nm_streq(cmd, "version")) {
        return cmd_version();
    }

    return RETURN_INVALID_CMD;
}
