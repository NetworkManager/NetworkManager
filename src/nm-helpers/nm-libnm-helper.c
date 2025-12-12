/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-std-aux/nm-default-std.h"

#include <stdio.h>

enum {
    RETURN_SUCCESS      = 0,
    RETURN_INVALID_CMD  = 1,
    RETURN_INVALID_ARGS = 2,
    RETURN_ERROR        = 3,
};

static int
read_file_as_user(const char *filename, const char *user)
{
    char error[1024];

    if (!nm_utils_set_effective_user(user, error, sizeof(error))) {
        fprintf(stderr, "Failed to set effective user '%s': %s", user, error);
        return RETURN_ERROR;
    }

    if (!nm_utils_read_file_to_stdout(filename, error, sizeof(error))) {
        fprintf(stderr, "Failed to read file '%s' as user '%s': %s", filename, user, error);
        return RETURN_ERROR;
    }

    return RETURN_SUCCESS;
}

int
main(int argc, char **argv)
{
    if (argc <= 1)
        return RETURN_INVALID_CMD;

    if (nm_streq(argv[1], "read-file-as-user")) {
        if (argc != 4)
            return RETURN_INVALID_ARGS;
        return read_file_as_user(argv[2], argv[3]);
    }

    return RETURN_INVALID_CMD;
}