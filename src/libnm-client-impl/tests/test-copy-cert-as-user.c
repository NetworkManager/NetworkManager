/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* 
 * This is a program to manually test the
 * nm_utils_copy_cert_as_user() libnm function.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "nm-utils.h"

int
main(int argc, char **argv)
{
    gs_free_error GError *error    = NULL;
    gs_free char         *filename = NULL;

    if (argc != 3) {
        g_printerr("Usage: %s <FILE> <USER>\n", argv[0]);
        return 1;
    }

    filename = nm_utils_copy_cert_as_user(argv[1], argv[2], &error);
    if (!filename) {
        g_printerr("Error: %s\n", error->message);
        return 1;
    }

    g_print("%s\n", filename);

    return 0;
}
