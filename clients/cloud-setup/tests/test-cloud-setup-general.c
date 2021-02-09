/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "libnm/nm-default-client.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

NMTST_DEFINE();

int
main(int argc, char **argv)
{
    nmtst_init(&argc, &argv, TRUE);

    return g_test_run();
}
