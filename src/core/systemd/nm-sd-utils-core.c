/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "src/core/systemd/nm-default-systemd.h"

#include "nm-sd-utils-core.h"

#include "libnm-core-intern/nm-core-internal.h"

#include "nm-sd-adapt-core.h"

#include "sd-id128.h"

/*****************************************************************************/

NMUuid *
nm_sd_utils_id128_get_machine(NMUuid *out_uuid)
{
    g_assert(out_uuid);

    G_STATIC_ASSERT_EXPR(sizeof(*out_uuid) == sizeof(sd_id128_t));
    if (sd_id128_get_machine((sd_id128_t *) out_uuid) < 0)
        return NULL;
    return out_uuid;
}
