/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_ETHTOOL_BASE_H__
#define __NM_ETHTOOL_BASE_H__

#include "nm-base/nm-base.h"

/*****************************************************************************/

typedef struct {
    const char *optname;
    NMEthtoolID id;
} NMEthtoolData;

extern const NMEthtoolData *const nm_ethtool_data[_NM_ETHTOOL_ID_NUM + 1];

const NMEthtoolData *nm_ethtool_data_get_by_optname(const char *optname);

NMEthtoolType nm_ethtool_id_to_type(NMEthtoolID id);

/****************************************************************************/

static inline NMEthtoolID
nm_ethtool_id_get_by_name(const char *optname)
{
    const NMEthtoolData *d;

    d = nm_ethtool_data_get_by_optname(optname);
    return d ? d->id : NM_ETHTOOL_ID_UNKNOWN;
}

/****************************************************************************/

#endif /* __NM_ETHTOOL_BASE_H__ */
