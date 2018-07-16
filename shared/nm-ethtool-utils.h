/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#ifndef __NM_ETHTOOL_UTILS_H__
#define __NM_ETHTOOL_UTILS_H__

/*****************************************************************************/

typedef enum {
	NM_ETHTOOL_ID_UNKNOWN = -1,

	_NM_ETHTOOL_ID_FIRST = 0,

	_NM_ETHTOOL_ID_FEATURE_FIRST = _NM_ETHTOOL_ID_FIRST,
	NM_ETHTOOL_ID_FEATURE_GRO = _NM_ETHTOOL_ID_FEATURE_FIRST,
	NM_ETHTOOL_ID_FEATURE_GSO,
	NM_ETHTOOL_ID_FEATURE_LRO,
	NM_ETHTOOL_ID_FEATURE_NTUPLE,
	NM_ETHTOOL_ID_FEATURE_RX,
	NM_ETHTOOL_ID_FEATURE_RXHASH,
	NM_ETHTOOL_ID_FEATURE_RXVLAN,
	NM_ETHTOOL_ID_FEATURE_SG,
	NM_ETHTOOL_ID_FEATURE_TSO,
	NM_ETHTOOL_ID_FEATURE_TX,
	NM_ETHTOOL_ID_FEATURE_TXVLAN,
	NM_ETHTOOL_ID_FEATURE_TX_TCP6_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_TCP_SEGMENTATION,
	_NM_ETHTOOL_ID_FEATURE_LAST = NM_ETHTOOL_ID_FEATURE_TX_TCP_SEGMENTATION,
	_NM_ETHTOOL_ID_FEATURE_NUM = (_NM_ETHTOOL_ID_FEATURE_LAST - _NM_ETHTOOL_ID_FEATURE_FIRST + 1),

	_NM_ETHTOOL_ID_LAST = _NM_ETHTOOL_ID_FEATURE_LAST,

	_NM_ETHTOOL_ID_NUM = (_NM_ETHTOOL_ID_LAST - _NM_ETHTOOL_ID_FIRST + 1),
} NMEthtoolID;

typedef struct {
	const char *optname;
	NMEthtoolID id;
} NMEthtoolData;

extern const NMEthtoolData *const nm_ethtool_data[/*_NM_ETHTOOL_ID_NUM + NULL-terminated*/];

const NMEthtoolData *nm_ethtool_data_get_by_optname (const char *optname);

/****************************************************************************/

static inline NMEthtoolID
nm_ethtool_id_get_by_name (const char *optname)
{
	const NMEthtoolData *d;

	d = nm_ethtool_data_get_by_optname (optname);
	return d ? d->id : NM_ETHTOOL_ID_UNKNOWN;
}

static inline gboolean
nm_ethtool_id_is_feature (NMEthtoolID id)
{
	return id >= _NM_ETHTOOL_ID_FEATURE_FIRST && id <= _NM_ETHTOOL_ID_FEATURE_LAST;
}

/****************************************************************************/

#endif /* __NM_ETHTOOL_UTILS_H__ */
