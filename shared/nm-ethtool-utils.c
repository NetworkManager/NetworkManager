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

#include "nm-default.h"

#include "nm-ethtool-utils.h"

#include "nm-setting-ethtool.h"

/*****************************************************************************/

#define ETHT_DATA(xname) \
	[NM_ETHTOOL_ID_##xname] = (&((const NMEthtoolData) { \
	   .optname = NM_ETHTOOL_OPTNAME_##xname, \
	   .id = NM_ETHTOOL_ID_##xname, \
	}))

const NMEthtoolData *const nm_ethtool_data[_NM_ETHTOOL_ID_NUM + 1] = {
	/* indexed by NMEthtoolID */
	ETHT_DATA (FEATURE_GRO),
	ETHT_DATA (FEATURE_GSO),
	ETHT_DATA (FEATURE_LRO),
	ETHT_DATA (FEATURE_NTUPLE),
	ETHT_DATA (FEATURE_RX),
	ETHT_DATA (FEATURE_RXHASH),
	ETHT_DATA (FEATURE_RXVLAN),
	ETHT_DATA (FEATURE_SG),
	ETHT_DATA (FEATURE_TSO),
	ETHT_DATA (FEATURE_TX),
	ETHT_DATA (FEATURE_TXVLAN),
	[_NM_ETHTOOL_ID_NUM] = NULL,
};

const guint8 const _by_name[_NM_ETHTOOL_ID_NUM] = {
	/* sorted by optname. */
	NM_ETHTOOL_ID_FEATURE_GRO,
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
};

/*****************************************************************************/

static void
_ASSERT_data (void)
{
#if NM_MORE_ASSERTS > 10
	int i;

	G_STATIC_ASSERT_EXPR (_NM_ETHTOOL_ID_FIRST == 0);
	G_STATIC_ASSERT_EXPR (_NM_ETHTOOL_ID_LAST == _NM_ETHTOOL_ID_NUM - 1);
	G_STATIC_ASSERT_EXPR (_NM_ETHTOOL_ID_NUM > 0);

	nm_assert (NM_PTRARRAY_LEN (nm_ethtool_data) == _NM_ETHTOOL_ID_NUM);
	nm_assert (G_N_ELEMENTS (_by_name)           == _NM_ETHTOOL_ID_NUM);
	nm_assert (G_N_ELEMENTS (nm_ethtool_data)    == _NM_ETHTOOL_ID_NUM + 1);

	for (i = 0; i < _NM_ETHTOOL_ID_NUM; i++) {
		const NMEthtoolData *d = nm_ethtool_data[i];

		nm_assert (d);
		nm_assert (d->id == (NMEthtoolID) i);
		nm_assert (d->optname && d->optname[0]);
	}

	for (i = 0; i < _NM_ETHTOOL_ID_NUM; i++) {
		NMEthtoolID id = _by_name[i];
		const NMEthtoolData *d;

		nm_assert (id >= 0);
		nm_assert (id < _NM_ETHTOOL_ID_NUM);

		d = nm_ethtool_data[id];
		if (i > 0) {
			/* since we assert that all optnames are sorted strictly monotonically increasing,
			 * it also follows that there are no duplicates in the _by_name.
			 * It also follows, that all names in nm_ethtool_data are unique. */
			if (strcmp (nm_ethtool_data[_by_name[i - 1]]->optname, d->optname) >= 0) {
				g_error ("nm_ethtool_data is not sorted asciibetically: %u/%s should be after %u/%s",
				         i - 1, nm_ethtool_data[_by_name[i - 1]]->optname,
				         i, d->optname);
			}
		}
	}
#endif
}

static int
_by_name_cmp (gconstpointer a,
              gconstpointer b,
              gpointer user_data)
{
	const guint8 *p_id = a;
	const char *optname = b;

	nm_assert (p_id && p_id >= _by_name && p_id <= &_by_name[_NM_ETHTOOL_ID_NUM]);
	nm_assert (*p_id < _NM_ETHTOOL_ID_NUM);

	return strcmp (nm_ethtool_data[*p_id]->optname, optname);
}

const NMEthtoolData *
nm_ethtool_data_get_by_optname (const char *optname)
{
	gssize idx;

	nm_assert (optname);

	_ASSERT_data ();

	idx = nm_utils_array_find_binary_search ((gconstpointer *) _by_name,
	                                         sizeof (_by_name[0]),
	                                         _NM_ETHTOOL_ID_NUM,
	                                         optname,
	                                         _by_name_cmp,
	                                         NULL);
	return (idx < 0) ? NULL : nm_ethtool_data[_by_name[idx]];
}
