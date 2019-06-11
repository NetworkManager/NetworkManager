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
	ETHT_DATA (FEATURE_ESP_HW_OFFLOAD),
	ETHT_DATA (FEATURE_ESP_TX_CSUM_HW_OFFLOAD),
	ETHT_DATA (FEATURE_FCOE_MTU),
	ETHT_DATA (FEATURE_GRO),
	ETHT_DATA (FEATURE_GSO),
	ETHT_DATA (FEATURE_HIGHDMA),
	ETHT_DATA (FEATURE_HW_TC_OFFLOAD),
	ETHT_DATA (FEATURE_L2_FWD_OFFLOAD),
	ETHT_DATA (FEATURE_LOOPBACK),
	ETHT_DATA (FEATURE_LRO),
	ETHT_DATA (FEATURE_NTUPLE),
	ETHT_DATA (FEATURE_RX),
	ETHT_DATA (FEATURE_RXHASH),
	ETHT_DATA (FEATURE_RXVLAN),
	ETHT_DATA (FEATURE_RX_ALL),
	ETHT_DATA (FEATURE_RX_FCS),
	ETHT_DATA (FEATURE_RX_GRO_HW),
	ETHT_DATA (FEATURE_RX_UDP_TUNNEL_PORT_OFFLOAD),
	ETHT_DATA (FEATURE_RX_VLAN_FILTER),
	ETHT_DATA (FEATURE_RX_VLAN_STAG_FILTER),
	ETHT_DATA (FEATURE_RX_VLAN_STAG_HW_PARSE),
	ETHT_DATA (FEATURE_SG),
	ETHT_DATA (FEATURE_TLS_HW_RECORD),
	ETHT_DATA (FEATURE_TLS_HW_TX_OFFLOAD),
	ETHT_DATA (FEATURE_TSO),
	ETHT_DATA (FEATURE_TX),
	ETHT_DATA (FEATURE_TXVLAN),
	ETHT_DATA (FEATURE_TX_CHECKSUM_FCOE_CRC),
	ETHT_DATA (FEATURE_TX_CHECKSUM_IPV4),
	ETHT_DATA (FEATURE_TX_CHECKSUM_IPV6),
	ETHT_DATA (FEATURE_TX_CHECKSUM_IP_GENERIC),
	ETHT_DATA (FEATURE_TX_CHECKSUM_SCTP),
	ETHT_DATA (FEATURE_TX_ESP_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_FCOE_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_GRE_CSUM_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_GRE_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_GSO_PARTIAL),
	ETHT_DATA (FEATURE_TX_GSO_ROBUST),
	ETHT_DATA (FEATURE_TX_IPXIP4_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_IPXIP6_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_NOCACHE_COPY),
	ETHT_DATA (FEATURE_TX_SCATTER_GATHER),
	ETHT_DATA (FEATURE_TX_SCATTER_GATHER_FRAGLIST),
	ETHT_DATA (FEATURE_TX_SCTP_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_TCP6_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_TCP_ECN_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_TCP_MANGLEID_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_TCP_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_UDP_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_UDP_TNL_CSUM_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_UDP_TNL_SEGMENTATION),
	ETHT_DATA (FEATURE_TX_VLAN_STAG_HW_INSERT),
	[_NM_ETHTOOL_ID_NUM] = NULL,
};

static const guint8 _by_name[_NM_ETHTOOL_ID_NUM] = {
	/* sorted by optname. */
	NM_ETHTOOL_ID_FEATURE_ESP_HW_OFFLOAD,
	NM_ETHTOOL_ID_FEATURE_ESP_TX_CSUM_HW_OFFLOAD,
	NM_ETHTOOL_ID_FEATURE_FCOE_MTU,
	NM_ETHTOOL_ID_FEATURE_GRO,
	NM_ETHTOOL_ID_FEATURE_GSO,
	NM_ETHTOOL_ID_FEATURE_HIGHDMA,
	NM_ETHTOOL_ID_FEATURE_HW_TC_OFFLOAD,
	NM_ETHTOOL_ID_FEATURE_L2_FWD_OFFLOAD,
	NM_ETHTOOL_ID_FEATURE_LOOPBACK,
	NM_ETHTOOL_ID_FEATURE_LRO,
	NM_ETHTOOL_ID_FEATURE_NTUPLE,
	NM_ETHTOOL_ID_FEATURE_RX,
	NM_ETHTOOL_ID_FEATURE_RX_ALL,
	NM_ETHTOOL_ID_FEATURE_RX_FCS,
	NM_ETHTOOL_ID_FEATURE_RX_GRO_HW,
	NM_ETHTOOL_ID_FEATURE_RX_UDP_TUNNEL_PORT_OFFLOAD,
	NM_ETHTOOL_ID_FEATURE_RX_VLAN_FILTER,
	NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_FILTER,
	NM_ETHTOOL_ID_FEATURE_RX_VLAN_STAG_HW_PARSE,
	NM_ETHTOOL_ID_FEATURE_RXHASH,
	NM_ETHTOOL_ID_FEATURE_RXVLAN,
	NM_ETHTOOL_ID_FEATURE_SG,
	NM_ETHTOOL_ID_FEATURE_TLS_HW_RECORD,
	NM_ETHTOOL_ID_FEATURE_TLS_HW_TX_OFFLOAD,
	NM_ETHTOOL_ID_FEATURE_TSO,
	NM_ETHTOOL_ID_FEATURE_TX,
	NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_FCOE_CRC,
	NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IP_GENERIC,
	NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV4,
	NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_IPV6,
	NM_ETHTOOL_ID_FEATURE_TX_CHECKSUM_SCTP,
	NM_ETHTOOL_ID_FEATURE_TX_ESP_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_FCOE_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_GRE_CSUM_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_GRE_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_GSO_PARTIAL,
	NM_ETHTOOL_ID_FEATURE_TX_GSO_ROBUST,
	NM_ETHTOOL_ID_FEATURE_TX_IPXIP4_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_IPXIP6_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_NOCACHE_COPY,
	NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER,
	NM_ETHTOOL_ID_FEATURE_TX_SCATTER_GATHER_FRAGLIST,
	NM_ETHTOOL_ID_FEATURE_TX_SCTP_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_TCP_ECN_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_TCP_MANGLEID_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_TCP_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_TCP6_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_UDP_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_CSUM_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_UDP_TNL_SEGMENTATION,
	NM_ETHTOOL_ID_FEATURE_TX_VLAN_STAG_HW_INSERT,
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
