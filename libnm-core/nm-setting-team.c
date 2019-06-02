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
 * Copyright 2017 Red Hat, Inc.
 * Copyright 2013 Jiri Pirko <jiri@resnulli.us>
 */

#include "nm-default.h"

#include "nm-setting-team.h"

#include <stdlib.h>

#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-team-utils.h"
#include "nm-connection-private.h"

/**
 * SECTION:nm-setting-team
 * @short_description: Describes connection properties for teams
 *
 * The #NMSettingTeam object is a #NMSetting subclass that describes properties
 * necessary for team connections.
 **/

/*****************************************************************************
 * NMTeamLinkWatcher
 *****************************************************************************/

G_DEFINE_BOXED_TYPE (NMTeamLinkWatcher, nm_team_link_watcher,
                     _nm_team_link_watcher_ref, nm_team_link_watcher_unref)

typedef enum {
	LINK_WATCHER_ETHTOOL   = 0,
	LINK_WATCHER_NSNA_PING = 1,
	LINK_WATCHER_ARP_PING  = 2,
} LinkWatcherTypes;

static const char* _link_watcher_name[] = {
	[LINK_WATCHER_ETHTOOL]   = NM_TEAM_LINK_WATCHER_ETHTOOL,
	[LINK_WATCHER_NSNA_PING] = NM_TEAM_LINK_WATCHER_NSNA_PING,
	[LINK_WATCHER_ARP_PING]  = NM_TEAM_LINK_WATCHER_ARP_PING
};

struct NMTeamLinkWatcher {

	int ref_count;

	guint8 type; /* LinkWatcherTypes */

	union {
		struct {
			int delay_up;
			int delay_down;
		} ethtool;
		struct {
			const char *target_host;
			int init_wait;
			int interval;
			int missed_max;
		} nsna_ping;
		struct {
			const char *target_host;
			const char *source_host;
			int init_wait;
			int interval;
			int missed_max;
			int vlanid;
			NMTeamLinkWatcherArpPingFlags flags;
		} arp_ping;
	};
};

#define _CHECK_WATCHER_VOID(watcher) \
	G_STMT_START { \
		g_return_if_fail (watcher != NULL); \
		g_return_if_fail (watcher->ref_count > 0); \
		nm_assert (watcher->type <= LINK_WATCHER_ARP_PING); \
	} G_STMT_END

#define _CHECK_WATCHER(watcher, err_val) \
	G_STMT_START { \
		g_return_val_if_fail (watcher != NULL, err_val); \
		g_return_val_if_fail (watcher->ref_count > 0, err_val); \
		nm_assert (watcher->type <= LINK_WATCHER_ARP_PING); \
	} G_STMT_END

/**
 * nm_team_link_watcher_new_ethtool:
 * @delay_up: delay_up value
 * @delay_down: delay_down value
 * @error: this call never fails, so this var is not used but kept for format
 *   consistency with the link_watcher constructors of other type
 *
 * Creates a new ethtool #NMTeamLinkWatcher object
 *
 * Returns: (transfer full): the new #NMTeamLinkWatcher object
 *
 * Since: 1.12
 **/
NMTeamLinkWatcher *
nm_team_link_watcher_new_ethtool (int delay_up,
                                  int delay_down,
                                  GError **error)
{
	NMTeamLinkWatcher *watcher;
	const char *val_fail = NULL;

	if (delay_up < 0 || !_NM_INT_LE_MAXINT32 (delay_up))
		val_fail = "delay-up";
	if (delay_down < 0 || !_NM_INT_LE_MAXINT32 (delay_down))
		val_fail = "delay-down";
	if (val_fail) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("%s is out of range [0, %d]"), val_fail, G_MAXINT32);
		return NULL;
	}

	watcher = g_malloc (nm_offsetofend (NMTeamLinkWatcher, ethtool));

	watcher->ref_count = 1;
	watcher->type = LINK_WATCHER_ETHTOOL;
	watcher->ethtool.delay_up = delay_up;
	watcher->ethtool.delay_down = delay_down;

	return watcher;
}

/**
 * nm_team_link_watcher_new_nsna_ping:
 * @init_wait: init_wait value
 * @interval: interval value
 * @missed_max: missed_max value
 * @target_host: the host name or the ipv6 address that will be used as
 *   target address in the NS packet
 * @error: (out) (allow-none): location to store the error on failure
 *
 * Creates a new nsna_ping #NMTeamLinkWatcher object
 *
 * Returns: (transfer full): the new #NMTeamLinkWatcher object, or %NULL on error
 *
 * Since: 1.12
 **/
NMTeamLinkWatcher *
nm_team_link_watcher_new_nsna_ping (int init_wait,
                                    int interval,
                                    int missed_max,
                                    const char *target_host,
                                    GError **error)
{
	NMTeamLinkWatcher *watcher;
	const char *val_fail = NULL;
	char *str;
	gsize l_target_host;

	if (!target_host) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("Missing target-host in nsna_ping link watcher"));
		return NULL;
	}

	if (strpbrk (target_host, " \\/\t=\"\'")) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("target-host '%s' contains invalid characters"), target_host);
		return NULL;
	}

	if (init_wait < 0 || !_NM_INT_LE_MAXINT32 (init_wait))
		val_fail = "init-wait";
	if (interval < 0 || !_NM_INT_LE_MAXINT32 (interval))
		val_fail = "interval";
	if (missed_max < 0 || !_NM_INT_LE_MAXINT32 (missed_max))
		val_fail = "missed-max";
	if (val_fail) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("%s is out of range [0, %d]"), val_fail, G_MAXINT32);
		return NULL;
	}

	l_target_host = strlen (target_host) + 1;

	watcher = g_malloc (  nm_offsetofend (NMTeamLinkWatcher, nsna_ping)
	                    + l_target_host);

	watcher->ref_count = 1;
	watcher->type = LINK_WATCHER_NSNA_PING;
	watcher->nsna_ping.init_wait = init_wait;
	watcher->nsna_ping.interval = interval;
	watcher->nsna_ping.missed_max = missed_max;

	str = &((char *) watcher)[nm_offsetofend (NMTeamLinkWatcher, nsna_ping)];
	watcher->nsna_ping.target_host = str;
	memcpy (str, target_host, l_target_host);

	return watcher;
}

/**
 * nm_team_link_watcher_new_arp_ping:
 * @init_wait: init_wait value
 * @interval: interval value
 * @missed_max: missed_max value
 * @target_host: the host name or the ip address that will be used as destination
 *   address in the arp request
 * @source_host: the host name or the ip address that will be used as source
 *   address in the arp request
 * @flags: the watcher #NMTeamLinkWatcherArpPingFlags
 * @error: (out) (allow-none): location to store the error on failure
 *
 * Creates a new arp_ping #NMTeamLinkWatcher object
 *
 * Returns: (transfer full): the new #NMTeamLinkWatcher object, or %NULL on error
 *
 * Since: 1.12
 **/
NMTeamLinkWatcher *
nm_team_link_watcher_new_arp_ping (int init_wait,
                                   int interval,
                                   int missed_max,
                                   const char *target_host,
                                   const char *source_host,
                                   NMTeamLinkWatcherArpPingFlags flags,
                                   GError **error)
{
	return nm_team_link_watcher_new_arp_ping2 (init_wait,
	                                           interval,
	                                           missed_max,
	                                           -1,
	                                           target_host,
	                                           source_host,
	                                           flags,
	                                           error);
}

/**
 * nm_team_link_watcher_new_arp_ping2:
 * @init_wait: init_wait value
 * @interval: interval value
 * @missed_max: missed_max value
 * @vlanid: vlanid value
 * @target_host: the host name or the ip address that will be used as destination
 *   address in the arp request
 * @source_host: the host name or the ip address that will be used as source
 *   address in the arp request
 * @flags: the watcher #NMTeamLinkWatcherArpPingFlags
 * @error: (out) (allow-none): location to store the error on failure
 *
 * Creates a new arp_ping #NMTeamLinkWatcher object
 *
 * Returns: (transfer full): the new #NMTeamLinkWatcher object, or %NULL on error
 *
 * Since: 1.16
 **/
NMTeamLinkWatcher *
nm_team_link_watcher_new_arp_ping2 (int init_wait,
                                    int interval,
                                    int missed_max,
                                    int vlanid,
                                    const char *target_host,
                                    const char *source_host,
                                    NMTeamLinkWatcherArpPingFlags flags,
                                    GError **error)
{
	NMTeamLinkWatcher *watcher;
	const char *val_fail = NULL;
	char *str;
	gsize l_target_host;
	gsize l_source_host;

	if (   !target_host
	    || !source_host) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("Missing %s in arp_ping link watcher"),
		             target_host ? "source-host" : "target-host");
		return NULL;
	}

	if (strpbrk (target_host, " \\/\t=\"\'")) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("target-host '%s' contains invalid characters"), target_host);
		return NULL;
	}

	if (strpbrk (source_host, " \\/\t=\"\'")) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("source-host '%s' contains invalid characters"), source_host);
		return NULL;
	}

	else if (init_wait < 0 || !_NM_INT_LE_MAXINT32 (init_wait))
		val_fail = "init-wait";
	else if (interval < 0 || !_NM_INT_LE_MAXINT32 (interval))
		val_fail = "interval";
	else if (missed_max < 0 || !_NM_INT_LE_MAXINT32 (missed_max))
		val_fail = "missed-max";
	if (val_fail) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("%s is out of range [0, %d]"), val_fail, G_MAXINT32);
		return NULL;
	}

	if (vlanid < -1 || vlanid > 4094) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		                     _("vlanid is out of range [-1, 4094]"));
		return NULL;
	}

	l_target_host = strlen (target_host) + 1;
	l_source_host = strlen (source_host) + 1;

	watcher = g_malloc (  nm_offsetofend (NMTeamLinkWatcher, arp_ping)
	                    + l_target_host
	                    + l_source_host);

	watcher->ref_count = 1;
	watcher->type = LINK_WATCHER_ARP_PING;
	watcher->arp_ping.init_wait = init_wait;
	watcher->arp_ping.interval = interval;
	watcher->arp_ping.missed_max = missed_max;
	watcher->arp_ping.flags = flags;
	watcher->arp_ping.vlanid = vlanid;

	str = &((char *) watcher)[nm_offsetofend (NMTeamLinkWatcher, arp_ping)];
	watcher->arp_ping.target_host = str;
	memcpy (str, target_host, l_target_host);

	str += l_target_host;
	watcher->arp_ping.source_host = str;
	memcpy (str, source_host, l_source_host);

	return watcher;
}

NMTeamLinkWatcher *
_nm_team_link_watcher_ref (NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, NULL);

	g_atomic_int_inc (&watcher->ref_count);
	return watcher;
}

/**
 * nm_team_link_watcher_ref:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Increases the reference count of the object.
 *
 * Since: 1.12
 **/
void
nm_team_link_watcher_ref (NMTeamLinkWatcher *watcher)
{
	_nm_team_link_watcher_ref (watcher);
}

/**
 * nm_team_link_watcher_unref:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 *
 * Since: 1.12
 **/
void
nm_team_link_watcher_unref (NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER_VOID (watcher);

	if (g_atomic_int_dec_and_test (&watcher->ref_count))
		g_free (watcher);
}

int
nm_team_link_watcher_cmp (const NMTeamLinkWatcher *watcher,
                          const NMTeamLinkWatcher *other)
{
	NM_CMP_SELF (watcher, other);

	NM_CMP_FIELD (watcher, other, type);

	switch (watcher->type) {
	case LINK_WATCHER_ETHTOOL:
		NM_CMP_FIELD (watcher, other, ethtool.delay_up);
		NM_CMP_FIELD (watcher, other, ethtool.delay_down);
		break;
	case LINK_WATCHER_NSNA_PING:
		NM_CMP_FIELD_STR (watcher, other, nsna_ping.target_host);
		NM_CMP_FIELD (watcher, other, nsna_ping.init_wait);
		NM_CMP_FIELD (watcher, other, nsna_ping.interval);
		NM_CMP_FIELD (watcher, other, nsna_ping.missed_max);
		break;
	case LINK_WATCHER_ARP_PING:
		NM_CMP_FIELD_STR (watcher, other, arp_ping.target_host);
		NM_CMP_FIELD_STR (watcher, other, arp_ping.source_host);
		NM_CMP_FIELD (watcher, other, arp_ping.init_wait);
		NM_CMP_FIELD (watcher, other, arp_ping.interval);
		NM_CMP_FIELD (watcher, other, arp_ping.missed_max);
		NM_CMP_FIELD (watcher, other, arp_ping.vlanid);
		NM_CMP_FIELD (watcher, other, arp_ping.flags);
		break;
	}
	return 0;
}

/**
 * nm_team_link_watcher_equal:
 * @watcher: the #NMTeamLinkWatcher
 * @other: the #NMTeamLinkWatcher to compare @watcher to.
 *
 * Determines if two #NMTeamLinkWatcher objects contain the same values
 * in all the properties.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 *
 * Since: 1.12
 **/
gboolean
nm_team_link_watcher_equal (const NMTeamLinkWatcher *watcher,
                            const NMTeamLinkWatcher *other)
{
	return nm_team_link_watcher_cmp (watcher, other) == 0;
}

static int
_team_link_watchers_cmp_p_with_data (gconstpointer data_a,
                                     gconstpointer data_b,
                                     gpointer user_data)
{
	return nm_team_link_watcher_cmp (*((const NMTeamLinkWatcher *const*) data_a),
	                                 *((const NMTeamLinkWatcher *const*) data_b));
}

int
nm_team_link_watchers_cmp (const NMTeamLinkWatcher *const*a,
                           const NMTeamLinkWatcher *const*b,
                           gsize len,
                           gboolean ignore_order)
{
	gs_free const NMTeamLinkWatcher **a_free = NULL;
	gs_free const NMTeamLinkWatcher **b_free = NULL;
	guint i;

	if (   ignore_order
	    && len > 1) {
		a = nm_memdup_maybe_a (200, a, len * sizeof (*a), &a_free);
		b = nm_memdup_maybe_a (200, b, len * sizeof (*b), &b_free);
		g_qsort_with_data ((gpointer) a, len, sizeof (*a), _team_link_watchers_cmp_p_with_data, NULL);
		g_qsort_with_data ((gpointer) b, len, sizeof (*b), _team_link_watchers_cmp_p_with_data, NULL);
	}
	for (i = 0; i < len; i++) {
		NM_CMP_RETURN (nm_team_link_watcher_cmp (a[i],
		                                         b[i]));
	}
	return 0;
}

gboolean
nm_team_link_watchers_equal (const GPtrArray *a,
                             const GPtrArray *b,
                             gboolean ignore_order)
{
	return    a == b
	       || (   a
	           && b
	           && a->len == b->len
	           && (nm_team_link_watchers_cmp ((const NMTeamLinkWatcher *const*) a->pdata,
	                                          (const NMTeamLinkWatcher *const*) b->pdata,
	                                          a->len,
	                                          ignore_order) == 0));
}

/**
 * nm_team_link_watcher_dup:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Creates a copy of @watcher
 *
 * Returns: (transfer full): a copy of @watcher
 *
 * Since: 1.12
 **/
NMTeamLinkWatcher *
nm_team_link_watcher_dup (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, NULL);

	switch (watcher->type) {
	case LINK_WATCHER_ETHTOOL:
		return nm_team_link_watcher_new_ethtool (watcher->ethtool.delay_up,
		                                         watcher->ethtool.delay_down,
		                                         NULL);
		break;
	case LINK_WATCHER_NSNA_PING:
		return nm_team_link_watcher_new_nsna_ping (watcher->nsna_ping.init_wait,
		                                           watcher->nsna_ping.interval,
		                                           watcher->nsna_ping.missed_max,
		                                           watcher->nsna_ping.target_host,
		                                           NULL);
		break;
	case LINK_WATCHER_ARP_PING:
		return nm_team_link_watcher_new_arp_ping2 (watcher->arp_ping.init_wait,
		                                           watcher->arp_ping.interval,
		                                           watcher->arp_ping.missed_max,
		                                           watcher->arp_ping.vlanid,
		                                           watcher->arp_ping.target_host,
		                                           watcher->arp_ping.source_host,
		                                           watcher->arp_ping.flags,
		                                          NULL);
	default:
		nm_assert_not_reached ();
		return NULL;
	}
}

/**
 * nm_team_link_watcher_get_name:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the name of the link watcher to be used.
 *
 * Since: 1.12
 **/
const char *
nm_team_link_watcher_get_name (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, NULL);

	return _link_watcher_name[watcher->type];
}

/**
 * nm_team_link_watcher_get_delay_up:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the delay_up interval (in milliseconds) that elapses between the link
 * coming up and the runner being notified about it.
 *
 * Since: 1.12
 **/
int
nm_team_link_watcher_get_delay_up (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, 0);

	if (watcher->type == LINK_WATCHER_ETHTOOL)
		return watcher->ethtool.delay_up;
	return -1;
}

/**
 * nm_team_link_watcher_get_delay_down:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the delay_down interval (in milliseconds) that elapses between the link
 * going down and the runner being notified about it.
 *
 * Since: 1.12
 **/
int
nm_team_link_watcher_get_delay_down (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, 0);

	if (watcher->type == LINK_WATCHER_ETHTOOL)
		return watcher->ethtool.delay_down;
	return -1;
}

/**
 * nm_team_link_watcher_get_init_wait:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the init_wait interval (in milliseconds) that the team slave should
 * wait before sending the first packet to the target host.
 *
 * Since: 1.12
 **/
int
nm_team_link_watcher_get_init_wait (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, 0);

	if (watcher->type == LINK_WATCHER_NSNA_PING)
		return watcher->nsna_ping.init_wait;
	if (watcher->type == LINK_WATCHER_ARP_PING)
		return watcher->arp_ping.init_wait;
	return -1;
}

/**
 * nm_team_link_watcher_get_interval:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the interval (in milliseconds) that the team slave should wait between
 * sending two check packets to the target host.
 *
 * Since: 1.12
 **/
int
nm_team_link_watcher_get_interval (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, 0);

	if (watcher->type == LINK_WATCHER_NSNA_PING)
		return watcher->nsna_ping.interval;
	if (watcher->type == LINK_WATCHER_ARP_PING)
		return watcher->arp_ping.interval;
	return -1;
}

/**
 * nm_team_link_watcher_get_missed_max:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the number of missed replies after which the link is considered down.
 *
 * Since: 1.12
 **/
int
nm_team_link_watcher_get_missed_max (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, 0);

	if (watcher->type == LINK_WATCHER_NSNA_PING)
		return watcher->nsna_ping.missed_max;
	if (watcher->type == LINK_WATCHER_ARP_PING)
		return watcher->arp_ping.missed_max;
	return -1;
}

/**
 * nm_team_link_watcher_get_vlanid:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the VLAN tag ID to be used to outgoing link probes
 *
 * Since: 1.16
 **/
int
nm_team_link_watcher_get_vlanid (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, -1);

	if (watcher->type == LINK_WATCHER_ARP_PING)
		return watcher->arp_ping.vlanid;
	return -1;
}

/**
 * nm_team_link_watcher_get_target_host:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the host name/ip address to be used as destination for the link probing
 * packets.
 *
 * Since: 1.12
 **/
const char *
nm_team_link_watcher_get_target_host (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, NULL);

	if (watcher->type == LINK_WATCHER_NSNA_PING)
		return watcher->nsna_ping.target_host;
	if (watcher->type == LINK_WATCHER_ARP_PING)
		return watcher->arp_ping.target_host;
	return NULL;
}

/**
 * nm_team_link_watcher_get_source_host:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the ip address to be used as source for the link probing packets.
 *
 * Since: 1.12
 **/
const char *
nm_team_link_watcher_get_source_host (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, NULL);

	if (watcher->type == LINK_WATCHER_ARP_PING)
		return watcher->arp_ping.source_host;
	return NULL;
}

/**
 * nm_team_link_watcher_get_flags:
 * @watcher: the #NMTeamLinkWatcher
 *
 * Gets the arp ping watcher flags.
 *
 * Since: 1.12
 **/
NMTeamLinkWatcherArpPingFlags
nm_team_link_watcher_get_flags (const NMTeamLinkWatcher *watcher)
{
	_CHECK_WATCHER (watcher, 0);

	if (watcher->type == LINK_WATCHER_ARP_PING)
		return watcher->arp_ping.flags;
	return 0;
}

/*****************************************************************************/

static GParamSpec *obj_properties[_NM_TEAM_ATTRIBUTE_MASTER_NUM] = { NULL, };

typedef struct {
	NMTeamSetting *team_setting;
} NMSettingTeamPrivate;

G_DEFINE_TYPE (NMSettingTeam, nm_setting_team, NM_TYPE_SETTING)

#define NM_SETTING_TEAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_TEAM, NMSettingTeamPrivate))

/*****************************************************************************/

NMTeamSetting *
_nm_setting_team_get_team_setting (NMSettingTeam *setting)
{
	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting;
}

/*****************************************************************************/

#define _maybe_changed(self, changed) \
	nm_team_setting_maybe_changed (NM_SETTING (_NM_ENSURE_TYPE (NMSettingTeam *, self)), (const GParamSpec *const*) obj_properties, (changed))

#define _maybe_changed_with_assert(self, changed) \
	G_STMT_START { \
		if (!_maybe_changed ((self), (changed))) \
			nm_assert_not_reached (); \
	} G_STMT_END

/**
 * nm_setting_team_get_config:
 * @setting: the #NMSettingTeam
 *
 * Returns: the #NMSettingTeam:config property of the setting
 **/
const char *
nm_setting_team_get_config (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return nm_team_setting_config_get (NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting);
}

/**
 * nm_setting_team_get_notify_peers_count:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:notify-peers-count property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_get_notify_peers_count (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.notify_peers_count;
}

/**
 * nm_setting_team_get_notify_peers_interval:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:notify-peers-interval property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_get_notify_peers_interval (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.notify_peers_interval;
}

/**
 * nm_setting_team_get_mcast_rejoin_count:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:mcast-rejoin-count property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_get_mcast_rejoin_count (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.mcast_rejoin_count;
}

/**
 * nm_setting_team_get_mcast_rejoin_interval:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:mcast-rejoin-interval property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_get_mcast_rejoin_interval (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.mcast_rejoin_interval;
}

/**
 * nm_setting_team_get_runner:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner property of the setting
 *
 * Since: 1.12
 **/
const char *
nm_setting_team_get_runner (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner;
}

/**
 * nm_setting_team_get_runner_hwaddr_policy:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-hwaddr-policy property of the setting
 *
 * Since: 1.12
 **/
const char *
nm_setting_team_get_runner_hwaddr_policy (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_hwaddr_policy;
}

/**
 * nm_setting_team_get_runner_tx_balancer:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-tx-balancer property of the setting
 *
 * Since: 1.12
 **/
const char *
nm_setting_team_get_runner_tx_balancer (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_tx_balancer;
}

/**
 * nm_setting_team_get_runner_tx_balancer_interval:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-tx-balancer_interval property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_get_runner_tx_balancer_interval (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_tx_balancer_interval;
}

/**
 * nm_setting_team_get_runner_active:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner_active property of the setting
 *
 * Since: 1.12
 **/
gboolean
nm_setting_team_get_runner_active (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_active;
}

/**
 * nm_setting_team_get_runner_fast_rate:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-fast-rate property of the setting
 *
 * Since: 1.12
 **/
gboolean
nm_setting_team_get_runner_fast_rate (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_fast_rate;
}

/**
 * nm_setting_team_get_runner_sys_prio:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-sys-prio property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_get_runner_sys_prio (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_sys_prio;
}

/**
 * nm_setting_team_get_runner_min_ports:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-min-ports property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_get_runner_min_ports (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_min_ports;
}

/**
 * nm_setting_team_get_runner_agg_select_policy:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-agg-select-policy property of the setting
 *
 * Since: 1.12
 **/
const char *
nm_setting_team_get_runner_agg_select_policy (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_agg_select_policy;
}

/**
 * nm_setting_team_remove_runner_tx_hash_by_value:
 * @setting: the #NMSetetingTeam
 * @txhash: the txhash element to remove
 *
 * Removes the txhash element #txhash
 *
 * Returns: %TRUE if the txhash element was found and removed; %FALSE if it was not.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_team_remove_runner_tx_hash_by_value (NMSettingTeam *setting,
                                                const char *txhash)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);
	const GPtrArray *arr;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);
	g_return_val_if_fail (txhash != NULL, FALSE);

	arr = priv->team_setting->d.master.runner_tx_hash;
	if (arr) {
		for (i = 0; i < arr->len; i++) {
			if (nm_streq (txhash, arr->pdata[i])) {
				_maybe_changed_with_assert (setting,
				                            nm_team_setting_value_master_runner_tx_hash_remove (priv->team_setting,
				                                                                                i));
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * nm_setting_team_get_num_runner_tx_hash:
 * @setting: the #NMSettingTeam
 *
 * Returns: the number of elements in txhash
 *
 * Since: 1.12
 **/
guint
nm_setting_team_get_num_runner_tx_hash (NMSettingTeam *setting)
{
	const GPtrArray *arr;

	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	arr = NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_tx_hash;
	return arr ? arr->len : 0u;
}

/**
 * nm_setting_team_get_runner_tx_hash
 * @setting: the #NMSettingTeam
 * @idx: index number of the txhash element to return
 *
 * Returns: the txhash element at index @idx
 *
 * Since: 1.12
 **/
const char *
nm_setting_team_get_runner_tx_hash (NMSettingTeam *setting, guint idx)
{
	const GPtrArray *arr;

	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	arr = NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.master.runner_tx_hash;

	g_return_val_if_fail (arr, NULL);
	g_return_val_if_fail (idx < arr->len, NULL);

	return arr->pdata[idx];
}

/**
 * nm_setting_team_remove_runner_tx_hash:
 * @setting: the #NMSettingTeam
 * @idx: index number of the element to remove from txhash
 *
 * Removes the txhash element at index @idx.
 *
 * Since: 1.12
 **/
void
nm_setting_team_remove_runner_tx_hash (NMSettingTeam *setting, guint idx)
{
	NMSettingTeamPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_TEAM (setting));

	priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	g_return_if_fail (priv->team_setting->d.master.runner_tx_hash);
	g_return_if_fail (idx < priv->team_setting->d.master.runner_tx_hash->len);

	_maybe_changed_with_assert (setting,
	                            nm_team_setting_value_master_runner_tx_hash_remove (priv->team_setting,
	                                                                                idx));
}

/**
 * nm_setting_team_add_runner_tx_hash:
 * @setting: the #NMSettingTeam
 * @txhash: the element to add to txhash
 *
 * Adds a new txhash element to the setting.
 *
 * Returns: %TRUE if the txhash element was added; %FALSE if the element
 * was already knnown.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_team_add_runner_tx_hash (NMSettingTeam *setting, const char *txhash)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);
	g_return_val_if_fail (txhash, FALSE);

	return _maybe_changed (setting,
	                       nm_team_setting_value_master_runner_tx_hash_add (NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting,
	                                                                        txhash));
}

/**
 * nm_setting_team_get_num_link_watchers:
 * @setting: the #NMSettingTeam
 *
 * Returns: the number of configured link watchers
 *
 * Since: 1.12
 **/
guint
nm_setting_team_get_num_link_watchers (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.link_watchers->len;
}

/**
 * nm_setting_team_get_link_watcher:
 * @setting: the #NMSettingTeam
 * @idx: index number of the link watcher to return
 *
 * Returns: (transfer none): the link watcher at index @idx.
 *
 * Since: 1.12
 **/
NMTeamLinkWatcher *
nm_setting_team_get_link_watcher (NMSettingTeam *setting, guint idx)
{
	const GPtrArray *arr;

	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	arr = NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting->d.link_watchers;

	g_return_val_if_fail (idx < arr->len, NULL);

	return arr->pdata[idx];
}

/**
 * nm_setting_team_add_link_watcher:
 * @setting: the #NMSettingTeam
 * @link_watcher: the link watcher to add
 *
 * Appends a new link watcher to the setting.
 *
 * Returns: %TRUE if the link watcher is added; %FALSE if an identical link
 * watcher was already there.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_team_add_link_watcher (NMSettingTeam *setting,
                                  NMTeamLinkWatcher *link_watcher)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);
	g_return_val_if_fail (link_watcher != NULL, FALSE);

	return _maybe_changed (setting,
	                       nm_team_setting_value_link_watchers_add (NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting,
	                                                                link_watcher));
}

/**
 * nm_setting_team_remove_link_watcher:
 * @setting: the #NMSettingTeam
 * @idx: index number of the link watcher to remove
 *
 * Removes the link watcher at index #idx.
 *
 * Since: 1.12
 **/
void
nm_setting_team_remove_link_watcher (NMSettingTeam *setting, guint idx)
{
	NMSettingTeamPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_TEAM (setting));

	priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	g_return_if_fail (idx < priv->team_setting->d.link_watchers->len);

	_maybe_changed_with_assert (setting,
	                            nm_team_setting_value_link_watchers_remove (priv->team_setting,
	                                                                        idx));
}

/**
 * nm_setting_team_remove_link_watcher_by_value:
 * @setting: the #NMSettingTeam
 * @link_watcher: the link watcher to remove
 *
 * Removes the link watcher entry matching link_watcher.
 *
 * Returns: %TRUE if the link watcher was found and removed, %FALSE otherwise.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_team_remove_link_watcher_by_value (NMSettingTeam *setting,
                                              NMTeamLinkWatcher *link_watcher)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);
	g_return_val_if_fail (link_watcher, FALSE);

	return _maybe_changed (setting,
	                       nm_team_setting_value_link_watchers_remove_by_value (NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting,
	                                                                            link_watcher));
}

/**
 * nm_setting_team_clear_link_watchers:
 * @setting: the #NMSettingTeam
 *
 * Removes all configured link watchers.
 *
 * Since: 1.12
 **/
void
nm_setting_team_clear_link_watchers (NMSettingTeam *setting)
{
	g_return_if_fail (NM_IS_SETTING_TEAM (setting));

	_maybe_changed (setting,
	                nm_team_setting_value_link_watchers_set_list (NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting,
	                                                              NULL,
	                                                              0));
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	if (!nm_team_setting_verify (priv->team_setting, error))
		return FALSE;

	return TRUE;
}

static NMTernary
compare_property (const NMSettInfoSetting *sett_info,
                  guint property_idx,
                  NMConnection *con_a,
                  NMSetting *set_a,
                  NMConnection *con_b,
                  NMSetting *set_b,
                  NMSettingCompareFlags flags)
{
	NMSettingTeamPrivate *a_priv, *b_priv;

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_TEAM_LINK_WATCHERS)) {
		if (NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_INFERRABLE))
			return NM_TERNARY_DEFAULT;
		if (!set_b)
			return TRUE;
		a_priv = NM_SETTING_TEAM_GET_PRIVATE (set_a);
		b_priv = NM_SETTING_TEAM_GET_PRIVATE (set_b);
		return nm_team_link_watchers_equal (a_priv->team_setting->d.link_watchers,
		                                    b_priv->team_setting->d.link_watchers,
		                                    TRUE);
	}

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_TEAM_CONFIG)) {
		if (set_b) {
			if (NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_INFERRABLE)) {
				/* If we are trying to match a connection in order to assume it (and thus
				 * @flags contains INFERRABLE), use the "relaxed" matching for team
				 * configuration. Otherwise, for all other purposes (including connection
				 * comparison before an update), resort to the default string comparison. */
				return TRUE;
			}

			a_priv = NM_SETTING_TEAM_GET_PRIVATE (set_a);
			b_priv = NM_SETTING_TEAM_GET_PRIVATE (set_b);

			return nm_streq0 (nm_team_setting_config_get (a_priv->team_setting),
			                  nm_team_setting_config_get (b_priv->team_setting));
		}

		return TRUE;
	}

	return NM_SETTING_CLASS (nm_setting_team_parent_class)->compare_property (sett_info,
	                                                                          property_idx,
	                                                                          con_a,
	                                                                          set_a,
	                                                                          con_b,
	                                                                          set_b,
	                                                                          flags);
}

static void
duplicate_copy_properties (const NMSettInfoSetting *sett_info,
                           NMSetting *src,
                           NMSetting *dst)
{
	_maybe_changed (NM_SETTING_TEAM (dst),
	                nm_team_setting_reset (NM_SETTING_TEAM_GET_PRIVATE (dst)->team_setting,
	                                       NM_SETTING_TEAM_GET_PRIVATE (src)->team_setting));
}

static gboolean
init_from_dbus (NMSetting *setting,
                GHashTable *keys,
                GVariant *setting_dict,
                GVariant *connection_dict,
                guint /* NMSettingParseFlags */ parse_flags,
                GError **error)
{
	guint32 changed = 0;
	gboolean success;

	if (keys)
		g_hash_table_remove (keys, "interface-name");

	success = nm_team_setting_reset_from_dbus (NM_SETTING_TEAM_GET_PRIVATE (setting)->team_setting,
	                                           setting_dict,
	                                           keys,
	                                           &changed,
	                                           parse_flags,
	                                           error);
	_maybe_changed (NM_SETTING_TEAM (setting), changed);
	return success;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingTeam *setting = NM_SETTING_TEAM (object);
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);
	const GPtrArray *v_ptrarr;

	switch (prop_id) {
	case NM_TEAM_ATTRIBUTE_CONFIG:
		g_value_set_string (value,
		                    nm_team_setting_config_get (priv->team_setting));
		break;
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE:
		g_value_set_boolean (value,
		                     nm_team_setting_value_get_bool (priv->team_setting,
		                                                     prop_id));
		break;
	case NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT:
	case NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL:
	case NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT:
	case NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS:
		g_value_set_int (value,
		                 nm_team_setting_value_get_int32 (priv->team_setting,
		                                                  prop_id));
		break;
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY:
		g_value_set_string (value,
		                    nm_team_setting_value_get_string (priv->team_setting,
		                                                      prop_id));
		break;
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH:
		v_ptrarr = priv->team_setting->d.master.runner_tx_hash;
		g_value_take_boxed (value,
		                      v_ptrarr
		                    ? _nm_utils_ptrarray_to_strv ((GPtrArray *) v_ptrarr)
		                    : NULL);
		break;
	case NM_TEAM_ATTRIBUTE_LINK_WATCHERS:
		g_value_take_boxed (value, _nm_utils_copy_array (priv->team_setting->d.link_watchers,
		                                                 (NMUtilsCopyFunc) _nm_team_link_watcher_ref,
		                                                 (GDestroyNotify) nm_team_link_watcher_unref));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingTeam *setting = NM_SETTING_TEAM (object);
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (object);
	guint32 changed;
	const GPtrArray *v_ptrarr;

	switch (prop_id) {
	case NM_TEAM_ATTRIBUTE_CONFIG:
		changed = nm_team_setting_config_set (priv->team_setting, g_value_get_string (value));
		break;
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE:
		changed = nm_team_setting_value_set_bool (priv->team_setting,
		                                          prop_id,
		                                          g_value_get_boolean (value));
		break;
	case NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT:
	case NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL:
	case NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT:
	case NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS:
		changed = nm_team_setting_value_set_int32 (priv->team_setting,
		                                           prop_id,
		                                           g_value_get_int (value));
		break;
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY:
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY:
		changed = nm_team_setting_value_set_string (priv->team_setting,
		                                            prop_id,
		                                            g_value_get_string (value));
		break;
	case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH:
		v_ptrarr = g_value_get_boxed (value);
		changed = nm_team_setting_value_master_runner_tx_hash_set_list (priv->team_setting,
		                                                                v_ptrarr ? (const char *const*) v_ptrarr->pdata : NULL,
		                                                                v_ptrarr ? v_ptrarr->len                        : 0u);
		break;
	case NM_TEAM_ATTRIBUTE_LINK_WATCHERS:
		v_ptrarr = g_value_get_boxed (value);
		changed = nm_team_setting_value_link_watchers_set_list (priv->team_setting,
		                                                        v_ptrarr ? (const NMTeamLinkWatcher *const*) v_ptrarr->pdata : NULL,
		                                                        v_ptrarr ? v_ptrarr->len                                     : 0u);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		return;
	}

	_maybe_changed (setting, changed & ~(((guint32) 1) << prop_id));
}

/*****************************************************************************/

static void
nm_setting_team_init (NMSettingTeam *setting)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	priv->team_setting = nm_team_setting_new (FALSE, NULL);
}

/**
 * nm_setting_team_new:
 *
 * Creates a new #NMSettingTeam object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingTeam object
 **/
NMSetting *
nm_setting_team_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_TEAM, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (object);

	nm_team_setting_free (priv->team_setting);

	G_OBJECT_CLASS (nm_setting_team_parent_class)->finalize (object);
}

static void
nm_setting_team_class_init (NMSettingTeamClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingTeamPrivate));

	object_class->get_property     = get_property;
	object_class->set_property     = set_property;
	object_class->finalize         = finalize;

	setting_class->compare_property          = compare_property;
	setting_class->verify                    = verify;
	setting_class->duplicate_copy_properties = duplicate_copy_properties;
	setting_class->init_from_dbus            = init_from_dbus;

#define _property_override(_properties_override, _param_spec, _variant_type, _is_link_watcher) \
	_properties_override_add ((_properties_override), \
	                          .param_spec          = (_param_spec), \
	                          .dbus_type           = G_VARIANT_TYPE (""_variant_type""), \
	                          .to_dbus_fcn         = _nm_team_settings_property_to_dbus, \
	                          .gprop_from_dbus_fcn = ((_is_link_watcher) ? _nm_team_settings_property_from_dbus_link_watchers : NULL))

	/**
	 * NMSettingTeam:config:
	 *
	 * The JSON configuration for the team network interface.  The property
	 * should contain raw JSON configuration data suitable for teamd, because
	 * the value is passed directly to teamd. If not specified, the default
	 * configuration is used.  See man teamd.conf for the format details.
	 **/
	/* ---ifcfg-rh---
	 * property: config
	 * variable: TEAM_CONFIG
	 * description: Team configuration in JSON. See man teamd.conf for details.
	 * ---end---
	 */
	obj_properties[NM_TEAM_ATTRIBUTE_CONFIG] =
	    g_param_spec_string (NM_SETTING_TEAM_CONFIG, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_CONFIG], "s", FALSE);

	/**
	 * NMSettingTeam:notify-peers-count:
	 *
	 * Corresponds to the teamd notify_peers.count.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT] =
	    g_param_spec_int (NM_SETTING_TEAM_NOTIFY_PEERS_COUNT, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT], "i", FALSE);

	/**
	 * NMSettingTeam:notify-peers-interval:
	 *
	 * Corresponds to the teamd notify_peers.interval.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL] =
	    g_param_spec_int (NM_SETTING_TEAM_NOTIFY_PEERS_INTERVAL, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL], "i", FALSE);

	/**
	 * NMSettingTeam:mcast-rejoin-count:
	 *
	 * Corresponds to the teamd mcast_rejoin.count.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT] =
	    g_param_spec_int (NM_SETTING_TEAM_MCAST_REJOIN_COUNT, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT], "i", FALSE);

	/**
	 * NMSettingTeam:mcast-rejoin-interval:
	 *
	 * Corresponds to the teamd mcast_rejoin.interval.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL] =
	    g_param_spec_int (NM_SETTING_TEAM_MCAST_REJOIN_INTERVAL, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL], "i", FALSE);

	/**
	 * NMSettingTeam:runner:
	 *
	 * Corresponds to the teamd runner.name.
	 * Permitted values are: "roundrobin", "broadcast", "activebackup",
	 * "loadbalance", "lacp", "random".
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER] =
	    g_param_spec_string (NM_SETTING_TEAM_RUNNER, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER], "s", FALSE);

	/**
	 * NMSettingTeam:runner-hwaddr-policy:
	 *
	 * Corresponds to the teamd runner.hwaddr_policy.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY] =
	    g_param_spec_string (NM_SETTING_TEAM_RUNNER_HWADDR_POLICY, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY], "s", FALSE);

	/**
	 * NMSettingTeam:runner-tx-hash:
	 *
	 * Corresponds to the teamd runner.tx_hash.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH] =
	    g_param_spec_boxed (NM_SETTING_TEAM_RUNNER_TX_HASH, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH], "as", FALSE);

	/**
	 * NMSettingTeam:runner-tx-balancer:
	 *
	 * Corresponds to the teamd runner.tx_balancer.name.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER] =
	    g_param_spec_string (NM_SETTING_TEAM_RUNNER_TX_BALANCER, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER], "s", FALSE);

	/**
	 * NMSettingTeam:runner-tx-balancer-interval:
	 *
	 * Corresponds to the teamd runner.tx_balancer.interval.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL] =
	    g_param_spec_int (NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL], "i", FALSE);

	/**
	 * NMSettingTeam:runner-active:
	 *
	 * Corresponds to the teamd runner.active.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE] =
	    g_param_spec_boolean (NM_SETTING_TEAM_RUNNER_ACTIVE, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE], "b", FALSE);

	/**
	 * NMSettingTeam:runner-fast-rate:
	 *
	 * Corresponds to the teamd runner.fast_rate.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE] =
	    g_param_spec_boolean (NM_SETTING_TEAM_RUNNER_FAST_RATE, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE], "b", FALSE);

	/**
	 * NMSettingTeam:runner-sys-prio:
	 *
	 * Corresponds to the teamd runner.sys_prio.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO] =
	    g_param_spec_int (NM_SETTING_TEAM_RUNNER_SYS_PRIO, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO], "i", FALSE);

	/**
	 * NMSettingTeam:runner-min-ports:
	 *
	 * Corresponds to the teamd runner.min_ports.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS] =
	    g_param_spec_int (NM_SETTING_TEAM_RUNNER_MIN_PORTS, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS], "i", FALSE);

	/**
	 * NMSettingTeam:runner-agg-select-policy:
	 *
	 * Corresponds to the teamd runner.agg_select_policy.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY] =
	    g_param_spec_string (NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY], "s", FALSE);

	/**
	 * NMSettingTeam:link-watchers: (type GPtrArray(NMTeamLinkWatcher))
	 *
	 * Link watchers configuration for the connection: each link watcher is
	 * defined by a dictionary, whose keys depend upon the selected link
	 * watcher. Available link watchers are 'ethtool', 'nsna_ping' and
	 * 'arp_ping' and it is specified in the dictionary with the key 'name'.
	 * Available keys are:   ethtool: 'delay-up', 'delay-down', 'init-wait';
	 * nsna_ping: 'init-wait', 'interval', 'missed-max', 'target-host';
	 * arp_ping: all the ones in nsna_ping and 'source-host', 'validate-active',
	 * 'validate-inactive', 'send-always'. See teamd.conf man for more details.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_LINK_WATCHERS] =
	    g_param_spec_boxed (NM_SETTING_TEAM_LINK_WATCHERS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_LINK_WATCHERS], "aa{sv}", TRUE);

	/* ---dbus---
	 * property: interface-name
	 * format: string
	 * description: Deprecated in favor of connection.interface-name, but can
	 *   be used for backward-compatibility with older daemons, to set the
	 *   team's interface name.
	 * ---end---
	 */
	_properties_override_add_dbus_only (properties_override,
	                                    "interface-name",
	                                    G_VARIANT_TYPE_STRING,
	                                    _nm_setting_get_deprecated_virtual_interface_name,
	                                    NULL);

	g_object_class_install_properties (object_class, G_N_ELEMENTS (obj_properties), obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_TEAM,
	                               NULL, properties_override);
}
