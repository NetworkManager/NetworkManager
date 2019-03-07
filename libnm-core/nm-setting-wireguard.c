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
 * Copyright 2018 - 2019 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-wireguard.h"

#include "nm-setting-private.h"
#include "nm-utils-private.h"
#include "nm-connection-private.h"
#include "nm-utils/nm-secret-utils.h"

/*****************************************************************************/

/**
 * SECTION:nm-setting-wireguard
 * @short_description: Describes connection properties for wireguard related options
 *
 * The #NMSettingWireGuard object is a #NMSetting subclass that contains settings
 * for configuring WireGuard.
 **/

/*****************************************************************************/

static NMWireGuardPeer *_wireguard_peer_dup (const NMWireGuardPeer *self);

G_DEFINE_BOXED_TYPE (NMWireGuardPeer, nm_wireguard_peer, _wireguard_peer_dup, nm_wireguard_peer_unref)

/* NMWireGuardPeer can also track invalid allowed-ip settings, and only reject
 * them later during is_valid(). Such values are marked by a leading 'X' character
 * in the @allowed_ips. It is expected, that such values are the expception, and
 * commonly not present. */
#define ALLOWED_IP_INVALID_X     'X'
#define ALLOWED_IP_INVALID_X_STR "X"

/**
 * NMWireGuardPeer:
 *
 * The settings of one WireGuard peer.
 *
 * Since: 1.16
 */
struct _NMWireGuardPeer {
	NMSockAddrEndpoint *endpoint;
	char *public_key;
	char *preshared_key;
	GPtrArray *allowed_ips;
	guint refcount;
	NMSettingSecretFlags preshared_key_flags;
	guint16 persistent_keepalive;
	bool public_key_valid:1;
	bool preshared_key_valid:1;
	bool sealed:1;
};

static gboolean
NM_IS_WIREGUARD_PEER (const NMWireGuardPeer *self, gboolean also_sealed)
{
	return    self
	       && self->refcount > 0
	       && (   also_sealed
	           || !self->sealed);
}

/**
 * nm_wireguard_peer_new:
 *
 * Returns: (transfer full): a new, default, unsealed #NMWireGuardPeer instance.
 *
 * Since: 1.16
 */
NMWireGuardPeer *
nm_wireguard_peer_new (void)
{
	NMWireGuardPeer *self;

	self = g_slice_new (NMWireGuardPeer);
	*self = (NMWireGuardPeer) {
		.refcount            = 1,
		.preshared_key_flags = NM_SETTING_SECRET_FLAG_NOT_REQUIRED,
	};
	return self;
}

/**
 * nm_wireguard_peer_new_clone:
 * @self: the #NMWireGuardPeer instance to copy.
 * @with_secrets: if %TRUE, the preshared-key secrets are copied
 *  as well. Otherwise, they will be removed.
 *
 * Returns: (transfer full): a clone of @self. This instance
 *   is always unsealed.
 *
 * Since: 1.16
 */
NMWireGuardPeer *
nm_wireguard_peer_new_clone (const NMWireGuardPeer *self,
                             gboolean with_secrets)
{
	NMWireGuardPeer *new;
	guint i;

	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), NULL);

	new = g_slice_new (NMWireGuardPeer);
	*new = (NMWireGuardPeer) {
		.refcount             = 1,
		.public_key           = g_strdup (self->public_key),
		.public_key_valid     = self->public_key_valid,
		.preshared_key        = with_secrets ? g_strdup (self->preshared_key) : NULL,
		.preshared_key_valid  = self->preshared_key_valid,
		.preshared_key_flags  = self->preshared_key_flags,
		.endpoint             = nm_sock_addr_endpoint_ref (self->endpoint),
		.persistent_keepalive = self->persistent_keepalive,
	};
	if (   self->allowed_ips
	    && self->allowed_ips->len > 0) {
		new->allowed_ips = g_ptr_array_new_full (self->allowed_ips->len,
		                                         g_free);
		for (i = 0; i < self->allowed_ips->len; i++) {
			g_ptr_array_add (new->allowed_ips,
			                 g_strdup (self->allowed_ips->pdata[i]));
		}
	}
	return new;
}

/**
 * nm_wireguard_peer_ref:
 * @self: (allow-none): the #NMWireGuardPeer instance
 *
 * This is not thread-safe.
 *
 * Returns: returns the input argument @self after incrementing
 *   the reference count.
 *
 * Since: 1.16
 */
NMWireGuardPeer *
nm_wireguard_peer_ref (NMWireGuardPeer *self)
{
	if (!self)
		return NULL;

	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), NULL);

	nm_assert (self->refcount < G_MAXUINT);

	self->refcount++;
	return self;
}

/**
 * nm_wireguard_peer_unref:
 * @self: (allow-none): the #NMWireGuardPeer instance
 *
 * Drop a reference to @self. If the last reference is dropped,
 * the instance is freed and all accociate data released.
 *
 * This is not thread-safe.
 *
 * Since: 1.16
 */
void
nm_wireguard_peer_unref (NMWireGuardPeer *self)
{
	if (!self)
		return;

	g_return_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE));

	if (--self->refcount > 0)
		return;

	nm_sock_addr_endpoint_unref (self->endpoint);
	if (self->allowed_ips)
		g_ptr_array_unref (self->allowed_ips);
	g_free (self->public_key);
	nm_free_secret (self->preshared_key);
	g_slice_free (NMWireGuardPeer, self);
}

/**
 * _wireguard_peer_dup:
 * @self: the #NMWireGuardPeer instance
 *
 * Duplicates the #NMWireGuardPeer instance. Note that if @self
 * is already sealed, this increments the reference count and
 * returns it. If the instance is still unsealed, it is copied.
 *
 * Returns: (transfer full): a duplicate of @self, or (if the
 *   instance is sealed and thus immutable) a reference to @self.
 *   As such, the instance will be sealed if and only if @self is
 *   sealed.
 */
static NMWireGuardPeer *
_wireguard_peer_dup (const NMWireGuardPeer *self)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), NULL);

	if (self->sealed)
		return nm_wireguard_peer_ref ((NMWireGuardPeer *) self);
	return nm_wireguard_peer_new_clone (self, TRUE);
}

/**
 * nm_wireguard_peer_seal:
 * @self: the #NMWireGuardPeer instance
 *
 * Seal the #NMWireGuardPeer instance. Afterwards, it is a bug
 * to call all functions that modify the instance (except ref/unref).
 * A sealed instance cannot be unsealed again, but you can create
 * an unsealed copy with nm_wireguard_peer_new_clone().
 *
 * Since: 1.16
 */
void
nm_wireguard_peer_seal (NMWireGuardPeer *self)
{
	g_return_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE));

	self->sealed = TRUE;

	if (self->allowed_ips) {
		if (self->allowed_ips->len == 0)
			nm_clear_pointer (&self->allowed_ips, g_ptr_array_unref);
	}
}

/**
 * nm_wireguard_peer_is_sealed:
 * @self: the #NMWireGuardPeer instance
 *
 * Returns: whether @self is sealed or not.
 *
 * Since: 1.16
 */
gboolean
nm_wireguard_peer_is_sealed (const NMWireGuardPeer *self)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), FALSE);

	return self->sealed;
}

/**
 * nm_wireguard_peer_get_public_key:
 * @self: the #NMWireGuardPeer instance
 *
 * Returns: (transfer none): the public key or %NULL if unset.
 *
 * Since: 1.16
 */
const char *
nm_wireguard_peer_get_public_key (const NMWireGuardPeer *self)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), NULL);

	return self->public_key;
}

/**
 * nm_wireguard_peer_set_public_key:
 * @self: the unsealed #NMWireGuardPeer instance
 * @public_key: (allow-none) (transfer none): the new public
 *   key or %NULL to clear the public key.
 * @accept_invalid: if %TRUE and @public_key is not %NULL and
 *   invalid, then do not modify the instance.
 *
 * Reset the public key. Note that if the public key is valid, it
 * will be normalized (which may or may not modify the set value).
 *
 * It is a bug trying to modify a sealed #NMWireGuardPeer instance.
 *
 * Returns: %TRUE if the key was valid or %NULL. Returns
 *   %FALSE for invalid keys. Depending on @accept_invalid
 *   will an invalid key be set or not.
 *
 * Since: 1.16
 */
gboolean
nm_wireguard_peer_set_public_key (NMWireGuardPeer *self,
                                  const char *public_key,
                                  gboolean accept_invalid)
{
	char *public_key_normalized = NULL;
	gboolean is_valid;

	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, FALSE), FALSE);

	if (!public_key) {
		nm_clear_g_free (&self->public_key);
		return TRUE;
	}

	is_valid = nm_utils_base64secret_normalize (public_key,
	                                            NM_WIREGUARD_PUBLIC_KEY_LEN,
	                                            &public_key_normalized);
	nm_assert (is_valid == (public_key_normalized != NULL));

	if (   !is_valid
	    && !accept_invalid)
		return FALSE;

	self->public_key_valid = is_valid;
	g_free (self->public_key);
	self->public_key = public_key_normalized ?: g_strdup (public_key);
	return is_valid;
}

void
_nm_wireguard_peer_set_public_key_bin (NMWireGuardPeer *self,
                                       const guint8 public_key[static NM_WIREGUARD_PUBLIC_KEY_LEN])
{
	g_return_if_fail (NM_IS_WIREGUARD_PEER (self, FALSE));

	nm_clear_g_free (&self->public_key);

	if (!public_key)
		return;

	self->public_key = g_base64_encode (public_key, NM_WIREGUARD_PUBLIC_KEY_LEN);
	self->public_key_valid = TRUE;
}

/**
 * nm_wireguard_peer_get_preshared_key:
 * @self: the #NMWireGuardPeer instance
 *
 * Returns: (transfer none): the preshared key or %NULL if unset.
 *
 * Since: 1.16
 */
const char *
nm_wireguard_peer_get_preshared_key (const NMWireGuardPeer *self)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), NULL);

	return self->preshared_key;
}

/**
 * nm_wireguard_peer_set_preshared_key:
 * @self: the unsealed #NMWireGuardPeer instance
 * @preshared_key: (allow-none) (transfer none): the new preshared
 *   key or %NULL to clear the preshared key.
 * @accept_invalid: whether to allow setting the key to an invalid
 *   value. If %FALSE, @self is unchanged if the key is invalid
 *   and if %FALSE is returned.
 *
 * Reset the preshared key. Note that if the preshared key is valid, it
 * will be normalized (which may or may not modify the set value).
 *
 * Note that the preshared-key is a secret and consequently has corresponding
 * preshared-key-flags property. This is so that secrets can be optional
 * and requested on demand from a secret-agent. Also, an invalid  preshared-key
 * may optionally cause nm_wireguard_peer_is_valid() to fail or it may
 * be accepted.
 *
 * It is a bug trying to modify a sealed #NMWireGuardPeer instance.
 *
 * Returns: %TRUE if the preshared-key is valid, otherwise %FALSE.
 *   %NULL is considered a valid value.
 *   If the key is invalid, it depends on @accept_invalid whether the
 *   previous value was reset.
 *
 * Since: 1.16
 */
gboolean
nm_wireguard_peer_set_preshared_key (NMWireGuardPeer *self,
                                     const char *preshared_key,
                                     gboolean accept_invalid)
{
	char *preshared_key_normalized = NULL;
	gboolean is_valid;

	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, FALSE), FALSE);

	if (!preshared_key) {
		nm_clear_pointer (&self->preshared_key, nm_free_secret);
		return TRUE;
	}

	is_valid = nm_utils_base64secret_normalize (preshared_key,
	                                            NM_WIREGUARD_SYMMETRIC_KEY_LEN,
	                                            &preshared_key_normalized);
	nm_assert (is_valid == (preshared_key_normalized != NULL));

	if (   !is_valid
	    && !accept_invalid)
		return FALSE;

	self->preshared_key_valid = is_valid;
	nm_free_secret (self->preshared_key);
	self->preshared_key = preshared_key_normalized ?: g_strdup (preshared_key);
	return is_valid;
}

/**
 * nm_wireguard_peer_get_preshared_key_flags:
 * @self: the #NMWireGuardPeer instance
 *
 * Returns: get the secret flags for the preshared-key.
 *
 * Since: 1.16
 */
NMSettingSecretFlags
nm_wireguard_peer_get_preshared_key_flags (const NMWireGuardPeer *self)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), 0);

	return self->preshared_key_flags;
}

/**
 * nm_wireguard_peer_set_preshared_key_flags:
 * @self: the unsealed #NMWireGuardPeer instance
 * @preshared_key_flags: the secret flags to set.
 *
 * It is a bug trying to modify a sealed #NMWireGuardPeer instance.
 *
 * Since: 1.16
 */
void
nm_wireguard_peer_set_preshared_key_flags (NMWireGuardPeer *self,
                                           NMSettingSecretFlags preshared_key_flags)
{
	g_return_if_fail (NM_IS_WIREGUARD_PEER (self, FALSE));

	self->preshared_key_flags = preshared_key_flags;
}

/**
 * nm_wireguard_peer_get_persistent_keepalive:
 * @self: the #NMWireGuardPeer instance
 *
 * Returns: get the persistent-keepalive setting in seconds. Set to zero to disable
 *   keep-alive.
 *
 * Since: 1.16
 */
guint16
nm_wireguard_peer_get_persistent_keepalive (const NMWireGuardPeer *self)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), 0);

	return self->persistent_keepalive;
}

/**
 * nm_wireguard_peer_set_persistent_keepalive:
 * @self: the unsealed #NMWireGuardPeer instance
 * @persistent_keepalive: the keep-alive value to set.
 *
 * It is a bug trying to modify a sealed #NMWireGuardPeer instance.
 *
 * Since: 1.16
 */
void
nm_wireguard_peer_set_persistent_keepalive (NMWireGuardPeer *self,
                                            guint16 persistent_keepalive)
{
	g_return_if_fail (NM_IS_WIREGUARD_PEER (self, FALSE));

	self->persistent_keepalive = persistent_keepalive;
}

NMSockAddrEndpoint *
_nm_wireguard_peer_get_endpoint (const NMWireGuardPeer *self)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), NULL);

	return self->endpoint;
}

/**
 * nm_wireguard_peer_get_endpoint:
 * @self: the #NMWireGuardPeer instance
 *
 * Returns: (transfer none): the endpoint or %NULL if none was set.
 *
 * Since: 1.16
 */
const char *
nm_wireguard_peer_get_endpoint (const NMWireGuardPeer *self)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), NULL);

	return   self->endpoint
	       ? nm_sock_addr_endpoint_get_endpoint (self->endpoint)
	       : NULL;
}

void
_nm_wireguard_peer_set_endpoint (NMWireGuardPeer *self,
                                 NMSockAddrEndpoint *endpoint)
{
	NMSockAddrEndpoint *old;

	nm_assert (NM_IS_WIREGUARD_PEER (self, FALSE));

	old = self->endpoint;
	self->endpoint = nm_sock_addr_endpoint_ref (endpoint);
	nm_sock_addr_endpoint_unref (old);
}

/**
 * nm_wireguard_peer_set_endpoint:
 * @self: the unsealed #NMWireGuardPeer instance
 * @endpoint: the socket address endpoint to set or %NULL.
 * @allow_invalid: if %TRUE, also invalid values are set.
 *   If %FALSE, the function does nothing for invalid @endpoint
 *   arguments.
 *
 * Sets or clears the endpoint of @self.
 *
 * It is a bug trying to modify a sealed #NMWireGuardPeer instance.
 *
 * Returns: %TRUE if the endpoint is %NULL or valid. For an
 *   invalid @endpoint argument, %FALSE is returned. Depending
 *   on @allow_invalid, the instance will be modified.
 *
 * Since: 1.16
 */
gboolean
nm_wireguard_peer_set_endpoint (NMWireGuardPeer *self,
                                const char *endpoint,
                                gboolean allow_invalid)
{
	NMSockAddrEndpoint *old;
	NMSockAddrEndpoint *new;
	gboolean is_valid;

	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, FALSE), FALSE);

	if (!endpoint) {
		nm_clear_pointer (&self->endpoint, nm_sock_addr_endpoint_unref);
		return TRUE;
	}

	new = nm_sock_addr_endpoint_new (endpoint);

	is_valid = (nm_sock_addr_endpoint_get_host (new) != NULL);

	if (   !allow_invalid
	    && !is_valid) {
		nm_sock_addr_endpoint_unref (new);
		return FALSE;
	}

	old = self->endpoint;
	self->endpoint = new;
	nm_sock_addr_endpoint_unref (old);
	return is_valid;
}

/**
 * nm_wireguard_peer_get_allowed_ips_len:
 * @self: the #NMWireGuardPeer instance
 *
 * Returns: the number of allowed-ips entries.
 *
 * Since: 1.16
 */
guint
nm_wireguard_peer_get_allowed_ips_len (const NMWireGuardPeer *self)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), 0);

	return self->allowed_ips ? self->allowed_ips->len : 0u;
}

/**
 * nm_wireguard_peer_get_allowed_ip:
 * @self: the #NMWireGuardPeer instance
 * @idx: the index from zero to (allowed-ips-len - 1) to
 *   retrieve.
 * @out_is_valid: (allow-none): %TRUE if the returned value is a valid allowed-ip
 *   setting.
 *
 * Returns: (transfer none): the allowed-ip setting at index @idx.
 *   If @idx is out of range, %NULL will be returned.
 *
 * Since: 1.16
 */
const char *
nm_wireguard_peer_get_allowed_ip (const NMWireGuardPeer *self,
                                  guint idx,
                                  gboolean *out_is_valid)
{
	const char *s;

	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), NULL);

	if (   !self->allowed_ips
	    || idx >= self->allowed_ips->len) {
		NM_SET_OUT (out_is_valid, FALSE);
		return NULL;
	}

	s = self->allowed_ips->pdata[idx];
	NM_SET_OUT (out_is_valid, s[0] != ALLOWED_IP_INVALID_X);
	return s[0] == ALLOWED_IP_INVALID_X ? &s[1] : s;
}

/**
 * nm_wireguard_peer_clear_allowed_ips:
 * @self: the unsealed #NMWireGuardPeer instance
 *
 * Removes all allowed-ip entries.
 *
 * It is a bug trying to modify a sealed #NMWireGuardPeer instance.
 *
 * Since: 1.16
 */
void
nm_wireguard_peer_clear_allowed_ips (NMWireGuardPeer *self)
{
	g_return_if_fail (NM_IS_WIREGUARD_PEER (self, FALSE));

	if (self->allowed_ips)
		g_ptr_array_set_size (self->allowed_ips, 0);
}

static gboolean
_peer_append_allowed_ip (NMWireGuardPeer *self,
                         const char *allowed_ip,
                         gboolean accept_invalid)
{
	int addr_family;
	int prefix;
	NMIPAddr addrbin;
	char *str;
	gboolean is_valid = TRUE;

	nm_assert (NM_IS_WIREGUARD_PEER (self, FALSE));
	nm_assert (allowed_ip);

	/* normalize the address (if it is valid. Otherwise, take it
	 * as-is (it will render the instance invalid). */
	if (!nm_utils_parse_inaddr_prefix_bin (AF_UNSPEC,
	                                       allowed_ip,
	                                       &addr_family,
	                                       &addrbin,
	                                       &prefix)) {
		if (!accept_invalid)
			return FALSE;
		/* mark the entry as invalid by having a "X" prefix. */
		str = g_strconcat (ALLOWED_IP_INVALID_X_STR, allowed_ip, NULL);
		is_valid = FALSE;
	} else {
		char addrstr[NM_UTILS_INET_ADDRSTRLEN];

		nm_assert_addr_family (addr_family);

		nm_utils_inet_ntop (addr_family, &addrbin, addrstr);
		if (prefix >= 0)
			str = g_strdup_printf ("%s/%d", addrstr, prefix);
		else
			str = g_strdup (addrstr);
		nm_assert (str[0] != ALLOWED_IP_INVALID_X);
	}

	if (!self->allowed_ips)
		self->allowed_ips = g_ptr_array_new_with_free_func (g_free);

	g_ptr_array_add (self->allowed_ips, str);
	return is_valid;
}

/**
 * nm_wireguard_peer_append_allowed_ip:
 * @self: the unsealed #NMWireGuardPeer instance
 * @allowed_ip: the allowed-ip entry to set.
 * @accept_invalid: if %TRUE, also invalid @allowed_ip value
 *   will be appended. Otherwise, the function does nothing
 *   in face of invalid values and returns %FALSE.
 *
 * Appends @allowed_ip setting to the list. This does not check
 * for duplicates and always appends @allowed_ip to the end of the
 * list. If @allowed_ip is valid, it will be normalized and a modified
 * for might be appended. If @allowed_ip is invalid, it will still be
 * appended, but later verification will fail.
 *
 * It is a bug trying to modify a sealed #NMWireGuardPeer instance.
 *
 * Returns: %TRUE if the value is a valid allowed-ips value, %FALSE otherwise.
 *   Depending on @accept_invalid, also invalid values are added.
 *
 * Since: 1.16
 */
gboolean
nm_wireguard_peer_append_allowed_ip (NMWireGuardPeer *self,
                                     const char *allowed_ip,
                                     gboolean accept_invalid)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, FALSE), FALSE);
	g_return_val_if_fail (allowed_ip, FALSE);

	return _peer_append_allowed_ip (self, allowed_ip, accept_invalid);
}

/**
 * nm_wireguard_peer_remove_allowed_ip:
 * @self: the unsealed #NMWireGuardPeer instance
 * @idx: the index from zero to (allowed-ips-len - 1) to
 *   retrieve. If the index is out of range, %FALSE is returned
 *   and nothing is done.
 *
 * Removes the allowed-ip at the given @idx. This shifts all
 * following entries one index down.
 *
 * It is a bug trying to modify a sealed #NMWireGuardPeer instance.
 *
 * Returns: %TRUE if @idx was valid and the allowed-ip was removed.
 *   %FALSE otherwise, and the peer will not be changed.
 *
 * Since: 1.16
 */
gboolean
nm_wireguard_peer_remove_allowed_ip (NMWireGuardPeer *self,
                                     guint idx)
{
	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, FALSE), FALSE);

	if (   !self->allowed_ips
	    || idx >= self->allowed_ips->len)
		return FALSE;

	g_ptr_array_remove_index (self->allowed_ips, idx);
	return TRUE;
}

/**
 * nm_wireguard_peer_is_valid:
 * @self: the #NMWireGuardPeer instance
 * @check_secrets: if %TRUE, non-secret properties are validated.
 *   Otherwise they are ignored for this purpose.
 * @check_non_secrets: if %TRUE, secret properties are validated.
 *   Otherwise they are ignored for this purpose.
 * @error: the #GError location for returning the failure reason.
 *
 * Returns:  %TRUE if the peer is valid or fails with an error
 *   reason.
 *
 * Since: 1.16
 */
gboolean
nm_wireguard_peer_is_valid (const NMWireGuardPeer *self,
                            gboolean check_non_secrets,
                            gboolean check_secrets,
                            GError **error)
{
	guint i;

	g_return_val_if_fail (NM_IS_WIREGUARD_PEER (self, TRUE), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (check_non_secrets) {
		if (!self->public_key) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("missing public-key for peer"));
			return FALSE;
		} else if (!self->public_key_valid) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid public-key for peer"));
			return FALSE;
		}
	}

	if (check_secrets) {
		if (   self->preshared_key
		    && !self->preshared_key_valid) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid preshared-key for peer"));
			return FALSE;
		}
	}

	if (check_non_secrets) {
		if (!_nm_utils_secret_flags_validate (self->preshared_key_flags,
		                                      NULL,
		                                      NULL,
		                                      NM_SETTING_SECRET_FLAG_NONE,
		                                      error))
			return FALSE;
	}

	if (check_non_secrets) {
		if (   self->endpoint
		    && !nm_sock_addr_endpoint_get_host (self->endpoint)) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid endpoint for peer"));
			return FALSE;
		}

		if (self->allowed_ips) {
			for (i = 0; i < self->allowed_ips->len; i++) {
				const char *s = self->allowed_ips->pdata[i];

				if (s[0] == ALLOWED_IP_INVALID_X) {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
					             _("invalid IP address \"%s\" for allowed-ip of peer"),
					             &s[1]);
					return FALSE;
				}
			}
		}

		if (!_nm_setting_secret_flags_valid (self->preshared_key_flags)) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid preshared-key-flags for peer"));
			return FALSE;
		}
	}

	return TRUE;
}

/**
 * nm_wireguard_peer_cmp:
 * @a: (allow-none): the #NMWireGuardPeer to compare.
 * @b: (allow-none): the other #NMWireGuardPeer to compare.
 * @compare_flags: #NMSettingCompareFlags to affect the comparison.
 *
 * Returns: zero of the two instances are equivalent or
 *   a non-zero integer otherwise. This defines a total ordering
 *   over the peers. Whether a peer is sealed or not, does not
 *   affect the comparison.
 *
 * Since: 1.16
 */
int
nm_wireguard_peer_cmp (const NMWireGuardPeer *a,
                       const NMWireGuardPeer *b,
                       NMSettingCompareFlags compare_flags)
{
	guint i, n;

	NM_CMP_SELF (a, b);

	/* regardless of the @compare_flags, the public-key is the ID of the peer. It must
	 * always be compared. */
	NM_CMP_FIELD_BOOL (a, b, public_key_valid);
	NM_CMP_FIELD_STR0 (a, b, public_key);

	if (NM_FLAGS_ANY (compare_flags,   NM_SETTING_COMPARE_FLAG_INFERRABLE
	                                 | NM_SETTING_COMPARE_FLAG_FUZZY))
		return 0;

	NM_CMP_FIELD_BOOL (a, b, endpoint);
	if (a->endpoint) {
		NM_CMP_DIRECT_STRCMP0 (nm_sock_addr_endpoint_get_endpoint (a->endpoint),
		                       nm_sock_addr_endpoint_get_endpoint (b->endpoint));
	}

	NM_CMP_FIELD (a, b, persistent_keepalive);

	NM_CMP_DIRECT ((n = (a->allowed_ips ? a->allowed_ips->len : 0u)),
	               (     b->allowed_ips ? b->allowed_ips->len : 0u ));
	for (i = 0; i < n; i++)
		NM_CMP_DIRECT_STRCMP0 (a->allowed_ips->pdata[i], b->allowed_ips->pdata[i]);

	NM_CMP_FIELD (a, b, preshared_key_flags);

	if (!NM_FLAGS_HAS (compare_flags, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS)) {
		if (   NM_FLAGS_HAS (compare_flags, NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS)
		    && NM_FLAGS_HAS (a->preshared_key_flags, NM_SETTING_SECRET_FLAG_AGENT_OWNED)) {
			/* pass */
		} else if (   NM_FLAGS_HAS (compare_flags, NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)
		           && NM_FLAGS_HAS (a->preshared_key_flags, NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			/* pass */
		} else {
			NM_CMP_FIELD_BOOL (a, b, preshared_key_valid);
			NM_CMP_FIELD_STR0 (a, b, preshared_key);
		}
	}

	return 0;
}

/*****************************************************************************/

typedef struct {
	const char *public_key;
	NMWireGuardPeer *peer;
	guint idx;
} PeerData;

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_FWMARK,
	PROP_LISTEN_PORT,
	PROP_MTU,
	PROP_PEER_ROUTES,
	PROP_PRIVATE_KEY,
	PROP_PRIVATE_KEY_FLAGS,
);

typedef struct {
	char *private_key;
	GPtrArray *peers_arr;
	GHashTable *peers_hash;
	NMSettingSecretFlags private_key_flags;
	guint32 fwmark;
	guint32 mtu;
	guint16 listen_port;
	bool private_key_valid:1;
	bool peer_routes:1;
} NMSettingWireGuardPrivate;

/**
 * NMSettingWireGuard:
 *
 * WireGuard Ethernet Settings
 *
 * Since: 1.16
 */
struct _NMSettingWireGuard {
	NMSetting parent;
	NMSettingWireGuardPrivate _priv;
};

struct _NMSettingWireGuardClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingWireGuard, nm_setting_wireguard, NM_TYPE_SETTING)

#define NM_SETTING_WIREGUARD_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSettingWireGuard, NM_IS_SETTING_WIREGUARD, NMSetting)

/*****************************************************************************/

#define peers_psk_get_secret_name_a(public_key, to_free) \
	nm_construct_name_a (NM_SETTING_WIREGUARD_PEERS".%s."NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY, (public_key), (to_free))

#define peers_psk_get_secret_name_dup(public_key) \
	g_strdup_printf (NM_SETTING_WIREGUARD_PEERS".%s."NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY, (public_key))

#define peers_psk_get_secret_parse_a(secret_public_key, public_key_free) \
	({ \
		const char *_secret_public_key = (secret_public_key); \
		char **_public_key_free = (public_key_free); \
		const char *_public_key = NULL; \
		\
		nm_assert (_public_key_free && !*_public_key_free); \
		\
		if (NM_STR_HAS_PREFIX (_secret_public_key, NM_SETTING_WIREGUARD_PEERS".")) { \
			_secret_public_key += NM_STRLEN (NM_SETTING_WIREGUARD_PEERS"."); \
			if (NM_STR_HAS_SUFFIX (_secret_public_key, "."NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY)) { \
				_public_key = nm_strndup_a (300, _secret_public_key, strlen (_secret_public_key) - NM_STRLEN ("."NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY), _public_key_free); \
			} \
		} \
		\
		_public_key; \
	})

/*****************************************************************************/

/**
 * nm_setting_wireguard_get_private_key:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: (transfer none): the set private-key or %NULL.
 *
 * Since: 1.16
 */
const char *
nm_setting_wireguard_get_private_key (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), NULL);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->private_key;
}

/**
 * nm_setting_wireguard_get_private_key_flags:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: the secret-flags for #NMSettingWireGuard:private-key.
 *
 * Since: 1.16
 */
NMSettingSecretFlags
nm_setting_wireguard_get_private_key_flags (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), 0);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->private_key_flags;
}

/**
 * nm_setting_wireguard_get_fwmark:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: the set firewall mark.
 *
 * Since: 1.16
 */
guint32
nm_setting_wireguard_get_fwmark (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), 0);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->fwmark;
}

/**
 * nm_setting_wireguard_get_listen_port:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: the set UDP listen port.
 *
 * Since: 1.16
 */
guint16
nm_setting_wireguard_get_listen_port (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), 0);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->listen_port;
}

/**
 * nm_setting_wireguard_get_peer_routes:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: whether automatically add peer routes.
 *
 * Since: 1.16
 */
gboolean
nm_setting_wireguard_get_peer_routes (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), TRUE);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->peer_routes;
}

/**
 * nm_setting_wireguard_get_mtu:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: the MTU of the setting.
 *
 * Since: 1.16
 */
guint32
nm_setting_wireguard_get_mtu (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), 0);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->mtu;
}

/*****************************************************************************/

static void
_peer_free (PeerData *pd)
{
	nm_assert (pd);

	nm_wireguard_peer_unref (pd->peer);
	g_slice_free (PeerData, pd);
}

/*****************************************************************************/

static void
_peers_notify (gpointer self)
{
	_nm_setting_emit_property_changed (self);
}

static PeerData *
_peers_get (NMSettingWireGuardPrivate *priv,
            guint idx)
{
	PeerData *pd;

	nm_assert (priv);
	nm_assert (idx < priv->peers_arr->len);

	pd = priv->peers_arr->pdata[idx];

	nm_assert (pd);
	nm_assert (pd->idx == idx);
	nm_assert (NM_IS_WIREGUARD_PEER (pd->peer, TRUE));
	nm_assert (nm_wireguard_peer_is_sealed (pd->peer));
	nm_assert (pd->public_key == nm_wireguard_peer_get_public_key (pd->peer));
	nm_assert (g_hash_table_lookup (priv->peers_hash, pd) == pd);

	return pd;
}

static PeerData *
_peers_get_by_public_key (NMSettingWireGuardPrivate *priv,
                          const char *public_key,
                          gboolean try_with_normalized_key)
{
	gs_free char *public_key_normalized = NULL;
	PeerData *pd;

again:
	nm_assert (priv);
	nm_assert (public_key);

	pd = g_hash_table_lookup (priv->peers_hash, &public_key);
	if (pd) {
		nm_assert (_peers_get (priv, pd->idx) == pd);
		return pd;
	}
	if (   try_with_normalized_key
	    && nm_utils_base64secret_normalize (public_key,
	                                        NM_WIREGUARD_PUBLIC_KEY_LEN,
	                                        &public_key_normalized)) {
		public_key = public_key_normalized;
		try_with_normalized_key = FALSE;
		goto again;
	}
	return NULL;
}

static void
_peers_remove (NMSettingWireGuardPrivate *priv,
               PeerData *pd,
               gboolean do_free)
{
	guint i;

	nm_assert (pd);
	nm_assert (_peers_get (priv, pd->idx) == pd);

	for (i = pd->idx + 1; i < priv->peers_arr->len; i++)
		_peers_get (priv, i)->idx--;

	g_ptr_array_remove_index (priv->peers_arr, pd->idx);
	if (!g_hash_table_remove (priv->peers_hash, pd))
		nm_assert_not_reached ();
	if (do_free)
		_peer_free (pd);
}

/**
 * nm_setting_wireguard_get_peers_len:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: the number of registered peers.
 *
 * Since: 1.16
 */
guint
nm_setting_wireguard_get_peers_len (NMSettingWireGuard *self)
{
	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), 0);

	return NM_SETTING_WIREGUARD_GET_PRIVATE (self)->peers_arr->len;
}

/**
 * nm_setting_wireguard_get_peer:
 * @self: the #NMSettingWireGuard instance
 * @idx: the index to lookup.
 *
 * Returns: (transfer none): the #NMWireGuardPeer entry at
 *   index @idx. If the index is out of range, %NULL is returned.
 *
 * Since: 1.16
 */
NMWireGuardPeer *
nm_setting_wireguard_get_peer (NMSettingWireGuard *self,
                               guint idx)
{
	NMSettingWireGuardPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), NULL);

	priv = NM_SETTING_WIREGUARD_GET_PRIVATE (self);

	if (idx >= priv->peers_arr->len)
		return NULL;

	return _peers_get (priv, idx)->peer;
}

/**
 * nm_setting_wireguard_get_peer_by_public_key:
 * @self: the #NMSettingWireGuard instance
 * @public_key: the public key for looking up the
 *   peer.
 * @out_idx: (out) (allow-none): optional output argument
 *   for the index of the found peer. If no index is found,
 *   this is set to the nm_setting_wireguard_get_peers_len().
 *
 * Returns: (transfer none): the #NMWireGuardPeer instance with a
 *   matching public key. If no such peer exists, %NULL is returned.
 *
 * Since: 1.16
 */
NMWireGuardPeer *
nm_setting_wireguard_get_peer_by_public_key (NMSettingWireGuard *self,
                                             const char *public_key,
                                             guint *out_idx)
{
	NMSettingWireGuardPrivate *priv;
	PeerData *pd;

	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), NULL);
	g_return_val_if_fail (public_key, NULL);

	priv = NM_SETTING_WIREGUARD_GET_PRIVATE (self);

	pd = _peers_get_by_public_key (priv, public_key, TRUE);
	if (!pd) {
		NM_SET_OUT (out_idx, priv->peers_arr->len);
		return NULL;
	}
	NM_SET_OUT (out_idx, pd->idx);
	return pd->peer;
}

static gboolean
_peers_set (NMSettingWireGuardPrivate *priv,
            NMWireGuardPeer *peer,
            guint idx,
            gboolean check_same_key)
{
	PeerData *pd_same_key = NULL;
	PeerData *pd_idx = NULL;
	const char *public_key;

	nm_assert (idx <= priv->peers_arr->len);

	public_key = nm_wireguard_peer_get_public_key (peer);

	if (idx < priv->peers_arr->len) {
		pd_idx = _peers_get (priv, idx);

		if (pd_idx->peer == peer)
			return FALSE;

		if (   check_same_key
		    && nm_streq (public_key, nm_wireguard_peer_get_public_key (pd_idx->peer)))
			check_same_key = FALSE;
	}

	nm_wireguard_peer_seal (peer);
	nm_wireguard_peer_ref (peer);

	if (check_same_key) {
		pd_same_key = _peers_get_by_public_key (priv, public_key, FALSE);
		if (pd_same_key) {
			if (pd_idx) {
				nm_assert (pd_same_key != pd_idx);
				_peers_remove (priv, pd_same_key, TRUE);
				pd_same_key = NULL;
			} else {
				if (   pd_same_key->peer == peer
				    && pd_same_key->idx == priv->peers_arr->len - 1) {
					nm_wireguard_peer_unref (peer);
					return FALSE;
				}
				_peers_remove (priv, pd_same_key, FALSE);
				nm_wireguard_peer_unref (pd_same_key->peer);
			}
		}
	} else
		nm_assert (_peers_get_by_public_key (priv, public_key, FALSE) == pd_idx);

	if (pd_idx) {
		g_hash_table_remove (priv->peers_hash, pd_idx);
		nm_wireguard_peer_unref (pd_idx->peer);
		pd_idx->public_key = public_key;
		pd_idx->peer = peer;
		g_hash_table_add (priv->peers_hash, pd_idx);
		return TRUE;
	}


	if (!pd_same_key)
		pd_same_key = g_slice_new (PeerData);

	*pd_same_key = (PeerData) {
		.peer = peer,
		.public_key = public_key,
		.idx = priv->peers_arr->len,
	};

	g_ptr_array_add (priv->peers_arr, pd_same_key);
	if (!nm_g_hash_table_add (priv->peers_hash, pd_same_key))
		nm_assert_not_reached ();

	nm_assert (_peers_get (priv, pd_same_key->idx) == pd_same_key);

	return TRUE;
}

static gboolean
_peers_append (NMSettingWireGuardPrivate *priv,
               NMWireGuardPeer *peer,
               gboolean check_same_key)
{
	return _peers_set (priv, peer, priv->peers_arr->len, check_same_key);
}

/**
 * nm_setting_wireguard_set_peer:
 * @self: the #NMSettingWireGuard instance
 * @peer: the #NMWireGuardPeer instance to set.
 *   This seals @peer and keeps a reference on the
 *   instance.
 * @idx: the index, in the range of 0 to the number of
 *   peers (including). That means, if @idx is one past
 *   the end of the number of peers, this is the same as
 *   nm_setting_wireguard_append_peer(). Otherwise, the
 *   peer at this index is replaced.
 *
 * If @idx is one past the last peer, the behavior is the same
 * as nm_setting_wireguard_append_peer().
 * Otherwise, the peer will be at @idx and replace the peer
 * instance at that index. Note that if a peer with the same
 * public-key exists on another index, then that peer will also
 * be replaced. In that case, the number of peers will shrink
 * by one (because the one at @idx got replace and then one
 * with the same public-key got removed). This also means,
 * that the resulting index afterwards may be one less than
 * @idx (if another peer with a lower index was dropped).
 *
 * Since: 1.16
 */
void
nm_setting_wireguard_set_peer (NMSettingWireGuard *self,
                               NMWireGuardPeer *peer,
                               guint idx)
{
	NMSettingWireGuardPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIREGUARD (self));
	g_return_if_fail (NM_IS_WIREGUARD_PEER (peer, TRUE));

	priv = NM_SETTING_WIREGUARD_GET_PRIVATE (self);

	g_return_if_fail (idx <= priv->peers_arr->len);

	if (_peers_set (priv, peer, idx, TRUE))
		_peers_notify (self);
}

/**
 * nm_setting_wireguard_append_peer:
 * @self: the #NMSettingWireGuard instance
 * @peer: the #NMWireGuardPeer instance to append.
 *   This seals @peer and keeps a reference on the
 *   instance.
 *
 * If a peer with the same public-key already exists, that
 * one is replaced by @peer. The new @peer is always appended
 * (or moved to) the end, so in case a peer is replaced, the
 * indexes are shifted and the number of peers stays unchanged.
 *
 * Since: 1.16
 */
void
nm_setting_wireguard_append_peer (NMSettingWireGuard *self,
                                  NMWireGuardPeer *peer)
{
	g_return_if_fail (NM_IS_SETTING_WIREGUARD (self));
	g_return_if_fail (NM_IS_WIREGUARD_PEER (peer, TRUE));

	if (_peers_append (NM_SETTING_WIREGUARD_GET_PRIVATE (self),
	                   peer,
	                   TRUE))
		_peers_notify (self);
}

/**
 * nm_setting_wireguard_remove_peer
 * @self: the #NMSettingWireGuard instance
 * @idx: the index to remove.
 *
 * Returns: %TRUE if @idx was in range and a peer
 *   was removed. Otherwise, @self is unchanged.
 *
 * Since: 1.16
 */
gboolean
nm_setting_wireguard_remove_peer (NMSettingWireGuard *self,
                                  guint idx)
{
	NMSettingWireGuardPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), FALSE);

	priv = NM_SETTING_WIREGUARD_GET_PRIVATE (self);

	if (idx >= priv->peers_arr->len)
		return FALSE;

	_peers_remove (priv, _peers_get (priv, idx), TRUE);
	_peers_notify (self);
	return TRUE;
}

static guint
_peers_clear (NMSettingWireGuardPrivate *priv)
{
	guint l;

	l = priv->peers_arr->len;
	while (priv->peers_arr->len > 0) {
		_peers_remove (priv,
		               _peers_get (priv, priv->peers_arr->len - 1),
		               TRUE);
	}
	return l;
}

/**
 * nm_setting_wireguard_:
 * @self: the #NMSettingWireGuard instance
 *
 * Returns: the number of cleared peers.
 *
 * Since: 1.16
 */
guint
nm_setting_wireguard_clear_peers (NMSettingWireGuard *self)
{
	guint l;

	g_return_val_if_fail (NM_IS_SETTING_WIREGUARD (self), 0);

	l = _peers_clear (NM_SETTING_WIREGUARD_GET_PRIVATE (self));
	if (l > 0)
		_peers_notify (self);
	return l;
}

/*****************************************************************************/

static GVariant *
_peers_dbus_only_synth (const NMSettInfoSetting *sett_info,
                        guint property_idx,
                        NMConnection *connection,
                        NMSetting *setting,
                        NMConnectionSerializationFlags flags)
{
	NMSettingWireGuard *self = NM_SETTING_WIREGUARD (setting);
	NMSettingWireGuardPrivate *priv;
	gboolean any_peers = FALSE;
	GVariantBuilder peers_builder;
	guint i_peer, n_peers;
	guint i;

	n_peers = nm_setting_wireguard_get_peers_len (self);
	if (n_peers == 0)
		return NULL;

	priv = NM_SETTING_WIREGUARD_GET_PRIVATE (self);

	for (i_peer = 0; i_peer < n_peers; i_peer++) {
		const NMWireGuardPeer *peer = _peers_get (priv, i_peer)->peer;
		GVariantBuilder builder;

		if (!peer->public_key)
			continue;

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

		g_variant_builder_add (&builder, "{sv}", NM_WIREGUARD_PEER_ATTR_PUBLIC_KEY, g_variant_new_string (peer->public_key));

		if (   !NM_FLAGS_HAS (flags, NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		    && peer->endpoint)
			g_variant_builder_add (&builder, "{sv}", NM_WIREGUARD_PEER_ATTR_ENDPOINT, g_variant_new_string (nm_sock_addr_endpoint_get_endpoint (peer->endpoint)));

		if (   !NM_FLAGS_HAS (flags, NM_CONNECTION_SERIALIZE_NO_SECRETS)
		    && peer->preshared_key)
			g_variant_builder_add (&builder, "{sv}", NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY, g_variant_new_string (peer->preshared_key));

		if (   !NM_FLAGS_HAS (flags, NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		    && peer->preshared_key_flags != NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			g_variant_builder_add (&builder, "{sv}", NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY_FLAGS, g_variant_new_uint32 (peer->preshared_key_flags));

		if (   !NM_FLAGS_HAS (flags, NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		    && peer->persistent_keepalive != 0)
			g_variant_builder_add (&builder, "{sv}", NM_WIREGUARD_PEER_ATTR_PERSISTENT_KEEPALIVE, g_variant_new_uint32 (peer->persistent_keepalive));

		if (   !NM_FLAGS_HAS (flags, NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		    && peer->allowed_ips
		    && peer->allowed_ips->len > 0) {
			const char *const*strv = (const char *const*) peer->allowed_ips->pdata;
			gs_free const char **strv_fixed = NULL;

			for (i = 0; i < peer->allowed_ips->len; i++) {
				if (strv[i][0] != ALLOWED_IP_INVALID_X)
					continue;
				if (!strv_fixed) {
					strv_fixed = nm_memdup (strv, sizeof (strv[0]) * peer->allowed_ips->len);
					strv = strv_fixed;
				}
				((const char **) strv)[i]++;
			}
			g_variant_builder_add (&builder, "{sv}", NM_WIREGUARD_PEER_ATTR_ALLOWED_IPS,
			                       g_variant_new_strv (strv, peer->allowed_ips->len));
		}

		if (!any_peers) {
			g_variant_builder_init (&peers_builder, G_VARIANT_TYPE ("aa{sv}"));
			any_peers = TRUE;
		}
		g_variant_builder_add (&peers_builder, "a{sv}", &builder);
	}

	return   any_peers
	       ? g_variant_builder_end (&peers_builder)
	       : NULL;
}

static gboolean
_peers_dbus_only_set (NMSetting     *setting,
                      GVariant      *connection_dict,
                      const char    *property,
                      GVariant      *value,
                      NMSettingParseFlags parse_flags,
                      GError       **error)
{
	GVariantIter iter_peers;
	GVariant *peer_var;
	guint i_peer;
	gboolean success = FALSE;
	gboolean peers_changed = FALSE;

	nm_assert (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")));

	g_variant_iter_init (&iter_peers, value);

	i_peer = 0;
	while (g_variant_iter_next (&iter_peers, "@a{sv}", &peer_var)) {
		_nm_unused gs_unref_variant GVariant *peer_var_unref = peer_var;
		nm_auto_unref_wgpeer NMWireGuardPeer *peer = NULL;
		const char *cstr;
		guint32 u32;
		GVariant *var;

		i_peer++;

		if (!g_variant_lookup (peer_var, NM_WIREGUARD_PEER_ATTR_PUBLIC_KEY, "&s", &cstr)) {
			if (NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT)) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
				             _("peer #%u has no public-key"),
				             i_peer);
				goto out;
			}
			continue;
		}

		peer = nm_wireguard_peer_new ();
		if (!nm_wireguard_peer_set_public_key (peer, cstr, TRUE)) {
			if (NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT)) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
				             _("peer #%u has invalid public-key"),
				             i_peer);
				goto out;
			}
			continue;
		}

		if (g_variant_lookup (peer_var, NM_WIREGUARD_PEER_ATTR_ENDPOINT, "&s", &cstr)) {
			nm_auto_unref_sockaddrendpoint NMSockAddrEndpoint *ep = NULL;

			ep = nm_sock_addr_endpoint_new (cstr);
			if (!nm_sock_addr_endpoint_get_host (ep)) {
				if (NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT)) {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
					             _("peer #%u has invalid endpoint"),
					             i_peer);
					goto out;
				}
			} else
				_nm_wireguard_peer_set_endpoint (peer, ep);
		}

		if (g_variant_lookup (peer_var, NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY, "&s", &cstr))
			nm_wireguard_peer_set_preshared_key (peer, cstr, TRUE);

		if (g_variant_lookup (peer_var, NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY_FLAGS, "u", &u32))
			nm_wireguard_peer_set_preshared_key_flags (peer, u32);

		if (g_variant_lookup (peer_var, NM_WIREGUARD_PEER_ATTR_PERSISTENT_KEEPALIVE, "u", &u32))
			nm_wireguard_peer_set_persistent_keepalive (peer, u32);

		if (g_variant_lookup (peer_var, NM_WIREGUARD_PEER_ATTR_ALLOWED_IPS, "@as", &var)) {
			_nm_unused gs_unref_variant GVariant *var_free = var;
			gs_free const char **allowed_ips = NULL;
			gsize i, l;

			allowed_ips = g_variant_get_strv (var, &l);
			if (allowed_ips) {
				for (i = 0; i < l; i++) {
					if (_peer_append_allowed_ip (peer, allowed_ips[i], FALSE))
						continue;
					if (!NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT))
						continue;
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
					             _("peer #%u has invalid allowed-ips setting"),
					             i_peer);
					goto out;
				}
			}
		}

		if (NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT)) {
			gs_free_error GError *local = NULL;

			if (!nm_wireguard_peer_is_valid (peer, TRUE, FALSE, &local)) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
				             _("peer #%u is invalid: %s"),
				             i_peer, local->message);
				goto out;
			}
		}

		/* we could easily reject duplicate peers (by public-key) or duplicate GVariant attributes.
		 * However, don't do that. In case of duplicate values, the latter peer overwrite the earlier
		 * and GVariant attributes are ignored by g_variant_lookup() above. */
		if (_peers_append (NM_SETTING_WIREGUARD_GET_PRIVATE (setting),
		                   peer,
		                   TRUE))
			peers_changed = TRUE;
	}

	success = TRUE;

out:
	if (peers_changed)
		_peers_notify (setting);
	return success;
}

/*****************************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWireGuard *s_wg = NM_SETTING_WIREGUARD (setting);
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);
	guint i;

	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	if (!_nm_utils_secret_flags_validate (nm_setting_wireguard_get_private_key_flags (s_wg),
	                                      NM_SETTING_WIREGUARD_SETTING_NAME,
	                                      NM_SETTING_WIREGUARD_PRIVATE_KEY_FLAGS,
	                                      NM_SETTING_SECRET_FLAG_NOT_REQUIRED,
	                                      error))
		return FALSE;

	for (i = 0; i < priv->peers_arr->len; i++) {
		NMWireGuardPeer *peer = _peers_get (priv, i)->peer;

		if (!nm_wireguard_peer_is_valid (peer, TRUE, FALSE, error)) {
			g_prefix_error (error,
			                "%s.%s[%u]: ",
			                NM_SETTING_WIREGUARD_SETTING_NAME,
			                NM_SETTING_WIREGUARD_PEERS,
			                i);
			return FALSE;
		}
	}

	if (connection) {
		NMSettingIPConfig *s_ip4;
		NMSettingIPConfig *s_ip6;
		const char *method;

		/* WireGuard is Layer 3 only. For the moment, we only support a restricted set of
		 * IP methods. We may relax that later, once we fix the implementations so they
		 * actually work. */

		if (   (s_ip4 = nm_connection_get_setting_ip4_config (connection))
		    && (method = nm_setting_ip_config_get_method (s_ip4))
		    && !NM_IN_STRSET (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED,
		                              NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("method \"%s\" is not supported for WireGuard"),
			             method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP4_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_METHOD);
			return FALSE;
		}

		if (   (s_ip6 = nm_connection_get_setting_ip6_config (connection))
		    && (method = nm_setting_ip_config_get_method (s_ip6))
		    && !NM_IN_STRSET (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE,
		                              NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL,
		                              NM_SETTING_IP6_CONFIG_METHOD_MANUAL)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("method \"%s\" is not supported for WireGuard"),
			             method);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_IP6_CONFIG_SETTING_NAME, NM_SETTING_IP_CONFIG_METHOD);
			return FALSE;
		}
	}

	/* private-key is a secret, hence we cannot verify it like a regular property. */
	return TRUE;
}

static gboolean
verify_secrets (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);
	guint i;

	if (   priv->private_key
	    && !priv->private_key_valid) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("key must be 32 bytes base64 encoded"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIREGUARD_SETTING_NAME, NM_SETTING_WIREGUARD_PRIVATE_KEY);
		return FALSE;
	}

	for (i = 0; i < priv->peers_arr->len; i++) {
		NMWireGuardPeer *peer = _peers_get (priv, i)->peer;

		if (!nm_wireguard_peer_is_valid (peer, FALSE, TRUE, error)) {
			g_prefix_error (error,
			                "%s.%s[%u]: ",
			                NM_SETTING_WIREGUARD_SETTING_NAME,
			                NM_SETTING_WIREGUARD_PEERS,
			                i);
			return FALSE;
		}
	}

	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);
	GPtrArray *secrets = NULL;
	guint i;

	if (   !priv->private_key
	    || !priv->private_key_valid) {
		secrets = g_ptr_array_new_full (1, g_free);
		g_ptr_array_add (secrets, g_strdup (NM_SETTING_WIREGUARD_PRIVATE_KEY));
	}

	for (i = 0; i < priv->peers_arr->len; i++) {
		NMWireGuardPeer *peer = _peers_get (priv, i)->peer;

		if (NM_FLAGS_HAS (peer->preshared_key_flags, NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			continue;

		if (peer->preshared_key_valid)
			continue;

		if (!peer->public_key_valid)
			continue;

		if (!secrets)
			secrets = g_ptr_array_new_full (1, g_free);
		g_ptr_array_add (secrets, peers_psk_get_secret_name_dup (peer->public_key));
	}

	return secrets;
}

static gboolean
clear_secrets (const NMSettInfoSetting *sett_info,
               guint property_idx,
               NMSetting *setting,
               NMSettingClearSecretsWithFlagsFn func,
               gpointer user_data)
{
	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_WIREGUARD_PEERS)) {
		NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);
		gboolean peers_changed = FALSE;
		guint i, j;

		j = 0;
		for (i = 0; i < priv->peers_arr->len; i++) {
			NMWireGuardPeer *peer = _peers_get (priv, i)->peer;

			if (!peer->preshared_key)
				continue;

			if (func) {
				gs_free char *name_free = NULL;
				const char *name;

				/* only stack-allocate (alloca) a few times. */
				if (j++ < 5)
					name = peers_psk_get_secret_name_a (peer->public_key, &name_free);
				else {
					name_free = peers_psk_get_secret_name_dup (peer->public_key);
					name = name_free;
				}

				if (!func (setting, name, peer->preshared_key_flags, user_data))
					continue;
			}

			{
				nm_auto_unref_wgpeer NMWireGuardPeer *peer2 = NULL;

				peer2 = nm_wireguard_peer_new_clone (peer, FALSE);

				if (_peers_set (priv, peer2, i, FALSE))
					peers_changed = TRUE;
			}
		}

		if (peers_changed)
			_peers_notify (setting);
		return peers_changed;
	}

	return NM_SETTING_CLASS (nm_setting_wireguard_parent_class)->clear_secrets (sett_info,
	                                                                            property_idx,
	                                                                            setting,
	                                                                            func,
	                                                                            user_data);
}

static int
update_one_secret (NMSetting *setting,
                   const char *key,
                   GVariant *value,
                   GError **error)
{
	NMSettingWireGuard *self = NM_SETTING_WIREGUARD (setting);
	NMSettingWireGuardPrivate *priv;
	gboolean has_changes = FALSE;
	gboolean has_error = FALSE;
	GVariantIter iter_peers;
	GVariant *peer_var;
	guint i_peer;

	if (!nm_streq (key, NM_SETTING_WIREGUARD_PEERS)) {
		return NM_SETTING_CLASS (nm_setting_wireguard_parent_class)->update_one_secret (setting,
		                                                                                key,
		                                                                                value,
		                                                                                error);
	}

	if (!g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}"))) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_PROPERTY_NOT_SECRET,
		                     _("invalid peer secrets"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIREGUARD_SETTING_NAME, NM_SETTING_WIREGUARD_PEERS);
		return NM_SETTING_UPDATE_SECRET_ERROR;
	}

	priv = NM_SETTING_WIREGUARD_GET_PRIVATE (self);

	g_variant_iter_init (&iter_peers, value);

	i_peer = 0;
	while (g_variant_iter_next (&iter_peers, "@a{sv}", &peer_var)) {
		_nm_unused gs_unref_variant GVariant *peer_var_unref = peer_var;
		PeerData *pd;
		NMWireGuardPeer *peer;
		const char *cstr;

		i_peer++;

		if (!g_variant_lookup (peer_var, NM_WIREGUARD_PEER_ATTR_PUBLIC_KEY, "&s", &cstr)) {
			if (!has_error) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_PROPERTY_NOT_SECRET,
				             _("peer #%u lacks public-key"),
				             i_peer - 1);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIREGUARD_SETTING_NAME, NM_SETTING_WIREGUARD_PEERS);
				has_error = TRUE;
			}
			continue;
		}

		pd = _peers_get_by_public_key (priv, cstr, TRUE);
		if (!pd) {
			if (!has_error) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_PROPERTY_NOT_SECRET,
				             _("non-existing peer '%s'"),
				             cstr);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIREGUARD_SETTING_NAME, NM_SETTING_WIREGUARD_PEERS);
				has_error = TRUE;
			}
			continue;
		}

		if (!g_variant_lookup (peer_var, NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY, "&s", &cstr)) {
			/* no preshared-key. Ignore the rest.
			 *
			 * In particular, we don't reject all unknown fields. */
			continue;
		}

		if (nm_streq0  (cstr, nm_wireguard_peer_get_preshared_key (pd->peer)))
			continue;

		peer = nm_wireguard_peer_new_clone (pd->peer, FALSE);
		nm_wireguard_peer_set_preshared_key (peer, cstr, TRUE);

		if (!_peers_set (priv, peer, pd->idx, FALSE))
			nm_assert_not_reached ();
		has_changes = TRUE;
	}

	if (has_error)
		return NM_SETTING_UPDATE_SECRET_ERROR;
	if (has_changes)
		return NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED;
	return NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;
}

static NMTernary
compare_property (const NMSettInfoSetting *sett_info,
                  guint property_idx,
                  NMSetting *setting,
                  NMSetting *other,
                  NMSettingCompareFlags flags)
{
	NMSettingWireGuardPrivate *a_priv;
	NMSettingWireGuardPrivate *b_priv;
	guint i;

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_WIREGUARD_PEERS)) {

		if (NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_INFERRABLE))
			return NM_TERNARY_DEFAULT;

		if (!other)
			return TRUE;

		a_priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);
		b_priv = NM_SETTING_WIREGUARD_GET_PRIVATE (other);

		if (a_priv->peers_arr->len != b_priv->peers_arr->len)
			return FALSE;
		for (i = 0; i < a_priv->peers_arr->len; i++) {
			NMWireGuardPeer *a_peer = _peers_get (a_priv, i)->peer;
			NMWireGuardPeer *b_peer = _peers_get (b_priv, i)->peer;

			if (nm_wireguard_peer_cmp (a_peer,
			                           b_peer,
			                           flags) != 0)
				return FALSE;
		}

		return TRUE;
	}

	return NM_SETTING_CLASS (nm_setting_wireguard_parent_class)->compare_property (sett_info,
	                                                                               property_idx,
	                                                                               setting,
	                                                                               other,
	                                                                               flags);
}

static void
duplicate_copy_properties (const NMSettInfoSetting *sett_info,
                           NMSetting *src,
                           NMSetting *dst)
{
	NMSettingWireGuardPrivate *priv_src = NM_SETTING_WIREGUARD_GET_PRIVATE (src);
	NMSettingWireGuardPrivate *priv_dst = NM_SETTING_WIREGUARD_GET_PRIVATE (dst);
	guint i;
	gboolean peers_changed = FALSE;

	NM_SETTING_CLASS (nm_setting_wireguard_parent_class)->duplicate_copy_properties (sett_info,
	                                                                                 src,
	                                                                                 dst);

	/* We don't bother comparing the existing peers with what we are about to set.
	 * Always reset all. */
	if (_peers_clear (priv_dst) > 0)
		peers_changed = TRUE;
	for (i = 0; i < priv_src->peers_arr->len; i++) {
		if (_peers_append (priv_dst,
		                   _peers_get (priv_src, i)->peer,
		                   FALSE))
			peers_changed = TRUE;
	}
	if (peers_changed)
		_peers_notify (dst);
}

static void
enumerate_values (const NMSettInfoProperty *property_info,
                  NMSetting *setting,
                  NMSettingValueIterFn func,
                  gpointer user_data)
{
	if (nm_streq (property_info->name, NM_SETTING_WIREGUARD_PEERS)) {
		NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);
		nm_auto_unset_gvalue GValue value = G_VALUE_INIT;
		GPtrArray *ptr = NULL;
		guint i;

		if (priv->peers_arr && priv->peers_arr->len > 0) {
			ptr = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_wireguard_peer_unref);
			for (i = 0; i < priv->peers_arr->len; i++)
				g_ptr_array_add (ptr, nm_wireguard_peer_ref (_peers_get (priv, i)->peer));
		}
		g_value_init (&value, G_TYPE_PTR_ARRAY);
		g_value_take_boxed (&value, ptr);
		func (setting,
		      property_info->name,
		      &value,
		      0,
		      user_data);
		return;
	}

	NM_SETTING_CLASS (nm_setting_wireguard_parent_class)->enumerate_values (property_info,
	                                                                        setting,
	                                                                        func,
	                                                                        user_data);
}

static gboolean
aggregate (NMSetting *setting,
           int type_i,
           gpointer arg)
{
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);
	NMConnectionAggregateType type = type_i;
	NMSettingSecretFlags secret_flags;
	guint i;

	nm_assert (NM_IN_SET (type, NM_CONNECTION_AGGREGATE_ANY_SECRETS,
	                            NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS));

	switch (type) {

	case NM_CONNECTION_AGGREGATE_ANY_SECRETS:
		if (priv->private_key)
			goto out_done;
		for (i = 0; i < priv->peers_arr->len; i++) {
			if (nm_wireguard_peer_get_preshared_key (_peers_get (priv, i)->peer))
				goto out_done;
		}
		break;

	case NM_CONNECTION_AGGREGATE_ANY_SYSTEM_SECRET_FLAGS:
#if NM_MORE_ASSERTS
		if (!nm_setting_get_secret_flags (setting, NM_SETTING_WIREGUARD_PRIVATE_KEY, &secret_flags, NULL))
			nm_assert_not_reached ();
		nm_assert (secret_flags == priv->private_key_flags);
#endif
		if (priv->private_key_flags == NM_SETTING_SECRET_FLAG_NONE)
			goto out_done;
		for (i = 0; i < priv->peers_arr->len; i++) {
			secret_flags = nm_wireguard_peer_get_preshared_key_flags (_peers_get (priv, i)->peer);
			if (secret_flags == NM_SETTING_SECRET_FLAG_NONE)
				goto out_done;
		}
		break;
	}

	return FALSE;

out_done:
	*((gboolean *) arg) = TRUE;
	return TRUE;
}

static gboolean
get_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  NMSettingSecretFlags *out_flags,
                  GError **error)
{
	if (NM_STR_HAS_PREFIX (secret_name, NM_SETTING_WIREGUARD_PEERS".")) {
		NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);
		gs_free char *public_key_free = NULL;
		const char *public_key;
		PeerData *pd;

		public_key = peers_psk_get_secret_parse_a (secret_name, &public_key_free);
		if (   public_key
		    && (pd = _peers_get_by_public_key (priv, public_key, FALSE))) {
			NM_SET_OUT (out_flags, nm_wireguard_peer_get_preshared_key_flags (pd->peer));
			return TRUE;
		}
	}

	return NM_SETTING_CLASS (nm_setting_wireguard_parent_class)->get_secret_flags (setting,
	                                                                               secret_name,
	                                                                               out_flags,
	                                                                               error);
}

static gboolean
set_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  NMSettingSecretFlags flags,
                  GError **error)
{
	if (NM_STR_HAS_PREFIX (secret_name, NM_SETTING_WIREGUARD_PEERS".")) {
		NMSettingWireGuard *self = NM_SETTING_WIREGUARD (setting);
		NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (self);
		gs_free char *public_key_free = NULL;
		const char *public_key;
		PeerData *pd;

		public_key = peers_psk_get_secret_parse_a (secret_name, &public_key_free);
		if (   public_key
		    && (pd = _peers_get_by_public_key (priv, public_key, FALSE))) {

			if (nm_wireguard_peer_get_preshared_key_flags (pd->peer) != flags) {
				nm_auto_unref_wgpeer NMWireGuardPeer *peer = NULL;

				peer = nm_wireguard_peer_new_clone (pd->peer, TRUE);
				peer->preshared_key_flags = flags;
				if (_peers_set (priv, peer, pd->idx, FALSE))
					_peers_notify (self);
			}

			return TRUE;
		}
	}

	return NM_SETTING_CLASS (nm_setting_wireguard_parent_class)->set_secret_flags (setting,
	                                                                               secret_name,
	                                                                               flags,
	                                                                               error);
}

static void
for_each_secret (NMSetting *setting,
                 const char *data_key,
                 GVariant *data_val,
                 gboolean remove_non_secrets,
                 _NMConnectionForEachSecretFunc callback,
                 gpointer callback_data,
                 GVariantBuilder *setting_builder)
{
	NMSettingWireGuard *s_wg;
	NMSettingWireGuardPrivate *priv;
	GVariantBuilder peers_builder;
	GVariantIter *peer_iter;
	GVariantIter data_iter;
	const char *key;

	if (!nm_streq (data_key, NM_SETTING_WIREGUARD_PEERS)) {
		NM_SETTING_CLASS (nm_setting_wireguard_parent_class)->for_each_secret (setting,
		                                                                       data_key,
		                                                                       data_val,
		                                                                       remove_non_secrets,
		                                                                       callback,
		                                                                       callback_data,
		                                                                       setting_builder);
		return;
	}

	if (!g_variant_is_of_type (data_val, G_VARIANT_TYPE ("aa{sv}"))) {
		/* invalid type. Silently ignore content as we cannot find secret-keys
		 * here. */
		return;
	}

	s_wg = NM_SETTING_WIREGUARD (setting);
	priv = NM_SETTING_WIREGUARD_GET_PRIVATE (s_wg);

	g_variant_builder_init (&peers_builder, G_VARIANT_TYPE ("aa{sv}"));
	g_variant_iter_init (&data_iter, data_val);
	while (g_variant_iter_next (&data_iter, "a{sv}", &peer_iter)) {
		_nm_unused nm_auto_free_variant_iter GVariantIter *peer_iter_free = peer_iter;
		gs_unref_variant GVariant *preshared_key = NULL;
		PeerData *pd = NULL;
		NMSettingSecretFlags secret_flags;
		GVariant *val;
		GVariantBuilder peer_builder;

		g_variant_builder_init (&peer_builder, G_VARIANT_TYPE ("a{sv}"));

		while (g_variant_iter_next (peer_iter, "{&sv}", &key, &val)) {
			_nm_unused gs_unref_variant GVariant *val_free = val;

			if (nm_streq (key, NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY)) {
				if (   !preshared_key
				    && g_variant_is_of_type (val, G_VARIANT_TYPE_STRING))
					preshared_key = g_variant_ref (val);
				continue;
			}

			if (nm_streq (key, NM_WIREGUARD_PEER_ATTR_PUBLIC_KEY)) {
				if (   !pd
				    && g_variant_is_of_type (val, G_VARIANT_TYPE_STRING))
					pd = _peers_get_by_public_key (priv, g_variant_get_string (val, NULL), TRUE);
			} else if (remove_non_secrets)
				continue;

			g_variant_builder_add (&peer_builder, "{sv}", key, val);
		}

		if (pd && preshared_key) {
			/* without specifying a public-key of an existing peer, the secret is
			 * ignored. */
			secret_flags = nm_wireguard_peer_get_preshared_key_flags (pd->peer);
			if (callback (secret_flags, callback_data))
				g_variant_builder_add (&peer_builder, "{sv}", NM_WIREGUARD_PEER_ATTR_PRESHARED_KEY, preshared_key);
		}

		g_variant_builder_add (&peers_builder, "a{sv}", &peer_builder);
	}

	g_variant_builder_add (setting_builder,
	                       "{sv}",
	                       NM_SETTING_WIREGUARD_PEERS,
	                       g_variant_builder_end (&peers_builder));
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingWireGuard *setting = NM_SETTING_WIREGUARD (object);
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_FWMARK:
		g_value_set_uint (value, priv->fwmark);
		break;
	case PROP_LISTEN_PORT:
		g_value_set_uint (value, priv->listen_port);
		break;
	case PROP_MTU:
		g_value_set_uint (value, priv->mtu);
		break;
	case PROP_PEER_ROUTES:
		g_value_set_boolean (value, priv->peer_routes);
		break;
	case PROP_PRIVATE_KEY:
		g_value_set_string (value, priv->private_key);
		break;
	case PROP_PRIVATE_KEY_FLAGS:
		g_value_set_flags (value, priv->private_key_flags);
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
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (object);
	const char *str;

	switch (prop_id) {
	case PROP_FWMARK:
		priv->fwmark = g_value_get_uint (value);
		break;
	case PROP_LISTEN_PORT:
		priv->listen_port = g_value_get_uint (value);
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_PEER_ROUTES:
		priv->peer_routes = g_value_get_boolean (value);
		break;
	case PROP_PRIVATE_KEY:
		nm_clear_pointer (&priv->private_key, nm_free_secret);
		str = g_value_get_string (value);
		if (str) {
			if (nm_utils_base64secret_normalize (str,
			                                     NM_WIREGUARD_PUBLIC_KEY_LEN,
			                                     &priv->private_key))
				priv->private_key_valid = TRUE;
			else {
				priv->private_key = g_strdup (str);
				priv->private_key_valid = FALSE;
			}
		}
		break;
	case PROP_PRIVATE_KEY_FLAGS:
		priv->private_key_flags = g_value_get_flags (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_wireguard_init (NMSettingWireGuard *setting)
{
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (setting);

	priv->peers_arr = g_ptr_array_new ();
	priv->peers_hash = g_hash_table_new (nm_pstr_hash, nm_pstr_equal);
	priv->peer_routes = TRUE;
}

/**
 * nm_setting_wireguard_new:
 *
 * Creates a new #NMSettingWireGuard object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWireGuard object
 *
 * Since: 1.16
 **/
NMSetting *
nm_setting_wireguard_new (void)
{
	return g_object_new (NM_TYPE_SETTING_WIREGUARD, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingWireGuardPrivate *priv = NM_SETTING_WIREGUARD_GET_PRIVATE (object);

	nm_free_secret (priv->private_key);

	_peers_clear (priv);
	g_ptr_array_unref (priv->peers_arr);
	g_hash_table_unref (priv->peers_hash);

	G_OBJECT_CLASS (nm_setting_wireguard_parent_class)->finalize (object);
}

static void
nm_setting_wireguard_class_init (NMSettingWireGuardClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify                    = verify;
	setting_class->verify_secrets            = verify_secrets;
	setting_class->need_secrets              = need_secrets;
	setting_class->clear_secrets             = clear_secrets;
	setting_class->update_one_secret         = update_one_secret;
	setting_class->compare_property          = compare_property;
	setting_class->duplicate_copy_properties = duplicate_copy_properties;
	setting_class->enumerate_values          = enumerate_values;
	setting_class->aggregate                 = aggregate;
	setting_class->get_secret_flags          = get_secret_flags;
	setting_class->set_secret_flags          = set_secret_flags;
	setting_class->for_each_secret           = for_each_secret;

	/**
	 * NMSettingWireGuard:private-key:
	 *
	 * The 256 bit private-key in base64 encoding.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_PRIVATE_KEY] =
	    g_param_spec_string (NM_SETTING_WIREGUARD_PRIVATE_KEY, "", "",
	                         NULL,
	                           G_PARAM_READWRITE
	                         | NM_SETTING_PARAM_SECRET
	                         | G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWireGuard:private-key-flags:
	 *
	 * Flags indicating how to handle the #NMSettingWirelessSecurity:private-key
	 * property.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_PRIVATE_KEY_FLAGS] =
	    g_param_spec_flags (NM_SETTING_WIREGUARD_PRIVATE_KEY_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                          G_PARAM_READWRITE
	                        | G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWireGuard:fwmark:
	 *
	 * The use of fwmark is optional and is by default off. Setting it to 0
	 * disables it. Otherwise it is a 32-bit fwmark for outgoing packets.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_FWMARK] =
	    g_param_spec_uint (NM_SETTING_WIREGUARD_FWMARK, "", "",
	                       0, G_MAXUINT32, 0,
	                         G_PARAM_READWRITE
	                       | NM_SETTING_PARAM_INFERRABLE
	                       | G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWireGuard:listen-port:
	 *
	 * The listen-port. If listen-port is not specified, the port will be chosen
	 * randomly when the interface comes up.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_LISTEN_PORT] =
	    g_param_spec_uint (NM_SETTING_WIREGUARD_LISTEN_PORT, "", "",
	                       0, 65535, 0,
	                         G_PARAM_READWRITE
	                       | NM_SETTING_PARAM_INFERRABLE
	                       | G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWireGuard:peer-routes:
	 *
	 * Whether to automatically add routes for the AllowedIPs ranges
	 * of the peers. If %TRUE (the default), NetworkManager will automatically
	 * add routes in the routing tables according to ipv4.route-table and
	 * ipv6.route-table.
	 * If %FALSE, no such routes are added automatically. In this case, the
	 * user may want to configure static routes in ipv4.routes and ipv6.routes,
	 * respectively.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_PEER_ROUTES] =
	    g_param_spec_boolean (NM_SETTING_WIREGUARD_PEER_ROUTES, "", "",
	                          TRUE,
	                            G_PARAM_READWRITE
	                          | NM_SETTING_PARAM_INFERRABLE
	                          | G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingWireGuard:mtu:
	 *
	 * If non-zero, only transmit packets of the specified size or smaller,
	 * breaking larger packets up into multiple fragments.
	 *
	 * If zero a default MTU is used. Note that contrary to wg-quick's MTU
	 * setting, this does not take into account the current routes at the
	 * time of activation.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_MTU] =
	    g_param_spec_uint (NM_SETTING_WIREGUARD_MTU, "", "",
	                       0, G_MAXUINT32, 0,
	                         G_PARAM_READWRITE
	                       | NM_SETTING_PARAM_INFERRABLE
	                       | G_PARAM_STATIC_STRINGS);

	/* ---dbus---
	 * property: peers
	 * format: array of 'a{sv}'
	 * description: Array of dictionaries for the WireGuard peers.
	 * ---end---
	 */
	_properties_override_add_dbus_only (properties_override,
	                                    NM_SETTING_WIREGUARD_PEERS,
	                                    G_VARIANT_TYPE ("aa{sv}"),
	                                    _peers_dbus_only_synth,
	                                    _peers_dbus_only_set);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_WIREGUARD, NULL, properties_override);
}
