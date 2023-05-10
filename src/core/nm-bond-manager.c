/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-bond-manager.h"

#include <linux/if.h>

#include "NetworkManagerUtils.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nmp-object.h"
#include "nm-firewall-utils.h"

/*****************************************************************************/

typedef enum _nm_packed {
    REGISTRATION_STATE_NONE,
    REGISTRATION_STATE_UPPING,
    REGISTRATION_STATE_UP,
    REGISTRATION_STATE_DOWNING,
} RegistrationState;

struct _NMBondManager {
    NMPlatform *platform;

    NMBondManagerCallback callback;
    gpointer              user_data;

    /* This is only used for structured logging. */
    char *connection_uuid;

    GSource *reconfigure_on_idle_source;

    /* During _reconfigure_check() we remember all ifindexes that are part
     * of the current SLB bond. This is used during _link_changed_cb() to
     * figure out whether a change on the interface might be relevant to
     * trigger a _reconfigure_check() on idle. */
    GHashTable *previous_ifindexes;

    /* We need to keep track of active members that we configured in NFT.
     * That is, because on update we use "add && flush" to reset the table,
     * however that leaves empty chains around. If we previously had an active
     * member, a chain for it was created that we need to clean up.
     *
     * Before every NFT call we use this to generate the list of members that
     * are to be cleaned up. Thereby also adding the new active-memebers to
     * the list. When the NFT calls returns with success, we can prune the
     * now deleted member/chain. */
    GHashTable *previous_members;

    GCancellable *cancellable;

    struct {
        char        *bond_ifname_curr;
        char        *bond_ifname_next;
        const char **active_members_curr;
        const char **active_members_next;
    } dat;

    gulong            link_changed_id;
    int               ifindex;
    RegistrationState reg_state;
    bool              destroyed : 1;

    /* Whether we noticed some changes that require us to _reconfigure_check().
     * Note that while a NFT call is pending, we postpone the check. */
    bool reconfigure_check : 1;

    /* Whether a `nft` call is in progress. Usually this corresponds to
     * having a cancellable, however, we may also cancel and clear the
     * cancellable while the call is still in progress. */
    bool nft_in_progress : 1;

    /* Whether the last NFT invocation was good. If not, we may have
     * an invalid state. Actually unused, so far because it's not
     * clear what to do about failure to configure NFT (aside logging
     * a warning). */
    bool nft_good : 1;

    /* The overall state. DEFAULT means that an update is pending.
     * FALSE means that the last "nft" command failed.
     * TRUE means that the last "nft" command was good. */
    NMOptionBool state : 3;
};

#define NM_IS_BOND_MANAGER(self)                    \
    ({                                              \
        const NMBondManager *_self = (self);        \
                                                    \
        (_self && NM_IS_PLATFORM(_self->platform)); \
    })

/*****************************************************************************/

static void _nft_call(NMBondManager     *self,
                      gboolean           up,
                      const char        *bond_ifname,
                      const char *const *bond_ifnames_down,
                      const char *const *active_members);

static void _bond_manager_destroy(NMBondManager *self);

static void _reconfigure_check(NMBondManager *self, gboolean reapply);

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_DEVICE
#define _NMLOG_PREFIX_NAME "mlag"
#define _NMLOG(level, ...)                                                                           \
    G_STMT_START                                                                                     \
    {                                                                                                \
        const NMLogLevel _level = (level);                                                           \
                                                                                                     \
        if (nm_logging_enabled(_level, _NMLOG_DOMAIN)) {                                             \
            NMBondManager *const _self = (self);                                                     \
            const char *_ifname        = nm_platform_link_get_name(_self->platform, _self->ifindex); \
            char        _sbuf[30];                                                                   \
                                                                                                     \
            _nm_log(_level,                                                                          \
                    _NMLOG_DOMAIN,                                                                   \
                    0,                                                                               \
                    _ifname,                                                                         \
                    _self->connection_uuid,                                                          \
                    "%s[" NM_HASH_OBFUSCATE_PTR_FMT ", %s]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),    \
                    _NMLOG_PREFIX_NAME,                                                              \
                    NM_HASH_OBFUSCATE_PTR(_self),                                                    \
                    (_ifname ?: nm_sprintf_buf(_sbuf, "(%d)", _self->ifindex))                       \
                        _NM_UTILS_MACRO_REST(__VA_ARGS__));                                          \
        }                                                                                            \
    }                                                                                                \
    G_STMT_END

static const char *
_log_info(NMStrBuf          *strbuf,
          const char        *bond_ifname,
          const char *const *active_members,
          const char *const *previous_members)
{
    gsize i;

    nm_str_buf_reset(strbuf);

    if (!bond_ifname)
        nm_str_buf_append(strbuf, "(disabled)");
    else {
        nm_str_buf_append_printf(strbuf, "(enabled, \"%s\"", bond_ifname);

        for (i = 0; active_members && active_members[i]; i++) {
            if (i == 0)
                nm_str_buf_append(strbuf, ", active-members=[ \"");
            else
                nm_str_buf_append(strbuf, "\", \"");
            nm_str_buf_append(strbuf, active_members[i]);
        }
        if (i > 0)
            nm_str_buf_append(strbuf, "\" ]");

        for (i = 0; previous_members && previous_members[i]; i++) {
            nm_assert(!nm_strv_contains(active_members, -1, previous_members[i]));
            if (i == 0)
                nm_str_buf_append(strbuf, ", previous-members=[ \"");
            else
                nm_str_buf_append(strbuf, "\", \"");
            nm_str_buf_append(strbuf, previous_members[i]);
        }
        if (i > 0)
            nm_str_buf_append(strbuf, "\" ]");

        nm_str_buf_append(strbuf, ")");
    }

    return nm_str_buf_get_str(strbuf);
}

/*****************************************************************************/

static gboolean
_nm_assert_self_(NMBondManager *self)
{
    nm_assert(self);
    nm_assert(NM_IS_PLATFORM(self->platform));
    nm_assert(!self->cancellable || G_IS_CANCELLABLE(self->cancellable));
    nm_assert(!self->cancellable || !g_cancellable_is_cancelled(self->cancellable));
    nm_assert(!self->dat.active_members_curr || self->dat.bond_ifname_curr);
    nm_assert(!self->dat.active_members_next || self->dat.bond_ifname_next);
    nm_assert(!self->cancellable || self->nft_in_progress);
    nm_assert(!self->reconfigure_on_idle_source || self->reconfigure_check);
    nm_assert(!self->nft_in_progress || !self->reconfigure_on_idle_source);

    nm_assert(!self->dat.active_members_curr || self->dat.bond_ifname_curr[0]);
    nm_assert(!self->dat.active_members_next || self->dat.bond_ifname_next[0]);

    nm_assert(!self->destroyed || !self->dat.bond_ifname_next);
    nm_assert(!self->destroyed
              || NM_IN_SET((RegistrationState) self->reg_state,
                           REGISTRATION_STATE_UPPING,
                           REGISTRATION_STATE_DOWNING));

    switch (self->reg_state) {
    case REGISTRATION_STATE_NONE:
        nm_assert(!self->nft_in_progress);
        nm_assert(!self->cancellable);
        nm_assert(!self->dat.bond_ifname_curr);
        nm_assert(!self->dat.bond_ifname_next);
        break;
    case REGISTRATION_STATE_UPPING:
        nm_assert(self->nft_in_progress);
        nm_assert(self->dat.bond_ifname_curr);
        break;
    case REGISTRATION_STATE_UP:
        nm_assert(!self->nft_in_progress);
        nm_assert(!self->cancellable);
        nm_assert(self->dat.bond_ifname_curr);
        nm_assert(!self->dat.bond_ifname_next);
        break;
    case REGISTRATION_STATE_DOWNING:
        nm_assert(self->nft_in_progress);
        nm_assert(self->dat.bond_ifname_curr);
        break;
    default:
        nm_assert_not_reached();
        break;
    }

    return TRUE;
}

#define _nm_assert_self(self) nm_assert(_nm_assert_self_(self))

/*****************************************************************************/

static void
_callback_invoke(NMBondManager *self, NMBondManagerEventType event_type)
{
    if (!self->callback)
        return;

    self->callback(self, event_type, self->user_data);
}

static void
_notify_state_change(NMBondManager *self)
{
    NMOptionBool state;

    if (self->nft_in_progress)
        state = NM_OPTION_BOOL_DEFAULT;
    else
        state = !!self->nft_good;

    if (state == self->state)
        return;

    self->state = state;
    _callback_invoke(self, NM_BOND_MANAGER_EVENT_TYPE_STATE);
}

/*****************************************************************************/

static void
_nft_call_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    nm_auto_str_buf NMStrBuf strbuf = NM_STR_BUF_INIT_A(NM_UTILS_GET_NEXT_REALLOC_SIZE_232, FALSE);
    NMBondManager           *self;
    gpointer                 ptr_up;
    gs_free const char     **previous_members = NULL;
    gs_free_error GError    *error            = NULL;

    nm_utils_user_data_unpack(user_data, &self, &ptr_up, &previous_members);

    _nm_assert_self(self);

    self->nft_in_progress = FALSE;

    nm_firewall_nft_call_finish(result, &error);

    if (!error) {
        gsize i;

        /* On success, we can forget about our previous members that we successfully
         * deleted. */
        if (!GPOINTER_TO_INT(ptr_up)) {
            /* We successfully deleted the NFT table. Forget all previous members. */
            g_hash_table_remove_all(self->previous_members);
        } else if (previous_members) {
            /* These previous members are now forgotten for good. */
            for (i = 0; previous_members[i]; i++)
                g_hash_table_remove(self->previous_members, previous_members[i]);
        }
    } else {
        /* If all our NFT calls keep failing, we never actually prune entries from
         * self->previous_members. That is a problem, however, under normal operation
         * NFT calls should not continuously fail, and we would have a small fixed
         * number of active-members. */
    }

    nm_clear_g_cancellable(&self->cancellable);

    if (nm_utils_error_is_cancelled(error)) {
        switch (self->reg_state) {
        case REGISTRATION_STATE_NONE:
        case REGISTRATION_STATE_UP:
        case REGISTRATION_STATE_DOWNING:
            /* It is not expected that we cancel anything in this state. */
            nm_assert_not_reached();
            goto out;
        case REGISTRATION_STATE_UPPING:
            nm_assert(self->dat.bond_ifname_curr);
            /* We cancelled while upping. We need to issue another down,
             * to make sure the data is gone. */
            if (!self->dat.bond_ifname_next) {
                /* There is no other name to configure. We just need to down
                 * the current one. */
                _LOGT("reconfigure: configuration cancelled, deconfigure %s",
                      self->dat.bond_ifname_curr);
                _nft_call(self, FALSE, self->dat.bond_ifname_curr, NULL, NULL);
                self->reg_state = REGISTRATION_STATE_DOWNING;
                goto out;
            }
            /* There is already another configuration. UPPING again. */
            _LOGT("reconfigure: configuration cancelled, configure %s",
                  _log_info(&strbuf,
                            self->dat.bond_ifname_next,
                            self->dat.active_members_next,
                            NULL));
            _nft_call(self,
                      TRUE,
                      self->dat.bond_ifname_next,
                      NM_MAKE_STRV(self->dat.bond_ifname_curr),
                      self->dat.active_members_next);
            self->reg_state = REGISTRATION_STATE_UPPING;
            nm_clear_g_free(&self->dat.bond_ifname_curr);
            nm_clear_g_free(&self->dat.active_members_curr);
            self->dat.bond_ifname_curr    = g_steal_pointer(&self->dat.bond_ifname_next);
            self->dat.active_members_curr = g_steal_pointer(&self->dat.active_members_next);
            goto out;
        }
        nm_assert_not_reached();
        goto out;
    }

    if (error) {
        self->nft_good = FALSE;
    } else {
        /* Technically, if a previous downing failed, we cannot know that
         * we were able to fix this bug a successful run now. That is, because
         * if the interface got renamed, and the downing for the previous
         * interface name failed, we leak that table and the success now doesn't
         * fix that.
         *
         * That is a bug, but probably not severe because:
         * - interfaces are not supposed to be renamed.
         * - if this NFT command succeed, we expect that also the previous downings worked.
         *
         * The problem here is only that nft_good might lie and indicate
         * no problem. However, when a downing fails, we anyway leak the table already
         * and the bad thing happend. We cannot fix if `nft` command fails.
         */
        self->nft_good = TRUE;
    }

    switch (self->reg_state) {
    case REGISTRATION_STATE_NONE:
    case REGISTRATION_STATE_UP:
        /* Unexpected to get a callback completion in these states. */
        nm_assert_not_reached();
        goto out;
    case REGISTRATION_STATE_UPPING:
        nm_assert(!self->dat.bond_ifname_next);
        if (error) {
            /* Unclear what to do about this error. Just log about it, nothing else. */
            _LOGW("reconfigure: nft configuration for balance-slb failed: %s", error->message);
        } else
            _LOGT("reconfigure: configuration completed");
        self->reg_state = REGISTRATION_STATE_UP;
        goto out;
    case REGISTRATION_STATE_DOWNING:
        nm_assert(self->dat.bond_ifname_curr);
        if (!self->dat.bond_ifname_next) {
            if (error) {
                /* Unclear what to do about this error. Just log about it, nothing else. */
                _LOGW("reconfigure: nft deconfiguration for balance-slb failed: %s",
                      error->message);
            } else
                _LOGT("reconfigure: deconfiguration completed");
            nm_clear_g_free(&self->dat.bond_ifname_curr);
            nm_clear_g_free(&self->dat.active_members_curr);
            self->reg_state = REGISTRATION_STATE_NONE;

            if (self->destroyed) {
                _bond_manager_destroy(self);
                return;
            }

            goto out;
        }
        if (error) {
            /* Unclear what to do about this error. Just log about it, nothing else. */
            _LOGW("reconfigure: nft deconfiguration failed before restart: %s", error->message);
        } else
            _LOGT("reconfigure: deconfiguration completed before restart");
        _nft_call(self,
                  TRUE,
                  self->dat.bond_ifname_next,
                  NM_MAKE_STRV(self->dat.bond_ifname_curr),
                  self->dat.active_members_next);
        nm_clear_g_free(&self->dat.bond_ifname_curr);
        nm_clear_g_free(&self->dat.active_members_curr);
        self->dat.bond_ifname_curr    = g_steal_pointer(&self->dat.bond_ifname_next);
        self->dat.active_members_curr = g_steal_pointer(&self->dat.active_members_next);
        self->reg_state               = REGISTRATION_STATE_UPPING;
        goto out;
    }

    nm_assert_not_reached();

out:
    if (self->reconfigure_check) {
        if (self->destroyed)
            nm_assert_not_reached();
        else if (!self->nft_in_progress) {
            nm_assert(!self->reconfigure_on_idle_source);
            _reconfigure_check(self, FALSE);
        }
    }

    _notify_state_change(self);
}

static void
_nft_call(NMBondManager     *self,
          gboolean           up,
          const char        *bond_ifname,
          const char *const *bond_ifnames_down,
          const char *const *active_members)
{
    gs_unref_bytes GBytes     *stdin_buf             = NULL;
    gs_free const char *const *previous_members_strv = NULL;
    gboolean                   with_counters;

    if (up) {
        gs_unref_ptrarray GPtrArray *arr = NULL;
        GHashTableIter               iter;
        const char                  *n;
        gsize                        i;

        /* We need to track the active-members that we add, because, when we update the
         * NFT table without the member from previously, we use "add && flush", which
         * leaves empty chains for the previous members around. We need to cleanup those
         * chains, hence the need to track which members we ever added.
         *
         * Before making an UP call, we add the newly configured active_members to the list
         * of previous_members. All the while, passing a list of previous_members_strv
         * which we currently no longer configure.
         *
         * Only when the call succeeds (in _nft_call_cb()), we will forget about previously added
         * members. This is done by passing the list of members that we are forgetting now
         * on to the callback below. */

        /* Get the list of previous members that are no longer in the current
         * active list. */
        g_hash_table_iter_init(&iter, self->previous_members);
        while (g_hash_table_iter_next(&iter, (gpointer *) &n, NULL)) {
            if (nm_strv_contains(active_members, -1, n))
                continue;
            if (!arr)
                arr = g_ptr_array_new();
            g_ptr_array_add(arr, (gpointer) n);
        }
        if (arr) {
            nm_strv_sort((const char **) arr->pdata, arr->len);
            previous_members_strv = nm_strv_dup_packed((const char *const *) arr->pdata, arr->len);
        }

        /* The now active member also get tracked as previous members for the future. */
        if (active_members) {
            for (i = 0; active_members[i]; i++)
                g_hash_table_add(self->previous_members, g_strdup(active_members[i]));
        }
    }

    /* counters in the nft rules are convenient for debugging, but have a performance overhead.
     * Enable counters based on whether NM logging is enabled. */
    with_counters = _NMLOG_ENABLED(LOGL_TRACE);

    stdin_buf = nm_firewall_nft_stdio_mlag(up,
                                           bond_ifname,
                                           bond_ifnames_down,
                                           active_members,
                                           previous_members_strv,
                                           with_counters);

    nm_clear_g_cancellable(&self->cancellable);
    self->cancellable = g_cancellable_new();

    nm_shutdown_wait_obj_register_cancellable(self->cancellable, "nft-mlag");

    if (_LOGT_ENABLED()) {
        if (up) {
            nm_auto_str_buf NMStrBuf strbuf =
                NM_STR_BUF_INIT_A(NM_UTILS_GET_NEXT_REALLOC_SIZE_232, FALSE);

            _LOGT("reconfigure: call nft: %s",
                  _log_info(&strbuf, bond_ifname, active_members, previous_members_strv));
        } else
            _LOGT("reconfigure: call nft: disable on \"%s\"", bond_ifname);
    }

    self->nft_in_progress = TRUE;

    if (self->reconfigure_check)
        nm_clear_g_source_inst(&self->reconfigure_on_idle_source);

    nm_firewall_nft_call(stdin_buf,
                         self->cancellable,
                         _nft_call_cb,
                         nm_utils_user_data_pack(self,
                                                 GINT_TO_POINTER(up),
                                                 g_steal_pointer(&previous_members_strv)));
}

/*****************************************************************************/

static void
_reconfigure_do(NMBondManager *self,
                gboolean       reapply,
                const char    *bond_ifname,
                const char   **active_members_take)
{
    nm_auto_str_buf NMStrBuf strbuf = NM_STR_BUF_INIT_A(NM_UTILS_GET_NEXT_REALLOC_SIZE_232, FALSE);
    gs_free const char     **active_members = g_steal_pointer(&active_members_take);

    _nm_assert_self(self);
    nm_assert(!active_members || bond_ifname);
    nm_assert(!active_members || active_members[0]);

    /* The difficulty of all of this is "state". In particular, since we make the nft call
     * async, we need to handle all the possible cases, how an update event can invalidate
     * a currently pending call. */

    switch (self->reg_state) {
    case REGISTRATION_STATE_NONE:
        nm_assert(!self->dat.bond_ifname_curr);
        nm_assert(!self->dat.active_members_curr);
        nm_assert(!self->dat.bond_ifname_next);
        nm_assert(!self->dat.active_members_next);
        nm_assert(!self->cancellable);
        nm_assert(!self->nft_in_progress);

        if (!bond_ifname) {
            /* No configuration done. Nothing to do. */
            goto out;
        }

        _LOGT("reconfigure: start configuring (%s)",
              _log_info(&strbuf, bond_ifname, active_members, NULL));
        self->dat.bond_ifname_curr    = g_strdup(bond_ifname);
        self->dat.active_members_curr = nm_strv_dup_packed(active_members, -1);
        _nft_call(self, TRUE, self->dat.bond_ifname_curr, NULL, self->dat.active_members_curr);
        self->reg_state = REGISTRATION_STATE_UPPING;
        goto out;
    case REGISTRATION_STATE_UPPING:
        nm_assert(self->dat.bond_ifname_curr);
        nm_assert(self->nft_in_progress);

        /* We are UPPING, we cancel the pending operation and will
         * handle the rest when the callback completes. */
        if (!bond_ifname) {
            if (self->cancellable || self->dat.bond_ifname_next)
                _LOGT("reconfigure: aborting configuring");
            nm_clear_g_free(&self->dat.bond_ifname_next);
            nm_clear_g_free(&self->dat.active_members_next);
            nm_clear_g_cancellable(&self->cancellable);
            goto out;
        }
        if (!reapply && self->cancellable && nm_streq0(bond_ifname, self->dat.bond_ifname_curr)
            && nm_strv_equal(active_members, self->dat.active_members_curr)) {
            /* Nothing to do. We are already upping this setup. */
            nm_assert(!self->dat.bond_ifname_next);
            nm_assert(!self->dat.active_members_next);
            goto out;
        }
        if (!reapply && !self->cancellable && nm_streq0(bond_ifname, self->dat.bond_ifname_next)
            && nm_strv_equal(active_members, self->dat.active_members_next)) {
            /* We already cancelled the current upping, and have scheduled another
             * (identical) run. Nothing to do. */
            goto out;
        }
        _LOGT("reconfigure: abort configuring to configure %s",
              _log_info(&strbuf, bond_ifname, active_members, NULL));
        nm_clear_g_free(&self->dat.bond_ifname_next);
        nm_clear_g_free(&self->dat.active_members_next);
        self->dat.bond_ifname_next    = g_strdup(bond_ifname);
        self->dat.active_members_next = nm_strv_dup_packed(active_members, -1);
        nm_clear_g_cancellable(&self->cancellable);
        goto out;
    case REGISTRATION_STATE_UP:
        nm_assert(self->dat.bond_ifname_curr);
        nm_assert(!self->dat.bond_ifname_next);
        nm_assert(!self->dat.active_members_next);
        nm_assert(!self->cancellable);
        nm_assert(!self->nft_in_progress);

        if (!bond_ifname) {
            _LOGT("reconfigure: deconfigure to disable");
            _nft_call(self, FALSE, self->dat.bond_ifname_curr, NULL, NULL);
            self->reg_state = REGISTRATION_STATE_DOWNING;
            goto out;
        }
        if (!reapply && nm_streq0(bond_ifname, self->dat.bond_ifname_curr)
            && nm_strv_equal(active_members, self->dat.active_members_curr)) {
            /* Nothing to do. The current configuration is already active. */
            goto out;
        }
        _LOGT("reconfigure: configure, update to %s",
              _log_info(&strbuf, bond_ifname, active_members, NULL));
        _nft_call(self,
                  TRUE,
                  bond_ifname,
                  NM_MAKE_STRV(self->dat.bond_ifname_curr),
                  active_members);
        self->reg_state = REGISTRATION_STATE_UPPING;
        nm_clear_g_free(&self->dat.bond_ifname_curr);
        nm_clear_g_free(&self->dat.active_members_curr);
        self->dat.bond_ifname_curr    = g_strdup(bond_ifname);
        self->dat.active_members_curr = nm_strv_dup_packed(active_members, -1);
        goto out;
    case REGISTRATION_STATE_DOWNING:
        nm_assert(self->dat.bond_ifname_curr);
        nm_assert(self->nft_in_progress);

        /* we are already DOWNING. It suffices to clear the scheduled "next"
         * config and wait, and reset the "next" configuration. */
        if (nm_streq0(bond_ifname, self->dat.bond_ifname_next)
            && nm_strv_equal(active_members, self->dat.active_members_next)) {
            /* Nothing to do. */
            goto out;
        }
        _LOGT("reconfigure: deconfiguring and waiting for %s",
              _log_info(&strbuf, bond_ifname, active_members, NULL));
        nm_clear_g_free(&self->dat.bond_ifname_next);
        nm_clear_g_free(&self->dat.active_members_next);
        if (bond_ifname) {
            self->dat.bond_ifname_next    = g_strdup(bond_ifname);
            self->dat.active_members_next = nm_strv_dup_packed(active_members, -1);
        }
        goto out;
    }
    nm_assert_not_reached();

out:
    _notify_state_change(self);
}

static void
_reconfigure_check(NMBondManager *self, gboolean reapply)
{
    const NMPlatformLink        *plink_ctrl;
    const NMPlatformLink        *plink_port;
    const NMPlatformLnkBond     *plnkbond_ctrl;
    NMDedupMultiIter             pliter;
    const NMDedupMultiHeadEntry *pl_links_head_entry;
    const char                  *active_members_lst_stack[16];
    gs_free const char         **active_members_lst_heap = NULL;
    const char                 **active_members_lst      = active_members_lst_stack;
    gsize                        active_members_alloc    = G_N_ELEMENTS(active_members_lst_stack);
    gsize                        active_members_n        = 0;
    gs_free const char         **active_members_result   = NULL;
    const char                  *bond_ifname             = NULL;

    _nm_assert_self(self);
    nm_assert(!self->destroyed);

    self->reconfigure_check = FALSE;
    nm_clear_g_source_inst(&self->reconfigure_on_idle_source);

    g_hash_table_remove_all(self->previous_ifindexes);

    plnkbond_ctrl = nm_platform_link_get_lnk_bond(self->platform, self->ifindex, &plink_ctrl);

    /* We only do bonding-slb MLAG handling if our ifindex is a bond with
     * mode=balance-xor && xmit_hash_policy=vlan+srcmac. */
    if (!plnkbond_ctrl)
        goto out;
    if (!plink_ctrl)
        goto out;
    if (plink_ctrl->type != NM_LINK_TYPE_BOND)
        goto out;
    if (plnkbond_ctrl->mode != NM_BOND_MODE_XOR)
        goto out;
    if (plnkbond_ctrl->xmit_hash_policy != NM_BOND_XMIT_HASH_POLICY_VLAN_SRCMAC)
        goto out;

    /* Find all the connected ports that are IFF_RUNNING. */
    pl_links_head_entry = nm_platform_lookup_obj_type(self->platform, NMP_OBJECT_TYPE_LINK);
    nmp_cache_iter_for_each_link (&pliter, pl_links_head_entry, &plink_port) {
        if (plink_port->master != self->ifindex)
            continue;
        if (!NM_FLAGS_HAS(plink_port->n_ifi_flags, IFF_RUNNING))
            continue;

        g_hash_table_add(self->previous_ifindexes, GINT_TO_POINTER(plink_port->ifindex));

        if (active_members_n == active_members_alloc) {
            active_members_alloc *= 2;
            active_members_lst_heap =
                g_renew(const char *, active_members_lst_heap, active_members_alloc);
            if (active_members_lst == active_members_lst_stack) {
                memcpy(active_members_lst_heap,
                       active_members_lst_stack,
                       sizeof(const char *) * active_members_n);
            }
            active_members_lst = active_members_lst_heap;
        }

        active_members_lst[active_members_n++] = plink_port->name;
    }

    if (active_members_n > 0) {
        gsize i;
        gsize j;

        /* We sort the active members by name */
        g_qsort_with_data(active_members_lst,
                          active_members_n,
                          sizeof(const char *),
                          nm_strcmp_p_with_data,
                          NULL);

        /* There really shouldn't be any duplicates. Nonetheless, check
         * and drop them. They must be unique, because nm_firewall_nft_stdio_mlag()
         * relies on that. */
        for (j = 1, i = 1; i < active_members_n; i++) {
            if (nm_streq(active_members_lst[j - 1], active_members_lst[i])) {
                /* Repeated. Skip. */
                continue;
            }
            if (j != i)
                active_members_lst[j] = active_members_lst[i];
            j++;
        }
        active_members_n = j;

        active_members_result = g_new(const char *, active_members_n + 1u);
        j                     = 0;

        if (self->dat.active_members_curr) {
            /* We configured a list earlier. We want to preserve the sort order
             * from before. Prefer entries that we already had, in their previous
             * order. */
            for (i = 0; self->dat.active_members_curr[i]; i++) {
                gssize idx;

                /* We cannot use binary search, because we steal the elements we found
                 * already. Hence this is O(n^2). We could use binary search if we would
                 * not modify active_members_lst, but then we would need to remember
                 * somehow which elements are already consumed. */
                idx = nm_strv_find_first(active_members_lst,
                                         active_members_n,
                                         self->dat.active_members_curr[i]);
                if (idx >= 0)
                    active_members_result[j++] = g_steal_pointer(&active_members_lst[idx]);
            }
        }

        /* append the remaining entries, which are sorted by name. */
        for (i = 0; i < active_members_n; i++) {
            if (active_members_lst[i])
                active_members_result[j++] = active_members_lst[i];
        }

        nm_assert(j == active_members_n);
        active_members_result[j] = NULL;
    }

    bond_ifname = plink_ctrl->name;

out:
    _reconfigure_do(self, reapply, bond_ifname, g_steal_pointer(&active_members_result));
}

static gboolean
_reconfigure_check_on_idle_cb(gpointer user_data)
{
    NMBondManager *self = user_data;

    nm_assert(!self->nft_in_progress);
    _reconfigure_check(self, FALSE);
    return G_SOURCE_CONTINUE;
}

/*****************************************************************************/

static void
_link_changed_cb(NMPlatform           *platform,
                 int                   obj_type_i,
                 int                   ifindex,
                 const NMPlatformLink *plink,
                 int                   change_type_i,
                 NMBondManager        *self)
{
    if (self->reconfigure_check) {
        /* Recheck already scheduled. */
        return;
    }

    if (self->destroyed) {
        /* We should not get another event at this point. Anyway, ignore. */
        return;
    }

    if (ifindex == self->ifindex)
        goto schedule;

    if (plink->master == self->ifindex)
        goto schedule;

    if (g_hash_table_contains(self->previous_ifindexes, GINT_TO_POINTER(ifindex)))
        goto schedule;

    /* This event is not relevant. Skip. */
    return;

schedule:
    self->reconfigure_check = TRUE;
    if (!self->nft_in_progress) {
        self->reconfigure_on_idle_source =
            nm_g_idle_add_source(_reconfigure_check_on_idle_cb, self);
    }
}

/*****************************************************************************/

void
nm_bond_manager_reapply(NMBondManager *self)
{
    _reconfigure_check(self, TRUE);
}

/*****************************************************************************/

int
nm_bond_manager_get_ifindex(NMBondManager *self)
{
    nm_assert(NM_IS_BOND_MANAGER(self));

    return self->ifindex;
}

const char *
nm_bond_manager_get_connection_uuid(NMBondManager *self)
{
    nm_assert(NM_IS_BOND_MANAGER(self));

    return self->connection_uuid;
}

NMOptionBool
nm_bond_manager_get_state(NMBondManager *self)
{
    nm_assert(NM_IS_BOND_MANAGER(self));

    return self->state;
}

/*****************************************************************************/

NMBondManager *
nm_bond_manager_new(struct _NMPlatform   *platform,
                    int                   ifindex,
                    const char           *connection_uuid,
                    NMBondManagerCallback callback,
                    gpointer              user_data)
{
    NMBondManager *self;

    nm_assert(NM_IS_PLATFORM(platform));
    nm_assert(ifindex > 0);

    self  = g_slice_new(NMBondManager);
    *self = (NMBondManager){
        .platform           = g_object_ref(platform),
        .ifindex            = ifindex,
        .reg_state          = REGISTRATION_STATE_NONE,
        .destroyed          = FALSE,
        .nft_good           = TRUE,
        .callback           = callback,
        .user_data          = user_data,
        .previous_ifindexes = g_hash_table_new(nm_direct_hash, NULL),
        .previous_members   = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, NULL),
        .connection_uuid    = g_strdup(connection_uuid),
        .state              = NM_OPTION_BOOL_DEFAULT,
    };

    self->link_changed_id = g_signal_connect(self->platform,
                                             NM_PLATFORM_SIGNAL_LINK_CHANGED,
                                             G_CALLBACK(_link_changed_cb),
                                             self);

    _LOGT("new balance-slb (MLAG) manager for interface %d", self->ifindex);

    _reconfigure_check(self, TRUE);

    return self;
}

void
nm_bond_manager_destroy(NMBondManager *self)
{
    g_return_if_fail(self);
    g_return_if_fail(!self->destroyed);

    self->destroyed = TRUE;

    self->callback  = NULL;
    self->user_data = NULL;

    nm_clear_g_signal_handler(self->platform, &self->link_changed_id);

    nm_clear_g_source_inst(&self->reconfigure_on_idle_source);
    self->reconfigure_check = FALSE;

    nm_clear_g_free(&self->dat.bond_ifname_next);
    nm_clear_g_free(&self->dat.active_members_next);

    switch (self->reg_state) {
    case REGISTRATION_STATE_NONE:
        break;
    case REGISTRATION_STATE_UPPING:
        /* We still have some nfts registered. We need to wrap them up. */
        _LOGT("destroying but deconfigure pending configuration first");
        nm_clear_g_free(&self->dat.bond_ifname_next);
        nm_clear_g_free(&self->dat.active_members_next);
        nm_clear_g_cancellable(&self->cancellable);
        return;
    case REGISTRATION_STATE_UP:
        _LOGT("destroying but deconfigure first");
        _nft_call(self, FALSE, self->dat.bond_ifname_curr, NULL, NULL);
        self->reg_state = REGISTRATION_STATE_DOWNING;
        return;
    case REGISTRATION_STATE_DOWNING:
        _LOGT("destroying but wait for deconfiguring");
        return;
    }

    _bond_manager_destroy(self);
}

static void
_bond_manager_destroy(NMBondManager *self)
{
    _LOGT("destroyed");

    nm_assert(self);
    nm_assert(self->destroyed);
    nm_assert(self->reg_state == REGISTRATION_STATE_NONE);
    nm_assert(self->link_changed_id == 0);
    nm_assert(!self->cancellable);
    nm_assert(!self->dat.bond_ifname_curr);
    nm_assert(!self->dat.active_members_curr);
    nm_assert(!self->reconfigure_on_idle_source);

    nm_clear_g_free(&self->dat.bond_ifname_next);
    nm_clear_g_free(&self->dat.active_members_next);

    g_object_unref(self->platform);
    g_hash_table_unref(self->previous_ifindexes);
    g_hash_table_unref(self->previous_members);
    g_free(self->connection_uuid);
    nm_g_slice_free(self);
}
