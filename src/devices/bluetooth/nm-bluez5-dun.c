// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <sys/socket.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>

#include "nm-bluez5-dun.h"
#include "nm-bt-error.h"
#include "NetworkManagerUtils.h"

#define RFCOMM_FMT "/dev/rfcomm%d"

/*****************************************************************************/

typedef struct {
	GCancellable *cancellable;
	NMBluez5DunConnectCb callback;
	gpointer callback_user_data;

	sdp_session_t *sdp_session;

	GError *rfcomm_sdp_search_error;

	gint64 connect_open_tty_started_at;

	gulong cancelled_id;

	guint source_id;

	guint8 sdp_session_try_count;
} ConnectData;

struct _NMBluez5DunContext {
	const char *dst_str;

	ConnectData *cdat;

	NMBluez5DunNotifyTtyHangupCb notify_tty_hangup_cb;
	gpointer notify_tty_hangup_user_data;

	char *rfcomm_tty_path;

	int rfcomm_sock_fd;
	int rfcomm_tty_fd;
	int rfcomm_tty_no;
	int rfcomm_channel;

	guint rfcomm_tty_poll_id;

	bdaddr_t src;
	bdaddr_t dst;

	char src_str[];
};

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_BT
#define _NMLOG_PREFIX_NAME "bluez"
#define _NMLOG(level, context, ...) \
    G_STMT_START { \
        if (nm_logging_enabled ((level), (_NMLOG_DOMAIN))) { \
            const NMBluez5DunContext *const _context = (context); \
            \
            _nm_log ((level), (_NMLOG_DOMAIN), 0, NULL, NULL, \
                     "%s: DUN[%s] " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                     _context->src_str \
                     _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

static void _context_invoke_callback_success (NMBluez5DunContext *context);
static void _context_invoke_callback_fail_and_free (NMBluez5DunContext *context,
                                                    GError *error);
static void _context_free (NMBluez5DunContext *context);
static int _connect_open_tty (NMBluez5DunContext *context);
static gboolean _connect_sdp_session_start (NMBluez5DunContext *context,
                                            GError **error);

/*****************************************************************************/

NM_AUTO_DEFINE_FCN0 (NMBluez5DunContext *, _nm_auto_free_context, _context_free)
#define nm_auto_free_context nm_auto(_nm_auto_free_context)

/*****************************************************************************/

const char *
nm_bluez5_dun_context_get_adapter (const NMBluez5DunContext *context)
{
	return context->src_str;
}

const char *
nm_bluez5_dun_context_get_remote (const NMBluez5DunContext *context)
{
	return context->dst_str;
}

const char *
nm_bluez5_dun_context_get_rfcomm_dev (const NMBluez5DunContext *context)
{
	return context->rfcomm_tty_path;
}

/*****************************************************************************/

static gboolean
_rfcomm_tty_poll_cb (GIOChannel *stream,
                     GIOCondition condition,
                     gpointer user_data)
{
	NMBluez5DunContext *context = user_data;

	_LOGD (context, "receive %s%s%s signal on rfcomm file descriptor",
	       NM_FLAGS_HAS (condition, G_IO_ERR)            ? "ERR" : "",
	       NM_FLAGS_ALL (condition, G_IO_HUP | G_IO_ERR) ? ","   : "",
	       NM_FLAGS_HAS (condition, G_IO_HUP)            ? "HUP" : "");

	context->rfcomm_tty_poll_id = 0;
	context->notify_tty_hangup_cb (context,
	                               context->notify_tty_hangup_user_data);
	return G_SOURCE_REMOVE;
}

static gboolean
_connect_open_tty_retry_cb (gpointer user_data)
{
	NMBluez5DunContext *context = user_data;
	int r;

	r = _connect_open_tty (context);
	if (r >= 0)
		return G_SOURCE_REMOVE;

	if (nm_utils_get_monotonic_timestamp_nsec () > context->cdat->connect_open_tty_started_at + (30 * 100 * NM_UTILS_NSEC_PER_MSEC)) {
		gs_free_error GError *error = NULL;

		context->cdat->source_id = 0;
		g_set_error (&error,
		             NM_BT_ERROR,
		             NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "give up waiting to open %s device: %s (%d)",
		             context->rfcomm_tty_path,
		             nm_strerror_native (r),
		             -r);
		_context_invoke_callback_fail_and_free (context, error);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int
_connect_open_tty (NMBluez5DunContext *context)
{
	nm_auto_unref_io_channel GIOChannel *io_channel = NULL;
	int fd;
	int errsv;

	fd = open (context->rfcomm_tty_path, O_RDONLY | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		errsv = NM_ERRNO_NATIVE (errno);

		if (context->cdat->source_id == 0) {
			_LOGD (context, "failed opening tty "RFCOMM_FMT": %s (%d). Start polling...",
			       context->rfcomm_tty_no,
			       nm_strerror_native (errsv),
			       errsv);
			context->cdat->connect_open_tty_started_at = nm_utils_get_monotonic_timestamp_nsec ();
			context->cdat->source_id = g_timeout_add (100,
			                                          _connect_open_tty_retry_cb,
			                                          context);
		}
		return -errsv;
	}

	context->rfcomm_tty_fd = fd;

	io_channel = g_io_channel_unix_new (context->rfcomm_tty_fd);
	context->rfcomm_tty_poll_id = g_io_add_watch (io_channel,
	                                              G_IO_ERR | G_IO_HUP,
	                                              _rfcomm_tty_poll_cb,
	                                              context);

	_context_invoke_callback_success (context);
	return 0;
}

static void
_connect_create_rfcomm (NMBluez5DunContext *context)
{
	gs_free_error GError *error = NULL;
	struct rfcomm_dev_req req;
	int devid;
	int errsv;
	int r;

	_LOGD (context, "connected to %s on channel %d",
	       context->dst_str, context->rfcomm_channel);

	/* Create an RFCOMM kernel device for the DUN channel */
	memset (&req, 0, sizeof (req));
	req.dev_id  = -1;
	req.flags   = (1 << RFCOMM_REUSE_DLC) | (1 << RFCOMM_RELEASE_ONHUP);
	req.channel = context->rfcomm_channel;
	memcpy (&req.src, &context->src, ETH_ALEN);
	memcpy (&req.dst, &context->dst, ETH_ALEN);
	devid = ioctl (context->rfcomm_sock_fd, RFCOMMCREATEDEV, &req);
	if (devid < 0) {
		errsv = NM_ERRNO_NATIVE (errno);
		if (errsv == EBADFD) {
			/* hm. We use a non-blocking socket to connect. Above getsockopt(SOL_SOCKET,SO_ERROR) indicated
			 * success, but still now we fail with EBADFD. I think that is a bug and we should get the
			 * failure during connect().
			 *
			 * Anyway, craft a less confusing error message than
			 * "failed to create rfcomm device: File descriptor in bad state (77)". */
			g_set_error (&error,
			             NM_BT_ERROR,
			             NM_BT_ERROR_DUN_CONNECT_FAILED,
			             "unknown failure to connect to DUN device");
		} else {
			g_set_error (&error,
			             NM_BT_ERROR,
			             NM_BT_ERROR_DUN_CONNECT_FAILED,
			             "failed to create rfcomm device: %s (%d)",
			             nm_strerror_native (errsv), errsv);
		}
		_context_invoke_callback_fail_and_free (context, error);
		return;
	}

	context->rfcomm_tty_no = devid;
	context->rfcomm_tty_path = g_strdup_printf (RFCOMM_FMT, devid);

	r = _connect_open_tty (context);
	if (r < 0) {
		/* we created the rfcomm device, but cannot yet open it. That means, we are
		 * not yet fully connected. However, we notify the caller about "what we learned
		 * so far". Note that this happens synchronously.
		 *
		 * The purpose is that once we proceed synchrnously, modem-manager races with
		 * the detection of the modem. We want to notify the caller first about the
		 * device name. */
		context->cdat->callback (NULL,
		                         context->rfcomm_tty_path,
		                         NULL,
		                         context->cdat->callback_user_data);
	}
}

static gboolean
_connect_socket_connect_cb (GIOChannel *stream,
                            GIOCondition condition,
                            gpointer user_data)
{
	NMBluez5DunContext *context = user_data;
	gs_free GError *error = NULL;
	int errsv = 0;
	socklen_t slen = sizeof(errsv);
	int r;

	context->cdat->source_id = 0;

	r = getsockopt (context->rfcomm_sock_fd, SOL_SOCKET, SO_ERROR, &errsv, &slen);

	if (r < 0) {
		errsv = errno;
		g_set_error (&error,
		             NM_BT_ERROR,
		             NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "failed to complete connecting RFCOMM socket: %s (%d)",
		             nm_strerror_native (errsv), errsv);
		_context_invoke_callback_fail_and_free (context, error);
		return G_SOURCE_REMOVE;
	}

	if (errsv != 0) {
		g_set_error (&error,
		             NM_BT_ERROR,
		             NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "failed to connect RFCOMM socket: %s (%d)",
		             nm_strerror_native (errsv), errsv);
		_context_invoke_callback_fail_and_free (context, error);
		return G_SOURCE_REMOVE;
	}

	_connect_create_rfcomm (context);
	return G_SOURCE_REMOVE;
}

static void
_connect_socket_connect (NMBluez5DunContext *context)
{
	gs_free_error GError *error = NULL;
	struct sockaddr_rc sa;
	int errsv;

	context->rfcomm_sock_fd = socket (AF_BLUETOOTH, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, BTPROTO_RFCOMM);
	if (context->rfcomm_sock_fd < 0) {
		errsv = errno;
		g_set_error (&error,
		             NM_BT_ERROR,
		             NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "failed to create RFCOMM socket: %s (%d)",
		             nm_strerror_native (errsv), errsv);
		_context_invoke_callback_fail_and_free (context, error);
		return;
	}

	/* Connect to the remote device */
	memset (&sa, 0, sizeof (sa));
	sa.rc_family = AF_BLUETOOTH;
	sa.rc_channel = 0;
	memcpy (&sa.rc_bdaddr, &context->src, ETH_ALEN);
	if (bind (context->rfcomm_sock_fd,
	          (struct sockaddr *) &sa,
	          sizeof(sa)) != 0) {
		errsv = errno;
		g_set_error (&error,
		             NM_BT_ERROR,
		             NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "failed to bind socket: %s (%d)",
		             nm_strerror_native (errsv), errsv);
		_context_invoke_callback_fail_and_free (context, error);
		return;
	}

	memset (&sa, 0, sizeof (sa));
	sa.rc_family = AF_BLUETOOTH;
	sa.rc_channel = context->rfcomm_channel;
	memcpy (&sa.rc_bdaddr, &context->dst, ETH_ALEN);
	if (connect (context->rfcomm_sock_fd,
	             (struct sockaddr *) &sa,
	             sizeof (sa)) != 0) {
		nm_auto_unref_io_channel GIOChannel *io_channel = NULL;

		errsv = errno;
		if (errsv != EINPROGRESS) {
			g_set_error (&error,
			             NM_BT_ERROR,
			             NM_BT_ERROR_DUN_CONNECT_FAILED,
			             "failed to connect to remote device: %s (%d)",
			             nm_strerror_native (errsv), errsv);
			_context_invoke_callback_fail_and_free (context, error);
			return;
		}

		_LOGD (context, "connecting to %s on channel %d...",
		       context->dst_str,
		       context->rfcomm_channel);

		io_channel = g_io_channel_unix_new (context->rfcomm_sock_fd);
		context->cdat->source_id = g_io_add_watch (io_channel,
		                                           G_IO_OUT,
		                                           _connect_socket_connect_cb,
		                                           context);
		return;
	}

	_connect_create_rfcomm (context);
}

static void
_connect_sdp_search_cb (uint8_t type,
                        uint16_t status,
                        uint8_t *rsp,
                        size_t size,
                        void *user_data)
{
	NMBluez5DunContext *context = user_data;
	int scanned;
	int seqlen = 0;
	int bytesleft = size;
	uint8_t dataType;
	int channel = -1;

	if (   context->cdat->rfcomm_sdp_search_error
	    || context->rfcomm_channel >= 0)
		return;

	_LOGD (context, "SDP search finished with type=%d status=%d",
	       status, type);

	/* SDP response received */
	if (   status
	    || type != SDP_SVC_SEARCH_ATTR_RSP) {
		g_set_error (&context->cdat->rfcomm_sdp_search_error,
		             NM_BT_ERROR,
		             NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "did not get a Service Discovery response");
		return;
	}

	scanned = sdp_extract_seqtype (rsp, bytesleft, &dataType, &seqlen);

	_LOGD (context, "SDP sequence type scanned=%d length=%d",
	       scanned, seqlen);

	scanned = sdp_extract_seqtype (rsp, bytesleft, &dataType, &seqlen);
	if (   !scanned
	    || !seqlen) {
		/* Short read or unknown sequence type */
		g_set_error (&context->cdat->rfcomm_sdp_search_error,
		             NM_BT_ERROR,
		             NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "improper Service Discovery response");
		return;
	}

	rsp += scanned;
	bytesleft -= scanned;
	do {
		sdp_record_t *rec;
		int recsize = 0;
		sdp_list_t *protos;

		rec = sdp_extract_pdu (rsp, bytesleft, &recsize);
		if (!rec)
			break;

		if (!recsize) {
			sdp_record_free (rec);
			break;
		}

		if (sdp_get_access_protos (rec, &protos) == 0) {
			/* Extract the DUN channel number */
			channel = sdp_get_proto_port (protos, RFCOMM_UUID);
			sdp_list_free (protos, NULL);

			_LOGD (context, "SDP channel=%d",
			       channel);
		}
		sdp_record_free (rec);

		scanned += recsize;
		rsp += recsize;
		bytesleft -= recsize;
	} while (   scanned < (ssize_t) size
	         && bytesleft > 0
	         && channel < 0);

	if (channel == -1) {
		g_set_error (&context->cdat->rfcomm_sdp_search_error,
		             NM_BT_ERROR,
		             NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "did not receive rfcomm-channel");
		return;
	}

	context->rfcomm_channel = channel;
}

static gboolean
_connect_sdp_search_io_cb (GIOChannel *io_channel,
                           GIOCondition condition,
                           gpointer user_data)
{
	NMBluez5DunContext *context = user_data;
	gs_free GError *error = NULL;
	int errsv;

	if (condition & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		_LOGD (context, "SDP search returned with invalid IO condition 0x%x",
		       (guint) condition);
		error = g_error_new (NM_BT_ERROR,
		                     NM_BT_ERROR_DUN_CONNECT_FAILED,
		                     "Service Discovery interrupted");
		context->cdat->source_id = 0;
		_context_invoke_callback_fail_and_free (context, error);
		return G_SOURCE_REMOVE;
	}

	if (sdp_process (context->cdat->sdp_session) == 0) {
		_LOGD (context, "SDP search still not finished");
		return G_SOURCE_CONTINUE;
	}

	context->cdat->source_id = 0;

	if (   context->rfcomm_channel < 0
	    && !context->cdat->rfcomm_sdp_search_error) {
		errsv = sdp_get_error (context->cdat->sdp_session);
		_LOGD (context, "SDP search failed: %s (%d)",
		       nm_strerror_native (errsv), errsv);
		error = g_error_new (NM_BT_ERROR,
		                     NM_BT_ERROR_DUN_CONNECT_FAILED,
		                     "Service Discovery failed with %s (%d)",
		                     nm_strerror_native (errsv), errsv);
		_context_invoke_callback_fail_and_free (context, error);
		return G_SOURCE_REMOVE;
	}

	if (context->cdat->rfcomm_sdp_search_error) {
		_LOGD (context, "SDP search failed to complete: %s", context->cdat->rfcomm_sdp_search_error->message);
		_context_invoke_callback_fail_and_free (context, context->cdat->rfcomm_sdp_search_error);
		return G_SOURCE_REMOVE;
	}

	nm_clear_pointer (&context->cdat->sdp_session, sdp_close);

	_connect_socket_connect (context);

	return G_SOURCE_REMOVE;
}

static gboolean
_connect_sdp_session_start_on_idle_cb (gpointer user_data)
{
	NMBluez5DunContext *context = user_data;
	gs_free_error GError *error = NULL;

	context->cdat->source_id = 0;

	_LOGD (context, "retry starting sdp-session...");

	if (!_connect_sdp_session_start (context, &error))
		_context_invoke_callback_fail_and_free (context, error);

	return G_SOURCE_REMOVE;
}

static gboolean
_connect_sdp_io_cb (GIOChannel *io_channel,
                    GIOCondition condition,
                    gpointer user_data)
{
	NMBluez5DunContext *context = user_data;
	sdp_list_t *search;
	sdp_list_t *attrs;
	uuid_t svclass;
	uint16_t attr;
	int fd;
	int errsv;
	int fd_err = 0;
	int r;
	socklen_t len = sizeof (fd_err);
	gs_free_error GError *error = NULL;

	context->cdat->source_id = 0;

	fd = g_io_channel_unix_get_fd (io_channel);

	_LOGD (context, "sdp-session ready to connect with fd=%d", fd);

	if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &fd_err, &len) < 0) {
		errsv = NM_ERRNO_NATIVE (errno);
		error = g_error_new (NM_BT_ERROR, NM_BT_ERROR_DUN_CONNECT_FAILED,
		                     "error for getsockopt on Service Discovery socket: %s (%d)",
		                     nm_strerror_native (errsv), errsv);
		goto done;
	}

	if (fd_err != 0) {
		errsv = nm_errno_native (fd_err);

		if (   NM_IN_SET (errsv, ECONNREFUSED, EHOSTDOWN)
		    && --context->cdat->sdp_session_try_count > 0) {
			/* *sigh* */
			_LOGD (context, "sdp-session failed with %s (%d). Retry in a bit", nm_strerror_native (errsv), errsv);
			nm_clear_g_source (&context->cdat->source_id);
			context->cdat->source_id = g_timeout_add (1000,
			                                          _connect_sdp_session_start_on_idle_cb,
			                                          context);
			return G_SOURCE_REMOVE;
		}

		error = g_error_new (NM_BT_ERROR, NM_BT_ERROR_DUN_CONNECT_FAILED,
		                     "error on Service Discovery socket: %s (%d)",
		                     nm_strerror_native (errsv), errsv);
		goto done;
	}

	if (sdp_set_notify (context->cdat->sdp_session, _connect_sdp_search_cb, context) < 0) {
		/* Should not be reached, only can fail if we passed bad sdp_session. */
		error = g_error_new (NM_BT_ERROR, NM_BT_ERROR_DUN_CONNECT_FAILED,
		                     "could not set Service Discovery notification");
		goto done;
	}

	sdp_uuid16_create (&svclass, DIALUP_NET_SVCLASS_ID);
	search = sdp_list_append (NULL, &svclass);
	attr = SDP_ATTR_PROTO_DESC_LIST;
	attrs = sdp_list_append (NULL, &attr);

	r = sdp_service_search_attr_async (context->cdat->sdp_session,
	                                   search,
	                                   SDP_ATTR_REQ_INDIVIDUAL,
	                                   attrs);

	sdp_list_free (attrs, NULL);
	sdp_list_free (search, NULL);

	if (r < 0) {
		errsv = nm_errno_native (sdp_get_error (context->cdat->sdp_session));
		error = g_error_new (NM_BT_ERROR,
		                     NM_BT_ERROR_DUN_CONNECT_FAILED,
		                     "error starting Service Discovery: %s (%d)",
		                     nm_strerror_native (errsv), errsv);
		goto done;
	}

	/* Set callback responsible for update the internal SDP transaction */
	context->cdat->source_id = g_io_add_watch (io_channel,
	                                           G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
	                                           _connect_sdp_search_io_cb,
	                                           context);

done:
	if (error)
		_context_invoke_callback_fail_and_free (context, error);
	return G_SOURCE_REMOVE;
}

/*****************************************************************************/

static void
_connect_cancelled_cb (GCancellable *cancellable,
                       NMBluez5DunContext *context)
{
	gs_free_error GError *error = NULL;

	if (!g_cancellable_set_error_if_cancelled (cancellable, &error))
		g_return_if_reached ();

	_context_invoke_callback_fail_and_free (context, error);
}

static gboolean
_connect_sdp_session_start (NMBluez5DunContext *context,
                            GError **error)
{
	nm_auto_unref_io_channel GIOChannel *io_channel = NULL;

	nm_assert (context->cdat);

	nm_clear_g_source (&context->cdat->source_id);
	nm_clear_pointer (&context->cdat->sdp_session, sdp_close);

	context->cdat->sdp_session = sdp_connect (&context->src, &context->dst, SDP_NON_BLOCKING);
	if (!context->cdat->sdp_session) {
		int errsv = nm_errno_native (errno);

		g_set_error (error, NM_BT_ERROR, NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "failed to connect to the SDP server: %s (%d)",
		             nm_strerror_native (errsv), errsv);
		return FALSE;
	}

	io_channel = g_io_channel_unix_new (sdp_get_socket (context->cdat->sdp_session));
	context->cdat->source_id = g_io_add_watch (io_channel,
	                                           G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
	                                           _connect_sdp_io_cb,
	                                           context);
	return TRUE;
}

/*****************************************************************************/

gboolean
nm_bluez5_dun_connect (const char *adapter,
                       const char *remote,
                       GCancellable *cancellable,
                       NMBluez5DunConnectCb callback,
                       gpointer callback_user_data,
                       NMBluez5DunNotifyTtyHangupCb notify_tty_hangup_cb,
                       gpointer notify_tty_hangup_user_data,
                       GError **error)
{
	nm_auto_free_context NMBluez5DunContext *context = NULL;
	ConnectData *cdat;
	gsize src_l;
	gsize dst_l;

	g_return_val_if_fail (adapter, FALSE);
	g_return_val_if_fail (remote, FALSE);
	g_return_val_if_fail (G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (callback, FALSE);
	g_return_val_if_fail (notify_tty_hangup_cb, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	nm_assert (!g_cancellable_is_cancelled (cancellable));

	src_l = strlen (adapter) + 1;
	dst_l = strlen (remote) + 1;

	cdat = g_slice_new (ConnectData);
	*cdat = (ConnectData) {
		.callback              = callback,
		.callback_user_data    = callback_user_data,
		.cancellable           = g_object_ref (cancellable),
		.sdp_session_try_count = 5,
	};

	context = g_malloc (sizeof (NMBluez5DunContext) + src_l + dst_l);
	*context = (NMBluez5DunContext) {
		.cdat                        = cdat,
		.notify_tty_hangup_cb        = notify_tty_hangup_cb,
		.notify_tty_hangup_user_data = notify_tty_hangup_user_data,
		.rfcomm_tty_no               = -1,
		.rfcomm_sock_fd              = -1,
		.rfcomm_tty_fd               = -1,
		.rfcomm_channel              = -1,
	};
	memcpy (&context->src_str[0], adapter, src_l);
	context->dst_str = &context->src_str[src_l];
	memcpy ((char *) context->dst_str, remote, dst_l);

	if (str2ba (adapter, &context->src) < 0) {
		g_set_error (error, NM_BT_ERROR, NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "invalid source");
		return FALSE;
	}

	if (str2ba (remote, &context->dst) < 0) {
		g_set_error (error, NM_BT_ERROR, NM_BT_ERROR_DUN_CONNECT_FAILED,
		             "invalid remote");
		return FALSE;
	}

	context->cdat->cancelled_id = g_signal_connect (context->cdat->cancellable,
	                                                "cancelled",
	                                                G_CALLBACK (_connect_cancelled_cb),
	                                                context);

	if (!_connect_sdp_session_start (context, error))
		return FALSE;

	_LOGD (context, "starting channel number discovery for device %s",
	       context->dst_str);

	g_steal_pointer (&context);
	return TRUE;
}

/*****************************************************************************/

void
nm_bluez5_dun_disconnect (NMBluez5DunContext *context)
{
	nm_assert (context);
	nm_assert (!context->cdat);

	_LOGD (context, "disconnecting DUN connection");

	_context_free (context);
}

/*****************************************************************************/

static void
_context_cleanup_connect_data (NMBluez5DunContext *context)
{
	ConnectData *cdat;

	cdat = g_steal_pointer (&context->cdat);
	if (!cdat)
		return;

	nm_clear_g_signal_handler (cdat->cancellable, &cdat->cancelled_id);

	nm_clear_g_source (&cdat->source_id);

	nm_clear_pointer (&cdat->sdp_session, sdp_close);

	g_clear_object (&cdat->cancellable);

	g_clear_error (&cdat->rfcomm_sdp_search_error);

	nm_g_slice_free (cdat);
}

static void
_context_invoke_callback (NMBluez5DunContext *context,
                          GError *error)
{
	NMBluez5DunConnectCb callback;
	gpointer callback_user_data;

	nm_assert (context);
	nm_assert (context->cdat);
	nm_assert (context->cdat->callback);
	nm_assert (error || context->rfcomm_tty_path);

	if (!error)
		_LOGD (context, "connected via \"%s\"", context->rfcomm_tty_path);
	else if (nm_utils_error_is_cancelled (error, FALSE))
		_LOGD (context, "cancelled");
	else
		_LOGD (context, "failed to connect: %s", error->message);

	callback = context->cdat->callback;
	callback_user_data = context->cdat->callback_user_data;

	_context_cleanup_connect_data (context);

	callback (error ? NULL : context,
	          error ? NULL : context->rfcomm_tty_path,
	          error,
	          callback_user_data);
}

static void
_context_invoke_callback_success (NMBluez5DunContext *context)
{
	nm_assert (context->rfcomm_tty_path);
	_context_invoke_callback (context, NULL);
}

static void
_context_invoke_callback_fail_and_free (NMBluez5DunContext *context,
                                        GError *error)
{
	nm_assert (error);
	_context_invoke_callback (context, error);
	_context_free (context);
}

static void
_context_free (NMBluez5DunContext *context)
{
	nm_assert (context);

	_context_cleanup_connect_data (context);

	nm_clear_g_source (&context->rfcomm_tty_poll_id);

	if (context->rfcomm_sock_fd >= 0) {
		if (context->rfcomm_tty_no >= 0) {
			struct rfcomm_dev_req req;

			memset (&req, 0, sizeof (struct rfcomm_dev_req));
			req.dev_id = context->rfcomm_tty_no;
			context->rfcomm_tty_no = -1;
			(void) ioctl (context->rfcomm_sock_fd, RFCOMMRELEASEDEV, &req);
		}
		nm_close (nm_steal_fd (&context->rfcomm_sock_fd));
	}

	if (context->rfcomm_tty_fd >= 0)
		nm_close (nm_steal_fd (&context->rfcomm_tty_fd));
	nm_clear_g_free (&context->rfcomm_tty_path);
	g_free (context);
}
