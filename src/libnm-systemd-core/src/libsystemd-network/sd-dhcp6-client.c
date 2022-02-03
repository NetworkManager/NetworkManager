/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include "nm-sd-adapt-core.h"

#include <errno.h>
#include <sys/ioctl.h>
#if 0 /* NM_IGNORED */
#include <linux/if_arp.h>
#else /* NM_IGNORED */
#include <net/if_arp.h>
#endif /* NM_IGNORED */
#include <linux/if_infiniband.h>

#include "sd-dhcp6-client.h"

#include "alloc-util.h"
#include "dhcp-identifier.h"
#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dhcp6-protocol.h"
#include "dns-domain.h"
#include "event-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "network-common.h"
#include "random-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "strv.h"
#include "util.h"
#include "web-util.h"

#define MAX_MAC_ADDR_LEN INFINIBAND_ALEN

#define IRT_DEFAULT (1 * USEC_PER_DAY)
#define IRT_MINIMUM (600 * USEC_PER_SEC)

/* what to request from the server, addresses (IA_NA) and/or prefixes (IA_PD) */
typedef enum DHCP6RequestIA {
        DHCP6_REQUEST_IA_NA = 1 << 0,
        DHCP6_REQUEST_IA_TA = 1 << 1, /* currently not used */
        DHCP6_REQUEST_IA_PD = 1 << 2,
} DHCP6RequestIA;

struct sd_dhcp6_client {
        unsigned n_ref;

        DHCP6State state;
        sd_event *event;
        int event_priority;
        int ifindex;
        char *ifname;
        DHCP6Address hint_pd_prefix;
        struct in6_addr local_address;
        uint8_t mac_addr[MAX_MAC_ADDR_LEN];
        size_t mac_addr_len;
        uint16_t arp_type;
        DHCP6IA ia_na;
        DHCP6IA ia_pd;
        sd_event_source *timeout_t1;
        sd_event_source *timeout_t2;
        DHCP6RequestIA request_ia;
        be32_t transaction_id;
        usec_t transaction_start;
        struct sd_dhcp6_lease *lease;
        int fd;
        bool information_request;
        bool iaid_set;
        be16_t *req_opts;
        size_t req_opts_len;
        char *fqdn;
        char *mudurl;
        char **user_class;
        char **vendor_class;
        sd_event_source *receive_message;
        usec_t retransmit_time;
        uint8_t retransmit_count;
        sd_event_source *timeout_resend;
        sd_event_source *timeout_resend_expire;
        sd_dhcp6_client_callback_t callback;
        void *userdata;
        struct duid duid;
        size_t duid_len;
        usec_t information_request_time_usec;
        usec_t information_refresh_time_usec;
        OrderedHashmap *extra_options;
        OrderedHashmap *vendor_options;

        /* Ignore ifindex when generating iaid. See dhcp_identifier_set_iaid(). */
        bool test_mode;
};

static const uint16_t default_req_opts[] = {
        SD_DHCP6_OPTION_DNS_SERVERS,
        SD_DHCP6_OPTION_DOMAIN_LIST,
        SD_DHCP6_OPTION_NTP_SERVER,
        SD_DHCP6_OPTION_SNTP_SERVERS,
};

const char * dhcp6_message_type_table[_DHCP6_MESSAGE_TYPE_MAX] = {
        [DHCP6_MESSAGE_SOLICIT]             = "Solicit",
        [DHCP6_MESSAGE_ADVERTISE]           = "Advertise",
        [DHCP6_MESSAGE_REQUEST]             = "Request",
        [DHCP6_MESSAGE_CONFIRM]             = "Confirm",
        [DHCP6_MESSAGE_RENEW]               = "Renew",
        [DHCP6_MESSAGE_REBIND]              = "Rebind",
        [DHCP6_MESSAGE_REPLY]               = "Reply",
        [DHCP6_MESSAGE_RELEASE]             = "Release",
        [DHCP6_MESSAGE_DECLINE]             = "Decline",
        [DHCP6_MESSAGE_RECONFIGURE]         = "Reconfigure",
        [DHCP6_MESSAGE_INFORMATION_REQUEST] = "Information Request",
        [DHCP6_MESSAGE_RELAY_FORWARD]       = "Relay Forward",
        [DHCP6_MESSAGE_RELAY_REPLY]         = "Relay Reply",
        [DHCP6_MESSAGE_LEASE_QUERY]         = "Lease Query",
        [DHCP6_MESSAGE_LEASE_QUERY_REPLY]   = "Lease Query Reply",
        [DHCP6_MESSAGE_LEASE_QUERY_DONE]    = "Lease Query Done",
        [DHCP6_MESSAGE_LEASE_QUERY_DATA]    = "Lease Query Data",
        [DHCP6_MESSAGE_RECONFIGURE_REQUEST] = "Reconfigure Request",
        [DHCP6_MESSAGE_RECONFIGURE_REPLY]   = "Reconfigure Reply",
        [DHCP6_MESSAGE_DHCPV4_QUERY]        = "DHCPv4 Query",
        [DHCP6_MESSAGE_DHCPV4_RESPONSE]     = "DHCPv4 Response",
        [DHCP6_MESSAGE_ACTIVE_LEASE_QUERY]  = "Active Lease Query",
        [DHCP6_MESSAGE_START_TLS]           = "Start TLS",
        [DHCP6_MESSAGE_BINDING_UPDATE]      = "Binding Update",
        [DHCP6_MESSAGE_BINDING_REPLY]       = "Binding Reply",
        [DHCP6_MESSAGE_POOL_REQUEST]        = "Pool Request",
        [DHCP6_MESSAGE_POOL_RESPONSE]       = "Pool Response",
        [DHCP6_MESSAGE_UPDATE_REQUEST]      = "Update Request",
        [DHCP6_MESSAGE_UPDATE_REQUEST_ALL]  = "Update Request All",
        [DHCP6_MESSAGE_UPDATE_DONE]         = "Update Done",
        [DHCP6_MESSAGE_CONNECT]             = "Connect",
        [DHCP6_MESSAGE_CONNECT_REPLY]       = "Connect Reply",
        [DHCP6_MESSAGE_DISCONNECT]          = "Disconnect",
        [DHCP6_MESSAGE_STATE]               = "State",
        [DHCP6_MESSAGE_CONTACT]             = "Contact",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_message_type, int);

const char * dhcp6_message_status_table[_DHCP6_STATUS_MAX] = {
        [DHCP6_STATUS_SUCCESS]                      = "Success",
        [DHCP6_STATUS_UNSPEC_FAIL]                  = "Unspecified failure",
        [DHCP6_STATUS_NO_ADDRS_AVAIL]               = "No addresses available",
        [DHCP6_STATUS_NO_BINDING]                   = "Binding unavailable",
        [DHCP6_STATUS_NOT_ON_LINK]                  = "Not on link",
        [DHCP6_STATUS_USE_MULTICAST]                = "Use multicast",
        [DHCP6_STATUS_NO_PREFIX_AVAIL]              = "No prefix available",
        [DHCP6_STATUS_UNKNOWN_QUERY_TYPE]           = "Unknown query type",
        [DHCP6_STATUS_MALFORMED_QUERY]              = "Malformed query",
        [DHCP6_STATUS_NOT_CONFIGURED]               = "Not configured",
        [DHCP6_STATUS_NOT_ALLOWED]                  = "Not allowed",
        [DHCP6_STATUS_QUERY_TERMINATED]             = "Query terminated",
        [DHCP6_STATUS_DATA_MISSING]                 = "Data missing",
        [DHCP6_STATUS_CATCHUP_COMPLETE]             = "Catch up complete",
        [DHCP6_STATUS_NOT_SUPPORTED]                = "Not supported",
        [DHCP6_STATUS_TLS_CONNECTION_REFUSED]       = "TLS connection refused",
        [DHCP6_STATUS_ADDRESS_IN_USE]               = "Address in use",
        [DHCP6_STATUS_CONFIGURATION_CONFLICT]       = "Configuration conflict",
        [DHCP6_STATUS_MISSING_BINDING_INFORMATION]  = "Missing binding information",
        [DHCP6_STATUS_OUTDATED_BINDING_INFORMATION] = "Outdated binding information",
        [DHCP6_STATUS_SERVER_SHUTTING_DOWN]         = "Server shutting down",
        [DHCP6_STATUS_DNS_UPDATE_NOT_SUPPORTED]     = "DNS update not supported",
        [DHCP6_STATUS_EXCESSIVE_TIME_SKEW]          = "Excessive time skew",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_message_status, int);

#define DHCP6_CLIENT_DONT_DESTROY(client) \
        _cleanup_(sd_dhcp6_client_unrefp) _unused_ sd_dhcp6_client *_dont_destroy_##client = sd_dhcp6_client_ref(client)

static int client_start(sd_dhcp6_client *client, DHCP6State state);

int sd_dhcp6_client_set_callback(
                sd_dhcp6_client *client,
                sd_dhcp6_client_callback_t cb,
                void *userdata) {

        assert_return(client, -EINVAL);

        client->callback = cb;
        client->userdata = userdata;

        return 0;
}

int sd_dhcp6_client_set_ifindex(sd_dhcp6_client *client, int ifindex) {
        assert_return(client, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        client->ifindex = ifindex;
        return 0;
}

int sd_dhcp6_client_set_ifname(sd_dhcp6_client *client, const char *ifname) {
        assert_return(client, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&client->ifname, ifname);
}

int sd_dhcp6_client_get_ifname(sd_dhcp6_client *client, const char **ret) {
        int r;

        assert_return(client, -EINVAL);

        r = get_ifname(client->ifindex, &client->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = client->ifname;

        return 0;
}

int sd_dhcp6_client_set_local_address(
                sd_dhcp6_client *client,
                const struct in6_addr *local_address) {

        assert_return(client, -EINVAL);
        assert_return(local_address, -EINVAL);
        assert_return(in6_addr_is_link_local(local_address) > 0, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        client->local_address = *local_address;

        return 0;
}

int sd_dhcp6_client_set_mac(
                sd_dhcp6_client *client,
                const uint8_t *addr, size_t addr_len,
                uint16_t arp_type) {

        assert_return(client, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(addr_len <= MAX_MAC_ADDR_LEN, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        if (arp_type == ARPHRD_ETHER)
                assert_return(addr_len == ETH_ALEN, -EINVAL);
        else if (arp_type == ARPHRD_INFINIBAND)
                assert_return(addr_len == INFINIBAND_ALEN, -EINVAL);
        else {
                client->arp_type = ARPHRD_NONE;
                client->mac_addr_len = 0;
                return 0;
        }

        memcpy(&client->mac_addr, addr, addr_len);
        client->mac_addr_len = addr_len;
        client->arp_type = arp_type;

        return 0;
}

int sd_dhcp6_client_set_prefix_delegation_hint(
                sd_dhcp6_client *client,
                uint8_t prefixlen,
                const struct in6_addr *pd_address) {

        assert_return(client, -EINVAL);
        assert_return(pd_address, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        client->hint_pd_prefix.iapdprefix.address = *pd_address;
        client->hint_pd_prefix.iapdprefix.prefixlen = prefixlen;

        return 0;
}

int sd_dhcp6_client_add_vendor_option(sd_dhcp6_client *client, sd_dhcp6_option *v) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(v, -EINVAL);

        r = ordered_hashmap_ensure_put(&client->vendor_options, &dhcp6_option_hash_ops, v, v);
        if (r < 0)
                return r;

        sd_dhcp6_option_ref(v);

        return 1;
}

static int client_ensure_duid(sd_dhcp6_client *client) {
        if (client->duid_len != 0)
                return 0;

        return dhcp_identifier_set_duid_en(&client->duid, &client->duid_len);
}

/**
 * Sets DUID. If duid is non-null, the DUID is set to duid_type + duid
 * without further modification. Otherwise, if duid_type is supported, DUID
 * is set based on that type. Otherwise, an error is returned.
 */
static int dhcp6_client_set_duid_internal(
                sd_dhcp6_client *client,
                uint16_t duid_type,
                const void *duid,
                size_t duid_len,
                usec_t llt_time) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(duid_len == 0 || duid != NULL, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        if (duid) {
                r = dhcp_validate_duid_len(duid_type, duid_len, true);
                if (r < 0) {
                        r = dhcp_validate_duid_len(duid_type, duid_len, false);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to validate length of DUID: %m");

                        log_dhcp6_client(client, "Using DUID of type %u of incorrect length, proceeding.", duid_type);
                }

                client->duid.type = htobe16(duid_type);
                memcpy(&client->duid.raw.data, duid, duid_len);
                client->duid_len = sizeof(client->duid.type) + duid_len;
        } else
#if 0 /* NM_IGNORED */
                switch (duid_type) {
                case DUID_TYPE_LLT:
                        if (client->mac_addr_len == 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EOPNOTSUPP), "Failed to set DUID-LLT, MAC address is not set.");

                        r = dhcp_identifier_set_duid_llt(&client->duid, llt_time, client->mac_addr, client->mac_addr_len, client->arp_type, &client->duid_len);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set DUID-LLT: %m");
                        break;
                case DUID_TYPE_EN:
                        r = dhcp_identifier_set_duid_en(&client->duid, &client->duid_len);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set DUID-EN: %m");
                        break;
                case DUID_TYPE_LL:
                        if (client->mac_addr_len == 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EOPNOTSUPP), "Failed to set DUID-LL, MAC address is not set.");

                        r = dhcp_identifier_set_duid_ll(&client->duid, client->mac_addr, client->mac_addr_len, client->arp_type, &client->duid_len);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set DUID-LL: %m");
                        break;
                case DUID_TYPE_UUID:
                        r = dhcp_identifier_set_duid_uuid(&client->duid, &client->duid_len);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set DUID-UUID: %m");
                        break;
                default:
                        return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "Invalid DUID type");
                }
#else /* NM_IGNORED */
                g_return_val_if_reached (-EINVAL);
#endif /* NM_IGNORED */

        return 0;
}

int sd_dhcp6_client_set_duid(
                sd_dhcp6_client *client,
                uint16_t duid_type,
                const void *duid,
                size_t duid_len) {
        return dhcp6_client_set_duid_internal(client, duid_type, duid, duid_len, 0);
}

int sd_dhcp6_client_set_duid_llt(
                sd_dhcp6_client *client,
                usec_t llt_time) {
        return dhcp6_client_set_duid_internal(client, DUID_TYPE_LLT, NULL, 0, llt_time);
}

static const char* const dhcp6_duid_type_table[_DUID_TYPE_MAX] = {
        [DUID_TYPE_LLT]  = "DUID-LLT",
        [DUID_TYPE_EN]   = "DUID-EN/Vendor",
        [DUID_TYPE_LL]   = "DUID-LL",
        [DUID_TYPE_UUID] = "UUID",
};
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(dhcp6_duid_type, DUIDType);

int sd_dhcp6_client_duid_as_string(
                sd_dhcp6_client *client,
                char **duid) {
        _cleanup_free_ char *p = NULL, *s = NULL, *t = NULL;
        const char *v;
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->duid_len > 0, -ENODATA);
        assert_return(duid, -EINVAL);

        v = dhcp6_duid_type_to_string(be16toh(client->duid.type));
        if (v) {
                s = strdup(v);
                if (!s)
                        return -ENOMEM;
        } else {
                r = asprintf(&s, "%0x", client->duid.type);
                if (r < 0)
                        return -ENOMEM;
        }

        t = hexmem(&client->duid.raw.data, client->duid_len);
        if (!t)
                return -ENOMEM;

        p = strjoin(s, ":", t);
        if (!p)
                return -ENOMEM;

        *duid = TAKE_PTR(p);

        return 0;
}

int sd_dhcp6_client_set_iaid(sd_dhcp6_client *client, uint32_t iaid) {
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        client->ia_na.ia_na.id = htobe32(iaid);
        client->ia_pd.ia_pd.id = htobe32(iaid);
        client->iaid_set = true;

        return 0;
}

void dhcp6_client_set_test_mode(sd_dhcp6_client *client, bool test_mode) {
        assert(client);

        client->test_mode = test_mode;
}

int sd_dhcp6_client_get_iaid(sd_dhcp6_client *client, uint32_t *iaid) {
        assert_return(client, -EINVAL);
        assert_return(iaid, -EINVAL);

        if (!client->iaid_set)
                return -ENODATA;

        *iaid = be32toh(client->ia_na.ia_na.id);

        return 0;
}

int sd_dhcp6_client_set_fqdn(
                sd_dhcp6_client *client,
                const char *fqdn) {

        assert_return(client, -EINVAL);

        /* Make sure FQDN qualifies as DNS and as Linux hostname */
        if (fqdn &&
            !(hostname_is_valid(fqdn, 0) && dns_name_is_valid(fqdn) > 0))
                return -EINVAL;

        return free_and_strdup(&client->fqdn, fqdn);
}

int sd_dhcp6_client_set_information_request(sd_dhcp6_client *client, int enabled) {
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        client->information_request = enabled;

        return 0;
}

int sd_dhcp6_client_get_information_request(sd_dhcp6_client *client, int *enabled) {
        assert_return(client, -EINVAL);
        assert_return(enabled, -EINVAL);

        *enabled = client->information_request;

        return 0;
}

int sd_dhcp6_client_set_request_option(sd_dhcp6_client *client, uint16_t option) {
        size_t t;

        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);

        if (!dhcp6_option_can_request(option))
                return -EINVAL;

        for (t = 0; t < client->req_opts_len; t++)
                if (client->req_opts[t] == htobe16(option))
                        return -EEXIST;

        if (!GREEDY_REALLOC(client->req_opts, client->req_opts_len + 1))
                return -ENOMEM;

        client->req_opts[client->req_opts_len++] = htobe16(option);

        return 0;
}

int sd_dhcp6_client_set_request_mud_url(sd_dhcp6_client *client, const char *mudurl) {
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);
        assert_return(mudurl, -EINVAL);
        assert_return(strlen(mudurl) <= UINT8_MAX, -EINVAL);
        assert_return(http_url_is_valid(mudurl), -EINVAL);

        return free_and_strdup(&client->mudurl, mudurl);
}

int sd_dhcp6_client_set_request_user_class(sd_dhcp6_client *client, char * const *user_class) {
        char * const *p;
        char **s;

        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);
        assert_return(!strv_isempty(user_class), -EINVAL);

        STRV_FOREACH(p, user_class) {
                size_t len = strlen(*p);

                if (len > UINT16_MAX || len == 0)
                        return -EINVAL;
        }

        s = strv_copy(user_class);
        if (!s)
                return -ENOMEM;

        return strv_free_and_replace(client->user_class, s);
}

int sd_dhcp6_client_set_request_vendor_class(sd_dhcp6_client *client, char * const *vendor_class) {
        char * const *p;
        char **s;

        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP6_STATE_STOPPED, -EBUSY);
        assert_return(!strv_isempty(vendor_class), -EINVAL);

        STRV_FOREACH(p, vendor_class) {
                size_t len = strlen(*p);

                if (len > UINT16_MAX || len == 0)
                        return -EINVAL;
        }

        s = strv_copy(vendor_class);
        if (!s)
                return -ENOMEM;

        return strv_free_and_replace(client->vendor_class, s);
}

int sd_dhcp6_client_get_prefix_delegation(sd_dhcp6_client *client, int *delegation) {
        assert_return(client, -EINVAL);
        assert_return(delegation, -EINVAL);

        *delegation = FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_PD);

        return 0;
}

int sd_dhcp6_client_set_prefix_delegation(sd_dhcp6_client *client, int delegation) {
        assert_return(client, -EINVAL);

        SET_FLAG(client->request_ia, DHCP6_REQUEST_IA_PD, delegation);

        return 0;
}

int sd_dhcp6_client_get_address_request(sd_dhcp6_client *client, int *request) {
        assert_return(client, -EINVAL);
        assert_return(request, -EINVAL);

        *request = FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_NA);

        return 0;
}

int sd_dhcp6_client_set_address_request(sd_dhcp6_client *client, int request) {
        assert_return(client, -EINVAL);

        SET_FLAG(client->request_ia, DHCP6_REQUEST_IA_NA, request);

        return 0;
}

int sd_dhcp6_client_set_transaction_id(sd_dhcp6_client *client, uint32_t transaction_id) {
        assert_return(client, -EINVAL);

        client->transaction_id = transaction_id;

        return 0;
}

int sd_dhcp6_client_get_lease(sd_dhcp6_client *client, sd_dhcp6_lease **ret) {
        assert_return(client, -EINVAL);

        if (!client->lease)
                return -ENOMSG;

        if (ret)
                *ret = client->lease;

        return 0;
}

int sd_dhcp6_client_add_option(sd_dhcp6_client *client, sd_dhcp6_option *v) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(v, -EINVAL);

        r = ordered_hashmap_ensure_put(&client->extra_options, &dhcp6_option_hash_ops, UINT_TO_PTR(v->option), v);
        if (r < 0)
                return r;

        sd_dhcp6_option_ref(v);
        return 0;
}

static void client_notify(sd_dhcp6_client *client, int event) {
        assert(client);

        if (client->callback)
                client->callback(client, event, client->userdata);
}

static int client_reset(sd_dhcp6_client *client) {
        assert(client);

        client->lease = sd_dhcp6_lease_unref(client->lease);

        client->receive_message =
                sd_event_source_unref(client->receive_message);

        client->transaction_id = 0;
        client->transaction_start = 0;

        client->retransmit_time = 0;
        client->retransmit_count = 0;

        (void) event_source_disable(client->timeout_resend);
        (void) event_source_disable(client->timeout_resend_expire);
        (void) event_source_disable(client->timeout_t1);
        (void) event_source_disable(client->timeout_t2);

        client->state = DHCP6_STATE_STOPPED;

        return 0;
}

static void client_stop(sd_dhcp6_client *client, int error) {
        DHCP6_CLIENT_DONT_DESTROY(client);

        assert(client);

        client_notify(client, error);

        client_reset(client);
}

static int client_send_message(sd_dhcp6_client *client, usec_t time_now) {
        _cleanup_free_ DHCP6Message *message = NULL;
        struct in6_addr all_servers =
                IN6ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS_INIT;
        struct sd_dhcp6_option *j;
        size_t len, optlen = 512;
        uint8_t *opt;
        int r;
        usec_t elapsed_usec;
        be16_t elapsed_time;

        assert(client);

        len = sizeof(DHCP6Message) + optlen;

        message = malloc0(len);
        if (!message)
                return -ENOMEM;

        opt = (uint8_t *)(message + 1);

        message->transaction_id = client->transaction_id;

        switch(client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                message->type = DHCP6_MESSAGE_INFORMATION_REQUEST;

                if (client->mudurl) {
                        r = dhcp6_option_append(&opt, &optlen,
                                                SD_DHCP6_OPTION_MUD_URL_V6, strlen(client->mudurl),
                                                client->mudurl);
                        if (r < 0)
                                return r;
                }

                break;

        case DHCP6_STATE_SOLICITATION:
                message->type = DHCP6_MESSAGE_SOLICIT;

                r = dhcp6_option_append(&opt, &optlen,
                                        SD_DHCP6_OPTION_RAPID_COMMIT, 0, NULL);
                if (r < 0)
                        return r;

                if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_NA)) {
                        r = dhcp6_option_append_ia(&opt, &optlen,
                                                   &client->ia_na);
                        if (r < 0)
                                return r;
                }

                if (client->fqdn) {
                        r = dhcp6_option_append_fqdn(&opt, &optlen, client->fqdn);
                        if (r < 0)
                                return r;
                }

                if (client->mudurl) {
                        r = dhcp6_option_append(&opt, &optlen,
                                                SD_DHCP6_OPTION_MUD_URL_V6, strlen(client->mudurl),
                                                client->mudurl);
                        if (r < 0)
                                return r;
                }

                if (client->user_class) {
                        r = dhcp6_option_append_user_class(&opt, &optlen, client->user_class);
                        if (r < 0)
                                return r;
                }

                if (client->vendor_class) {
                        r = dhcp6_option_append_vendor_class(&opt, &optlen, client->vendor_class);
                        if (r < 0)
                                return r;
                }

                if (!ordered_hashmap_isempty(client->vendor_options)) {
                        r = dhcp6_option_append_vendor_option(&opt, &optlen,
                                                       client->vendor_options);
                        if (r < 0)
                                return r;
                }

                if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_PD)) {
                        r = dhcp6_option_append_pd(&opt, &optlen, &client->ia_pd, &client->hint_pd_prefix);
                        if (r < 0)
                                return r;
                }

                break;

        case DHCP6_STATE_REQUEST:
        case DHCP6_STATE_RENEW:

                if (client->state == DHCP6_STATE_REQUEST)
                        message->type = DHCP6_MESSAGE_REQUEST;
                else
                        message->type = DHCP6_MESSAGE_RENEW;

                r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_SERVERID,
                                        client->lease->serverid_len,
                                        client->lease->serverid);
                if (r < 0)
                        return r;

                if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_NA) && client->lease->ia.addresses) {
                        r = dhcp6_option_append_ia(&opt, &optlen,
                                                   &client->lease->ia);
                        if (r < 0)
                                return r;
                }

                if (client->fqdn) {
                        r = dhcp6_option_append_fqdn(&opt, &optlen, client->fqdn);
                        if (r < 0)
                                return r;
                }

                if (client->mudurl) {
                        r = dhcp6_option_append(&opt, &optlen,
                                                SD_DHCP6_OPTION_MUD_URL_V6, strlen(client->mudurl),
                                                client->mudurl);
                        if (r < 0)
                                return r;
                }

                if (client->user_class) {
                        r = dhcp6_option_append_user_class(&opt, &optlen, client->user_class);
                        if (r < 0)
                                return r;
                }

                if (client->vendor_class) {
                        r = dhcp6_option_append_vendor_class(&opt, &optlen, client->vendor_class);
                        if (r < 0)
                                return r;
                }

                if (!ordered_hashmap_isempty(client->vendor_options)) {
                        r = dhcp6_option_append_vendor_option(&opt, &optlen, client->vendor_options);
                        if (r < 0)
                                return r;
                }

                if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_PD) && client->lease->pd.addresses) {
                        r = dhcp6_option_append_pd(&opt, &optlen, &client->lease->pd, NULL);
                        if (r < 0)
                                return r;
                }

                break;

        case DHCP6_STATE_REBIND:
                message->type = DHCP6_MESSAGE_REBIND;

                if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_NA)) {
                        r = dhcp6_option_append_ia(&opt, &optlen, &client->lease->ia);
                        if (r < 0)
                                return r;
                }

                if (client->fqdn) {
                        r = dhcp6_option_append_fqdn(&opt, &optlen, client->fqdn);
                        if (r < 0)
                                return r;
                }

                if (client->mudurl) {
                        r = dhcp6_option_append(&opt, &optlen,
                                                SD_DHCP6_OPTION_MUD_URL_V6, strlen(client->mudurl),
                                                client->mudurl);
                        if (r < 0)
                                return r;
                }

                if (client->user_class) {
                        r = dhcp6_option_append_user_class(&opt, &optlen, client->user_class);
                        if (r < 0)
                                return r;
                }

                if (client->vendor_class) {
                        r = dhcp6_option_append_vendor_class(&opt, &optlen, client->vendor_class);
                        if (r < 0)
                                return r;
                }

                if (!ordered_hashmap_isempty(client->vendor_options)) {
                        r = dhcp6_option_append_vendor_option(&opt, &optlen, client->vendor_options);
                        if (r < 0)
                                return r;
                }

                if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_PD) && client->lease->pd.addresses) {
                        r = dhcp6_option_append_pd(&opt, &optlen, &client->lease->pd, NULL);
                        if (r < 0)
                                return r;
                }

                break;

        case DHCP6_STATE_STOPPED:
        case DHCP6_STATE_BOUND:
                return -EINVAL;
        default:
                assert_not_reached();
        }

        r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_ORO,
                                client->req_opts_len * sizeof(be16_t),
                                client->req_opts);
        if (r < 0)
                return r;

        assert(client->duid_len);
        r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_CLIENTID,
                                client->duid_len, &client->duid);
        if (r < 0)
                return r;

        /* RFC 8415 Section 21.9.
         * A client MUST include an Elapsed Time option in messages to indicate how long the client has
         * been trying to complete a DHCP message exchange. */
        elapsed_usec = MIN(usec_sub_unsigned(time_now, client->transaction_start) / USEC_PER_MSEC / 10, (usec_t) UINT16_MAX);
        elapsed_time = htobe16(elapsed_usec);
        r = dhcp6_option_append(&opt, &optlen, SD_DHCP6_OPTION_ELAPSED_TIME, sizeof(elapsed_time), &elapsed_time);
        if (r < 0)
                return r;

        ORDERED_HASHMAP_FOREACH(j, client->extra_options) {
                r = dhcp6_option_append(&opt, &optlen, j->option, j->length, j->data);
                if (r < 0)
                        return r;
        }

        r = dhcp6_network_send_udp_socket(client->fd, &all_servers, message,
                                          len - optlen);
        if (r < 0)
                return r;

        log_dhcp6_client(client, "Sent %s",
                         dhcp6_message_type_to_string(message->type));

        return 0;
}

static int client_timeout_t2(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp6_client *client = userdata;

        assert(s);
        assert(client);
        assert(client->lease);

        (void) event_source_disable(client->timeout_t2);

        log_dhcp6_client(client, "Timeout T2");

        client_start(client, DHCP6_STATE_REBIND);

        return 0;
}

static int client_timeout_t1(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp6_client *client = userdata;

        assert(s);
        assert(client);
        assert(client->lease);

        (void) event_source_disable(client->timeout_t1);

        log_dhcp6_client(client, "Timeout T1");

        client_start(client, DHCP6_STATE_RENEW);

        return 0;
}

static int client_timeout_resend_expire(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp6_client *client = userdata;
        DHCP6_CLIENT_DONT_DESTROY(client);
        DHCP6State state;

        assert(s);
        assert(client);
        assert(client->event);

        state = client->state;

        client_stop(client, SD_DHCP6_CLIENT_EVENT_RESEND_EXPIRE);

        /* RFC 3315, section 18.1.4., says that "...the client may choose to
           use a Solicit message to locate a new DHCP server..." */
        if (state == DHCP6_STATE_REBIND)
                client_start(client, DHCP6_STATE_SOLICITATION);

        return 0;
}

static usec_t client_timeout_compute_random(usec_t val) {
        return val - (random_u32() % USEC_PER_SEC) * val / 10 / USEC_PER_SEC;
}

static int client_timeout_resend(sd_event_source *s, uint64_t usec, void *userdata) {
        int r = 0;
        sd_dhcp6_client *client = userdata;
        usec_t time_now, init_retransmit_time = 0, max_retransmit_time = 0;
        usec_t max_retransmit_duration = 0;
        uint8_t max_retransmit_count = 0;

        assert(s);
        assert(client);
        assert(client->event);

        (void) event_source_disable(client->timeout_resend);

        switch (client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                init_retransmit_time = DHCP6_INF_TIMEOUT;
                max_retransmit_time = DHCP6_INF_MAX_RT;

                break;

        case DHCP6_STATE_SOLICITATION:

                if (client->retransmit_count > 0 && client->lease) {
                        client_start(client, DHCP6_STATE_REQUEST);
                        return 0;
                }

                init_retransmit_time = DHCP6_SOL_TIMEOUT;
                max_retransmit_time = DHCP6_SOL_MAX_RT;

                break;

        case DHCP6_STATE_REQUEST:
                init_retransmit_time = DHCP6_REQ_TIMEOUT;
                max_retransmit_time = DHCP6_REQ_MAX_RT;
                max_retransmit_count = DHCP6_REQ_MAX_RC;

                break;

        case DHCP6_STATE_RENEW:
                init_retransmit_time = DHCP6_REN_TIMEOUT;
                max_retransmit_time = DHCP6_REN_MAX_RT;

                /* RFC 3315, section 18.1.3. says max retransmit duration will
                   be the remaining time until T2. Instead of setting MRD,
                   wait for T2 to trigger with the same end result */

                break;

        case DHCP6_STATE_REBIND:
                init_retransmit_time = DHCP6_REB_TIMEOUT;
                max_retransmit_time = DHCP6_REB_MAX_RT;

                if (event_source_is_enabled(client->timeout_resend_expire) <= 0) {
                        uint32_t expire = 0;

                        r = dhcp6_lease_ia_rebind_expire(&client->lease->ia, &expire);
                        if (r < 0) {
                                client_stop(client, r);
                                return 0;
                        }
                        max_retransmit_duration = expire * USEC_PER_SEC;
                }

                break;

        case DHCP6_STATE_STOPPED:
        case DHCP6_STATE_BOUND:
                return 0;
        default:
                assert_not_reached();
        }

        if (max_retransmit_count > 0 &&
            client->retransmit_count >= max_retransmit_count) {
                client_stop(client, SD_DHCP6_CLIENT_EVENT_RETRANS_MAX);
                return 0;
        }

        r = sd_event_now(client->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                goto error;

        r = client_send_message(client, time_now);
        if (r >= 0)
                client->retransmit_count++;

        if (client->retransmit_time == 0) {
                client->retransmit_time =
                        client_timeout_compute_random(init_retransmit_time);

                if (client->state == DHCP6_STATE_SOLICITATION)
                        client->retransmit_time += init_retransmit_time / 10;

        } else {
                assert(max_retransmit_time > 0);
                if (client->retransmit_time > max_retransmit_time / 2)
                        client->retransmit_time = client_timeout_compute_random(max_retransmit_time);
                else
                        client->retransmit_time += client_timeout_compute_random(client->retransmit_time);
        }

        log_dhcp6_client(client, "Next retransmission in %s",
                         FORMAT_TIMESPAN(client->retransmit_time, USEC_PER_SEC));

        r = event_reset_time(client->event, &client->timeout_resend,
                             clock_boottime_or_monotonic(),
                             time_now + client->retransmit_time, 10 * USEC_PER_MSEC,
                             client_timeout_resend, client,
                             client->event_priority, "dhcp6-resend-timer", true);
        if (r < 0)
                goto error;

        if (max_retransmit_duration > 0 && event_source_is_enabled(client->timeout_resend_expire) <= 0) {

                log_dhcp6_client(client, "Max retransmission duration %"PRIu64" secs",
                                 max_retransmit_duration / USEC_PER_SEC);

                r = event_reset_time(client->event, &client->timeout_resend_expire,
                                     clock_boottime_or_monotonic(),
                                     time_now + max_retransmit_duration, USEC_PER_SEC,
                                     client_timeout_resend_expire, client,
                                     client->event_priority, "dhcp6-resend-expire-timer", true);
                if (r < 0)
                        goto error;
        }

error:
        if (r < 0)
                client_stop(client, r);

        return 0;
}

static int client_ensure_iaid(sd_dhcp6_client *client) {
        int r;
        uint32_t iaid;

        assert(client);

        if (client->iaid_set)
                return 0;

        r = dhcp_identifier_set_iaid(client->ifindex, client->mac_addr, client->mac_addr_len,
                                     /* legacy_unstable_byteorder = */ true,
                                     /* use_mac = */ client->test_mode,
                                     &iaid);
        if (r < 0)
                return r;

        client->ia_na.ia_na.id = iaid;
        client->ia_pd.ia_pd.id = iaid;
        client->iaid_set = true;

        return 0;
}

int client_parse_message(
                sd_dhcp6_client *client,
                DHCP6Message *message,
                size_t len,
                sd_dhcp6_lease *lease) {

        uint32_t lt_t1 = UINT32_MAX, lt_t2 = UINT32_MAX;
        usec_t irt = IRT_DEFAULT;
        int r;

        assert(client);
        assert(message);
        assert(len >= sizeof(DHCP6Message));
        assert(lease);

        len -= sizeof(DHCP6Message);
        for (size_t offset = 0; offset < len;) {
                uint16_t optcode;
                size_t optlen;
                const uint8_t *optval;

                r = dhcp6_option_parse(message->options, len, &offset, &optcode, &optlen, &optval);
                if (r < 0)
                        return r;

                switch (optcode) {
                case SD_DHCP6_OPTION_CLIENTID:
                        if (dhcp6_lease_get_clientid(lease, NULL, NULL) >= 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "%s contains multiple client IDs",
                                                              dhcp6_message_type_to_string(message->type));

                        r = dhcp6_lease_set_clientid(lease, optval, optlen);
                        if (r < 0)
                                return r;

                        break;

                case SD_DHCP6_OPTION_SERVERID:
                        if (dhcp6_lease_get_serverid(lease, NULL, NULL) >= 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "%s contains multiple server IDs",
                                                              dhcp6_message_type_to_string(message->type));

                        r = dhcp6_lease_set_serverid(lease, optval, optlen);
                        if (r < 0)
                                return r;

                        break;

                case SD_DHCP6_OPTION_PREFERENCE:
                        if (optlen != 1)
                                return -EINVAL;

                        r = dhcp6_lease_set_preference(lease, optval[0]);
                        if (r < 0)
                                return r;

                        break;

                case SD_DHCP6_OPTION_STATUS_CODE: {
                        _cleanup_free_ char *msg = NULL;

                        r = dhcp6_option_parse_status(optval, optlen, &msg);
                        if (r < 0)
                                return r;

                        if (r > 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                                              "Received %s message with non-zero status: %s%s%s",
                                                              dhcp6_message_type_to_string(message->type),
                                                              strempty(msg), isempty(msg) ? "" : ": ",
                                                              dhcp6_message_status_to_string(r));
                        break;
                }
                case SD_DHCP6_OPTION_IA_NA: {
                        _cleanup_(dhcp6_lease_free_ia) DHCP6IA ia = {};

                        if (client->state == DHCP6_STATE_INFORMATION_REQUEST) {
                                log_dhcp6_client(client, "Ignoring IA NA option in information requesting mode.");
                                break;
                        }

                        r = dhcp6_option_parse_ia(client, client->ia_pd.ia_na.id, optcode, optlen, optval, &ia);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                continue;

                        if (lease->ia.addresses) {
                                log_dhcp6_client(client, "Received duplicate matching IA_NA option, ignoring.");
                                continue;
                        }

                        lease->ia = ia;
                        ia = (DHCP6IA) {};

                        lt_t1 = MIN(lt_t1, be32toh(lease->ia.ia_na.lifetime_t1));
                        lt_t2 = MIN(lt_t2, be32toh(lease->ia.ia_na.lifetime_t2));

                        break;
                }
                case SD_DHCP6_OPTION_IA_PD: {
                        _cleanup_(dhcp6_lease_free_ia) DHCP6IA ia = {};

                        if (client->state == DHCP6_STATE_INFORMATION_REQUEST) {
                                log_dhcp6_client(client, "Ignoring IA PD option in information requesting mode.");
                                break;
                        }

                        r = dhcp6_option_parse_ia(client, client->ia_pd.ia_pd.id, optcode, optlen, optval, &ia);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                continue;

                        if (lease->pd.addresses) {
                                log_dhcp6_client(client, "Received duplicate matching IA_PD option, ignoring.");
                                continue;
                        }

                        lease->pd = ia;
                        ia = (DHCP6IA) {};

                        lt_t1 = MIN(lt_t1, be32toh(lease->pd.ia_pd.lifetime_t1));
                        lt_t2 = MIN(lt_t2, be32toh(lease->pd.ia_pd.lifetime_t2));

                        break;
                }
                case SD_DHCP6_OPTION_RAPID_COMMIT:
                        r = dhcp6_lease_set_rapid_commit(lease);
                        if (r < 0)
                                return r;

                        break;

                case SD_DHCP6_OPTION_DNS_SERVERS:
                        r = dhcp6_lease_add_dns(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse DNS server option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_DOMAIN_LIST:
                        r = dhcp6_lease_add_domains(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse domain list option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_NTP_SERVER:
                        r = dhcp6_lease_add_ntp(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse NTP server option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_SNTP_SERVERS:
                        r = dhcp6_lease_add_sntp(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse SNTP server option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_CLIENT_FQDN:
                        r = dhcp6_lease_set_fqdn(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse FQDN option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_INFORMATION_REFRESH_TIME:
                        if (optlen != 4)
                                return -EINVAL;

                        irt = unaligned_read_be32((be32_t *) optval) * USEC_PER_SEC;
                        break;
                }
        }

        uint8_t *clientid;
        size_t clientid_len;
        if (dhcp6_lease_get_clientid(lease, &clientid, &clientid_len) < 0)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "%s message does not contain client ID. Ignoring.",
                                              dhcp6_message_type_to_string(message->type));

        if (clientid_len != client->duid_len ||
            memcmp(clientid, &client->duid, clientid_len) != 0)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "The client ID in %s message does not match. Ignoring.",
                                              dhcp6_message_type_to_string(message->type));

        if (client->state != DHCP6_STATE_INFORMATION_REQUEST) {
                r = dhcp6_lease_get_serverid(lease, NULL, NULL);
                if (r < 0)
                        return log_dhcp6_client_errno(client, r, "%s has no server id",
                                                      dhcp6_message_type_to_string(message->type));

                if (!lease->ia.addresses && !lease->pd.addresses)
                        return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "No IA_PD prefix or IA_NA address received. Ignoring.");

                if (lease->ia.addresses) {
                        lease->ia.ia_na.lifetime_t1 = htobe32(lt_t1);
                        lease->ia.ia_na.lifetime_t2 = htobe32(lt_t2);
                }

                if (lease->pd.addresses) {
                        lease->pd.ia_pd.lifetime_t1 = htobe32(lt_t1);
                        lease->pd.ia_pd.lifetime_t2 = htobe32(lt_t2);
                }
        }

        client->information_refresh_time_usec = MAX(irt, IRT_MINIMUM);

        return 0;
}

static int client_receive_reply(
                sd_dhcp6_client *client,
                DHCP6Message *reply,
                size_t len,
                const triple_timestamp *t,
                const struct in6_addr *server_address) {

        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        bool rapid_commit;
        int r;

        assert(client);
        assert(reply);
        assert(t);

        if (reply->type != DHCP6_MESSAGE_REPLY)
                return 0;

        r = dhcp6_lease_new(&lease);
        if (r < 0)
                return -ENOMEM;

        lease->timestamp = *t;
        if (server_address)
                lease->server_address = *server_address;

        r = client_parse_message(client, reply, len, lease);
        if (r < 0)
                return r;

        if (client->state == DHCP6_STATE_SOLICITATION) {
                r = dhcp6_lease_get_rapid_commit(lease, &rapid_commit);
                if (r < 0)
                        return r;

                if (!rapid_commit)
                        return 0;
        }

        sd_dhcp6_lease_unref(client->lease);
        client->lease = TAKE_PTR(lease);

        return DHCP6_STATE_BOUND;
}

static int client_receive_advertise(
                sd_dhcp6_client *client,
                DHCP6Message *advertise,
                size_t len,
                const triple_timestamp *t,
                const struct in6_addr *server_address) {

        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        uint8_t pref_advertise = 0, pref_lease = 0;
        int r;

        assert(client);
        assert(advertise);
        assert(t);

        if (advertise->type != DHCP6_MESSAGE_ADVERTISE)
                return 0;

        r = dhcp6_lease_new(&lease);
        if (r < 0)
                return r;

        lease->timestamp = *t;
        if (server_address)
                lease->server_address = *server_address;

        r = client_parse_message(client, advertise, len, lease);
        if (r < 0)
                return r;

        r = dhcp6_lease_get_preference(lease, &pref_advertise);
        if (r < 0)
                return r;

        r = dhcp6_lease_get_preference(client->lease, &pref_lease);

        if (r < 0 || pref_advertise > pref_lease) {
                sd_dhcp6_lease_unref(client->lease);
                client->lease = TAKE_PTR(lease);
                r = 0;
        }

        if (pref_advertise == 255 || client->retransmit_count > 1)
                r = DHCP6_STATE_REQUEST;

        return r;
}

static int client_receive_message(
                sd_event_source *s,
                int fd, uint32_t
                revents,
                void *userdata) {

        sd_dhcp6_client *client = userdata;
        DHCP6_CLIENT_DONT_DESTROY(client);
        /* This needs to be initialized with zero. See #20741. */
        CMSG_BUFFER_TYPE(CMSG_SPACE_TIMEVAL) control = {};
        struct iovec iov;
        union sockaddr_union sa = {};
        struct msghdr msg = {
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        triple_timestamp t = {};
        _cleanup_free_ DHCP6Message *message = NULL;
        struct in6_addr *server_address = NULL;
        ssize_t buflen, len;
        int r = 0;

        assert(s);
        assert(client);
        assert(client->event);

        buflen = next_datagram_size_fd(fd);
        if (buflen < 0) {
                if (ERRNO_IS_TRANSIENT(buflen) || ERRNO_IS_DISCONNECT(buflen))
                        return 0;

                log_dhcp6_client_errno(client, buflen, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        message = malloc(buflen);
        if (!message)
                return -ENOMEM;

        iov = IOVEC_MAKE(message, buflen);

        len = recvmsg_safe(fd, &msg, MSG_DONTWAIT);
        if (len < 0) {
                if (ERRNO_IS_TRANSIENT(len) || ERRNO_IS_DISCONNECT(len))
                        return 0;

                log_dhcp6_client_errno(client, len, "Could not receive message from UDP socket, ignoring: %m");
                return 0;
        }
        if ((size_t) len < sizeof(DHCP6Message)) {
                log_dhcp6_client(client, "Too small to be DHCP6 message: ignoring");
                return 0;
        }

        /* msg_namelen == 0 happens when running the test-suite over a socketpair */
        if (msg.msg_namelen > 0) {
                if (msg.msg_namelen != sizeof(struct sockaddr_in6) || sa.in6.sin6_family != AF_INET6) {
                        log_dhcp6_client(client, "Received message from invalid source, ignoring.");
                        return 0;
                }

                server_address = &sa.in6.sin6_addr;
        }

        CMSG_FOREACH(cmsg, &msg) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SO_TIMESTAMP &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval)))
                        triple_timestamp_from_realtime(&t, timeval_load((struct timeval*) CMSG_DATA(cmsg)));
        }

        if (!triple_timestamp_is_set(&t))
                triple_timestamp_get(&t);

        if (!IN_SET(message->type, DHCP6_MESSAGE_ADVERTISE, DHCP6_MESSAGE_REPLY, DHCP6_MESSAGE_RECONFIGURE)) {
                const char *type_str = dhcp6_message_type_to_string(message->type);
                if (type_str)
                        log_dhcp6_client(client, "Received unexpected %s message, ignoring.", type_str);
                else
                        log_dhcp6_client(client, "Received unsupported message type %u, ignoring.", message->type);
                return 0;
        }

        if (client->transaction_id != (message->transaction_id & htobe32(0x00ffffff)))
                return 0;

        switch (client->state) {
        case DHCP6_STATE_INFORMATION_REQUEST:
                r = client_receive_reply(client, message, len, &t, server_address);
                if (r < 0) {
                        log_dhcp6_client_errno(client, r, "Failed to process received reply message, ignoring: %m");
                        return 0;
                }

                client_notify(client, SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST);

                client_start(client, DHCP6_STATE_STOPPED);

                break;

        case DHCP6_STATE_SOLICITATION:
                r = client_receive_advertise(client, message, len, &t, server_address);
                if (r < 0) {
                        log_dhcp6_client_errno(client, r, "Failed to process received advertise message, ignoring: %m");
                        return 0;
                }

                if (r == DHCP6_STATE_REQUEST) {
                        client_start(client, r);
                        break;
                }

                _fallthrough_; /* for Solicitation Rapid Commit option check */
        case DHCP6_STATE_REQUEST:
        case DHCP6_STATE_RENEW:
        case DHCP6_STATE_REBIND:

                r = client_receive_reply(client, message, len, &t, server_address);
                if (r < 0) {
                        log_dhcp6_client_errno(client, r, "Failed to process received reply message, ignoring: %m");
                        return 0;
                }

                if (r == DHCP6_STATE_BOUND) {
                        r = client_start(client, DHCP6_STATE_BOUND);
                        if (r < 0) {
                                client_stop(client, r);
                                return 0;
                        }

                        client_notify(client, SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE);
                }

                break;

        case DHCP6_STATE_BOUND:

                break;

        case DHCP6_STATE_STOPPED:
                return 0;
        default:
                assert_not_reached();
        }

        log_dhcp6_client(client, "Recv %s",
                         dhcp6_message_type_to_string(message->type));

        return 0;
}

static int client_get_lifetime(sd_dhcp6_client *client, uint32_t *lifetime_t1,
                               uint32_t *lifetime_t2) {
        assert_return(client, -EINVAL);
        assert_return(client->lease, -EINVAL);

        if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_NA) && client->lease->ia.addresses) {
                *lifetime_t1 = be32toh(client->lease->ia.ia_na.lifetime_t1);
                *lifetime_t2 = be32toh(client->lease->ia.ia_na.lifetime_t2);

                return 0;
        }

        if (FLAGS_SET(client->request_ia, DHCP6_REQUEST_IA_PD) && client->lease->pd.addresses) {
                *lifetime_t1 = be32toh(client->lease->pd.ia_pd.lifetime_t1);
                *lifetime_t2 = be32toh(client->lease->pd.ia_pd.lifetime_t2);

                return 0;
        }

        return -ENOMSG;
}

static int client_start(sd_dhcp6_client *client, DHCP6State state) {
        int r;
        usec_t timeout, time_now;
        uint32_t lifetime_t1, lifetime_t2;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->ifindex > 0, -EINVAL);
        assert_return(client->state != state, -EINVAL);

        (void) event_source_disable(client->timeout_resend_expire);
        (void) event_source_disable(client->timeout_resend);
        client->retransmit_time = 0;
        client->retransmit_count = 0;

        r = sd_event_now(client->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                return r;

        if (!client->receive_message) {
                r = sd_event_add_io(client->event, &client->receive_message,
                                    client->fd, EPOLLIN, client_receive_message,
                                    client);
                if (r < 0)
                        goto error;

                r = sd_event_source_set_priority(client->receive_message,
                                                 client->event_priority);
                if (r < 0)
                        goto error;

                r = sd_event_source_set_description(client->receive_message,
                                                    "dhcp6-receive-message");
                if (r < 0)
                        goto error;
        }

        switch (state) {
        case DHCP6_STATE_STOPPED:
                if (client->state == DHCP6_STATE_INFORMATION_REQUEST) {
                        client->state = DHCP6_STATE_STOPPED;

                        return 0;
                }

                _fallthrough_;
        case DHCP6_STATE_SOLICITATION:
                client->state = DHCP6_STATE_SOLICITATION;

                break;

        case DHCP6_STATE_INFORMATION_REQUEST:
        case DHCP6_STATE_REQUEST:
        case DHCP6_STATE_RENEW:
        case DHCP6_STATE_REBIND:

                client->state = state;

                break;

        case DHCP6_STATE_BOUND:

                r = client_get_lifetime(client, &lifetime_t1, &lifetime_t2);
                if (r < 0)
                        goto error;

                if (lifetime_t1 == 0xffffffff || lifetime_t2 == 0xffffffff) {
                        log_dhcp6_client(client, "Infinite T1 0x%08x or T2 0x%08x",
                                         lifetime_t1, lifetime_t2);

                        return 0;
                }

                timeout = client_timeout_compute_random(lifetime_t1 * USEC_PER_SEC);

                log_dhcp6_client(client, "T1 expires in %s", FORMAT_TIMESPAN(timeout, USEC_PER_SEC));

                r = event_reset_time(client->event, &client->timeout_t1,
                                     clock_boottime_or_monotonic(),
                                     time_now + timeout, 10 * USEC_PER_SEC,
                                     client_timeout_t1, client,
                                     client->event_priority, "dhcp6-t1-timeout", true);
                if (r < 0)
                        goto error;

                timeout = client_timeout_compute_random(lifetime_t2 * USEC_PER_SEC);

                log_dhcp6_client(client, "T2 expires in %s", FORMAT_TIMESPAN(timeout, USEC_PER_SEC));

                r = event_reset_time(client->event, &client->timeout_t2,
                                     clock_boottime_or_monotonic(),
                                     time_now + timeout, 10 * USEC_PER_SEC,
                                     client_timeout_t2, client,
                                     client->event_priority, "dhcp6-t2-timeout", true);
                if (r < 0)
                        goto error;

                client->state = state;

                return 0;
        default:
                assert_not_reached();
        }

        client->transaction_id = random_u32() & htobe32(0x00ffffff);
        client->transaction_start = time_now;

        r = event_reset_time(client->event, &client->timeout_resend,
                             clock_boottime_or_monotonic(),
                             0, 0,
                             client_timeout_resend, client,
                             client->event_priority, "dhcp6-resend-timeout", true);
        if (r < 0)
                goto error;

        return 0;

 error:
        client_reset(client);
        return r;
}

int sd_dhcp6_client_stop(sd_dhcp6_client *client) {
        if (!client)
                return 0;

        client_stop(client, SD_DHCP6_CLIENT_EVENT_STOP);

        client->fd = safe_close(client->fd);

        return 0;
}

int sd_dhcp6_client_is_running(sd_dhcp6_client *client) {
        assert_return(client, -EINVAL);

        return client->state != DHCP6_STATE_STOPPED;
}

int sd_dhcp6_client_start(sd_dhcp6_client *client) {
        DHCP6State state = DHCP6_STATE_SOLICITATION;
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->ifindex > 0, -EINVAL);
        assert_return(in6_addr_is_link_local(&client->local_address) > 0, -EINVAL);

        if (client->state != DHCP6_STATE_STOPPED)
                return -EBUSY;

        if (!client->information_request && client->request_ia == 0)
                return -EINVAL;

        r = client_reset(client);
        if (r < 0)
                return r;

        r = client_ensure_iaid(client);
        if (r < 0)
                return r;

        r = client_ensure_duid(client);
        if (r < 0)
                return r;

        if (client->fd < 0) {
                r = dhcp6_network_bind_udp_socket(client->ifindex, &client->local_address);
                if (r < 0) {
                        _cleanup_free_ char *p = NULL;

                        (void) in_addr_to_string(AF_INET6, (const union in_addr_union*) &client->local_address, &p);
                        return log_dhcp6_client_errno(client, r,
                                                      "Failed to bind to UDP socket at address %s: %m", strna(p));
                }

                client->fd = r;
        }

        if (client->information_request) {
                usec_t t = now(CLOCK_MONOTONIC);

                if (t < usec_add(client->information_request_time_usec, client->information_refresh_time_usec))
                        return 0;

                client->information_request_time_usec = t;
                state = DHCP6_STATE_INFORMATION_REQUEST;
        }

        log_dhcp6_client(client, "Started in %s mode",
                         client->information_request ? "Information request" : "Managed");

        return client_start(client, state);
}

int sd_dhcp6_client_attach_event(sd_dhcp6_client *client, sd_event *event, int64_t priority) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(!client->event, -EBUSY);

        if (event)
                client->event = sd_event_ref(event);
        else {
                r = sd_event_default(&client->event);
                if (r < 0)
                        return 0;
        }

        client->event_priority = priority;

        return 0;
}

int sd_dhcp6_client_detach_event(sd_dhcp6_client *client) {
        assert_return(client, -EINVAL);

        client->event = sd_event_unref(client->event);

        return 0;
}

sd_event *sd_dhcp6_client_get_event(sd_dhcp6_client *client) {
        assert_return(client, NULL);

        return client->event;
}

static sd_dhcp6_client *dhcp6_client_free(sd_dhcp6_client *client) {
        assert(client);

        client->timeout_resend = sd_event_source_unref(client->timeout_resend);
        client->timeout_resend_expire = sd_event_source_unref(client->timeout_resend_expire);
        client->timeout_t1 = sd_event_source_unref(client->timeout_t1);
        client->timeout_t2 = sd_event_source_unref(client->timeout_t2);

        client_reset(client);

        client->fd = safe_close(client->fd);

        sd_dhcp6_client_detach_event(client);

        free(client->req_opts);
        free(client->fqdn);
        free(client->mudurl);

        ordered_hashmap_free(client->extra_options);
        strv_free(client->user_class);
        strv_free(client->vendor_class);
        free(client->ifname);

        return mfree(client);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_client, sd_dhcp6_client, dhcp6_client_free);

int sd_dhcp6_client_new(sd_dhcp6_client **ret) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_free_ be16_t *req_opts = NULL;
        size_t t;

        assert_return(ret, -EINVAL);

        req_opts = new(be16_t, ELEMENTSOF(default_req_opts));
        if (!req_opts)
                return -ENOMEM;

        for (t = 0; t < ELEMENTSOF(default_req_opts); t++)
                req_opts[t] = htobe16(default_req_opts[t]);

        client = new(sd_dhcp6_client, 1);
        if (!client)
                return -ENOMEM;

        *client = (sd_dhcp6_client) {
                .n_ref = 1,
                .ia_na.type = SD_DHCP6_OPTION_IA_NA,
                .ia_pd.type = SD_DHCP6_OPTION_IA_PD,
                .ifindex = -1,
                .request_ia = DHCP6_REQUEST_IA_NA | DHCP6_REQUEST_IA_PD,
                .fd = -1,
                .req_opts_len = ELEMENTSOF(default_req_opts),
                .hint_pd_prefix.iapdprefix.lifetime_preferred = (be32_t) -1,
                .hint_pd_prefix.iapdprefix.lifetime_valid = (be32_t) -1,
                .req_opts = TAKE_PTR(req_opts),
        };

        *ret = TAKE_PTR(client);

        return 0;
}
