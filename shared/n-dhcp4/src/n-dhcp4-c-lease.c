/*
 * DHCP4 Client Leases
 *
 * This implements the public API wrapping DHCP4 client leases. A lease object
 * conists of the information given to us from the server, together with the
 * timestamp recording the start of the validity of the lease.
 *
 * A probe may yield many OFFERS, each of which contains a lease object. One of
 * these offers may be SELECTED, which implicitly rejects all the others.
 * The server may then ACK or NAK the lease which tells us whether or not we
 * are permitted to start using it. Once an ACK has been received, we can
 * configure the address, and only then can we SELECT the lease. If we
 * determine that the offered lease was not appropriate after all we
 * may DECLINE it instead.
 */

#include <assert.h>
#include <c-list.h>
#include <c-stdaux.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"

/*
 * Compute the absolute timeouts from an incoming message. A message contains relative timeouts and the userdata
 * of the incoming message is set to the offset we must apply to get the absolute values.
 *
 * The special value UINT64_MAX is returned to indicate no or infinite timeouts. In case the given timeouts
 * are invalid relative to each other, we recompute T1 and/or T2 to take their default values. Later timeouts
 * take predecende above earlier ones (T1 is adjusted if it conflicts with T2, etc).
 */
static int n_dhcp4_incoming_get_timeouts(NDhcp4Incoming *message, uint64_t *t1p, uint64_t *t2p, uint64_t *lifetimep) {
        uint64_t lifetime, t2, t1;
        uint32_t u32;
        int r;

        r = n_dhcp4_incoming_query_lifetime(message, &u32);
        if (r == N_DHCP4_E_UNSET) {
                lifetime = UINT64_MAX;
        } else if (r) {
                return r;
        } else if (u32 == UINT32_MAX) {
                lifetime = UINT64_MAX;
        } else {
                lifetime = u32 * (1000000000ULL);
        }

        r = n_dhcp4_incoming_query_t2(message, &u32);
        if (r == N_DHCP4_E_UNSET) {
                if (lifetime == UINT64_MAX)
                        t2 = UINT64_MAX;
                else
                        t2 = (lifetime * 7) / 8;
        } else if (r) {
                return r;
        } else {
                if (u32 == UINT32_MAX)
                        t2 = UINT64_MAX;
                else
                        t2 = u32 * (1000000000ULL);

                if (t2 > lifetime)
                        t2 = (lifetime * 7) / 8;
        }

        r = n_dhcp4_incoming_query_t1(message, &u32);
        if (r == N_DHCP4_E_UNSET) {
                if (t2 == UINT64_MAX)
                        t1 = UINT64_MAX;
                else
                        t1 = (t2 * 4) / 7;
        } else if (r) {
                return r;
        } else {
                if (u32 == UINT32_MAX)
                        t1 = UINT64_MAX;
                else
                        t1 = u32 * (1000000000ULL);

                if (t1 > t2)
                        t1 = (t2 * 4) / 7;
        }

        if (lifetime != UINT64_MAX)
                lifetime += message->userdata.base_time;
        if (t2 != UINT64_MAX)
                t2 += message->userdata.base_time;
        if (t1 != UINT64_MAX)
                t1 += message->userdata.base_time;

        *lifetimep = lifetime;
        *t2p = t2;
        *t1p = t1;
        return 0;
}

/**
 * n_dhcp4_client_lease_new() - allocate new client lease object
 * @leasep:                     output argumnet for new client lease object
 * @message:                    incoming message representing the lease
 *
 * This creates a new client lease object. Client lease objects are simple
 * wrappers around an incoming message representing a lease.
 *
 * Return: 0 on success, negative error code on failure.
 */
int n_dhcp4_client_lease_new(NDhcp4ClientLease **leasep, NDhcp4Incoming *message) {
        _c_cleanup_(n_dhcp4_client_lease_unrefp) NDhcp4ClientLease *lease = NULL;
        int r;

        c_assert(leasep);

        lease = malloc(sizeof(*lease));
        if (!lease)
                return -ENOMEM;

        *lease = (NDhcp4ClientLease)N_DHCP4_CLIENT_LEASE_NULL(*lease);

        r = n_dhcp4_incoming_get_timeouts(message, &lease->t1, &lease->t2, &lease->lifetime);
        if (r)
                return r;

        lease->message = message;
        *leasep = lease;
        lease = NULL;
        return 0;
}

static void n_dhcp4_client_lease_free(NDhcp4ClientLease *lease) {
        n_dhcp4_client_lease_unlink(lease);
        n_dhcp4_incoming_free(lease->message);
        free(lease);
}

/**
 * n_dhcp4_client_lease_ref() - reference client lease
 * @lease:                      the client lease object to reference
 *
 * Take a new reference to a client lease.
 *
 * Return: the lease.
 */
_c_public_ NDhcp4ClientLease *n_dhcp4_client_lease_ref(NDhcp4ClientLease *lease) {
        if (lease)
                ++lease->n_refs;
        return lease;
}

/**
 * n_dhcp4_client_lease_unref() - dereference client lease
 * @lease:                      the client lease object to dereference
 *
 * Relase a reference to a client lease.
 *
 * Return: NULL.
 */
_c_public_ NDhcp4ClientLease *n_dhcp4_client_lease_unref(NDhcp4ClientLease *lease) {
        if (lease && !--lease->n_refs)
                n_dhcp4_client_lease_free(lease);
        return NULL;
}

/**
 * n_dhcp4_client_lease_link() - link lease into probe
 * @lease:                      the lease to operate on
 * @probe:                      the probe to link the lease into
 *
 * Associate a lease with a probe. The lease may not already be linked.
 */
void n_dhcp4_client_lease_link(NDhcp4ClientLease *lease, NDhcp4ClientProbe *probe) {
        c_assert(!lease->probe);
        c_assert(!c_list_is_linked(&lease->probe_link));

        lease->probe = probe;
        c_list_link_tail(&probe->lease_list, &lease->probe_link);
}

/**
 * n_dhcp4_client_lease_unlink() - unlinke lease from its probe
 * @lease:                      the lease to operate on
 *
 * Dissassociate a lease from a probe if it is associated with one. Otherwise,
 * this is a noop.
 */
void n_dhcp4_client_lease_unlink(NDhcp4ClientLease *lease) {
        lease->probe = NULL;
        c_list_unlink(&lease->probe_link);
}

/**
 * n_dhcp4_client_lease_get_yiaddr() - get the IP address
 * @lease:                      the lease to operate on
 * @yiaddr:                     return argument for the IP address
 *
 * Gets the IP address cotained in the lease. Or INADDR_ANY if the lease
 * does not contain an IP address.
 */
_c_public_ void n_dhcp4_client_lease_get_yiaddr(NDhcp4ClientLease *lease, struct in_addr *yiaddr) {
        NDhcp4Header *header = n_dhcp4_incoming_get_header(lease->message);

        yiaddr->s_addr = header->yiaddr;
}

/**
 * n_dhcp4_client_lease_get_lifetime() - get the lifetime
 * @lease:                      the lease to operate on
 * @ns_lifetimep:               return argument for the lifetime in nano seconds
 *
 * Gets the end of the lease's lifetime in nanoseconds according to CLOCK_BOOTTIME,
 * or (uint64_t)-1 for permanent leases.
 */
_c_public_ void n_dhcp4_client_lease_get_lifetime(NDhcp4ClientLease *lease, uint64_t *ns_lifetimep) {
        *ns_lifetimep = lease->lifetime;
}

/**
 * n_dhcp4_client_lease_query() - query the lease for an option
 * @lease:                      the lease to operate on
 * @option:                     the DHCP4 option code
 * @datap:                      return argument of the data pointer
 * @n_datap:                    return argument of data length in bytes
 *
 * Query the lease for a given option. Options internal to the DHCP protocol cannot
 * be queried, and only options that were explicitly requested can be queried.
 *
 * Return: 0 on success,
 *         N_DCHP4_E_INTERNAL if an invalid option is queried,
 *         N_DHCP4_E_UNSET if the lease did not contain the option, or
 *         a negative error code on failure.
 */
_c_public_ int n_dhcp4_client_lease_query(NDhcp4ClientLease *lease, uint8_t option, uint8_t **datap, size_t *n_datap) {
        switch (option) {
        case N_DHCP4_OPTION_PAD:
        case N_DHCP4_OPTION_REQUESTED_IP_ADDRESS:
        case N_DHCP4_OPTION_IP_ADDRESS_LEASE_TIME:
        case N_DHCP4_OPTION_OVERLOAD:
        case N_DHCP4_OPTION_MESSAGE_TYPE:
        case N_DHCP4_OPTION_SERVER_IDENTIFIER:
        case N_DHCP4_OPTION_PARAMETER_REQUEST_LIST:
        case N_DHCP4_OPTION_ERROR_MESSAGE:
        case N_DHCP4_OPTION_MAXIMUM_MESSAGE_SIZE:
        case N_DHCP4_OPTION_RENEWAL_T1_TIME:
        case N_DHCP4_OPTION_REBINDING_T2_TIME:
        case N_DHCP4_OPTION_END:
                return N_DHCP4_E_INTERNAL;
        }

        /* XXX: refuse to return options that were not requested */

        return n_dhcp4_incoming_query(lease->message, option, datap, n_datap);
}

/**
 * n_dhcp4_client_lease_select() - select an offered lease
 * @lease:                      lease to operate on
 *
 * Select a lease. This must be a lease that was offered, once
 * one of the leases that were offered in response to a probe was
 * selected none of the others can be.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
_c_public_ int n_dhcp4_client_lease_select(NDhcp4ClientLease *lease) {
        NDhcp4ClientLease *l, *t_l;
        NDhcp4ClientProbe *probe;
        int r;

        /* XXX error handling, this must be an OFFER */

        if (!lease->probe)
                return -ENOTRECOVERABLE;
        if (lease->probe->current_lease)
                return -ENOTRECOVERABLE;

        r = n_dhcp4_client_probe_transition_select(lease->probe, lease->message, n_dhcp4_gettime(CLOCK_BOOTTIME));
        if (r)
                return r;

        /*
         * Only one of the offered leases can be selected, so flush the list.
         * All offered lease, including this one are now dead.
         */
        probe = lease->probe;
        c_list_for_each_entry_safe(l, t_l, &probe->lease_list, probe_link)
                n_dhcp4_client_lease_unlink(l);

        return 0;
}

/**
 * n_dhcp4_client_lease_accept() - accept an ack'ed lease
 * @lease:                      lease to operate on
 *
 * Accept a lease. This must be a lease that was ack'ed by the
 * server.
 *
 * The offered IP address must be fully configured before the lease
 * can be accepted.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
_c_public_ int n_dhcp4_client_lease_accept(NDhcp4ClientLease *lease) {
        int r;

        /* XXX error handling, this must be an ACK */

        if (!lease->probe)
                return -ENOTRECOVERABLE;
        if (lease->probe->current_lease != lease)
                return -ENOTRECOVERABLE;

        r = n_dhcp4_client_probe_transition_accept(lease->probe, lease->message);
        if (r)
                return r;

        n_dhcp4_client_lease_unlink(lease);

        return 0;
}

/**
 * n_dhcp4_client_lease_decline() - decline an ack'ed lease
 * @lease:                      lease to operate on
 *
 * Decline a lease. This must be a lease that was ack'ed by the
 * server.
 *
 * The offered IP address must not be used once the lease has been
 * decline.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
_c_public_ int n_dhcp4_client_lease_decline(NDhcp4ClientLease *lease, const char *error) {
        int r;

        /* XXX: error handling, this must be an ACK */

        if (!lease->probe)
                return -ENOTRECOVERABLE;
        if (lease->probe->current_lease != lease)
                return -ENOTRECOVERABLE;

        r = n_dhcp4_client_probe_transition_decline(lease->probe, lease->message, error, n_dhcp4_gettime(CLOCK_BOOTTIME));
        if (r)
                return r;

        lease->probe->current_lease = n_dhcp4_client_lease_unref(lease->probe->current_lease);
        n_dhcp4_client_lease_unlink(lease);

        return 0;
}
