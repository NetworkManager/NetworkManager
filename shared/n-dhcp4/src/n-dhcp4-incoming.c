/*
 * DHCPv4 Incoming Messages
 *
 * This file implements the message parser object for incoming DHCP4 messages.
 * It takes a linear data blob as input, and provides accessors for the message
 * content.
 *
 * This wrapper mainly deals with the OPTIONs array. That is, in hides the
 * different overload-sections the DHCP4 spec defines, it concatenates
 * duplicate option fields (as described by the spec), and provides a
 * consistent view to the caller.
 *
 * Internally, for every incoming message we linearize its OPTIONs. This means,
 * we create a copy of the contents, and merge all duplicate options into a
 * single option entry. We then provide accessors to the caller to easily get
 * O(1) access to individual fields.
 */

#include <assert.h>
#include <c-stdaux.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"

static void n_dhcp4_incoming_prefetch(NDhcp4Incoming *incoming, size_t *offset, uint8_t option, const uint8_t *raw, size_t n_raw) {
        uint8_t o, l;
        size_t pos;

        for (pos = 0; pos < n_raw; ) {
                o = raw[pos++];
                if (o == N_DHCP4_OPTION_PAD)
                        continue;
                if (o == N_DHCP4_OPTION_END)
                        return;

                /* bail out if no remaining space for length field */
                if (pos >= n_raw)
                        return;

                /* bail out if length exceeds the available space */
                l = raw[pos++];
                if (l > n_raw || pos > n_raw - l)
                        return;

                /* prefetch content if it matches @option */
                if (o == option) {
                        memcpy((uint8_t *)&incoming->message + *offset, raw + pos, l);
                        *offset += l;
                }

                pos += l;
        }
}

static void n_dhcp4_incoming_merge(NDhcp4Incoming *incoming, size_t *offset, uint8_t overload, uint8_t option) {
        uint8_t *m = (uint8_t *)&incoming->message;
        size_t pos;

        /*
         * Prefetch all options matching @option from the 3 sections,
         * concatenating their content. Remember the offset and size of the
         * option in our message state.
         */

        pos = *offset;

        /* prefetch option from OPTIONS */
        n_dhcp4_incoming_prefetch(incoming, offset, option,
                                  m + offsetof(NDhcp4Message, options),
                                  incoming->n_message - offsetof(NDhcp4Message, options));

        /* prefetch option from FILE */
        if (overload & N_DHCP4_OVERLOAD_FILE)
                n_dhcp4_incoming_prefetch(incoming, offset, option,
                                          m + offsetof(NDhcp4Message, file),
                                          sizeof(incoming->message.file));

        /* prefetch option from SNAME */
        if (overload & N_DHCP4_OVERLOAD_SNAME)
                n_dhcp4_incoming_prefetch(incoming, offset, option,
                                          m + offsetof(NDhcp4Message, sname),
                                          sizeof(incoming->message.sname));

        incoming->options[option].value = m + pos;
        incoming->options[option].size = *offset - pos;
}

static void n_dhcp4_incoming_linearize(NDhcp4Incoming *incoming) {
        uint8_t *m, o, l, overload;
        size_t i, pos, end, offset;

        /*
         * Linearize all OPTIONs of the incoming message. We know that
         * @incoming->message is preallocated to be big enough to hold the
         * entire linearized message _trailing_ the original copy. All we have
         * to do is walk the raw message in @incoming->message and for each
         * option we find, copy it into the trailing space, concatenating all
         * instances we find.
         *
         * Before we can copy the individual options, we must scan for the
         * OVERLOAD option. This is required so our prefetcher knows which data
         * arrays to scan for prefetching.
         *
         * So far, we require the OVERLOAD option to be present in the
         * options-array (which is obvious and a given). However, if the option
         * occurs multiple times outside of the options-array (i.e., SNAME or
         * FILE), we silently ignore them. The specification does not allow
         * multiple OVERLOAD options, anyway. Hence, this behavior only defines
         * what we do when we see broken implementations, and we currently seem
         * to support all styles we saw in the wild so far.
         */

        m = (uint8_t *)&incoming->message;
        offset = incoming->n_message;

        n_dhcp4_incoming_merge(incoming, &offset, 0, N_DHCP4_OPTION_OVERLOAD);
        if (incoming->options[N_DHCP4_OPTION_OVERLOAD].size >= 1)
                overload = *incoming->options[N_DHCP4_OPTION_OVERLOAD].value;
        else
                overload = 0;

        for (i = 0; i < 3; ++i) {
                if (i == 0) { /* walk OPTIONS */
                        pos = offsetof(NDhcp4Message, options);
                        end = incoming->n_message;
                } else if (i == 1) { /* walk FILE */
                        if (!(overload & N_DHCP4_OVERLOAD_FILE))
                                continue;

                        pos = offsetof(NDhcp4Message, file);
                        end = pos + sizeof(incoming->message.file);
                } else { /* walk SNAME */
                        if (!(overload & N_DHCP4_OVERLOAD_SNAME))
                                continue;

                        pos = offsetof(NDhcp4Message, sname);
                        end = pos + sizeof(incoming->message.sname);
                }

                while (pos < end) {
                        o = m[pos++];
                        if (o == N_DHCP4_OPTION_PAD)
                                continue;
                        if (o == N_DHCP4_OPTION_END)
                                break;
                        if (pos >= end)
                                break;

                        l = m[pos++];
                        if (l > end || pos > end - l)
                                break;

                        if (!incoming->options[o].value)
                                n_dhcp4_incoming_merge(incoming, &offset, overload, o);

                        pos += l;
                }
        }
}

/**
 * n_dhcp4_incoming_new() - Allocate new incoming message object
 * @incomingp:          output argument for new object
 * @raw:                raw message blob
 * @n_raw:              length of the raw message blob
 *
 * This function allocates a new incoming-message object to wrap a received
 * message blob. It performs basic verification of the message length and
 * header, and then linearizes the DHCP4 options.
 *
 * The incoming-message object mainly provides accessors for the option-array.
 * It handles all the different quirks around parsing and concatenating the
 * options array, and provides the assembled data to the caller. It does not,
 * however, in any way interpret the data of the individual options. This is up
 * to the caller to do.
 *
 * Return: 0 on success, negative error code on failure, N_DHCP4_E_MALFORMED if
 *         the message is not a valid DHCP4 message.
 */
int n_dhcp4_incoming_new(NDhcp4Incoming **incomingp, const void *raw, size_t n_raw) {
        _c_cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming = NULL;
        size_t size;

        if (n_raw < sizeof(NDhcp4Message) || n_raw > UINT16_MAX)
                return N_DHCP4_E_MALFORMED;

        /*
         * Allocate enough space for book-keeping, a copy of @raw and trailing
         * space for linearized options. The trailing space must be big enough
         * to hold the entire options array unmodified (linearizing can only
         * make it smaller). Hence, just allocate enough space to hold the raw
         * message without the header.
         */
        size = sizeof(*incoming) + n_raw - sizeof(NDhcp4Message);
        size += n_raw - sizeof(NDhcp4Header);

        incoming = calloc(1, size);
        if (!incoming)
                return -ENOMEM;

        *incoming = (NDhcp4Incoming)N_DHCP4_INCOMING_NULL(*incoming);
        incoming->n_message = n_raw;
        memcpy(&incoming->message, raw, n_raw);

        if (incoming->message.magic != htobe32(N_DHCP4_MESSAGE_MAGIC))
                return N_DHCP4_E_MALFORMED;

        /* linearize options */
        n_dhcp4_incoming_linearize(incoming);

        *incomingp = incoming;
        incoming = NULL;
        return 0;
}

/**
 * n_dhcp4_incoming_free() - Deallocate message object
 * @incoming:           object to operate on, or NULL
 *
 * This deallocates and frees the given incoming-message object. If NULL is
 * passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
NDhcp4Incoming *n_dhcp4_incoming_free(NDhcp4Incoming *incoming) {
        if (!incoming)
                return NULL;

        free(incoming);

        return NULL;
}

/**
 * n_dhcp4_incoming_get_header() - Return message header
 * @incoming:           message to operate on
 *
 * This returns a pointer to the message header. Note that modifications to
 * this header are permanent and will affect the original message.
 *
 * Return: A pointer to the message header is returned.
 */
NDhcp4Header *n_dhcp4_incoming_get_header(NDhcp4Incoming *incoming) {
        return &incoming->message.header;
}

/**
 * n_dhcp4_incoming_get_raw() - Get access to the raw original message
 * @incoming:           message to operate on
 * @rawp:               output argument for the raw blob, or NULL
 *
 * This hands out a pointer to the raw message blob to the caller. This will
 * point to the original message content, rather than the linearized version.
 *
 * Note that if the caller queried the contents of the message before, any
 * modifications done by the caller will not affect the original message. It
 * only affects the linearized content (which is a duplicate trailing the
 * original message). However, modifications to the message header *DO* also
 * appear in the original, since the message header is not duplicated.
 *
 * In either case, it is better to never modify the message, if you intend to
 * forward it further.
 *
 * Return: The length of the raw message blob is returned.
 */
size_t n_dhcp4_incoming_get_raw(NDhcp4Incoming *incoming, const void **rawp) {
        if (rawp)
                *rawp = &incoming->message;
        return incoming->n_message;
}

/**
 * n_dhcp4_incoming_query() - Query the contents of a specific option
 * @incoming:           message to query
 * @option:             option to look for
 * @datap:              output argument for the option-data, or NULL
 * @n_datap:            output argument for the length of the option, or NULL
 *
 * This returns a pointer to the requested option blob in the message. It
 * points to a linearized version of all respective option-fields of the same
 * type. Hence, the caller is not required to deal with multiple occurrences of
 * the same option.
 *
 * If an option was not present in the incoming message, N_DHCP4_E_UNSET is
 * returned. Note that this is different from an empty option! And empty option
 * will return a valid pointer and size 0.
 *
 * Note that the pointer to the option-blob does not point to the original
 * message, but a duplicated version. Modifications to the blob will not be
 * reflected in the original message, but they will be permanent regarding
 * further queries through this function.
 *
 * Note that the original message alignment might no longer be reflected in the
 * returned blob. You must not alias the content of the blob, but always copy
 * it out, or consume piecemeal.
 *
 * This function runs in O(1).
 *
 * Return: 0 on success, negative error code on failure, N_DHCP4_E_UNSET if the
 *         option was not found,
 */
int n_dhcp4_incoming_query(NDhcp4Incoming *incoming, uint8_t option, uint8_t **datap, size_t *n_datap) {
        if (!incoming->options[option].value)
                return N_DHCP4_E_UNSET;

        if (datap)
                *datap = incoming->options[option].value;
        if (n_datap)
                *n_datap = incoming->options[option].size;
        return 0;
}

static int n_dhcp4_incoming_query_u8(NDhcp4Incoming *message, uint8_t option, uint8_t *u8p) {
        uint8_t *data;
        size_t n_data;
        int r;

        r = n_dhcp4_incoming_query(message, option, &data, &n_data);
        if (r)
                return r;
        else if (n_data != sizeof(*data))
                return N_DHCP4_E_MALFORMED;

        *u8p = *data;
        return 0;
}

static int n_dhcp4_incoming_query_u16(NDhcp4Incoming *message, uint8_t option, uint16_t *u16p) {
        uint8_t *data;
        size_t n_data;
        uint16_t be16;
        int r;

        r = n_dhcp4_incoming_query(message, option, &data, &n_data);
        if (r)
                return r;
        else if (n_data != sizeof(be16))
                return N_DHCP4_E_MALFORMED;

        memcpy(&be16, data, sizeof(be16));

        *u16p = ntohs(be16);
        return 0;
}

static int n_dhcp4_incoming_query_u32(NDhcp4Incoming *message, uint8_t option, uint32_t *u32p) {
        uint8_t *data;
        size_t n_data;
        uint32_t be32;
        int r;

        r = n_dhcp4_incoming_query(message, option, &data, &n_data);
        if (r)
                return r;
        else if (n_data != sizeof(be32))
                return N_DHCP4_E_MALFORMED;

        memcpy(&be32, data, sizeof(be32));

        if (be32 == (uint32_t)-1)
                *u32p = 0;
        else
                *u32p = ntohl(be32);
        return 0;
}

static int n_dhcp4_incoming_query_in_addr(NDhcp4Incoming *message, uint8_t option, struct in_addr *addrp) {
        uint8_t *data;
        size_t n_data;
        uint32_t be32;
        int r;

        r = n_dhcp4_incoming_query(message, option, &data, &n_data);
        if (r)
                return r;
        else if (n_data != sizeof(be32))
                return N_DHCP4_E_MALFORMED;

        memcpy(&be32, data, sizeof(be32));

        addrp->s_addr = be32;
        return 0;
}

int n_dhcp4_incoming_query_message_type(NDhcp4Incoming *message, uint8_t *typep) {
        return n_dhcp4_incoming_query_u8(message, N_DHCP4_OPTION_MESSAGE_TYPE, typep);
}

int n_dhcp4_incoming_query_lifetime(NDhcp4Incoming *message, uint32_t *lifetimep) {
        return n_dhcp4_incoming_query_u32(message, N_DHCP4_OPTION_IP_ADDRESS_LEASE_TIME, lifetimep);
}

int n_dhcp4_incoming_query_t2(NDhcp4Incoming *message, uint32_t *t2p) {
        return n_dhcp4_incoming_query_u32(message, N_DHCP4_OPTION_REBINDING_T2_TIME, t2p);
}

int n_dhcp4_incoming_query_t1(NDhcp4Incoming *message, uint32_t *t1p) {
        return n_dhcp4_incoming_query_u32(message, N_DHCP4_OPTION_RENEWAL_T1_TIME, t1p);
}

int n_dhcp4_incoming_query_server_identifier(NDhcp4Incoming *message, struct in_addr *idp) {
        return n_dhcp4_incoming_query_in_addr(message, N_DHCP4_OPTION_SERVER_IDENTIFIER, idp);
}

int n_dhcp4_incoming_query_max_message_size(NDhcp4Incoming *message, uint16_t *max_message_sizep) {
        return n_dhcp4_incoming_query_u16(message, N_DHCP4_OPTION_MAXIMUM_MESSAGE_SIZE, max_message_sizep);
}

int n_dhcp4_incoming_query_requested_ip(NDhcp4Incoming *message, struct in_addr *requested_ipp) {
        return n_dhcp4_incoming_query_in_addr(message, N_DHCP4_OPTION_REQUESTED_IP_ADDRESS, requested_ipp);
}

void n_dhcp4_incoming_get_xid(NDhcp4Incoming *message, uint32_t *xidp) {
        NDhcp4Header *header = n_dhcp4_incoming_get_header(message);

        *xidp = header->xid;
}

void n_dhcp4_incoming_get_yiaddr(NDhcp4Incoming *message, struct in_addr *yiaddr) {
        NDhcp4Header *header = n_dhcp4_incoming_get_header(message);

        yiaddr->s_addr = header->yiaddr;
}
