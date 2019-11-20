/*
 * DHCPv4 Outgoing Messages
 *
 * XXX
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

/**
 * N_DHCP4_OUTGOING_MAX_PHDR - maximum protocol header size
 *
 * All DHCP4 messages-limits specify the size of the entire packet including
 * the protocol layer (i.e., including the IP headers and UDP headers). To
 * calculate the size we have remaining for the actual DHCP message, we need to
 * substract the maximum possible header-length the linux-kernel might prepend
 * to our messages. This turns out to be the maximum IP-header size (including
 * optional IP headers, hence 60 bytes) plus the UDP header size (i.e., 8
 * bytes).
 */
#define N_DHCP4_OUTGOING_MAX_PHDR (N_DHCP4_NETWORK_IP_MAXIMUM_HEADER_SIZE + sizeof(struct udphdr))

/**
 * n_dhcp4_outgoing_new() - Allocate new outgoing message
 * @outgoingp:          output argument to return allocate object through
 * @max_size:           maximum transmission size to use
 * @overload:           select sections to overload
 *
 * This allocates a new outgoing message and returns it to the caller. The
 * caller can then append data to it and send it over the wire.
 *
 * The @max_size parameter specifies the transport-layer MTU to consider. If 0,
 * N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE is used. Note that this argument
 * specifies the maximum packet size *INCLUDING* the IP-headers and UDP-header.
 * Internally, the allocator makes sure to never create packets bigger than the
 * specified MTU. The append functions will return an error, if the packet size
 * would exceed the MTU.
 * If you use a full UDP stack that supports packet fragmentation, you can
 * specify the maximum packet size here (e.g., UINT16_MAX).
 *
 * Return: 0 on success, error code on failure.
 */
int n_dhcp4_outgoing_new(NDhcp4Outgoing **outgoingp, size_t max_size, uint8_t overload) {
        _c_cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;

        /*
         * Make sure the minimum limit is bigger than the maximum protocol
         * header plus the DHCP-message-header plus a single OPTION_END byte.
         */
        static_assert(N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE >= N_DHCP4_OUTGOING_MAX_PHDR +
                                                             sizeof(NDhcp4Message) + 1,
                      "Invalid minimum IP packet limit");

        c_assert(!(overload & ~(N_DHCP4_OVERLOAD_FILE | N_DHCP4_OVERLOAD_SNAME)));

        outgoing = calloc(1, sizeof(*outgoing));
        if (!outgoing)
                return -ENOMEM;

        *outgoing = (NDhcp4Outgoing)N_DHCP4_OUTGOING_NULL(*outgoing);
        outgoing->n_message = N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE - N_DHCP4_OUTGOING_MAX_PHDR;
        outgoing->i_message = offsetof(NDhcp4Message, options);
        outgoing->max_size = outgoing->n_message;
        outgoing->overload = overload;

        if (max_size > N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE)
                outgoing->max_size = max_size - N_DHCP4_OUTGOING_MAX_PHDR;

        outgoing->message = calloc(1, outgoing->n_message);
        if (!outgoing->message)
                return -ENOMEM;

        outgoing->message->magic = htonl(N_DHCP4_MESSAGE_MAGIC);
        outgoing->message->options[0] = N_DHCP4_OPTION_END;

        *outgoingp = outgoing;
        outgoing = NULL;
        return 0;
}

/**
 * n_dhcp4_outgoing_free() - Deallocate outgoing message
 * @outgoing:           message to deallocate, or NULL
 *
 * This is the opposite to n_dhcp4_outgoing_new(). It deallocates and frees the
 * passed object. If @outgoing is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
NDhcp4Outgoing *n_dhcp4_outgoing_free(NDhcp4Outgoing *outgoing) {
        if (!outgoing)
                return NULL;

        free(outgoing->message);
        free(outgoing);

        return NULL;
}

/**
 * n_dhcp4_outgoing_get_header() - Get pointer to the message header
 * @outgoing:           message to operate on
 *
 * This returns a pointer to the DHCP4 message header to the caller. The caller
 * can use this to fill-in the header-fields. Note that all fields are
 * initialized to their default values. Hence, you only need to override the
 * fields where the default is not sufficient.
 *
 * Return: A pointer to the message header is returned.
 */
NDhcp4Header *n_dhcp4_outgoing_get_header(NDhcp4Outgoing *outgoing) {
        return &outgoing->message->header;
}

/**
 * n_dhcp4_outgoing_get_raw() - Get the raw message blob
 * @outgoing:           message to operat on
 * @rawp:               output argument for the message-blob
 *
 * This function gives the caller access to the raw message-blob. That is, once
 * message-marshaling is complete, use this to get the raw blob for sending.
 * Note that this blob is only valid as long as you no longer append any
 * further options to the message, nor modify it in any other way.
 *
 * Return: The size of the raw message blob is returned.
 */
size_t n_dhcp4_outgoing_get_raw(NDhcp4Outgoing *outgoing, const void **rawp) {
        if (rawp)
                *rawp = outgoing->message;

        /*
         * Return the DHCP message until the END option, excluding any
         * trailing padding. We overallocate during append, so the
         * allocated message might be bigger than what we want to
         * send on the wire.
         */
        return outgoing->i_message + 1;
}

static void n_dhcp4_outgoing_append_option(NDhcp4Outgoing *outgoing,
                                           uint8_t option,
                                           const void *data,
                                           uint8_t n_data) {
        uint8_t *blob = (void *)outgoing->message;

        blob[outgoing->i_message++] = option;
        blob[outgoing->i_message++] = n_data;
        memcpy(blob + outgoing->i_message, data, n_data);
        outgoing->i_message += n_data;
        blob[outgoing->i_message] = N_DHCP4_OPTION_END;
}

/**
 * n_dhcp4_outgoing_append() - Append option to outgoing message
 * @outgoing:           message to operate on
 * @option:             option code to append
 * @data:               data to append in the option
 * @n_data:             length of the data blob
 *
 * This appends another option to the given outgoing message. The data is taken
 * verbatim and copied into the message. Note that no validation is done. If
 * you provide an option multiple times, it will be added multiple times (spec
 * then requires them to be interpreted as concatenated option, in case the
 * option is marked as such).
 *
 * The size of a message is limited, based on the restriction passed to the
 * outgoing-message constructor. If there is not enough free space to copy in
 * the new option, N_DHCP4_E_NO_SPACE is returned.
 *
 * The order in which you append options might matter to some implementations.
 * For example, the message-type is often expected to be the first option. We
 * do not place such restrictions, but for compatibility with external
 * implementations, you should follow these recommendations.
 * Furthermore, we do not implement any kind of smart allocators. That is, all
 * options are simply appended when you call this. But due to the overloading
 * feature, fragmentation might matter. Hence, if you use overloading, overly
 * big options might cause padding, and as such waste space.
 *
 * Return: 0 on success, negative error code on failure, N_DHCP4_E_NO_SPACE
 *         when there is not sufficient free space in the message.
 */
int n_dhcp4_outgoing_append(NDhcp4Outgoing *outgoing,
                            uint8_t option,
                            const void *data,
                            uint8_t n_data) {
        NDhcp4Message *m;
        uint8_t overload;
        size_t rem, n;

        c_assert(option != N_DHCP4_OPTION_PAD);
        c_assert(option != N_DHCP4_OPTION_END);
        c_assert(option != N_DHCP4_OPTION_OVERLOAD);

        /*
         * If the iterator is on the OPTIONs field, try appending the new blob.
         * We need 2 header-bytes plus @n_data bytes. Additionally, we always
         * reserve 3 trailing bytes for a possible OVERLOAD option, and 1 byte
         * for the END marker.
         */
        if (outgoing->i_message >= offsetof(NDhcp4Message, options)) {
                rem = outgoing->n_message - outgoing->i_message;

                /* try fitting into remaining OPTIONs space */
                if (rem >= n_data + 2U + 3U + 1U) {
                        n_dhcp4_outgoing_append_option(outgoing, option, data, n_data);
                        return 0;
                }

                /* try fitting into allowed OPTIONs space */
                if (outgoing->max_size - outgoing->i_message >= n_data + 2U + 3U + 1U) {
                        /* try over-allocation to reduce allocation pressure */
                        n = outgoing->n_message + n_data + 128;
                        if (n > outgoing->max_size)
                                n = outgoing->max_size;
                        m = realloc(outgoing->message, n);
                        if (!m)
                                return -ENOMEM;

                        memset((void *)m + outgoing->i_message, 0, n - outgoing->i_message);
                        outgoing->message = m;
                        outgoing->n_message = n;
                        n_dhcp4_outgoing_append_option(outgoing, option, data, n_data);
                        return 0;
                }

                /* not enough remaining space, try OVERLOAD */
                if (!outgoing->overload)
                        return N_DHCP4_E_NO_SPACE;

                /*
                 * We ran out of space in the OPTIONs array, but overloading
                 * was enabled. This means, we can insert an OVERLOAD option
                 * and then use SNAME/FILE to store more options.
                 * Note that the three different sections cannot overlap and
                 * all must have an END marker. So as soon as we add the
                 * OVERLOAD option, we must make sure the other sections have
                 * the valid END marker. From then on, our *_append_option()
                 * helper makes sure to move the END marker with every
                 * insertion.
                 */
                overload = outgoing->overload;
                n_dhcp4_outgoing_append_option(outgoing, N_DHCP4_OPTION_OVERLOAD, &overload, 1);

                if (overload & N_DHCP4_OVERLOAD_FILE)
                        outgoing->message->file[0] = N_DHCP4_OPTION_END;
                if (overload & N_DHCP4_OVERLOAD_SNAME)
                        outgoing->message->sname[0] = N_DHCP4_OPTION_END;

                if (overload & N_DHCP4_OVERLOAD_FILE)
                        outgoing->i_message = offsetof(NDhcp4Message, file);
                else if (overload & N_DHCP4_OVERLOAD_SNAME)
                        outgoing->i_message = offsetof(NDhcp4Message, sname);
        }

        /*
         * The OPTIONs section is full and OVERLOAD was enabled. Try writing
         * into the FILE section. Always reserve 1 byte for the trailing END
         * marker.
         */
        if (outgoing->i_message >= offsetof(NDhcp4Message, file)) {
                rem = sizeof(outgoing->message->file);
                rem -= outgoing->i_message - offsetof(NDhcp4Message, file);

                if (rem >= n_data + 2U + 1U) {
                        n_dhcp4_outgoing_append_option(outgoing, option, data, n_data);
                        return 0;
                }

                if (overload & N_DHCP4_OVERLOAD_SNAME)
                        outgoing->i_message = offsetof(NDhcp4Message, sname);
                else
                        return N_DHCP4_E_NO_SPACE;
        }

        /*
         * OPTIONs and FILE are full, try putting data into the SNAME section
         * as a last resort.
         */
        if (outgoing->i_message >= offsetof(NDhcp4Message, sname)) {
                rem = sizeof(outgoing->message->sname);
                rem -= outgoing->i_message - offsetof(NDhcp4Message, sname);

                if (rem >= n_data + 2U + 1U) {
                        n_dhcp4_outgoing_append_option(outgoing, option, data, n_data);
                        return 0;
                }
        }

        return N_DHCP4_E_NO_SPACE;
}

static int n_dhcp4_outgoing_append_u32(NDhcp4Outgoing *message, uint8_t option, uint32_t u32) {
        uint32_t be32 = htonl(u32);
        int r;

        r = n_dhcp4_outgoing_append(message, option, &be32, sizeof(be32));
        if (r)
                return r;

        return 0;
}

static int n_dhcp4_outgoing_append_in_addr(NDhcp4Outgoing *message, uint8_t option, struct in_addr addr) {
        int r;

        r = n_dhcp4_outgoing_append(message, option, &addr.s_addr, sizeof(addr.s_addr));
        if (r)
                return r;

        return 0;
}

int n_dhcp4_outgoing_append_t1(NDhcp4Outgoing *message, uint32_t t1) {
        return n_dhcp4_outgoing_append_u32(message, N_DHCP4_OPTION_RENEWAL_T1_TIME, t1);
}

int n_dhcp4_outgoing_append_t2(NDhcp4Outgoing *message, uint32_t t2) {
        return n_dhcp4_outgoing_append_u32(message, N_DHCP4_OPTION_REBINDING_T2_TIME, t2);
}

int n_dhcp4_outgoing_append_lifetime(NDhcp4Outgoing *message, uint32_t lifetime) {
        return n_dhcp4_outgoing_append_u32(message, N_DHCP4_OPTION_IP_ADDRESS_LEASE_TIME, lifetime);
}

int n_dhcp4_outgoing_append_server_identifier(NDhcp4Outgoing *message, struct in_addr addr) {
        return n_dhcp4_outgoing_append_in_addr(message, N_DHCP4_OPTION_SERVER_IDENTIFIER, addr);
}

int n_dhcp4_outgoing_append_requested_ip(NDhcp4Outgoing *message, struct in_addr addr) {
        return n_dhcp4_outgoing_append_in_addr(message, N_DHCP4_OPTION_REQUESTED_IP_ADDRESS, addr);
}

void n_dhcp4_outgoing_set_secs(NDhcp4Outgoing *message, uint32_t secs) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(message);

        /*
         * Some DHCP servers will reject DISCOVER or REQUEST messages if 'secs'
         * is not set (i.e., set to 0), even though the spec allows it.
         */
        c_assert(secs);

        header->secs = htonl(secs);
}

void n_dhcp4_outgoing_set_xid(NDhcp4Outgoing *message, uint32_t xid) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(message);

        header->xid = xid;
}

void n_dhcp4_outgoing_get_xid(NDhcp4Outgoing *message, uint32_t *xidp) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(message);

        *xidp = header->xid;
}

void n_dhcp4_outgoing_set_yiaddr(NDhcp4Outgoing *message, struct in_addr yiaddr) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(message);

        header->yiaddr = yiaddr.s_addr;
}
