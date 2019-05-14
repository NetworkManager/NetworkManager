/*
 * Tests for DHCP4 Message Handling
 */

#undef NDEBUG
#include <assert.h>
#include <c-stdaux.h>
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4-private.h"

static void test_outgoing(void) {
        NDhcp4Outgoing *outgoing;
        int r;

        /* verify basic NEW/FREE */

        outgoing = NULL;
        r = n_dhcp4_outgoing_new(&outgoing, 0, 0);
        c_assert(!r);
        c_assert(outgoing);

        outgoing = n_dhcp4_outgoing_free(outgoing);
        c_assert(!outgoing);
}

static void test_incoming(void) {
        NDhcp4Incoming *incoming;
        struct {
                NDhcp4Header header;
                uint8_t sname[64];
                uint8_t file[128];
                uint32_t magic;
                uint8_t options[1024];
        } m;
        uint8_t *v;
        size_t l;
        int r;

        /* verify that messages must be at least the size of the header */

        r = n_dhcp4_incoming_new(&incoming, NULL, 0);
        c_assert(r == N_DHCP4_E_MALFORMED);

        r = n_dhcp4_incoming_new(&incoming, NULL, sizeof(m.header) + 64 + 128 + 3);
        c_assert(r == N_DHCP4_E_MALFORMED);

        /* verify that magic must be set */

        memset(&m, 0, sizeof(m));
        r = n_dhcp4_incoming_new(&incoming, &m, sizeof(m));
        c_assert(r == N_DHCP4_E_MALFORMED);

        /* verify basic NEW/FREE */

        memset(&m, 0, sizeof(m));
        m.magic = htobe32(N_DHCP4_MESSAGE_MAGIC);
        incoming = NULL;
        r = n_dhcp4_incoming_new(&incoming, &m, sizeof(m.header) + 64 + 128 + 4);
        c_assert(!r);
        c_assert(incoming);

        incoming = n_dhcp4_incoming_free(incoming);
        c_assert(!incoming);

        /* verify that PAD is properly handled */

        r = n_dhcp4_incoming_new(&incoming, &m, sizeof(m));
        c_assert(!r);
        incoming = n_dhcp4_incoming_free(incoming);

        /* verify that SNAME/FILE are only looked at if OVERLOAD is set */

        m.sname[0] = 1;
        m.sname[1] = 0;
        m.file[0] = 2;
        m.file[1] = 0;

        r = n_dhcp4_incoming_new(&incoming, &m, sizeof(m));
        c_assert(!r);
        r = n_dhcp4_incoming_query(incoming, 1, NULL, NULL);
        c_assert(r == N_DHCP4_E_UNSET);
        r = n_dhcp4_incoming_query(incoming, 2, NULL, NULL);
        c_assert(r == N_DHCP4_E_UNSET);
        incoming = n_dhcp4_incoming_free(incoming);

        m.options[0] = N_DHCP4_OPTION_OVERLOAD;
        m.options[1] = 1;
        m.options[2] = 0;

        r = n_dhcp4_incoming_new(&incoming, &m, sizeof(m));
        c_assert(!r);
        r = n_dhcp4_incoming_query(incoming, 1, NULL, NULL);
        c_assert(r == N_DHCP4_E_UNSET);
        r = n_dhcp4_incoming_query(incoming, 2, NULL, NULL);
        c_assert(r == N_DHCP4_E_UNSET);
        incoming = n_dhcp4_incoming_free(incoming);

        m.options[0] = N_DHCP4_OPTION_OVERLOAD;
        m.options[1] = 1;
        m.options[2] = N_DHCP4_OVERLOAD_SNAME;

        r = n_dhcp4_incoming_new(&incoming, &m, sizeof(m));
        c_assert(!r);
        r = n_dhcp4_incoming_query(incoming, 1, NULL, NULL);
        c_assert(r == 0);
        r = n_dhcp4_incoming_query(incoming, 2, NULL, NULL);
        c_assert(r == N_DHCP4_E_UNSET);
        incoming = n_dhcp4_incoming_free(incoming);

        m.options[0] = N_DHCP4_OPTION_OVERLOAD;
        m.options[1] = 1;
        m.options[2] = N_DHCP4_OVERLOAD_FILE;

        r = n_dhcp4_incoming_new(&incoming, &m, sizeof(m));
        c_assert(!r);
        r = n_dhcp4_incoming_query(incoming, 1, NULL, NULL);
        c_assert(r == N_DHCP4_E_UNSET);
        r = n_dhcp4_incoming_query(incoming, 2, NULL, NULL);
        c_assert(r == 0);
        incoming = n_dhcp4_incoming_free(incoming);

        m.options[0] = N_DHCP4_OPTION_OVERLOAD;
        m.options[1] = 1;
        m.options[2] = N_DHCP4_OVERLOAD_FILE | N_DHCP4_OVERLOAD_SNAME;

        r = n_dhcp4_incoming_new(&incoming, &m, sizeof(m));
        c_assert(!r);
        r = n_dhcp4_incoming_query(incoming, 1, NULL, NULL);
        c_assert(r == 0);
        r = n_dhcp4_incoming_query(incoming, 2, NULL, NULL);
        c_assert(r == 0);
        incoming = n_dhcp4_incoming_free(incoming);

        /* verify basic concatenation */

        m.options[3] = 1;
        m.options[4] = 1;
        m.options[5] = 0xef;
        m.sname[1] = 1;
        m.sname[2] = 0xcf;

        r = n_dhcp4_incoming_new(&incoming, &m, sizeof(m));
        c_assert(!r);
        r = n_dhcp4_incoming_query(incoming, 1, &v, &l);
        c_assert(r == 0);
        c_assert(l == 2);
        c_assert(v[0] == 0xef && v[1] == 0xcf);
        incoming = n_dhcp4_incoming_free(incoming);
}

int main(int argc, char **argv) {
        test_outgoing();
        test_incoming();
        return 0;
}
