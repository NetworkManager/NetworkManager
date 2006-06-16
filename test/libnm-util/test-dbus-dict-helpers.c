/* NetworkManager -- Forget about your network
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2006 Red Hat, Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dbus/dbus.h>

#include "test-common.h"
#include "dbus-dict-helpers.h"

static char *progname = NULL;


struct DictEntries
{
	const char * key_string;  const char *        val_string;  dbus_bool_t string_found;
	const char * key_byte;    const char          val_byte;    dbus_bool_t byte_found;
	const char * key_bool;    const dbus_bool_t   val_bool;    dbus_bool_t bool_found;
	const char * key_int16;   const dbus_int16_t  val_int16;   dbus_bool_t int16_found;
	const char * key_uint16;  const dbus_uint16_t val_uint16;  dbus_bool_t uint16_found;
	const char * key_int32;   const dbus_int32_t  val_int32;   dbus_bool_t int32_found;
	const char * key_uint32;  const dbus_uint32_t val_uint32;  dbus_bool_t uint32_found;
	const char * key_int64;   const dbus_int64_t  val_int64;   dbus_bool_t int64_found;
	const char * key_uint64;  const dbus_uint64_t val_uint64;  dbus_bool_t uint64_found;
	const char * key_double;  const double        val_double;  dbus_bool_t double_found;
	const char * key_op;      const char *        val_op;      dbus_bool_t op_found;
};

#define TEST_KEY_STRING "String"
#define TEST_KEY_BYTE   "Byte"
#define TEST_KEY_BOOL   "Bool"
#define TEST_KEY_INT16  "Int16"
#define TEST_KEY_UINT16 "UInt16"
#define TEST_KEY_INT32  "Int32"
#define TEST_KEY_UINT32 "UInt32"
#define TEST_KEY_INT64  "Int64"
#define TEST_KEY_UINT64 "UInt64"
#define TEST_KEY_DOUBLE "Double"
#define TEST_KEY_OP     "ObjectPath"

struct DictEntries entries = {
	TEST_KEY_STRING,  "foobar22",       FALSE,
	TEST_KEY_BYTE,    0x78,             FALSE,
	TEST_KEY_BOOL,    TRUE,             FALSE,
	TEST_KEY_INT16,   -28567,           FALSE,
	TEST_KEY_UINT16,  12345,            FALSE,
	TEST_KEY_INT32,   -5987654,         FALSE,
	TEST_KEY_UINT32,  45678912,         FALSE,
	TEST_KEY_INT64,   -12491340761ll,   FALSE,
	TEST_KEY_UINT64,  8899223582883ll,  FALSE,
	TEST_KEY_DOUBLE,  54.3355632f,      FALSE,
	TEST_KEY_OP,      "/com/it/foobar", FALSE
};


static void
test_write_dict (DBusMessage *message)
{
	TestResult result = TEST_FAIL;
	DBusMessageIter iter, iter_dict;
	char * err_string = "failure";

	fprintf (stdout, "\n\n---- START: WRITE DICT ---------------------------------------------\n");

	dbus_message_iter_init_append (message, &iter);
	if (!nmu_dbus_dict_open_write (&iter, &iter_dict)) {
		err_string = "failed on open_write";
		goto done;
	}
	if (!nmu_dbus_dict_append_string (&iter_dict, entries.key_string, entries.val_string)) {
		err_string = "failed to append string entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_byte (&iter_dict, entries.key_byte, entries.val_byte)) {
		err_string = "failed to append byte entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_bool (&iter_dict, entries.key_bool, entries.val_bool)) {
		err_string = "failed to append boolean entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_int16 (&iter_dict, entries.key_int16, entries.val_int16)) {
		err_string = "failed to append int16 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_uint16 (&iter_dict, entries.key_uint16, entries.val_uint16)) {
		err_string = "failed to append uint16 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_int32 (&iter_dict, entries.key_int32, entries.val_int32)) {
		err_string = "failed to append int32 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_uint32 (&iter_dict, entries.key_uint32, entries.val_uint32)) {
		err_string = "failed to append uint32 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_int64 (&iter_dict, entries.key_int64, entries.val_int64)) {
		err_string = "failed to append int64 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_uint64 (&iter_dict, entries.key_uint64, entries.val_uint64)) {
		err_string = "failed to append uint64 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_double (&iter_dict, entries.key_double, entries.val_double)) {
		err_string = "failed to append double entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_object_path (&iter_dict, entries.key_op, entries.val_op)) {
		err_string = "failed to append object path entry";
		goto done;
	}
	if (!nmu_dbus_dict_close_write (&iter, &iter_dict)) {
		err_string = "failed to close dictionary";
		goto done;
	}

	result = TEST_SUCCEED;
	err_string = "success";

done:
	test_result (progname, "Dict Write", result, err_string);
}

#define TEST_CASE(test_key, found_var, comparison) \
		if (!strcmp (entry.key, test_key)) { \
			fprintf (stderr, "Testing type " test_key ".\n"); \
			if (!(comparison)) { \
				err_string = "Test item " test_key " was unexpected value."; \
				goto done; \
			} \
			found_var = TRUE; \
			goto next; \
		}

static void
test_read_dict (DBusMessage *message)
{
	TestResult result = TEST_FAIL;
	NMUDictEntry	entry = { .type = DBUS_TYPE_STRING };
	DBusMessageIter	iter, iter_dict;
	char * err_string = "failure";

	dbus_message_iter_init (message, &iter);

	if (!nmu_dbus_dict_open_read (&iter, &iter_dict)) {
		err_string = "failure on open_read";
		goto done;
	}

	while (nmu_dbus_dict_has_dict_entry (&iter_dict))
	{
		if (!nmu_dbus_dict_get_entry (&iter_dict, &entry)) {
			err_string = "failure reading dict entry";
			goto done;
		}

		TEST_CASE (TEST_KEY_STRING, entries.string_found, !strcmp (entry.str_value, entries.val_string))
		TEST_CASE (TEST_KEY_BYTE, entries.byte_found, entry.byte_value == entries.val_byte)
		TEST_CASE (TEST_KEY_BOOL, entries.bool_found, entry.bool_value == entries.val_bool)
		TEST_CASE (TEST_KEY_INT16, entries.int16_found, entry.int16_value == entries.val_int16)
		TEST_CASE (TEST_KEY_UINT16, entries.uint16_found, entry.uint16_value == entries.val_uint16)
		TEST_CASE (TEST_KEY_INT32, entries.int32_found, entry.int32_value == entries.val_int32)
		TEST_CASE (TEST_KEY_UINT32, entries.uint32_found, entry.uint32_value == entries.val_uint32)
		TEST_CASE (TEST_KEY_INT64, entries.int64_found, entry.int64_value == entries.val_int64)
		TEST_CASE (TEST_KEY_UINT64, entries.uint64_found, entry.uint64_value == entries.val_uint64)
		TEST_CASE (TEST_KEY_DOUBLE, entries.double_found, !memcmp (&entry.double_value, &entries.val_double, sizeof (double)))
		TEST_CASE (TEST_KEY_OP, entries.op_found, !strcmp (entry.str_value, entries.val_op))

		err_string = "Unknown dict entry encountered.";
		goto done;

	next:
		continue;
	}

	if (!entries.string_found || !entries.byte_found || !entries.bool_found || !entries.int16_found
		|| !entries.uint16_found || !entries.int32_found || !entries.uint32_found
		|| !entries.int64_found || !entries.uint64_found || !entries.double_found
		|| !entries.op_found) {
		err_string = "A required entry was not found in the dict.";
		goto done;
	}

	result = TEST_SUCCEED;
	err_string = "";

done:
	test_result (progname, "Dict Read", result, err_string);
}


int main (int argc, char **argv)
{
	DBusMessage * message;
	progname = argv[0];

	message = dbus_message_new_method_call ("com.it", "/com/it",
			"com.it", "someMethod");
	test_write_dict (message);
	test_read_dict (message);

	fprintf (stderr, "\n\n------ DONE\n");

	return 0;
}
