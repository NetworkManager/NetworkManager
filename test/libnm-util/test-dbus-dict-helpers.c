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


#define DECLARE_ENTRY(name, val_type) \
struct name { \
	const char *key; \
	val_type val; \
	dbus_bool_t found; \
	int type; \
};

DECLARE_ENTRY(StringEntry, const char *)
DECLARE_ENTRY(ByteEntry, const char)
DECLARE_ENTRY(BoolEntry, dbus_bool_t)
DECLARE_ENTRY(Int16Entry, dbus_int16_t)
DECLARE_ENTRY(UInt16Entry, dbus_uint16_t)
DECLARE_ENTRY(Int32Entry, dbus_int32_t)
DECLARE_ENTRY(UInt32Entry, dbus_uint32_t)
DECLARE_ENTRY(Int64Entry, dbus_int64_t)
DECLARE_ENTRY(UInt64Entry, dbus_uint64_t)
DECLARE_ENTRY(DoubleEntry, double)
DECLARE_ENTRY(OPEntry, const char *)
DECLARE_ENTRY(ByteArrayEntry, const char *)
DECLARE_ENTRY(StringArrayEntry, char **)

struct DictEntries {
	struct StringEntry string;
	struct ByteEntry byte;
	struct BoolEntry bool;
	struct Int16Entry int16;
	struct UInt16Entry uint16;
	struct Int32Entry int32;
	struct UInt32Entry uint32;
	struct Int64Entry int64;
	struct UInt64Entry uint64;
	struct DoubleEntry dbl;
	struct OPEntry op;
	struct ByteArrayEntry bytearr;
	struct ByteArrayEntry zlbytearr;
	struct StringArrayEntry strarr;
	struct StringArrayEntry zlstrarr;
};

#define TEST_KEY_STRING      "String"
#define TEST_KEY_BYTE        "Byte"
#define TEST_KEY_BOOL        "Bool"
#define TEST_KEY_INT16       "Int16"
#define TEST_KEY_UINT16      "UInt16"
#define TEST_KEY_INT32       "Int32"
#define TEST_KEY_UINT32      "UInt32"
#define TEST_KEY_INT64       "Int64"
#define TEST_KEY_UINT64      "UInt64"
#define TEST_KEY_DOUBLE      "Double"
#define TEST_KEY_OP          "ObjectPath"
#define TEST_KEY_BYTEARR     "ByteArray"
#define TEST_KEY_ZLBYTEARR   "ZLByteArray"
#define STRARR_LEN	2
#define TEST_KEY_STRINGARR   "StringArray"
#define TEST_KEY_ZLSTRINGARR "ZLStringArray"

struct DictEntries entries = {
	{ TEST_KEY_STRING,   "foobar22",       FALSE, DBUS_TYPE_STRING },
	{ TEST_KEY_BYTE,     0x78,             FALSE, DBUS_TYPE_BYTE },
	{ TEST_KEY_BOOL,     TRUE,             FALSE, DBUS_TYPE_BOOLEAN },
	{ TEST_KEY_INT16,    -28567,           FALSE, DBUS_TYPE_INT16 },
	{ TEST_KEY_UINT16,   12345,            FALSE, DBUS_TYPE_UINT16 },
	{ TEST_KEY_INT32,    -5987654,         FALSE, DBUS_TYPE_INT32 },
	{ TEST_KEY_UINT32,   45678912,         FALSE, DBUS_TYPE_UINT32 },
	{ TEST_KEY_INT64,    -12491340761ll,   FALSE, DBUS_TYPE_INT64 },
	{ TEST_KEY_UINT64,   8899223582883ll,  FALSE, DBUS_TYPE_UINT64 },
	{ TEST_KEY_DOUBLE,   54.3355632f,      FALSE, DBUS_TYPE_DOUBLE },
	{ TEST_KEY_OP,       "/com/it/foobar", FALSE, DBUS_TYPE_OBJECT_PATH },
	{ TEST_KEY_BYTEARR,  "qazwsxedcrfvtgb",FALSE, DBUS_TYPE_BYTE },
	{ TEST_KEY_ZLBYTEARR,NULL,             FALSE, DBUS_TYPE_BYTE },
	{ TEST_KEY_STRINGARR,NULL,             FALSE, DBUS_TYPE_STRING },
	{ TEST_KEY_ZLSTRINGARR,NULL,           FALSE, DBUS_TYPE_STRING }
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
	if (!nmu_dbus_dict_append_string (&iter_dict, entries.string.key, entries.string.val)) {
		err_string = "failed to append string entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_byte (&iter_dict, entries.byte.key, entries.byte.val)) {
		err_string = "failed to append byte entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_bool (&iter_dict, entries.bool.key, entries.bool.val)) {
		err_string = "failed to append boolean entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_int16 (&iter_dict, entries.int16.key, entries.int16.val)) {
		err_string = "failed to append int16 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_uint16 (&iter_dict, entries.uint16.key, entries.uint16.val)) {
		err_string = "failed to append uint16 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_int32 (&iter_dict, entries.int32.key, entries.int32.val)) {
		err_string = "failed to append int32 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_uint32 (&iter_dict, entries.uint32.key, entries.uint32.val)) {
		err_string = "failed to append uint32 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_int64 (&iter_dict, entries.int64.key, entries.int64.val)) {
		err_string = "failed to append int64 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_uint64 (&iter_dict, entries.uint64.key, entries.uint64.val)) {
		err_string = "failed to append uint64 entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_double (&iter_dict, entries.dbl.key, entries.dbl.val)) {
		err_string = "failed to append double entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_object_path (&iter_dict, entries.op.key, entries.op.val)) {
		err_string = "failed to append object path entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_byte_array (&iter_dict, entries.bytearr.key, entries.bytearr.val,
			strlen (entries.bytearr.val))) {
		err_string = "failed to append byte array entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_byte_array (&iter_dict, entries.zlbytearr.key, entries.zlbytearr.val, 0)) {
		err_string = "failed to append zero-length byte array entry";
		goto done;
	}
	entries.strarr.val = malloc (sizeof (char *) * STRARR_LEN);
	entries.strarr.val[0] = "foo";
	entries.strarr.val[1] = "bar";
	if (!nmu_dbus_dict_append_string_array (&iter_dict, entries.strarr.key,
			(const char **)entries.strarr.val, STRARR_LEN)) {
		err_string = "failed to append string array entry";
		goto done;
	}
	if (!nmu_dbus_dict_append_string_array (&iter_dict, entries.zlstrarr.key,
			(const char **)entries.zlstrarr.val, 0)) {
		err_string = "failed to append zero-length string array entry";
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

#define TEST_CASE(key_string, test_entry, comparison) \
		if (!strcmp (entry.key, test_entry.key)) { \
			fprintf (stderr, "Testing type " key_string ".\n"); \
			if (entry.type != test_entry.type) { \
				err_string = "Test item " key_string " was an unexpected type."; \
				goto done; \
			} \
			if (!(comparison)) { \
				err_string = "Test item " key_string " was unexpected value."; \
				goto done; \
			} \
			test_entry.found = TRUE; \
			goto next; \
		}

#define TEST_CASE_ARRAY(key_string, test_entry, exp_len, comparison) \
		if (!strcmp (entry.key, test_entry.key)) { \
			fprintf (stderr, "Testing type " key_string ".\n"); \
			if (entry.type != DBUS_TYPE_ARRAY) { \
				err_string = "Test item " key_string " was an unexpected type."; \
				goto done; \
			} \
			if (entry.array_type != test_entry.type) { \
				err_string = "Test item " key_string " was an unexpected element type."; \
				goto done; \
			} \
			if (exp_len != entry.array_len) { \
				err_string = "Test item " key_string " had unexpected length!"; \
				goto done; \
			} \
			if (!(comparison)) { \
				err_string = "Test item " key_string " was unexpected value."; \
				goto done; \
			} \
			test_entry.found = TRUE; \
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
		dbus_uint32_t bytearr_len = strlen (entries.bytearr.val);

		if (!nmu_dbus_dict_get_entry (&iter_dict, &entry)) {
			err_string = "failure reading dict entry";
			goto done;
		}

		TEST_CASE (TEST_KEY_STRING, entries.string, !strcmp (entry.str_value, entries.string.val))
		TEST_CASE (TEST_KEY_BYTE, entries.byte, entry.byte_value == entries.byte.val)
		TEST_CASE (TEST_KEY_BOOL, entries.bool, entry.bool_value == entries.bool.val)
		TEST_CASE (TEST_KEY_INT16, entries.int16, entry.int16_value == entries.int16.val)
		TEST_CASE (TEST_KEY_UINT16, entries.uint16, entry.uint16_value == entries.uint16.val)
		TEST_CASE (TEST_KEY_INT32, entries.int32, entry.int32_value == entries.int32.val)
		TEST_CASE (TEST_KEY_UINT32, entries.uint32, entry.uint32_value == entries.uint32.val)
		TEST_CASE (TEST_KEY_INT64, entries.int64, entry.int64_value == entries.int64.val)
		TEST_CASE (TEST_KEY_UINT64, entries.uint64, entry.uint64_value == entries.uint64.val)
		TEST_CASE (TEST_KEY_DOUBLE, entries.dbl, !memcmp (&entry.double_value, &entries.dbl.val, sizeof (double)))
		TEST_CASE (TEST_KEY_OP, entries.op, !strcmp (entry.str_value, entries.op.val))
		TEST_CASE_ARRAY (TEST_KEY_BYTEARR, entries.bytearr, bytearr_len,
				!memcmp (entry.bytearray_value, entries.bytearr.val, bytearr_len))
		TEST_CASE_ARRAY (TEST_KEY_ZLBYTEARR, entries.zlbytearr, 0,
				entry.bytearray_value == entries.zlbytearr.val)
		TEST_CASE_ARRAY (TEST_KEY_STRINGARR, entries.strarr, STRARR_LEN,
				(!strcmp (entry.strarray_value[0], "foo") && !strcmp (entry.strarray_value[1], "bar")))
		TEST_CASE_ARRAY (TEST_KEY_ZLSTRINGARR, entries.zlstrarr, 0,
				entry.strarray_value == entries.zlstrarr.val)

		err_string = "Unknown dict entry encountered.";
		goto done;

	next:
		nmu_dbus_dict_entry_clear (&entry);
	}

	if (!entries.string.found || !entries.byte.found || !entries.bool.found || !entries.int16.found
		|| !entries.uint16.found || !entries.int32.found || !entries.uint32.found
		|| !entries.int64.found || !entries.uint64.found || !entries.dbl.found
		|| !entries.op.found || !entries.bytearr.found || !entries.zlbytearr.found
		|| !entries.strarr.found || !entries.zlstrarr.found) {
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
