#!/bin/bash

# patch gtk-doc for https://gitlab.gnome.org/GNOME/gtk-doc/merge_requests/2

cd /

patch -f -p 1 --fuzz 0 --reject-file=- <<EOF
diff --git a/usr/share/gtk-doc/python/gtkdoc/scan.py b/usr/share/gtk-doc/python/gtkdoc/scan.py
index f1f167235ab2e4c62676fbcfb87ebbe55c95b944..b59dd17abfa5f42b7bb06d239f9c78e5efffbf5d 100644
--- a/usr/share/gtk-doc/python/gtkdoc/scan.py
+++ b/usr/share/gtk-doc/python/gtkdoc/scan.py
@@ -427,20 +427,26 @@ def ScanHeader(input_file, section_list, decl_list, get_types, options):
             elif m9:
                 # We've found a 'typedef struct _<name> <name>;'
                 # This could be an opaque data structure, so we output an
                 # empty declaration. If the structure is actually found that
                 # will override this.
                 structsym = m9.group(1).upper()
                 logging.info('%s typedef: "%s"', structsym, m9.group(2))
                 forward_decls[m9.group(2)] = '<%s>\n<NAME>%s</NAME>\n%s</%s>\n' % (
                     structsym, m9.group(2), deprecated, structsym)
 
+                bm = re.search(r'^(\S+)(Class|Iface|Interface)\b', m9.group(2))
+                if bm:
+                    objectname = bm.group(1)
+                    logging.info('Found object: "%s"', objectname)
+                    title = '<TITLE>%s</TITLE>' % objectname
+
             elif re.search(r'^\s*(?:struct|union)\s+_(\w+)\s*;', line):
                 # Skip private structs/unions.
                 logging.info('private struct/union')
 
             elif m10:
                 # Do a similar thing for normal structs as for typedefs above.
                 # But we output the declaration as well in this case, so we
                 # can differentiate it from a typedef.
                 structsym = m10.group(1).upper()
                 logging.info('%s:%s', structsym, m10.group(2))
EOF

