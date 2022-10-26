#!/bin/sh

set -e

f_commited="$1"
f_generated="$2"

[ -n "$NMTST_NO_CHECK_SETTINGS_DOCS" ] && exit 0

cmp -s "$f_commited" "$f_generated" && exit 0

if [ "$NM_TEST_REGENERATE" = 1 ] ; then
   cp -f "$f_generated" "$f_commited"
else
   echo "*** Error: the generated file '$f_generated' differs from the source file '$f_commited'. You probably should copy the generated file over to the source file. You can skip this test by setting NMTST_NO_CHECK_SETTINGS_DOCS=yes. You can also automatically copy the file by rerunning the test with NM_TEST_REGENERATE=1"
   exit 1
fi
