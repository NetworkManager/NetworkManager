#!/bin/sh

set -e

srcdir="$1"
builddir="$2"
doc_h="$3"

[ -n "$NMTST_NO_CHECK_SETTINGS_DOCS" ] && exit 0

cmp -s "${srcdir}/${doc_h}.in" "${builddir}/${doc_h}" && exit 0

if [ "$NM_TEST_REGENERATE" = 1 ] ; then
   cp -f "${builddir}/${doc_h}" "${srcdir}/${doc_h}.in"
else
   echo "*** Error: the generated file '${builddir}/${doc_h}' differs from the source file '${srcdir}/${doc_h}.in'. You probably should copy the generated file over to the source file. You can skip this test by setting NMTST_NO_CHECK_SETTINGS_DOCS=yes. You can also automatically copy the file by rerunning the test with NM_TEST_REGENERATE=1"
   exit 1
fi
