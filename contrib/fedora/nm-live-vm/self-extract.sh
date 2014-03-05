#!/bin/sh

NAME=__NAME_PLACEHOLDER__
BUNDLE=`readlink -f "$0"` || exit 1
TEMP=`mktemp -d "$PWD/$NAME.XXXXXXXXXX"` || exit 1

echo "Extracting to: $TEMP"
cd "$TEMP" || exit 1
sed '1,/^__MARK__$/d' "$BUNDLE" > $NAME.tar.gz || exit 1
tar -xvf $NAME.tar.gz || exit 1
cd $NAME || exit 1

./run.sh || exit 1

#rm -rf "$TEMP"
exit 0
__MARK__
