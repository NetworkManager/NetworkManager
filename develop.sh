#!/bin/sh

exec ./autogen.sh \
    --enable-develop \
    --disable-doc --disable-gtk-doc \
    --disable-polkit \
    --prefix=/usr \
    --sysconfdir=/etc \
    --localstatedir=/var \
    "$@"
