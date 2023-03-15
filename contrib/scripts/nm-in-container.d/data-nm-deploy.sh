#!/bin/bash

set -ex

cd /NetworkManager

if [ -f ./config.log ] ; then
    make -j 5 install
else
    meson install -C build
fi

systemctl daemon-reload
systemctl restart NetworkManager.service
