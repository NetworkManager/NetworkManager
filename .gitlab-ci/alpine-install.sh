#!/bin/sh

set -ex

./contrib/alpine/REQUIRED_PACKAGES

ln -snf elogind/systemd /usr/include/systemd
