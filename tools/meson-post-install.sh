#!/bin/sh

datadir=$1
bindir=$2
pkgconfdir=$3
pkglibdir=$4
pkgstatedir=$5

[ -n "$DESTDIR" ] && DESTDIR=${DESTDIR%%/}/

if [ -f "${DESTDIR}${datadir}/bash-completion/completions/nmcli-completion" ]; then
    mv "${DESTDIR}${datadir}/bash-completion/completions/nmcli-completion" \
       "${DESTDIR}${datadir}/bash-completion/completions/nmcli"
fi

if [ -x "${DESTDIR}${bindir}/nmtui" ]; then
    for alias in nmtui-connect nmtui-edit nmtui-hostname; do
        ln -sf nmtui "${DESTDIR}${bindir}/$alias"
    done
fi

for dir in "${pkgconfdir}/conf.d" \
           "${pkgconfdir}/system-connections" \
           "${pkgconfdir}/dispatcher.d/no-wait.d" \
           "${pkgconfdir}/dispatcher.d/pre-down.d" \
           "${pkgconfdir}/dispatcher.d/pre-up.d" \
           "${pkgconfdir}/dnsmasq.d" \
           "${pkgconfdir}/dnsmasq-shared.d" \
           "${pkglibdir}/conf.d" \
           "${pkglibdir}/dispatcher.d/no-wait.d" \
           "${pkglibdir}/dispatcher.d/pre-down.d" \
           "${pkglibdir}/dispatcher.d/pre-up.d" \
           "${pkglibdir}/system-connections" \
           "${pkglibdir}/VPN"; do
    mkdir -p "${DESTDIR}${dir}"
    chmod 0755 "${DESTDIR}${dir}"
done

mkdir -p "${DESTDIR}${pkgstatedir}"
chmod 0700 "${DESTDIR}${pkgstatedir}"

if [ "$6" = install_docs ]; then
    mandir=$7

    for alias in nmtui-connect nmtui-edit nmtui-hostname; do
        ln -f "${DESTDIR}${mandir}/man1/nmtui.1" "${DESTDIR}${mandir}/man1/${alias}.1"
    done

    ln -f "${DESTDIR}${mandir}/man5/NetworkManager.conf.5" "${DESTDIR}${mandir}/man5/nm-system-settings.conf.5"
fi

