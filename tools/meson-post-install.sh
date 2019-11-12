#!/bin/sh

nm_datadir="$1"
nm_bindir="$2"
nm_pkgconfdir="$3"
nm_pkglibdir="$4"
nm_pkgstatedir="$5"
nm_mandir="$6"
nm_sysconfdir="$7"
enable_docs="$8"
enable_ifcfg_rh="$9"
enable_nm_cloud_setup="${10}"
install_systemdunitdir="${11}"

[ -n "$DESTDIR" ] && DESTDIR="${DESTDIR%%/}/"

if [ -f "${DESTDIR}${nm_datadir}/bash-completion/completions/nmcli-completion" ]; then
    mv "${DESTDIR}${nm_datadir}/bash-completion/completions/nmcli-completion" \
       "${DESTDIR}${nm_datadir}/bash-completion/completions/nmcli"
fi

if [ -x "${DESTDIR}${nm_bindir}/nmtui" ]; then
    for alias in nmtui-connect nmtui-edit nmtui-hostname; do
        ln -sf nmtui "${DESTDIR}${nm_bindir}/$alias"
    done
fi

for dir in "${nm_pkgconfdir}/conf.d" \
           "${nm_pkgconfdir}/system-connections" \
           "${nm_pkgconfdir}/dispatcher.d/no-wait.d" \
           "${nm_pkgconfdir}/dispatcher.d/pre-down.d" \
           "${nm_pkgconfdir}/dispatcher.d/pre-up.d" \
           "${nm_pkgconfdir}/dnsmasq.d" \
           "${nm_pkgconfdir}/dnsmasq-shared.d" \
           "${nm_pkglibdir}/conf.d" \
           "${nm_pkglibdir}/dispatcher.d/no-wait.d" \
           "${nm_pkglibdir}/dispatcher.d/pre-down.d" \
           "${nm_pkglibdir}/dispatcher.d/pre-up.d" \
           "${nm_pkglibdir}/system-connections" \
           "${nm_pkglibdir}/VPN"; do
    mkdir -p "${DESTDIR}${dir}"
    chmod 0755 "${DESTDIR}${dir}"
done

mkdir -p "${DESTDIR}${nm_pkgstatedir}"
chmod 0700 "${DESTDIR}${nm_pkgstatedir}"

if [ "$enable_docs" = 1 ]; then

    for alias in nmtui-connect nmtui-edit nmtui-hostname; do
        ln -f "${DESTDIR}${nm_mandir}/man1/nmtui.1" "${DESTDIR}${nm_mandir}/man1/${alias}.1"
    done

    ln -f "${DESTDIR}${nm_mandir}/man5/NetworkManager.conf.5" "${DESTDIR}${nm_mandir}/man5/nm-system-settings.conf.5"
fi

if [ "$enable_ifcfg_rh" = 1 ]; then
    mkdir -p "${DESTDIR}${nm_sysconfdir}/sysconfig/network-scripts"
fi

if [ "$enable_nm_cloud_setup" = 1 -a "$install_systemdunitdir" = 1 ]; then
    ln -s 'no-wait.d/90-nm-cloud-setup.sh' "${DESTDIR}${nm_pkglibdir}/dispatcher.d/90-nm-cloud-setup.sh"
fi

