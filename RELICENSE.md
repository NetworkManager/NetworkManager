Relicensing NetworkManager GPL Code as LGPL-2.1+
================================================

This NetworkManager project consists of the daemon, client tools, and libnm.
libnm is licensed LGPL-2.1+, while the rest is licensed under GPL-2.0+.


Why Relicensing?
================

Mixing two licenses in the same source tree is cumbersome:

1) We want to share code internally and reuse it. In particular under "shared/" directory
there are internal static libraries that get linked both into LGPL and GPL code.
That implies that this shared code itself must be LGPL licensed. Being unable to
move code around within our source tree is a painful restriction. Possibly we get
that wrong sometimes, wrongly moving GPL code as LGPL (either directly or by rewriting
it based on GPL code).

2) For example keyfile and ifcfg-rh implementations are GPL licensed as they
are historically part of core. It would be useful to add this functionality
to libnm, so that libnm users can handle the file formats directly. That is
not possible without relicensing.

3) Maybe one day we would relicense the entire source tree as LGPL-2.1+ to avoid
this issue. This would require agreement from all copyright holders.


Full relicensing (point 3) is a large effort, or maybe even impossible. However sometimes
we may need to evaluate whether small parts can be relicensed (points 2 and 1). This
file keeps track of copyright holders that agree or disapprove to such a license change.


Which Code?
===========

This applies to all GPL-2.0+ code in commit a3e75f329446a93a61ca4c458a7657bd919f4fe6 ([1]) and
all its parent commits.

Since commit a3e75f329446a93a61ca4c458a7657bd919f4fe6 ([1]), the CONTRIBUTING file ([2]) makes
it clear that all new contributions must to be provided under terms of LGPL-2.1+. So this
approval process is only relevant for GPL-2.0+ code from before that. This was also announced on
the mailing list on June 12 2019 ([3]). Note that the announcement was still talking about LGPL-2.0+
but in the meantime we only request LGPL-2.1+ ([4]).

- [1] https://gitlab.freedesktop.org/NetworkManager/NetworkManager/commit/a3e75f329446a93a61ca4c458a7657bd919f4fe6
- [2] https://gitlab.freedesktop.org/NetworkManager/NetworkManager/blob/a3e75f329446a93a61ca4c458a7657bd919f4fe6/CONTRIBUTING#L37
- [3] https://mail.gnome.org/archives/networkmanager-list/2019-June/msg00006.html
- [4] https://gitlab.freedesktop.org/NetworkManager/NetworkManager/commit/3c36231706a9314f6bf03901dd13923cd32a5457


Consent/Disapproval about What?
===============================

Whether the copyright holder agrees to relicense the code in a3e75f329446a93a61ca4c458a7657bd919f4fe6
and its parent commits under terms of LGPL-2.1+.


How to Track Consent/Disapproval?
=================================

The consent/disapproval is tracked in this file for the copyright holders
who made their wish known. In the list below [Y] indicates consent while [N]
indicates disapproval. [?] indicates yet unknown data.
To express the wish either send an email to our mailing list <networkmanager-list@gnome.org>
or open a merge request against this file, adding your name to the list. Then this
file will be updated to track the information. The git commit messages in the history
of this file will give details when/how an entry was added.


Consent/Disapproval List
========================

- [Y] Aleksander Morgado <aleksander@aleksander.es>
- [Y] Antoine Faure <antoine.faure@sigfox.com> (Sigfox)
- [Y] Antony Mee <antony@onlymee.co.uk>
- [Y] Atul Anand <atulhjp@gmail.com>
- [Y] Beniamino Galvani <bgalvani@redhat.com> (Red Hat, Inc.)
- [Y] Benjamin Berg <bberg@redhat.com> (Red Hat, Inc.)
- [Y] Christian Kellner <christian@kellner.me> (Red Hat, Inc.)
- [Y] Colin Walters <walters@verbum.org> (Red Hat, Inc.)
- [Y] Corentin Noël <corentin@elementary.io>
- [Y] Dan Williams <dcbw@redhat.com> (Red Hat, Inc.)
- [Y] Dan Winship <danw@redhat.com> (Red Hat, Inc.)
- [Y] Daniel Drake <dsd@laptop.org> (One Laptop per Child)
- [Y] Evan Broder <evan@ebroder.net>
- [Y] Francesco Giudici <fgiudici@redhat.com> (Red Hat, Inc.)
- [Y] Frédéric Danis <frederic.danis.oss@gmail.com> (Collabora Ltd, Sigfox)
- [Y] Giovanni Campagna <gcampagna@src.gnome.org>
- [Y] Iñigo Martínez <inigomartinez@gmail.com>
- [Y] Jan Alexander Steffens (heftig) <jan.steffens@gmail.com>
- [Y] Jan Tojnar <jtojnar@gmail.com>
- [Y] Javier Arteaga <jarteaga@jbeta.is>
- [Y] Jiří Klimeš <blueowl@centrum.cz> (Red Hat, Inc.)
- [Y] Lubomir Rintel <lkundrak@v3.sk> (Red Hat, Inc.)
- [Y] Mario Sanchez Prada <mario@endlessm.com> (Endless Mobile, Inc.)
- [Y] Michael Biebl <biebl@debian.org>
- [Y] Pantelis Koukousoulas <pktoss@gmail.com>
- [Y] Pavel Šimerda <pavlix@pavlix.net> (Red Hat, Inc.)
- [Y] Przemysław Grzegorczyk <pgrzegorczyk@gmail.com>
- [Y] Ray Strode <rstrode@redhat.com> (Red Hat, Inc.)
- [Y] Robert Love <rml@novell.com> (Novell, Inc.)
- [Y] Sebastien Fabre <sebastien.fabre@sigfox.com> (Sigfox)
- [Y] Soapux <2375-Soapux@users.noreply.gitlab.freedesktop.org>
- [Y] Taegil Bae <esrevinu@gmail.com>
- [Y] Tambet Ingo <tambet@gmail.com> (Novell, Inc.)
- [Y] Thomas Haller <thaller@redhat.com> (Red Hat, Inc.)
- [Y] Timothy Redaelli <tredaelli@redhat.com> (Red Hat, Inc.)
- [Y] luz.paz <luzpaz@users.noreply.github.com>

Copyright Held by Other Legal Entities
======================================

The contributors above may have contributed the code on behalf of a company
that holds the copyright. This list tracks such legal entities. The contributor
list above indicates whether a contributor provided code for a legal entity here.

- [?] Canonical, Ltd.
- [?] Endless Mobile, Inc.
- [?] Intel Corporation
- [?] Novell, Inc.
- [?] One Laptop per Child
- [?] SUSE

- [Y] Endless Mobile, Inc.
- [Y] Endless OS LLC
- [Y] Red Hat, Inc.
- [Y] Sigfox
