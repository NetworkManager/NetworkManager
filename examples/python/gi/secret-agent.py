#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM, Gio

# This example shows how to implement a very simple secret agent for
# NetworkManager. The secret agent registers to the NM daemon and can
# provide missing secrets like Wi-Fi or VPN passwords. Set environment
# variable "LIBNM_CLIENT_DEBUG=trace" to enable libnm verbose logging.


class SecretAgent(NM.SecretAgentOld):
    def __init__(self):
        super().__init__(identifier="MySecretAgent")
        super().init()

    def do_get_secrets(
        self,
        connection,
        connection_path,
        setting_name,
        hints,
        flags,
        callback,
        callback_data,
    ):
        print(
            "get_secrets for '{}', interface '{}', setting '{}'".format(
                connection.get_id(), connection.get_interface_name(), setting_name
            )
        )

        # Implement here the logic to retrieve the secrets.
        # As an example, we return a hardcoded Wi-Fi PSK.
        if (
            connection.get_connection_type() == "802-11-wireless"
            and setting_name == "802-11-wireless-security"
        ):
            s_wifi = connection.get_setting_wireless()
            ssid = NM.utils_ssid_to_utf8(s_wifi.get_ssid().get_data())

            if ssid == "home":
                secrets = GLib.Variant(
                    "a{sa{sv}}",
                    {
                        "802-11-wireless-security": {
                            "psk": GLib.Variant("s", "abcd1234")
                        }
                    },
                )
                print("Sending secrets {}".format(secrets))
                callback(self, connection, secrets, None)
                return

        # We don't have the secret, NM will ask to another agent or fail
        callback(
            self,
            connection,
            None,
            GLib.GError.new_literal(
                NM.SecretAgentError.quark(),
                "No secrets found",
                NM.SecretAgentError.NOSECRETS,
            ),
        )

    def do_cancel_get_secrets(self, connection_path, connection_name):
        pass

    def do_save_secrets(self, connection, connection_path, callback, callback_data):
        # Implement this if you want to store "agent-owned" secrets
        callback(self, connection, None)

    def do_delete_secrets(self, connection, connection_path, callback, callback_data):
        # Implement this if you want to store "agent-owned" secrets
        callback(self, connection, None)


def main():
    agent = SecretAgent()
    loop = GLib.MainLoop()
    try:
        loop.run()
    except KeyboardInterrupt:
        print("Exiting Secret Agent...")


if __name__ == "__main__":
    main()
