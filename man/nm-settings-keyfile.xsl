<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stylesheet [
<!ENTITY % entities SYSTEM "common.ent" >
%entities;
]>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:output
      method="xml"
      doctype-public="-//OASIS//DTD DocBook XML V4.3//EN"
      doctype-system="http://www.oasis-open.org/docbook/xml/4.3/docbookx.dtd"
      />

  <xsl:template match="nm-keyfile-docs">
    <refentry id="nm-settings-keyfile">
      <refentryinfo>
        <title>nm-settings-keyfile</title>
        <author>NetworkManager developers</author>
      </refentryinfo>
      <refmeta>
        <refentrytitle>nm-settings-keyfile</refentrytitle>
        <manvolnum>5</manvolnum>
        <refmiscinfo class="source">NetworkManager</refmiscinfo>
        <refmiscinfo class="manual">Configuration</refmiscinfo>
        <refmiscinfo class="version">&NM_VERSION;</refmiscinfo>
      </refmeta>
      <refnamediv>
        <refname>nm-settings-keyfile</refname>
        <refpurpose>Description of <emphasis>keyfile</emphasis> settings plugin</refpurpose>
      </refnamediv>
      <refsect1 id='description'><title>Description</title>
        <para>
          NetworkManager is based on the concept of connection profiles that contain
          network configuration (see <citerefentry><refentrytitle>nm-settings</refentrytitle>
          <manvolnum>5</manvolnum></citerefentry> for details). The profiles can be
          stored in various formats. NetworkManager uses plugins for reading and writing
          the data. The plugins can be configured in <citerefentry>
          <refentrytitle>NetworkManager.conf</refentrytitle><manvolnum>5</manvolnum></citerefentry>.
        </para>
        <para>
          The <emphasis>keyfile</emphasis> plugin is the generic plugin that supports all
          the connection types and capabilities that NetworkManager has. It writes files
          out in a .ini-style format in <filename>/etc/NetworkManager/system-connections/</filename>.
          This plugin is always enabled and will automatically be used to store
          any connections that are not supported by any other active plugin.
          For security, it will ignore files that are readable or writable by any user
          or group other than 'root' since private keys and passphrases may be stored
          in plaintext inside the file.
        </para>
      </refsect1>
      <refsect1 id='file_format'><title>File Format</title>
        <para>
          The <emphasis>keyfile</emphasis> config format is a simple .ini-style
          format. It consists of sections (groups) of key-value pairs. Each section
          corresponds to a setting name as described in the settings specification
          (<citerefentry><refentrytitle>nm-settings</refentrytitle>
          <manvolnum>5</manvolnum></citerefentry>). Each configuration key/value
          pair in the section is one of the properties listed in the settings
          specification. The majority of properties of the specification is written
          in the same format into the <emphasis>keyfile</emphasis> too. However
          some values are inconvenient for people to use. These are stored in the
          files in more readable ways. These properties are described below.
          An example could be IP addresses that are not written as integer arrays,
          but more reasonably as "1.2.3.4/12 1.2.3.254".
          More information of the generic key file format can be found at
          <ulink url="https://developer.gnome.org/glib/stable/glib-Key-value-file-parser.html#glib-Key-value-file-parser.description">
          GLib key file format</ulink> (Lines beginning with a '#' are comments,
          lists are separated by character <literal>;</literal> etc.).
        </para>
        <para>
          Users can create or modify the <emphasis>keyfile</emphasis> connection files
          manually, even if that is not the recommended way of managing the profiles.
          However, if they choose to do that, they must inform NetworkManager about
          their changes (see <emphasis>monitor-connection-file</emphasis> in
          <citerefentry><refentrytitle>nm-settings</refentrytitle><manvolnum>5</manvolnum>
          </citerefentry> and <emphasis>nmcli con (re)load</emphasis>).
        </para>
        <formalpara>
          <title>Examples of <emphasis>keyfile</emphasis> configuration</title>
          <para>
            <programlisting>
            <emphasis role="bold">A sample configuration for an ethernet network:</emphasis>
[connection]
id=Main eth0
uuid=27afa607-ee36-43f0-b8c3-9d245cdc4bb3
type=802-3-ethernet
autoconnect=true

[ipv4]
method=auto

[802-3-ethernet]
mac-address=00:23:5a:47:1f:71
            </programlisting>
          </para>
          <para>
            <programlisting>
            <emphasis role="bold">A sample configuration for WPA-EAP (PEAP with MSCHAPv2) and always-ask secret:</emphasis>
[connection]
id=CompanyWIFI
uuid=cdac6154-a33b-4b15-9904-666772cfa5ee
type=wifi
autoconnect=false

[wifi]
ssid=CorpWLAN
mode=infrastructure
security=802-11-wireless-security

[wifi-security]
key-mgmt=wpa-eap

[ipv4]
method=auto

[ipv6]
method=auto

[802-1x]
eap=peap;
identity=joe
ca-cert=/home/joe/.cert/corp.crt
phase1-peapver=1
phase2-auth=mschapv2
password-flags=2
            </programlisting>
          </para>
          <para>
            <programlisting>
            <emphasis role="bold">A sample configuration for openvpn:</emphasis>
[connection]
id=RedHat-openvpn
uuid=7f9b3356-b210-4c0e-8123-bd116c9c280f
type=vpn
timestamp=1385401165

[vpn]
service-type=org.freedesktop.NetworkManager.openvpn
connection-type=password
password-flags=3
remote=ovpn.my-company.com
cipher=AES-256-CBC
reneg-seconds=0
port=443
username=joe
ca=/etc/openvpn/ISCA.pem
tls-remote=ovpn.my-company.com

[ipv6]
method=auto

[ipv4]
method=auto
ignore-auto-dns=true
never-default=true
            </programlisting>
          </para>
          <para>
            <programlisting>
            <emphasis role="bold">A sample configuration for a bridge and a bridge port:</emphasis>
[connection]                                 [connection]
id=MainBridge                                id=br-port-1
uuid=171ae855-a0ab-42b6-bd0c-60f5812eea9d    uuid=d6e8ae98-71f8-4b3d-9d2d-2e26048fe794
interface-name=MainBridge                    interface-name=em1
type=bridge                                  type=ethernet
                                             master=MainBridge
[bridge]                                     slave-type=bridge
interface-name=MainBridge
            </programlisting>
          </para>
          <para>
            <programlisting>
            <emphasis role="bold">A sample configuration for a VLAN:</emphasis>
[connection]
id=VLAN for building 4A
uuid=8ce1c9e0-ce7a-4d2c-aa28-077dda09dd7e
interface-name=VLAN-4A
type=vlan

[vlan]
interface-name=VLAN-4A
parent=eth0
id=4
            </programlisting>
          </para>
        </formalpara>
      </refsect1>

      <refsect1 id='details'><title>Details</title>
        <para>
          <emphasis>keyfile</emphasis> plugin variables for the majority of NetworkManager
          properties have one-to-one mapping. It means a NetworkManager property is stored
          in the keyfile as a variable of the same name and in the same format.
          There are several exceptions to this rule, mainly for making keyfile syntax easier
          for humans. The exceptions handled specially by <emphasis>keyfile</emphasis>
          plugin are listed below. Refer to
          <citerefentry><refentrytitle>nm-settings</refentrytitle><manvolnum>5</manvolnum></citerefentry>
          for all available settings and properties and their description.
        </para>
        <formalpara><title>Name aliases</title>
          <para>
            Some of the NetworkManager setting names are somewhat hard to type or remember. Therefore
            <emphasis>keyfile</emphasis> introduces aliases that can be used instead of the names.
            <!-- Hmm, why doesn't <simplelist type='horiz' columns='2'> create two columns? -->
            <simplelist type='horiz' columns='1'>
              <member><emphasis>setting name                 keyfile alias</emphasis></member>
              <member>802-3-ethernet            =  ethernet</member>
              <member>802-11-wireless           =  wifi</member>
              <member>802-11-wireless-security  =  wifi-security</member>
            </simplelist>
          </para>
        </formalpara>
        <xsl:apply-templates/>
        <refsect2 id="secrets-flags">
          <title>Secret flags</title>
          <para>
            Each secret property in a NetworkManager setting has an associated <emphasis>flags</emphasis>
            property that describes how to handle that secret. In the <emphasis>keyfile</emphasis> plugin,
            the value of <emphasis>-flags</emphasis> variable is a decimal number (0 - 7) defined as a sum
            of the following values:
          </para>
          <itemizedlist>
            <listitem>
              <para>0 - (NM owned) - the system is responsible for providing and storing this secret.</para>
            </listitem>
            <listitem>
              <para>1 - (agent-owned) - a user-session secret agent is responsible for providing
              and storing this secret; when it is required, agents will be asked to provide it.</para>
            </listitem>
            <listitem>
              <para>2 - (not-saved) - this secret should not be saved but should be requested
              from the user each time it is required.</para>
            </listitem>
            <listitem>
              <para>4 - (not-required) - in some situations it cannot be automatically determined
              that a secret is required or not. This flag hints that the secret is not required
              and should not be requested from the user.</para>
            </listitem>
          </itemizedlist>
        </refsect2>
      </refsect1>

      <refsect1 id='files'><title>Files</title>
        <para><filename>/etc/NetworkManager/system-connections/*</filename></para>
      </refsect1>

      <refsect1 id='see_also'><title>See Also</title>
        <para><citerefentry><refentrytitle>nm-settings</refentrytitle><manvolnum>5</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>nm-settings-ifcfg-rh</refentrytitle><manvolnum>5</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>NetworkManager</refentrytitle><manvolnum>8</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>NetworkManager.conf</refentrytitle><manvolnum>5</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>nmcli</refentrytitle><manvolnum>1</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>nmcli-examples</refentrytitle><manvolnum>7</manvolnum></citerefentry></para>
      </refsect1>
    </refentry>
  </xsl:template>

  <xsl:template match="setting">
    <xsl:variable name="setting_name" select="../@name"/>
    <xsl:if test="property/@name != ''">
      <table>
        <title><xsl:value-of select="@name"/> setting (section)</title>
        <tgroup cols="4">
          <thead>
            <row>
              <entry>Property</entry>
              <entry>Keyfile Variable</entry>
              <entry>Format</entry>
              <entry>Description</entry>
            </row>
          </thead>
          <tbody>
            <xsl:apply-templates/>
          </tbody>
        </tgroup>
      </table>
    </xsl:if>
  </xsl:template>

  <xsl:template match="property">
    <row>
      <entry align="left"><xsl:value-of select="@name"/></entry>
      <entry align="left"><xsl:value-of select="@variable"/></entry>
      <entry align="left"><xsl:value-of select="@format"/></entry>
      <entry align="left">
        <xsl:value-of select="@description"/>
        <xsl:if test="string-length(@example)">
          <emphasis role="bold">

Example: </emphasis><xsl:value-of select="@example"/>
        </xsl:if>
        <xsl:if test="string-length(@values)">
          <emphasis role="bold">

Allowed values: </emphasis><xsl:value-of select="@values"/>
        </xsl:if>
      </entry>
    </row>
  </xsl:template>

</xsl:stylesheet>
