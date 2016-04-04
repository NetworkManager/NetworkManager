<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stylesheet [
<!ENTITY % entities SYSTEM "common.ent" >
%entities;
]>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <!-- We need to strip whitespaces so that position() function counts correctly.
       http://www.oxygenxml.com/archives/xsl-list/200305/msg00430.html -->
  <xsl:strip-space elements="nm-ifcfg-rh-docs setting" />

  <xsl:output
      method="xml"
      doctype-public="-//OASIS//DTD DocBook XML V4.3//EN"
      doctype-system="http://www.oasis-open.org/docbook/xml/4.3/docbookx.dtd"
      />

  <xsl:template match="nm-ifcfg-rh-docs">
    <xsl:variable name="unsupported" select="'adsl, bluetooth, ppp, pppoe, serial, generic, gsm, cdma, 802-11-olpc-mesh, wimax, vpn'"/>
    <refentry id="nm-settings-ifcfg-rh">
      <refentryinfo>
        <title>nm-settings-ifcfg-rh</title>
        <author>NetworkManager developers</author>
      </refentryinfo>
      <refmeta>
        <refentrytitle>nm-settings-ifcfg-rh</refentrytitle>
        <manvolnum>5</manvolnum>
        <refmiscinfo class="source">NetworkManager</refmiscinfo>
        <refmiscinfo class="manual">Configuration</refmiscinfo>
        <refmiscinfo class="version">&NM_VERSION;</refmiscinfo>
      </refmeta>
      <refnamediv>
        <refname>nm-settings-ifcfg-rh</refname>
        <refpurpose>Description of <emphasis>ifcfg-rh</emphasis> settings plugin</refpurpose>
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
          The <emphasis>ifcfg-rh</emphasis> plugin is used on the Fedora and Red Hat
          Enterprise Linux distributions to read/write configuration from/to
          the traditional <filename>/etc/sysconfig/network-scripts/ifcfg-*</filename> files.
          Each NetworkManager connection maps to one <filename>ifcfg-*</filename> file, with
          possible usage of <filename>keys-*</filename> for passwords, <filename>route-*</filename>
          for static IPv4 routes and <filename>route6-*</filename> for static IPv6 routes.
          The plugin currently supports reading and writing Ethernet, Wi-Fi, InfiniBand,
          VLAN, Bond, Bridge, and Team connections. Unsupported connection types (such as
          WWAN, PPPoE, VPN, or ADSL) are handled by <emphasis>keyfile</emphasis> plugin
          (<citerefentry><refentrytitle>nm-settings-keyfile</refentrytitle><manvolnum>5</manvolnum></citerefentry>).
          The main reason for using <emphasis>ifcfg-rh</emphasis> plugin is the compatibility
          with legacy configurations for <emphasis>ifup</emphasis> and <emphasis>ifdown</emphasis>
          (initscripts).
        </para>
      </refsect1>
      <refsect1 id='file_format'><title>File Format</title>
        <para>
          The <emphasis>ifcfg-rh</emphasis> config format is a simple text file containing
          VARIABLE="value" lines. The format is described in <filename>sysconfig.txt</filename>
          of <emphasis>initscripts</emphasis> package. Note that the configuration files
          may be sourced by <emphasis>initscripts</emphasis>, so they must be valid shell
          scripts. That means, for instance, that <literal>#</literal> character can be used
          for comments, strings with spaces must be quoted, special characters must be escaped,
          etc.
        </para>
        <para>
          Users can create or modify the <emphasis>ifcfg-rh</emphasis> connection files
          manually, even if that is not the recommended way of managing the profiles.
          However, if they choose to do that, they must inform NetworkManager about
          their changes (see <emphasis>monitor-connection-file</emphasis> in
          <citerefentry><refentrytitle>nm-settings</refentrytitle><manvolnum>5</manvolnum>
          </citerefentry>, and <emphasis>nmcli con (re)load</emphasis>).
        </para>
        <formalpara>
          <title>Some <emphasis>ifcfg-rh</emphasis> configuration examples:</title>
          <para>
            <programlisting>
            <emphasis role="bold">Simple DHCP ethernet configuration:</emphasis>
NAME=ethernet
UUID=1c4ddf70-01bf-46d6-b04f-47e842bd98da
TYPE=Ethernet
BOOTPROTO=dhcp
DEFROUTE=yes
PEERDNS=yes
PEERROUTES=yes
IPV4_FAILURE_FATAL=no
ONBOOT=yes
            </programlisting>
          </para>
          <para>
            <programlisting>
            <emphasis role="bold">Simple ethernet configuration with static IP:</emphasis>
TYPE=Ethernet
BOOTPROTO=none
IPADDR=10.1.0.25
PREFIX=24
GATEWAY=10.1.0.1
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_PEERDNS=yes
IPV6_PEERROUTES=yes
IPV6_FAILURE_FATAL=no
NAME=ethernet-em2
UUID=51bb3904-c0fc-4dfe-83b2-0a71e7928c13
DEVICE=em2
ONBOOT=yes
            </programlisting>
          </para>
          <para>
            <programlisting>
            <emphasis role="bold">WPA2 Enterprise WLAN (TTLS with inner MSCHAPV2 authentication):</emphasis>
ESSID="CompanyWLAN"
MODE=Managed
KEY_MGMT=WPA-EAP
TYPE=Wireless
IEEE_8021X_EAP_METHODS=TTLS
IEEE_8021X_IDENTITY=joe
IEEE_8021X_PASSWORD_FLAGS=ask
IEEE_8021X_INNER_AUTH_METHODS=MSCHAPV2
IEEE_8021X_CA_CERT=/home/joe/.cert/company.crt
BOOTPROTO=dhcp
DEFROUTE=yes
PEERDNS=yes
PEERROUTES=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=no
NAME=MyCompany
UUID=f79848ff-11a6-4810-9e1a-99039dea84c4
ONBOOT=yes
            </programlisting>
          </para>
          <para>
            <programlisting>
            <emphasis role="bold">Bridge and bridge port configuration:</emphasis>
ifcfg-bridge:                                ifcfg-bridge-port:
NAME=bridge                                  NAME=bridge007-port-eth0
UUID=4be99ce0-c5b2-4764-8b77-ec226e440125    UUID=3ad56c4a-47e1-419b-b0d4-8ad86eb967a3
DEVICE=bridge007                             DEVICE=eth0
STP=yes                                      ONBOOT=yes
TYPE=Bridge                                  TYPE=Ethernet
BRIDGING_OPTS=priority=32768                 BRIDGE=bridge007
ONBOOT=yes
BOOTPROTO=dhcp

            </programlisting>
          </para>
          <para>
            <programlisting>
            <emphasis role="bold">Bonding configuration:</emphasis>
ifcfg-BOND:                                  ifcfg-BOND-slave:
NAME=BOND                                    NAME=BOND-slave
UUID=b41888aa-924c-450c-b0f8-85a4f0a51b4a    UUID=9bb048e4-286a-4cc3-b104-007dbd20decb
DEVICE=bond100                               DEVICE=eth0
BONDING_OPTS="mode=balance-rr miimon=100"    ONBOOT=yes
TYPE=Bond                                    TYPE=Ethernet
BONDING_MASTER=yes                           MASTER=bond100
ONBOOT=yes                                   SLAVE=yes
BOOTPROTO=dhcp

            </programlisting>
          </para>
          <para>
            <programlisting>
            <emphasis role="bold">Team and team port configuration:</emphasis>
ifcfg-my_team0:
DEVICE=team0
TEAM_CONFIG="{ \"device\": \"team0\", \"runner\": {\"name\": \"roundrobin\"}, \"ports\": {\"eth1\": {}, \"eth2\": {}} }"
DEVICETYPE=Team
BOOTPROTO=dhcp
NAME=team0-profile
UUID=1d3460a0-7b37-457f-a300-fe8d92da4807
ONBOOT=yes

ifcfg-my_team0_slave1:
NAME=team0-slave1
UUID=d5aed298-c567-4cc1-b808-6d38ecef9e64
DEVICE=eth1
ONBOOT=yes
TEAM_MASTER=team0
DEVICETYPE=TeamPort

ifcfg-my_team0_slave2:
NAME=team0-slave2
UUID=94e75f4e-e5ad-401c-8962-31e0ae5d2215
DEVICE=eth2
ONBOOT=yes
TEAM_MASTER=team0
DEVICETYPE=TeamPort
            </programlisting>
          </para>
          <para>
            The UUID values in the config files must be unique. You can use <emphasis>uuidgen</emphasis>
            command line tool to generate such values. Alternatively, you can leave out UUID
            entirely. In that case NetworkManager will generate a UUID based on the file name.
          </para>
        </formalpara>
      </refsect1>

      <refsect1 id='differences_against_initscripts'><title>Differences against initscripts</title>
        <para>
          The main differences of NetworkManager ifcfg-rh plugin and traditional
          initscripts are:
          <variablelist class="NM-initscripts-differences">
            <varlistentry>
              <term><emphasis role="bold">NM_CONTROLLED=yes|no</emphasis></term>
              <listitem><para>
                NM_CONTROLLED is NetworkManager-specific variable used by NetworkManager
                for determining whether the device of the <emphasis>ifcfg</emphasis> file
                should be managed. NM_CONTROLLED=yes is supposed if the variable is not
                present in the file.
                Note that if you have more <emphasis>ifcfg</emphasis> files for a single
                device, NM_CONTROLLED=no in one of the files will cause the device not
                to be managed. The profile may not even be the active one.
              </para></listitem>
            </varlistentry>
            <varlistentry>
              <term><emphasis role="bold">New variables</emphasis></term>
              <listitem><para>
                NetworkManager has introduced some new variable, not present in initscripts,
                to be able to store data for its new features. The variables are marked
                as extensions in the tables below.
              </para></listitem>
            </varlistentry>
            <varlistentry>
              <term><emphasis role="bold">Semantic change of variables</emphasis></term>
              <listitem><para>
                NetworkManager had to slightly change the semantic for a few variables.
                <itemizedlist>
                  <listitem>
                    <para><literal>PEERDNS</literal> -
                    initscripts interpret PEERDNS=no to mean "never touch resolv.conf".
                    NetworkManager interprets it to say "never add automatic (DHCP, PPP, VPN, etc.)
                    nameservers to resolv.conf".</para>
                  </listitem>
                  <listitem>
                    <para><literal>ONBOOT</literal> -
                    initscripts use ONBOOT=yes to mark the devices that are to be activated
                    during boot. NetworkManager extents this to also mean that this profile
                    can be used for auto-connecting at any time.</para>
                  </listitem>
                  <listitem>
                    <para><literal>BOOTPROTO</literal> -
                    NetworkManager supports traditional values <emphasis>none</emphasis> (static),
                    <emphasis>dhcp</emphasis>. But it also allows additional values to
                    enable new addressing methods. They are <emphasis>autoip</emphasis> for IPv4
                    link-local addressing using Avahi daemon and <emphasis>shared</emphasis> for
                    connection sharing. When <emphasis>shared</emphasis> is used, NetworkManager
                    assigns the interface 10.42.0.1, or it uses the first static address,
                    if configured.</para>
                 </listitem>
                </itemizedlist>
              </para></listitem>
            </varlistentry>
          </variablelist>
        </para>
        <para>
          See the next section for detailed mapping of NetworkManager properties and
          <emphasis>ifcfg-rh</emphasis> variables. Variable names, format and usage
          differences in NetworkManager and initscripts are documented in the tables below.
        </para>
      </refsect1>

      <refsect1 id='details'><title>Details</title>
        <para>
          <emphasis>ifcfg-rh</emphasis> plugin variables marked with <emphasis>(+)</emphasis>
          are NetworkManager specific extensions not understood by traditional initscripts.
        </para>
        <xsl:apply-templates />
        <refsect2 id="secrets-flags">
          <title>Secret flags</title>
          <para>
            Each secret property in a NetworkManager setting has an associated
            <emphasis>flags</emphasis> property that describes how to handle that secret.
            In the <emphasis>fcfg-rh</emphasis> plugin variables for secret flags have a
            <emphasis>_FLAGS</emphasis> suffix. The variables contain one or more of the
            following values (space separated). Missing (or empty) *_FLAGS variable means
            that the password is owned by NetworkManager.
          </para>
          <itemizedlist>
            <listitem>
              <para><literal>user</literal> - a user-session secret agent is responsible for providing
              and storing this secret; when it is required, agents will be asked to provide it.</para>
            </listitem>
            <listitem>
              <para><literal>ask</literal> - the associated password is not saved but it will be
              requested from the user each time it is required.</para>
            </listitem>
            <listitem>
              <para><literal>unused</literal> - in some situations it cannot be automatically determined
              that a secret is required or not. This flag hints that the secret is not required and should
              not be requested from the user.</para>
            </listitem>
          </itemizedlist>
        </refsect2>
      </refsect1>

      <refsect1 id='files'><title>Files</title>
        <para><filename>/etc/sysconfig/network-scripts/ifcfg-*</filename></para>
        <para><filename>/etc/sysconfig/network-scripts/keys-*</filename></para>
        <para><filename>/etc/sysconfig/network-scripts/route-*</filename></para>
        <para><filename>/etc/sysconfig/network-scripts/route6-*</filename></para>
        <para><filename>/usr/share/doc/initscripts/sysconfig.txt</filename></para>
      </refsect1>
      <refsect1 id='see_also'><title>See Also</title>
        <para><citerefentry><refentrytitle>nm-settings</refentrytitle><manvolnum>5</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>nm-settings-keyfile</refentrytitle><manvolnum>5</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>NetworkManager</refentrytitle><manvolnum>8</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>NetworkManager.conf</refentrytitle><manvolnum>5</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>nmcli</refentrytitle><manvolnum>1</manvolnum></citerefentry>,
        <citerefentry><refentrytitle>nmcli-examples</refentrytitle><manvolnum>7</manvolnum></citerefentry></para>
      </refsect1>
    </refentry>
  </xsl:template>

  <xsl:template match="setting">
    <xsl:variable name="setting_name" select="../@name"/>
    <xsl:variable name="unsupported" select="'adsl, bluetooth, ppp, pppoe, serial, generic, gsm, cdma, 802-11-olpc-mesh, wimax, vpn'"/>
      <xsl:if test="not (contains($unsupported, @name))">
        <table>
          <title><xsl:value-of select="@name"/> setting</title>
          <tgroup cols="4">
            <thead>
              <row>
                <entry>Property</entry>
                <entry>Ifcfg-rh Variable</entry>
                <entry>Default</entry>
                <entry>Description</entry>
              </row>
            </thead>
            <tbody>
              <xsl:apply-templates/>
            </tbody>
          </tgroup>
        </table>
      </xsl:if>

      <xsl:if test="@name = 'dcb'">
        <para>
          All DCB related configuration is a NetworkManager extension. DCB=yes must be
          used explicitly to enable DCB so that the rest of the DCB_* variables can apply.
        </para>
      </xsl:if>

      <xsl:if test="position() = last()">
        <para>The following settings are not supported by <emphasis>ifcfg-rh</emphasis> plugin:</para>
        <para><xsl:value-of select="$unsupported"/></para>
      </xsl:if>
  </xsl:template>

  <xsl:template match="property">
    <xsl:variable name="setting_name" select="../@name"/>


    <row>
      <entry align="left"><xsl:value-of select="@name"/></entry>
      <entry align="left">
        <xsl:call-template name="string-emphasize-all">
          <xsl:with-param name="text" select="@variable"/>
          <xsl:with-param name="emphasize" select="'(+)'"/>
        </xsl:call-template>
      </entry>
      <entry align="left"><xsl:value-of select="@default"/></entry>
      <entry align="left">
        <xsl:value-of select="@description"/><xsl:if test="@format = 'NMSettingSecretFlags'"> (see <xref linkend="secrets-flags"/> for _FLAGS values)</xsl:if>

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

  <xsl:template name="string-emphasize-all">
    <xsl:param name="text"/>
    <xsl:param name="emphasize"/>
    <xsl:choose>
      <xsl:when test="contains($text, $emphasize)">
        <xsl:value-of select="substring-before($text,$emphasize)"/>
        <emphasis><xsl:value-of select="$emphasize"/></emphasis>
        <xsl:call-template name="string-emphasize-all">
          <xsl:with-param name="text" select="substring-after($text,$emphasize)"/>
          <xsl:with-param name="emphasize" select="$emphasize"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$text"/>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

</xsl:stylesheet>
