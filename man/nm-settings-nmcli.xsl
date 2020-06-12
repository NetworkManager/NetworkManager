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

  <xsl:template match="nm-setting-docs">
    <refentry id="nm-settings-nmcli">
      <refentryinfo>
        <title>nm-settings-nmcli</title>
        <author>NetworkManager developers</author>
      </refentryinfo>
      <refmeta>
        <refentrytitle>nm-settings-nmcli</refentrytitle>
        <manvolnum>5</manvolnum>
        <refmiscinfo class="source">NetworkManager</refmiscinfo>
        <refmiscinfo class="manual">Configuration</refmiscinfo>
        <refmiscinfo class="version">&NM_VERSION;</refmiscinfo>
      </refmeta>
      <refnamediv>
        <refname>nm-settings-nmcli</refname>
        <refpurpose>Description of settings and properties of NetworkManager connection profiles for nmcli</refpurpose>
      </refnamediv>

      <refsect1 id='description'><title>Description</title>
        <para>
          NetworkManager is based on a concept of connection profiles, sometimes referred to as
          connections only. These connection profiles contain a network configuration. When
          NetworkManager activates a connection profile on a network device the configuration will
          be applied and an active network connection will be established. Users are free to create
          as many connection profiles as they see fit. Thus they are flexible in having various network
          configurations for different networking needs.
        </para>
        <para>
          NetworkManager provides an API for configuring connection profiles, for activating them
          to configure the network, and inspecting the current network configuration. The command
          line tool <emphasis>nmcli</emphasis> is a client application to NetworkManager that uses
          this API. See <link linkend='nmcli'><citerefentry><refentrytitle>nmcli</refentrytitle><manvolnum>1</manvolnum></citerefentry></link>
          for details.
        </para>
        <para>
          With commands like <literal>nmcli connection add</literal>, <literal>nmcli connection modify</literal>
          and <literal>nmcli connection show</literal>, connection profiles can be created, modified
          and inspected. A profile consists of properties. On D-Bus this follows the format
          as described by <link linkend='nm-settings-dbus'><citerefentry><refentrytitle>nm-settings-dbus</refentrytitle><manvolnum>5</manvolnum></citerefentry></link>,
          while this manual page describes the settings format how they are expected by <emphasis>nmcli</emphasis>.
        </para>
        <para>
          The settings and properties shown in tables below list all available connection
          configuration options. However, note that not all settings are applicable to all
          connection types. <emphasis>nmcli</emphasis> connection editor has also a built-in
          <emphasis>describe</emphasis> command that can display description of particular settings
          and properties of this page.
        </para>
        <para>
          The <replaceable>setting</replaceable> and
          <replaceable>property</replaceable> can be abbreviated provided they are unique. The list below
          also shows aliases that can be used unqualified instead of the full name. For example
          <literal>connection.interface-name</literal> and <literal>ifname</literal> refer to the same
          property.
        </para>
        <xsl:apply-templates/>
        <refsect2 id="secrets-flags">
          <title>Secret flag types:</title>
          <para>
            Each password or secret property in a setting has an associated <emphasis>flags</emphasis> property
            that describes how to handle that secret. The <emphasis>flags</emphasis> property is a bitfield
            that contains zero or more of the following values logically OR-ed together.
          </para>
          <itemizedlist>
            <listitem>
              <para>0x0 (none) - the system is responsible for providing and storing this secret. This
              may be required so that secrets are already available before the user logs in.
              It also commonly means that the secret will be stored in plain text on disk, accessible
              to root only. For example via the keyfile settings plugin as described in the "PLUGINS" section
              in <link linkend='NetworkManager.conf'><citerefentry><refentrytitle>NetworkManager.conf</refentrytitle><manvolnum>5</manvolnum></citerefentry></link>.
              </para>
            </listitem>
            <listitem>
              <para>0x1 (agent-owned) - a user-session secret agent is responsible for providing and storing
              this secret; when it is required, agents will be asked to provide it.</para>
            </listitem>
            <listitem>
              <para>0x2 (not-saved) - this secret should not be saved but should be requested from the user
              each time it is required. This flag should be used for One-Time-Pad secrets, PIN codes from hardware tokens,
              or if the user simply does not want to save the secret.</para>
            </listitem>
            <listitem>
              <para>0x4 (not-required) - in some situations it cannot be automatically determined that a secret
              is required or not. This flag hints that the secret is not required and should not be requested from the user.</para>
            </listitem>
          </itemizedlist>
        </refsect2>
      </refsect1>

      <refsect1 id='files'><title>Files</title>
        <para><filename>/etc/NetworkManager/system-connections</filename> or distro plugin-specific location</para>
      </refsect1>

      <refsect1 id='see_also'><title>See Also</title>
        <para>
        <link linkend='nmcli'><citerefentry><refentrytitle>nmcli</refentrytitle><manvolnum>1</manvolnum></citerefentry></link>,
        <link linkend='nmcli-examples'><citerefentry><refentrytitle>nmcli-examples</refentrytitle><manvolnum>7</manvolnum></citerefentry></link>,
        <link linkend='NetworkManager'><citerefentry><refentrytitle>NetworkManager</refentrytitle><manvolnum>8</manvolnum></citerefentry></link>,
        <link linkend='nm-settings-dbus'><citerefentry><refentrytitle>nm-settings-dbus</refentrytitle><manvolnum>5</manvolnum></citerefentry></link>,
        <link linkend='nm-settings-keyfile'><citerefentry><refentrytitle>nm-settings-keyfile</refentrytitle><manvolnum>5</manvolnum></citerefentry></link>,
        <link linkend='NetworkManager.conf'><citerefentry><refentrytitle>NetworkManager.conf</refentrytitle><manvolnum>5</manvolnum></citerefentry></link></para>
      </refsect1>
    </refentry>
  </xsl:template>

  <xsl:template match="setting">
    <refsect2>
      <title><xsl:value-of select="@name"/> setting</title>
      <para><xsl:value-of select="@description"/>.</para>
      <para>
        Properties:
        <variablelist>
          <xsl:apply-templates/>
        </variablelist>
      </para>
    </refsect2>
  </xsl:template>

  <xsl:template match="property">
    <xsl:variable name="setting_name" select="../@name"/>
    <varlistentry>
      <term>
        <option>
          <xsl:attribute name="id">nm-settings-nmcli.property.<xsl:value-of select="../@name"/>.<xsl:value-of select="@name"/></xsl:attribute>
          <xsl:value-of select="@name"/>
        </option>
      </term>
      <listitem>
        <xsl:if test="@alias">
          <para>
            Alias: <xsl:value-of select="@alias"/>
          </para>
        </xsl:if>
        <para>
          <xsl:value-of select="@description"/>
          <xsl:if test="@type = 'NMSettingSecretFlags (uint32)'">
           See <xref linkend="secrets-flags"/> for flag values.
          </xsl:if>
        </para>
        <xsl:if test="@type">
          <para>
            Format: <xsl:value-of select="@type"/>
          </para>
        </xsl:if>
      </listitem>
    </varlistentry>
  </xsl:template>

</xsl:stylesheet>
