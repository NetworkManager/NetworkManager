<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:output
      method="xml"
      doctype-public="-//OASIS//DTD DocBook XML V4.3//EN"
      doctype-system="http://www.oasis-open.org/docbook/xml/4.3/docbookx.dtd"
      />

  <xsl:template match="nm-setting-docs">
    <chapter>
      <title>Configuration Settings</title>
      <xsl:apply-templates/>
    </chapter>
  </xsl:template>

  <xsl:template match="setting">
    <refentry>
      <xsl:attribute name="id">settings-<xsl:value-of select="@name"/></xsl:attribute>
      <refnamediv>
        <refname><xsl:value-of select="@name"/></refname>
        <refpurpose><xsl:value-of select="@description"/></refpurpose>
      </refnamediv>
      <refsect1 role="properties">
        <title>
            <xsl:attribute name="id">settings-<xsl:value-of select="@name"/>.properties</xsl:attribute>
            Properties
        </title>
        <para>
          <table>
            <tgroup cols="4">
              <thead>
                <row>
                  <entry>Key Name</entry>
                  <entry>Value Type</entry>
                  <entry>Default Value</entry>
                  <entry>Value Description</entry>
                </row>
              </thead>
              <tbody>
                <xsl:apply-templates/>
              </tbody>
            </tgroup>
          </table>
        </para>
      </refsect1>
    </refentry>
  </xsl:template>

  <xsl:template match="property">
    <xsl:variable name="setting_name" select="../@name"/>
    <row>
      <entry><screen>
        <xsl:value-of select="@name"/>
        <indexterm>
           <xsl:attribute name="zone">settings-<xsl:value-of select="../@name"/></xsl:attribute>
           <primary>
             <xsl:attribute name="sortas"><xsl:value-of select="@name"/></xsl:attribute>
             <xsl:value-of select="@name"/>
           </primary>
        </indexterm>
      </screen></entry>
      <entry><screen><xsl:value-of select="@type"/></screen></entry>
      <entry><screen><xsl:value-of select="@default"/></screen></entry>
      <entry><xsl:value-of select="@description"/><xsl:if test="@type = 'NMSettingSecretFlags'"> (see <xref linkend="secrets-flags"/> for flag values)</xsl:if></entry>
    </row>
  </xsl:template>

</xsl:stylesheet>
