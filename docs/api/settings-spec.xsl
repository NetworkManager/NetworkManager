<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:output
      method="xml"
      doctype-public="-//OASIS//DTD DocBook XML V4.3//EN"
      doctype-system="http://www.oasis-open.org/docbook/xml/4.3/docbookx.dtd"
      />

  <xsl:template match="nm-setting-docs">
    <section>
      <title>Configuration Settings</title>
      <xsl:apply-templates/>
    </section>
  </xsl:template>

  <xsl:template match="setting">
    <para>
      <table>
	<title><xsl:value-of select="@name"/> setting</title>
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
  </xsl:template>

  <xsl:template match="property">
    <xsl:variable name="setting_name" select="../@name"/>
    <row>
      <entry><screen><xsl:value-of select="@name"/></screen></entry>
      <entry><screen><xsl:value-of select="@type"/></screen></entry>
      <entry><screen><xsl:value-of select="@default"/></screen></entry>
      <entry><xsl:value-of select="@description"/><xsl:if test="@type = 'NMSettingSecretFlags'"> (see <xref linkend="secrets-flags"/> for flag values)</xsl:if></entry>
    </row>
  </xsl:template>

</xsl:stylesheet>
