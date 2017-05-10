<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:output
      method="text"
      doctype-public="-//OASIS//DTD DocBook XML V4.3//EN"
      doctype-system="http://www.oasis-open.org/docbook/xml/4.3/docbookx.dtd"
      />

  <xsl:template match="nm-setting-docs">/* Generated file. Do not edit. */

<xsl:apply-templates select="setting" mode="properties"><xsl:sort select="@name"/></xsl:apply-templates>
  </xsl:template>


  <xsl:template match="setting" mode="properties">
<xsl:apply-templates select="property">
    <xsl:sort select="@name"/>
    <xsl:with-param name="setting_name_upper" select="@name_upper"/>
</xsl:apply-templates>

</xsl:template>

  <xsl:template match="property">
    <xsl:param name="setting_name_upper" />
    <xsl:variable name="docs">
      <xsl:call-template name="escape_quotes">
        <xsl:with-param name="string" select="@description"/>
      </xsl:call-template>
    </xsl:variable>#define DESCRIBE_DOC_NM_SETTING_<xsl:value-of select="$setting_name_upper"/>_<xsl:value-of select="@name_upper"/> N_("<xsl:value-of select="$docs"/>")
</xsl:template>

  <xsl:template match="setting" mode="settings">
        { "<xsl:value-of select="@name"/>", setting_<xsl:value-of select="translate(@name,'-','_')"/>, <xsl:value-of select="count(./property)"/> },</xsl:template>

  <xsl:template name="escape_quotes">
    <xsl:param name="string" />
      <xsl:choose>
        <xsl:when test="contains($string, '&quot;')">
          <xsl:value-of select="substring-before($string, '&quot;')" />\&quot;<xsl:call-template name="escape_quotes"><xsl:with-param name="string" select="substring-after($string, '&quot;')" /></xsl:call-template>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="$string" />
        </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

</xsl:stylesheet>
