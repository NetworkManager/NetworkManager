<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:output
      method="text"
      doctype-public="-//OASIS//DTD DocBook XML V4.3//EN"
      doctype-system="http://www.oasis-open.org/docbook/xml/4.3/docbookx.dtd"
      />

  <xsl:template match="nm-setting-docs">/* Generated file. Do not edit. */

typedef struct {
	const char *name;
	const char *docs;
} NmcPropertyDesc;
<xsl:apply-templates select="setting" mode="properties"><xsl:sort select="@name"/></xsl:apply-templates>

typedef struct {
	const char *name;
	NmcPropertyDesc *properties;
	int n_properties;
} NmcSettingDesc;

NmcSettingDesc all_settings[] = {
<xsl:apply-templates select="setting" mode="settings"><xsl:sort select="@name"/></xsl:apply-templates>
};

static int
find_by_name (gconstpointer keyv, gconstpointer cmpv)
{
	const char *key = keyv;
	struct { const char *name; gpointer data; } *cmp = (gpointer)cmpv;

	return strcmp (key, cmp->name);
}

static const char *
nmc_setting_get_property_doc (NMSetting *setting, const char *prop)
{
	NmcSettingDesc *setting_desc;
	NmcPropertyDesc *property_desc;

	setting_desc = bsearch (nm_setting_get_name (setting),
	                        all_settings, G_N_ELEMENTS (all_settings),
	                        sizeof (NmcSettingDesc), find_by_name);
	if (!setting_desc)
		return NULL;
	property_desc = bsearch (prop,
	                         setting_desc->properties, setting_desc->n_properties,
	                         sizeof (NmcPropertyDesc), find_by_name);
	if (!property_desc)
		return NULL;
	return property_desc->docs;
}
  </xsl:template>

  <xsl:template match="setting" mode="properties">
NmcPropertyDesc setting_<xsl:value-of select="translate(@name,'-','_')"/>[] = {<xsl:apply-templates select="property"><xsl:sort select="@name"/></xsl:apply-templates>
};
  </xsl:template>

  <xsl:template match="property">
    <xsl:variable name="docs">
      <xsl:call-template name="escape_quotes">
	<xsl:with-param name="string" select="@description"/>
      </xsl:call-template>
    </xsl:variable>
	{ "<xsl:value-of select="@name"/>", "<xsl:value-of select="$docs"/>" },</xsl:template>

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
