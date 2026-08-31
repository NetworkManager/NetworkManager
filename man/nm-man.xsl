<?xml version='1.0'?>
<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:import href="http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl"/>

  <!--
    Our man pages cross-reference each other with <link linkend='...'>
    wrappers around <citerefentry>. Those IDs only resolve in the combined
    HTML documentation (docs/api/network-manager-docs.xml), where every page
    is included in a single book. When each man page is built on its own the
    targets are absent, and DocBook's check.id.unique prints a bogus
    "Error: no ID for constraint linkend: ..." to stderr for every such link.
    The generated man page is correct regardless, so override the check with
    an empty template to keep the build output clean.
  -->
  <xsl:template name="check.id.unique">
    <xsl:param name="linkend"/>
  </xsl:template>

</xsl:stylesheet>
