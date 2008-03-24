<!-- Generate HTML documentation from the Telepathy specification.
The master copy of this stylesheet is in the Telepathy spec repository -
please make any changes there.

Copyright (C) 2006, 2007 Collabora Limited

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:tp="http://telepathy.freedesktop.org/wiki/DbusSpec#extensions-v0"
  exclude-result-prefixes="tp">
  <!--Don't move the declaration of the HTML namespace up here - XMLNSs
  don't work ideally in the presence of two things that want to use the
  absence of a prefix, sadly. -->

  <xsl:template match="*" mode="identity">
    <xsl:copy>
      <xsl:apply-templates mode="identity"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="tp:docstring">
    <xsl:apply-templates select="node()" mode="identity"/>
  </xsl:template>

  <xsl:template match="tp:errors">
    <h1 xmlns="http://www.w3.org/1999/xhtml">Errors:</h1>
    <xsl:apply-templates/>
  </xsl:template>

  <xsl:template match="tp:generic-types">
    <h1 xmlns="http://www.w3.org/1999/xhtml">Generic types:</h1>
    <xsl:call-template name="do-types"/>
  </xsl:template>

  <xsl:template name="do-types">
    <xsl:if test="tp:simple-type">
      <h2 xmlns="http://www.w3.org/1999/xhtml">Simple types:</h2>
      <xsl:apply-templates select="tp:simple-type"/>
    </xsl:if>

    <xsl:if test="tp:enum">
      <h2 xmlns="http://www.w3.org/1999/xhtml">Enumerated types:</h2>
      <xsl:apply-templates select="tp:enum"/>
    </xsl:if>

    <xsl:if test="tp:flags">
      <h2 xmlns="http://www.w3.org/1999/xhtml">Sets of flags:</h2>
      <xsl:apply-templates select="tp:flags"/>
    </xsl:if>

    <xsl:if test="tp:struct">
      <h2 xmlns="http://www.w3.org/1999/xhtml">Structure types:</h2>
      <xsl:apply-templates select="tp:struct"/>
    </xsl:if>

    <xsl:if test="tp:mapping">
      <h2 xmlns="http://www.w3.org/1999/xhtml">Mapping types:</h2>
      <xsl:apply-templates select="tp:mapping"/>
    </xsl:if>

    <xsl:if test="tp:external-type">
      <h2 xmlns="http://www.w3.org/1999/xhtml">Types defined elsewhere:</h2>
      <dl><xsl:apply-templates select="tp:external-type"/></dl>
    </xsl:if>
  </xsl:template>

  <xsl:template match="tp:error">
    <h2 xmlns="http://www.w3.org/1999/xhtml"><a name="{concat(../@namespace, '.', translate(@name, ' ', ''))}"></a><xsl:value-of select="concat(../@namespace, '.', translate(@name, ' ', ''))"/></h2>
    <xsl:apply-templates select="tp:docstring"/>
  </xsl:template>

  <xsl:template match="/tp:spec/tp:copyright">
    <div xmlns="http://www.w3.org/1999/xhtml">
      <xsl:apply-templates/>
    </div>
  </xsl:template>
  <xsl:template match="/tp:spec/tp:license">
    <div xmlns="http://www.w3.org/1999/xhtml" class="license">
      <xsl:apply-templates mode="identity"/>
    </div>
  </xsl:template>

  <xsl:template match="tp:copyright"/>
  <xsl:template match="tp:license"/>

  <xsl:template match="interface">
    <h1 xmlns="http://www.w3.org/1999/xhtml"><a name="{@name}"></a><xsl:value-of select="@name"/></h1>

    <xsl:if test="@tp:causes-havoc">
      <p xmlns="http://www.w3.org/1999/xhtml" class="causes-havoc">
        This interface is <xsl:value-of select="@tp:causes-havoc"/>
        and is likely to cause havoc to your API/ABI if bindings are generated.
        Don't include it in libraries that care about compatibility.
      </p>
    </xsl:if>

    <xsl:if test="tp:requires">
      <p>Implementations of this interface must also implement:</p>
      <ul xmlns="http://www.w3.org/1999/xhtml">
        <xsl:for-each select="tp:requires">
          <li><code><a href="#{@interface}"><xsl:value-of select="@interface"/></a></code></li>
        </xsl:for-each>
      </ul>
    </xsl:if>

    <xsl:apply-templates select="tp:docstring" />

    <xsl:choose>
      <xsl:when test="method">
        <h2 xmlns="http://www.w3.org/1999/xhtml">Methods:</h2>
        <xsl:apply-templates select="method"/>
      </xsl:when>
      <xsl:otherwise>
        <p xmlns="http://www.w3.org/1999/xhtml">Interface has no methods.</p>
      </xsl:otherwise>
    </xsl:choose>

    <xsl:choose>
      <xsl:when test="signal">
        <h2 xmlns="http://www.w3.org/1999/xhtml">Signals:</h2>
        <xsl:apply-templates select="signal"/>
      </xsl:when>
      <xsl:otherwise>
        <p xmlns="http://www.w3.org/1999/xhtml">Interface has no signals.</p>
      </xsl:otherwise>
    </xsl:choose>

    <xsl:choose>
      <xsl:when test="property">
        <h2 xmlns="http://www.w3.org/1999/xhtml">Properties:</h2>
        <dl xmlns="http://www.w3.org/1999/xhtml">
          <xsl:apply-templates select="property"/>
        </dl>
      </xsl:when>
      <xsl:otherwise>
        <p xmlns="http://www.w3.org/1999/xhtml">Interface has no properties.</p>
      </xsl:otherwise>
    </xsl:choose>

    <xsl:call-template name="do-types"/>

  </xsl:template>

  <xsl:template match="tp:flags">
    <h3>
      <a name="type-{@name}">
        <xsl:value-of select="@name"/>
      </a>
    </h3>
    <xsl:apply-templates select="tp:docstring" />
    <dl xmlns="http://www.w3.org/1999/xhtml">
        <xsl:variable name="value-prefix">
          <xsl:choose>
            <xsl:when test="@value-prefix">
              <xsl:value-of select="@value-prefix"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="@name"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
      <xsl:for-each select="tp:flag">
        <dt xmlns="http://www.w3.org/1999/xhtml"><code><xsl:value-of select="concat($value-prefix, '_', @suffix)"/> = <xsl:value-of select="@value"/></code></dt>
        <xsl:choose>
          <xsl:when test="tp:docstring">
            <dd xmlns="http://www.w3.org/1999/xhtml"><xsl:apply-templates select="tp:docstring" /></dd>
          </xsl:when>
          <xsl:otherwise>
            <dd xmlns="http://www.w3.org/1999/xhtml">(Undocumented)</dd>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:for-each>
    </dl>
  </xsl:template>

  <xsl:template match="tp:enum">
    <h3 xmlns="http://www.w3.org/1999/xhtml">
      <a name="type-{@name}">
        <xsl:value-of select="@name"/>
      </a>
    </h3>
    <xsl:apply-templates select="tp:docstring" />
    <dl xmlns="http://www.w3.org/1999/xhtml">
        <xsl:variable name="value-prefix">
          <xsl:choose>
            <xsl:when test="@value-prefix">
              <xsl:value-of select="@value-prefix"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="@name"/>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
      <xsl:for-each select="tp:enumvalue">
        <dt xmlns="http://www.w3.org/1999/xhtml"><code><xsl:value-of select="concat($value-prefix, '_', @suffix)"/> = <xsl:value-of select="@value"/></code></dt>
        <xsl:choose>
          <xsl:when test="tp:docstring">
            <dd xmlns="http://www.w3.org/1999/xhtml"><xsl:apply-templates select="tp:docstring" /></dd>
          </xsl:when>
          <xsl:otherwise>
            <dd xmlns="http://www.w3.org/1999/xhtml">(Undocumented)</dd>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:for-each>
    </dl>
  </xsl:template>

  <xsl:template match="property">
    <dt xmlns="http://www.w3.org/1999/xhtml">
      <xsl:if test="@name">
        <code><xsl:value-of select="@name"/></code> -
      </xsl:if>
      <code><xsl:value-of select="@type"/></code> -
      <code>(<xsl:value-of select="@access"/>)</code>
      <xsl:call-template name="parenthesized-tp-type"/>
    </dt>
    <dd xmlns="http://www.w3.org/1999/xhtml">
      <xsl:apply-templates select="tp:docstring"/>
    </dd>
  </xsl:template>

  <xsl:template match="tp:mapping">
    <div xmlns="http://www.w3.org/1999/xhtml" class="struct">
      <h3>
        <a name="type-{@name}">
          <xsl:value-of select="@name"/>
        </a> - a{
        <xsl:for-each select="tp:member">
          <xsl:value-of select="@type"/>
          <xsl:text>: </xsl:text>
          <xsl:value-of select="@name"/>
          <xsl:if test="position() != last()"> &#x2192; </xsl:if>
        </xsl:for-each>
        }
      </h3>
      <div class="docstring">
        <xsl:apply-templates select="tp:docstring"/>
      </div>
      <div>
        <h4>Members</h4>
        <dl>
          <xsl:apply-templates select="tp:member" mode="members-in-docstring"/>
        </dl>
      </div>
    </div>
  </xsl:template>

  <xsl:template match="tp:docstring" mode="in-index"/>

  <xsl:template match="tp:simple-type | tp:enum | tp:flags | tp:external-type"
    mode="in-index">
    - <xsl:value-of select="@type"/>
  </xsl:template>

  <xsl:template match="tp:simple-type">
    <div xmlns="http://www.w3.org/1999/xhtml" class="simple-type">
      <h3>
        <a name="type-{@name}">
          <xsl:value-of select="@name"/>
        </a> - <xsl:value-of select="@type"/>
      </h3>
      <div class="docstring">
        <xsl:apply-templates select="tp:docstring"/>
      </div>
    </div>
  </xsl:template>

  <xsl:template match="tp:external-type">
    <div xmlns="http://www.w3.org/1999/xhtml" class="external-type">
      <dt>
        <a name="type-{@name}">
          <xsl:value-of select="@name"/>
        </a> - <xsl:value-of select="@type"/>
      </dt>
      <dd>Defined by: <xsl:value-of select="@from"/></dd>
    </div>
  </xsl:template>

  <xsl:template match="tp:struct" mode="in-index">
    - ( <xsl:for-each select="tp:member">
          <xsl:value-of select="@type"/>
          <xsl:if test="position() != last()">, </xsl:if>
        </xsl:for-each> )
  </xsl:template>

  <xsl:template match="tp:mapping" mode="in-index">
    - a{ <xsl:for-each select="tp:member">
          <xsl:value-of select="@type"/>
          <xsl:if test="position() != last()"> &#x2192; </xsl:if>
        </xsl:for-each> }
  </xsl:template>

  <xsl:template match="tp:struct">
    <div xmlns="http://www.w3.org/1999/xhtml" class="struct">
      <h3>
        <a name="type-{@name}">
          <xsl:value-of select="@name"/>
        </a> - (
        <xsl:for-each select="tp:member">
          <xsl:value-of select="@type"/>
          <xsl:text>: </xsl:text>
          <xsl:value-of select="@name"/>
          <xsl:if test="position() != last()">, </xsl:if>
        </xsl:for-each>
        )
      </h3>
      <div class="docstring">
        <xsl:apply-templates select="tp:docstring"/>
      </div>
      <xsl:choose>
        <xsl:when test="string(@array-name) != ''">
          <p>In bindings that need a separate name, arrays of
            <xsl:value-of select="@name"/> should be called
            <xsl:value-of select="@array-name"/>.</p>
        </xsl:when>
        <xsl:otherwise>
          <p>Arrays of <xsl:value-of select="@name"/> don't generally
            make sense.</p>
        </xsl:otherwise>
      </xsl:choose>
      <div>
        <h4>Members</h4>
        <dl>
          <xsl:apply-templates select="tp:member" mode="members-in-docstring"/>
        </dl>
      </div>
    </div>
  </xsl:template>

  <xsl:template match="method">
    <div xmlns="http://www.w3.org/1999/xhtml" class="method">
      <h3 xmlns="http://www.w3.org/1999/xhtml">
        <a name="{concat(../@name, concat('.', @name))}">
          <xsl:value-of select="@name"/>
        </a> (
        <xsl:for-each xmlns="" select="arg[@direction='in']">
          <xsl:value-of select="@type"/>: <xsl:value-of select="@name"/>
          <xsl:if test="position() != last()">, </xsl:if>
        </xsl:for-each>
        ) &#x2192;
        <xsl:choose>
          <xsl:when test="arg[@direction='out']">
            <xsl:for-each xmlns="" select="arg[@direction='out']">
              <xsl:value-of select="@type"/>
              <xsl:if test="position() != last()">, </xsl:if>
            </xsl:for-each>
          </xsl:when>
          <xsl:otherwise>nothing</xsl:otherwise>
        </xsl:choose>
      </h3>
      <div xmlns="http://www.w3.org/1999/xhtml" class="docstring">
        <xsl:apply-templates select="tp:docstring" />
      </div>

      <xsl:if test="arg[@direction='in']">
        <div xmlns="http://www.w3.org/1999/xhtml">
          <h4>Parameters</h4>
          <dl xmlns="http://www.w3.org/1999/xhtml">
            <xsl:apply-templates select="arg[@direction='in']"
              mode="parameters-in-docstring"/>
          </dl>
        </div>
      </xsl:if>

      <xsl:if test="arg[@direction='out']">
        <div xmlns="http://www.w3.org/1999/xhtml">
          <h4>Returns</h4>
          <dl xmlns="http://www.w3.org/1999/xhtml">
            <xsl:apply-templates select="arg[@direction='out']"
              mode="returns-in-docstring"/>
          </dl>
        </div>
      </xsl:if>

      <xsl:if test="tp:possible-errors">
        <div xmlns="http://www.w3.org/1999/xhtml">
          <h4>Possible errors</h4>
          <dl xmlns="http://www.w3.org/1999/xhtml">
            <xsl:apply-templates select="tp:possible-errors/tp:error"/>
          </dl>
        </div>
      </xsl:if>

    </div>
  </xsl:template>

  <xsl:template name="parenthesized-tp-type">
    <xsl:if test="@tp:type">
      <xsl:variable name="tp-type" select="@tp:type"/>
      <xsl:variable name="single-type">
        <xsl:choose>
          <xsl:when test="contains($tp-type, '[]')">
            <xsl:value-of select="substring-before($tp-type, '[]')"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="$tp-type"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:choose>
        <xsl:when test="//tp:simple-type[@name=$tp-type]" />
        <xsl:when test="//tp:simple-type[concat(@name, '[]')=$tp-type]" />
        <xsl:when test="//tp:struct[concat(@name, '[]')=$tp-type][string(@array-name) != '']" />
        <xsl:when test="//tp:struct[@name=$tp-type]" />
        <xsl:when test="//tp:enum[@name=$tp-type]" />
        <xsl:when test="//tp:enum[concat(@name, '[]')=$tp-type]" />
        <xsl:when test="//tp:flags[@name=$tp-type]" />
        <xsl:when test="//tp:flags[concat(@name, '[]')=$tp-type]" />
        <xsl:when test="//tp:mapping[@name=$tp-type]" />
        <xsl:when test="//tp:external-type[concat(@name, '[]')=$tp-type]" />
        <xsl:when test="//tp:external-type[@name=$tp-type]" />
        <xsl:otherwise>
          <xsl:message terminate="yes">
            <xsl:text>ERR: Unable to find type '</xsl:text>
            <xsl:value-of select="$tp-type"/>
            <xsl:text>'&#10;</xsl:text>
          </xsl:message>
        </xsl:otherwise>
      </xsl:choose>
      (<a href="#type-{$single-type}"><xsl:value-of select="$tp-type"/></a>)
    </xsl:if>
  </xsl:template>

  <xsl:template match="tp:member" mode="members-in-docstring">
    <dt xmlns="http://www.w3.org/1999/xhtml">
      <code><xsl:value-of select="@name"/></code> -
      <code><xsl:value-of select="@type"/></code>
      <xsl:call-template name="parenthesized-tp-type"/>
    </dt>
    <dd xmlns="http://www.w3.org/1999/xhtml">
      <xsl:choose>
        <xsl:when test="tp:docstring">
          <xsl:apply-templates select="tp:docstring" />
        </xsl:when>
        <xsl:otherwise>
          <em>(undocumented)</em>
        </xsl:otherwise>
      </xsl:choose>
    </dd>
  </xsl:template>

  <xsl:template match="arg" mode="parameters-in-docstring">
    <dt xmlns="http://www.w3.org/1999/xhtml">
      <code><xsl:value-of select="@name"/></code> -
      <code><xsl:value-of select="@type"/></code>
      <xsl:call-template name="parenthesized-tp-type"/>
    </dt>
    <dd xmlns="http://www.w3.org/1999/xhtml">
      <xsl:apply-templates select="tp:docstring" />
    </dd>
  </xsl:template>

  <xsl:template match="arg" mode="returns-in-docstring">
    <dt xmlns="http://www.w3.org/1999/xhtml">
      <xsl:if test="@name">
        <code><xsl:value-of select="@name"/></code> -
      </xsl:if>
      <code><xsl:value-of select="@type"/></code>
      <xsl:call-template name="parenthesized-tp-type"/>
    </dt>
    <dd xmlns="http://www.w3.org/1999/xhtml">
      <xsl:apply-templates select="tp:docstring"/>
    </dd>
  </xsl:template>

  <xsl:template match="tp:possible-errors/tp:error">
    <dt xmlns="http://www.w3.org/1999/xhtml">
      <code><xsl:value-of select="@name"/></code>
    </dt>
    <dd xmlns="http://www.w3.org/1999/xhtml">
        <xsl:variable name="name" select="@name"/>
        <xsl:choose>
          <xsl:when test="tp:docstring">
            <xsl:apply-templates select="tp:docstring"/>
          </xsl:when>
          <xsl:when test="//tp:errors/tp:error[concat(../@namespace, '.', translate(@name, ' ', ''))=$name]/tp:docstring">
            <xsl:apply-templates select="//tp:errors/tp:error[concat(../@namespace, '.', translate(@name, ' ', ''))=$name]/tp:docstring"/> <em xmlns="http://www.w3.org/1999/xhtml">(generic description)</em>
          </xsl:when>
          <xsl:otherwise>
            (Undocumented.)
          </xsl:otherwise>
        </xsl:choose>
    </dd>
  </xsl:template>

  <xsl:template match="signal">
    <div xmlns="http://www.w3.org/1999/xhtml" class="signal">
      <h3 xmlns="http://www.w3.org/1999/xhtml">
        <a name="{concat(../@name, concat('.', @name))}">
          <xsl:value-of select="@name"/>
        </a> (
        <xsl:for-each xmlns="" select="arg">
          <xsl:value-of select="@type"/>: <xsl:value-of select="@name"/>
          <xsl:if test="position() != last()">, </xsl:if>
        </xsl:for-each>
        )</h3>
      <div xmlns="http://www.w3.org/1999/xhtml" class="docstring">
        <xsl:apply-templates select="tp:docstring"/>
      </div>

      <xsl:if test="arg">
        <div xmlns="http://www.w3.org/1999/xhtml">
          <h4>Parameters</h4>
          <dl xmlns="http://www.w3.org/1999/xhtml">
            <xsl:apply-templates select="arg" mode="parameters-in-docstring"/>
          </dl>
        </div>
      </xsl:if>
    </div>
  </xsl:template>

  <xsl:output method="xml" indent="no" encoding="ascii"
    omit-xml-declaration="yes"
    doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"
    doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN" />

  <xsl:template match="/tp:spec">
    <html xmlns="http://www.w3.org/1999/xhtml">
      <head>
        <title>
          <xsl:value-of select="tp:title"/>
          <xsl:if test="tp:version">
            <xsl:text> version </xsl:text>
            <xsl:value-of select="tp:version"/>
          </xsl:if>
        </title>
        <style type="text/css">

          body {
            font-family: sans-serif;
            margin: 2em;
            height: 100%;
            font-size: 1.2em;
          }
          h1 {
            padding-top: 5px;
            padding-bottom: 5px;
            font-size: 1.6em;
            background: #dadae2;
          }
          h2 {
            font-size: 1.3em;
          }
          h3 {
            font-size: 1.2em;
          }
          a:link, a:visited, a:link:hover, a:visited:hover {
            font-weight: bold;
          }
          .topbox {
            padding-top: 10px;
            padding-left: 10px;
            border-bottom: black solid 1px;
            padding-bottom: 10px;
            background: #dadae2;
            font-size: 2em;
            font-weight: bold;
            color: #5c5c5c;
          }
          .topnavbox {
            padding-left: 10px;
            padding-top: 5px;
            padding-bottom: 5px;
            background: #abacba;
            border-bottom: black solid 1px;
            font-size: 1.2em;
          }
          .topnavbox a{
            color: black;
            font-weight: normal;
          }
          .sidebar {
            float: left;
            /* width:9em;
            border-right:#abacba solid 1px;
            border-left: #abacba solid 1px;
            height:100%; */
            border: #abacba solid 1px;
            padding-left: 10px;
            margin-left: 10px;
            padding-right: 10px;
            margin-right: 10px;
            color: #5d5d5d;
            background: #dadae2;
          }
          .sidebar a {
            text-decoration: none;
            border-bottom: #e29625 dotted 1px;
            color: #e29625;
            font-weight: normal;
          }
          .sidebar h1 {
            font-size: 1.2em;
            color: black;
          }
          .sidebar ul {
            padding-left: 25px;
            padding-bottom: 10px;
            border-bottom: #abacba solid 1px;
          }
          .sidebar li {
            padding-top: 2px;
            padding-bottom: 2px;
          }
          .sidebar h2 {
            font-style:italic;
            font-size: 0.81em;
            padding-left: 5px;
            padding-right: 5px;
            font-weight: normal;
          }
          .date {
            font-size: 0.6em;
            float: right;
            font-style: italic;
          }
          .method {
            margin-left: 1em;
            margin-right: 4em;
          }
          .signal {
            margin-left: 1em;
            margin-right: 4em;
          }

        </style>
      </head>
      <body>
        <h1 class="topbox">
          <xsl:value-of select="tp:title" />
        </h1>
        <xsl:if test="tp:version">
          <h2>Version <xsl:apply-templates select="tp:version"/></h2>
        </xsl:if>
        <xsl:apply-templates select="tp:copyright"/>
        <xsl:apply-templates select="tp:license"/>
        <xsl:apply-templates select="tp:docstring"/>

        <h2>Interfaces</h2>
        <ul>
        <xsl:for-each select="node/interface">
            <li><code><a href="#{@name}"><xsl:value-of select="@name"/></a></code></li>
          </xsl:for-each>
        </ul>

        <xsl:apply-templates select="node"/>
        <xsl:apply-templates select="tp:generic-types"/>
        <xsl:apply-templates select="tp:errors"/>

        <h1>Index</h1>
        <h2>Index of interfaces</h2>
        <ul>
        <xsl:for-each select="node/interface">
            <li><code><a href="#{@name}"><xsl:value-of select="@name"/></a></code></li>
          </xsl:for-each>
        </ul>
        <h2>Index of types</h2>
        <ul>
          <xsl:for-each select="//tp:simple-type | //tp:enum | //tp:flags | //tp:mapping | //tp:struct | //tp:external-type">
            <xsl:sort select="@name"/>
            <li>
              <code>
                <a href="#type-{@name}">
                  <xsl:value-of select="@name"/>
                </a>
              </code>
              <xsl:apply-templates mode="in-index" select="."/>
            </li>
          </xsl:for-each>
        </ul>
      </body>
    </html>
  </xsl:template>

</xsl:stylesheet>

<!-- vim:set sw=2 sts=2 et: -->
