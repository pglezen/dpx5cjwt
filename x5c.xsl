<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
   xmlns:dp="http://www.datapower.com/extensions"
   xmlns:dpconfig="http://www.datapower.com/param/config"
   exclude-result-prefixes="dp dpconfig"
   extension-element-prefixes="dp dpconfig"
   version="1.0">

   <!--
     Input: a DataPower certificate object.
     Output: the base64 PEM contents in var://context/jwt/x5c.

     This stylesheet fills a gap missing in the GatewayScript
     crypto API for retreiving certificate information.
     -->

  <dp:summary xmlns="">
    <operation>xform</operation>
    <description>Retrieve certificate as base64.</description>
  </dp:summary>
   
  <xsl:param name="dpconfig:certName" select="'name:jwtSigner'"/>
  <dp:param  name="dpconfig:certName" type="dmString" xmlns="">
    <display>JWT Signer Certificate Name</display>
    <description>
      Specify the DP certificate object name
    </description>
    <default>name:jwtSigner</default>
  </dp:param>   

  <xsl:variable name="domain" select="dp:variable('var://service/domain-name')"/>
  <xsl:variable name="cat"    select="concat('as-',$domain)"/>
  
  <xsl:template match="/">
    <xsl:message dp:type="{$cat}" dp:priority="debug">Login: Retrieving base64 contents for certificate object <xsl:value-of select="$dpconfig:certName"/> </xsl:message>

    <dp:set-variable name="'var://context/jwt/x5c'" value="dp:base64-cert($dpconfig:certName)"/>
    
    <xsl:message dp:type="{$cat}" dp:priority="debug">Login: JWT Signer Cert: <xsl:value-of select="dp:variable('var://context/jwt/x5c')"/></xsl:message>


  </xsl:template>

</xsl:stylesheet>
