"use strict";

var Saml2JwtMapper = function (rootElement, debug) {
  this.rootElement = rootElement;
  this.claims = {};
  if (debug === null)
    this.debug = false;
  else
    this.debug = debug;
  if (this.rootElement) {
    this.processAttributes();
  } else {
    console.log("Warning: DOM root element is null.");
  }
}

Saml2JwtMapper.prototype.setDebug = function(debug) {
  this.debug = debug;
}

Saml2JwtMapper.prototype.processAttributes = function (attrProcessor) {
  this.claims = {};
  if (this.rootElement) {
    var nl = this.rootElement.getElementsByTagName('Attribute');
    if (nl) {
      console.log('Encountered ' + nl.length + ' Attribute tags.');
      for (var i=0; i < nl.length; i++) {
        var attrNode = nl.item(i);
        if (attrProcessor) {
          attrProcessor(attrNode, this.claims, i);
        } else {
          this.extractClaim(attrNode, this.claims, i);
        }
      }
    } else {
      console.log('No attribute tags encountered.');
    }
  } else {
    console.log("Root element is null.");
  }
}

Saml2JwtMapper.prototype.getClaims = function() {
  return this.claims;
}

// Extract a JWT claim from a SAML <Attribute> element.
// This function would be called for each <Attribute> element
// in the list of SAML attributes.
//
//   samlAttr  - DOM element object of type <Attribute>
//   jwtClaims - an existing JWT object to be modified by this
//               funtion.
//   index     - index of attribute within SAML attribute list
//    
Saml2JwtMapper.prototype.extractClaim = extractPlainClaim;

function extractPlainClaim(samlAttr, jwtClaims, index) {
  var name = samlAttr.getAttribute('Name');
  var valueNodeList = samlAttr.getElementsByTagName('AttributeValue');
  if (valueNodeList.length == 1) {
    var valueNode = valueNodeList.item(0);
    jwtClaims[name] = valueNode.textContent;
    if (this.debug)
      console.log(index + ": name / value = " + name + " / " + value);
  }
}

exports.Saml2JwtMapper = Saml2JwtMapper;

