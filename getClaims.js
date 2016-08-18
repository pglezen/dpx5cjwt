// The input to this script is a set of context variables:
//
//     var://context/saml/sp/entityID  - SP Entity ID
//                       /idp/entityID - IDP Entity ID
//                       /idp/redirect - IDP redirect URL
//                       /nameid       - user id
//                       /audience     - audience restriction
//                       /notafter     - expiration time as XML Date
//                       /attributes   - GFIPM claims
//
// The GFIPM claims are in the form:
//
//   <profile>
//     <GfipmAttribute id="GfipmIdentityProviderId">GFIPM:TIB:LAC-ISAB:IDP:CWS:Local</GfipmAttribute>
//     <GfipmAttribute id="GfipmLocalId">someId</GfipmAttribute>
//     ...
//   </profile>
//

// Set a log prefix to identify this script in the log files.
//
var lp = "Login (GetClaims):";

// Set up logging with a category of the form as-<domain name>.
//
var serviceData = require('service-metadata');
var domainName = null;
if (serviceData) {
  domainName = serviceData.domainName;
} else {
  console.log("%s serviceData not defined.", lp);
}

var logCategory = 'as';
if (domainName) {
  logCategory += "-" + domainName;
}
var aslog = console.options({'category': logCategory});
try {
  aslog.debug("%s logging to %s", lp, logCategory);
} catch(e) {
  aslog = console;
  aslog.warn("%s %s category does not exist.  Using default.", lp, logCategory);
}

// Token validity in seconds from this instant.
//
var tokenDuration = 7200;
if (session.parameters.TokenDuration) {
  tokenDuration = session.parameters.TokenDuration;
  aslog.info("%s Token duration set as a parameter: %d", lp, tokenDuration);
} else {
  aslog.info("%s Using default token duration: %d", lp, tokenDuration);
}

// This parameter sets the issuer field for the JWT.
//
var issuer = 'Your:Issuer:URI:Here';
if (session.parameters.Issuer) {
  issuer = session.parameters.Issuer;
  aslog.info("%s Issuer set as a parameter: %s", lp, issuer);
} else {
  aslog.info("%s Using default issuer: %s", lp, issuer);
}

var samlCtx = session.name('saml');
var jwt = {};
var subject = samlCtx.getVariable('nameid');
if (subject) {
  jwt['sub'] = subject;
  aslog.info("%s 'sub': %s", lp, subject);
} else {
  aslog.notice("%s 'nameid' in saml context was empty.", lp);
}

jwt['iss'] = issuer;
var now = new Date();
var expiry = new Date(now.getTime() + tokenDuration * 1000);
jwt['exp'] = Math.floor(expiry.getTime() / 1000);
jwt['iat'] = Math.floor(   now.getTime() / 1000);

aslog.info("%s 'iss': %s", lp, jwt['iss']);
aslog.info("%s 'exp': %s", lp, jwt['exp']);
aslog.info("%s 'iat': %s", lp, jwt['iat']);

var samlAttrNodeList = samlCtx.getVariable('attributes');
aslog.debug("%s SAML attribute context length = %d", lp, samlAttrNodeList.length);

if (samlAttrNodeList.length > 0) {
   // Process your SAML attributes here by adding relevant attributes
   // to the jwt dictionary.
} else {
  aslog.warn('%s No attributes found under "attributes" context.', lp);
}

var jwtCtx = session.name('jwt') || session.createContext('jwt');
jwtCtx.setVariable('claims', jwt);
