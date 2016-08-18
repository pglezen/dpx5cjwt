// The input to this script is a set of context variables:
//
//     var://context/jwt/claims      - a JSON object containing JWT claims
//                   saml/RelayState - a redirect URL
//
// and an input parameter for the cookie domain name:
//
//     CookieDomain - "None" means don't set the cookie domain.

var crypto      = require('crypto');
var jwk         = require('jwk');
var util        = require('util');
var httpHeader  = require('header-metadata');
var serviceData = require('service-metadata');

// Initialize aslog, the Authorization Server log category.
// If the expected log category does not exist, then use
// the default log category for GatewayScript.
//
var lp = "Login (JWS):";  // Log msg Prefix
var domainName = null;
if (serviceData) {
  domainName = serviceData.domainName;
} else {
  console.warn("%s service-metadata not available.", lp);
}
var logCategory = "as";
if (domainName) {
  logCategory += "-" + domainName;
}
var aslog = console.options({'category': logCategory});
try {
  aslog.debug("%s log category = %s", lp, logCategory);
} catch (e) {
  aslog = console;
  aslog.warn("%s Log category %s does not exist.  Using default.", lp, logCategory);
}

// Retrieve cookie domain from GatewayScript action parameter.
//
var cookieDomain = "None";
if (session.parameters.CookieDomain) {
  cookieDomain = session.parameters.CookieDomain;
  aslog.info("%s Cookie domain set as a parameter to %s", lp, cookieDomain);
} else {
  aslog.info("%s Using default cookie domain: %s", lp, cookieDomain);
}

// Retrieve cookie name from GatewayScript action parameter.
//
var cookieName = "JWT";
if (session.parameters.JwtCookieName) {
  cookieName = session.parameters.JwtCookieName;
  aslog.info("%s JWT cookie name configured to be: %s", lp, cookieName);
} else {
  aslog.notice("%s JWT cookie name not provided.  Default name: %s", lp, cookieName);
}

var jwtCtx = session.name('jwt') || session.createContext('jwt');

var jwtHdr = {"typ":"JWT","alg":"RS256"};
jwtHdr["x5c"] = [jwtCtx.getVariable('x5c')];
var jwtHdrBuf = new Buffer(JSON.stringify(jwtHdr));
aslog.debug("%s Header plain: %s",  lp, jwtHdrBuf.toString('utf8'));
aslog.debug("%s Header b64url: %s", lp, jwtHdrBuf.toString('base64url'));

var claims = jwtCtx.getVariable('claims');
var claimsBuf = new Buffer(JSON.stringify(claims));
aslog.info("%s claims plain: %s",   lp, claimsBuf.toString('utf8'));
aslog.debug("%s claims b64url: %s", lp, claimsBuf.toString('base64url'));

// The content to be signed is
//
//    b64url(header) + '.' + b64url(claims)
//
var signer = crypto.createSign('rsa-sha256');
signer.update(jwtHdrBuf.toString('base64url'));
signer.update('.');
signer.update(claimsBuf.toString('base64url'));
signer.sign('jwtSigner', 'base64url', function(err, sig) {
  if (err) {
    aslog.error("%s signature error: %s", lp, err);
  } else {
    aslog.debug("%s JWS signature string: %s", lp, sig);
    var jws = util.format("%s.%s.%s", jwtHdrBuf.toString('base64url'),
                                      claimsBuf.toString('base64url'),
                                      sig);
    aslog.debug("%s JWS = [%s]", lp, jws);
    if (jws.length < 3000) {
      aslog.info("%s JWS token size = %d", lp, jws.length);
    } else if (jws.length < 4000) {
      aslog.notice("%s JWS token size = %d", lp, jws.length);
    } else {
      aslog.warn("%s JWS token size = %d", lp, jws.length);
    }
    if (jws.length > 5000) {
      aslog.warn("%s warning: Browsers don't handle large HTTP headers consistently.  Curl will truncate Set-Cookie values larger than 5,000", lp);
    }
    var cookieValue = util.format("%s=%s", cookieName, jws);
    if (cookieDomain !== 'None') {
       cookieValue += ';Domain=' + cookieDomain;
    } else {
      aslog.info("%s Cookie domain not set.", lp);
    }
    aslog.debug("%s cookieValue=%s", lp, cookieValue);
    httpHeader.response.set('Set-Cookie', cookieValue);
  }
});

// If RelayState was provided in the POST body, redirect to it.  
// Otherwise, just return.
//
var samlCtx = session.name('saml') || session.createContext('saml');
var relayState = samlCtx.getVariable('RelayState');
if (relayState) {
  aslog.info("%s Sending 302 redirect based on relay state: %s", lp, relayState);
  httpHeader.response.statusCode = "302";
  httpHeader.response.set('Location', relayState);
  serviceData.mpgw.skipBackside = true;
} else {
  aslog.info("%s No relay state found.  Simply returning JWT cookie.", lp);
}
