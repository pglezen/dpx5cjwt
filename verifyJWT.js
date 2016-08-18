// The input to this script is a HTTP cookie header.
//

var util        = require('util');
var crypto      = require('crypto');
var httpHeader  = require('header-metadata');
var serviceData = require('service-metadata');
var cookieUtils = require('./cookie');

// Initialize the EP (Enforcement Point) log category.
// If the expected log category does not exist, then
// use the default log category for GatewayScript.
//
var lp = "EP (Verify):";  // Log message Prefix
var domainName = null;
if (serviceData) {
  domainName = serviceData.domainName;
} else {
  console.warn("%s service-metadata not available.", lp);
}
var logCategory = "ep";
if (domainName) {
  logCategory += "-" + domainName;
}
var eplog = console.options({'category': logCategory});
try {
  eplog.debug("%s log category = %s", lp, logCategory);
} catch (e) {
  eplog = console;
  eplog.warn("%s Log category %s does not exist.  Using default.", lp, logCategory);
}

// Retrieve key object name from GatewayScript action parameter.
//
var jwtSigner = "name:jwtSigner";
if (session.parameters.JwtSigner) {
  jwtSigner = session.parameters.JwtSigner;
  eplog.info("%s JWT signer object configured to be: [%s]", lp, jwtSigner);
} else {
  eplog.notice("%s JWT signer object default value: [%s]", lp, jwtSigner);
}

// Retrieve cookie name from GatewayScript action parameter.
//
var cookieName = "JWT";
if (session.parameters.JwtCookieName) {
  cookieName = session.parameters.JwtCookieName;
  eplog.info("%s JWT cookie name configured to be: %s", lp, cookieName);
} else {
  eplog.notice("%s JWT cookie name not provided.  Default name: %s", lp, cookieName);
}

// Retrieve JWT expiration interval from GatewayScript action parameter.
// These are the seconds after which a JWT is no longer considered valid.
// If set to zero, do not validate expiry.  This is useful for testing
// in some cases; not good for production.
//
var jwtExpiry = 7200;  // Seconds after which JWT is no longer valid.
if (session.parameters.JwtExpiry) {
  jwtExpiry = session.parameters.JwtExpiry;
  if (jwtExpiry == 0) {
    eplog.warn("%s JwtExpiry parameter for verifyJWT.js set to zero. "
             + "No expiration validation will be enforced.", lp);
  } else {
    eplog.info("%s JwtExpiry configured to be: %s", lp, jwtExpiry);
  }
} else {
  eplog.notice("%s JwtExpiry not provided.  Default value: %s", lp, jwtExpiry);
}

// Define function for causing error rule to be invoked.
// This is usually done when authentication fails for various reasons.
//
function authenticationFailed(reason) {
  httpHeader.response.statusCode = "302";
  session.reject(reason);
}

// Fetch the signed JWT (JWS) from the cookie header.
//
var cookieValue  = null;
var cookieHeader = httpHeader.original.get('cookie');
if (cookieHeader) {
  var cookies = cookieUtils.parse(cookieHeader);
  if (cookies) {
    cookieValue = cookies[cookieName];
    if (cookieValue) {
      eplog.debug("%s %s cookie value = %s", lp, cookieName, cookieValue);
      parseJWS(cookieValue);
    } else {
      authenticationFailed(util.format("%s cookie absent", cookieName));
    }
  } else {
    authenticationFailed("Failed to parse cookie header");
  }
} else {
  authenticationFailed("Cookie header absent");
}

// A signed JWT is three base64-url encoded fields separated by periods.
//
function parseJWS(jws) {
  var jwsComponents = jws.split('.');
  if (jwsComponents.length === 3) {
    eplog.info("%s Found 3 JWS components.", lp);
    var jwsHeaderBuf = new Buffer(jwsComponents[0], 'base64url');
    var jwsBodyBuf   = new Buffer(jwsComponents[1], 'base64url');
    var jwsSigBuf    = new Buffer(jwsComponents[2], 'ascii');
    eplog.debug("%s JWS header: %s", lp, jwsHeaderBuf.toString());
    eplog.info("%s JWS body: %s",    lp, jwsBodyBuf.toString());
    eplog.debug("%s JWS sig: %s",    lp, jwsSigBuf.toString());
    var jwsHeader = JSON.parse(jwsHeaderBuf.toString());
    var jwsClaims = JSON.parse(jwsBodyBuf.toString());
    var alg = jwsHeader['alg'];
    eplog.info("%s JWT 'alg' header specified %s", lp, alg);
    if (alg != 'RS256') {
      eplog.warn("%s This class only supports signature verification for 'RS256'", lp);
      eplog.info("%s JWT specified '%s' in 'alg' header", lp, alg);
      authenticationFailed("Unsupported 'alg' header.");
    } else {
      var jwsSig   = jwsSigBuf.toString();
      var verifier = crypto.createVerify('rsa-sha256');
      verifier.update(jwsComponents[0]); // b64url(header)
      verifier.update('.');              // separator
      verifier.update(jwsComponents[1]); // b64url(claims)
      verifier.verify(jwtSigner, jwsSig, function(err) {
        if (err) {
          eplog.warn("%s Failed to verify signature for JWT token.", lp);
          authenticationFailed("Token verification failed.");
          var errCtx = session.name('error') || session.createContext('error');
          errCtx.setVariable('status', '403');
          eplog.warn("%s Returning 403 to client", lp);
        } else {
          validateTS(jwsClaims);
          eplog.info("%s Token verification succeeded.", lp);
          var jwtCtx = session.name('jwt') || session.createContext('jwt');
          jwtCtx.setVariable('header', jwsHeader);
          jwtCtx.setVariable('claims', jwsClaims);
        }
      });
    }
  } else {
    authenticationFailed("Invalid JWS format.");
  }
}

// Returns true if valid;
//
function validateTS(claims) {
  var exp = claims && claims['exp'];
  var valid = false;
  if (exp) {
    var now = new Date();
    var secondsLeft = exp - now.getTime() / 1000;
    if (secondsLeft > 0) {
      valid = true;
      eplog.info("%s Token still valid for %d more seconds.", lp, secondsLeft);
    } else {
      eplog.notice("%s Token expired %s seconds ago.", lp, -secondsLeft);
    }
  } else {
    eplog.warn("%s 'exp' header not found.  Consider token expired.", lp);
  }
  return valid;
}

