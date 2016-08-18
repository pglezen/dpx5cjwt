var hm          = require('header-metadata');
var serviceData = require('service-metadata');

// Initialize the EP (Enforcement Point) log category.
// If the expected log category does not exist, then
// use the default log category for GatewayScript.
//
var lp = "EP (Process):";  // Log message Prefix
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

// Read from var://context/jwt/claims.
//
var ctx = session.name('jwt');
var jwtClaimStr = null;
if (ctx) {
  jwtClaimStr = ctx.getVariable('claims');
  var claimType = typeof jwtClaimStr;
  eplog.debug("%s typeof(claims) = %s", lp, claimType );
}
var failureWarning = "Failing to set the HTTP headers should cause backend to reject the request.";

if (jwtClaimStr) {
  eplog.debug('%s Claims String = %s', lp, jwtClaimStr);
  try {
    var claims = jwtClaimStr;
    eplog.info("%s JWT claims parsed.  Setting HTTP headers.", lp);
    var sub = claims['sub'];
    if (sub) {
       eplog.notice('%s HTTP JWT Subject: %s', lp, sub);
    } else {
       eplog.warn('%s HTTP JWT \"sub\" claim is missing.', lp);
    }
    for (var claimName in claims) {
      eplog.debug('%s %-20s = %s', lp, claimName, claims[claimName]);
      hm.current.set(claimName, claims[claimName]);
    }
  } catch (ex) {
    console.error("%s Failed to parse HTTP JWT Claims. %s", lp, ex);
    console.info("%s Claim string: %s", lp, jwtClaimStr);
    console.warn("%s %s", lp, failureWarning);
  }
} else {
  eplog.warn("%s HTTP JWT processing cannot locate JWT in var://context/jwt/claims context.", lp);
  eplog.warn("%s %s", lp, failureWarning);
}
