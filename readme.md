HTTP Basic/Digest authentication helper for XMLHttpRequest.

Works both as npm package and as pure JS.

Usage:

1. Create new AuthCalc(). Pass username/password or override getCredentials().
2. Sign EACH request with AuthCalc.sign(xhr, req).
3. Got 401/407? Pass the response to AuthCalc.updateServerParams() to init/restart the digest.
4. Got 401/407 second+ time in a row? Ask for new username/password.

Handles both Basic and Digest authentication. Prefers Digest, unless you configure it for Basic, in which case first tries to pass Basic and switches to Digest if required.

See httpauth.js for more comments.

To work in pure JS, crypto-js needs to be loaded and available as CryptoJS.

References/See also:
* https://github.com/Kynec/digest-ajax