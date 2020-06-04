/*
The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
if (typeof exports == 'undefined')
	exports = {};

/*
HTTP Authentication Calculator (Basic and Digest)
Parts are based on:
  https://github.com/Kynec/digest-ajax
  Copyright (c) 2014 Kynec Studios, Andrew Mitchell (MIT License)

Both Basic and Digest challenges are supported by default. Use .authType to limit to Digest only.

1. Create new AuthCalc(). Pass username/password or override getCredentials().
2. Sign EACH request with AuthCalc.sign(xhr, req).
3. Got 401/407? Pass the response to AuthCalc.updateServerParams() to init/restart the digest.
4. Got 401/407 second+ time in a row? Ask for new username/password.
 
Example:
  digest = new AuthCalc(username, password)
  function send(url, type, data) {
    var xhr = new XMLHttpRequest();
    xhr.open(type, url, false);
    digest.sign(xhr, {url: url, type: type, data: data});
    xhr.send();
    return xhr;
  }
  var xhr = send(URL, "GET");
  if (xhr.status in [401, 403]) {
    digest.updateServerParams(xhr);
    xhr = send(URL, "GET");
  }


HTTP Authentication cheatsheet:
  http://www.rfc-editor.org/rfc/rfc2617.txt

The server rejects all unsigned/non-authenticated requests with 401/407 and requests authentication
by providing challenges for one or more methods of authentication:
  WWW-Authenticate:	Basic param1=value, param2=value
  WWW-Authenticate: Digest param1=value, param2=value

The client chooses one and responds:
  Authenticate: Basic params params
  Authenticate: Digest params params


Basic Authentication:
  Username and password in plaintext. Can be sent even without a challenge.
  Less secure, though okay with HTTPS.

Digest Authentication:
  https://en.wikipedia.org/wiki/Digest_access_authentication

1. The server rejects each unsigned/missigned request with WWW-Authenticate -> server_nonce and other server_params
2. You should repeat the request + signature(own_nonce, request_details, server_nonce, server_params)
3. Following compatible requests can be signed with the same (server_nonce, server_params), just update own params

Which requests are compatible? The server decides. Therefore you should always expect 401/407 and restart the sequence
with new server_params.

  > At this point the client may make another request, reusing the server nonce value (the server only issues a new nonce
  > for each "401" response) but providing a new client nonce (cnonce). For subsequent requests, the hexadecimal request
  > counter (nc) must be greater than the last value it used
  > Obviously changing the method, URI and/or counter value will result in a different response value.

Q: Should you skip AuthCalc.sign() before you've got the initial challenge? No! It'll work everything out by itself.
  Sometimes you can sign without a challenge (basic auth), otherwise it'll skip signing. Just sign() every request.

Q: Should you tell AuthCalc if the handshake has failed? No! We don't care; if the signature is bad,
  the server must return new server_params all the same.
*/


/*
Constructs a new AuthCalc.
Username and password can either be provided directly or by overriding getCredentials().
*/
AuthCalc = function(username, password) {
	this.username = username;
	this.password = password;
};
exports.AuthCalc = AuthCalc;
/*
Override to supply credentials on demand instead of storing them inside AuthCalc.
Returns an Object that must contain a 'username' and 'password' key/value pairs.
*/
AuthCalc.prototype.getCredentials = function() {
    return {
        username: this.username,
        password: this.password,
    };
};

/*
The server may support multiple authentication methods, configure what you prefer/approve:
	'digest'	Digest only
	'basic'		Basic by default	Digest if required
	null		Auto/Both			Digest by default, Basic if required
*/
AuthCalc.prototype.authType = null;


/*
Value of the WWW-Authenticate header name to retrieve. This can be 
changed if the server is returning authentication information on a 
different header name value. This is commonly the case when avoiding 
built-in browser authentication prompts.
*/
AuthCalc.prototype.WWW_AUTHENTICATE = 'WWW-Authenticate';

//Latest WWW-Authenticate challenge of the supported type (including the type itself)
AuthCalc.prototype.AUTH_PARAMS = null;

AuthCalc.prototype.parseWWWAuthenticateHeader = function(header) {
    var params = {};
    params[null] = header.split(' ').shift(); //challenge type
    var regex = /([^"',\s]*)="([^"]*)/gm;
    var result = null;
    do {
        result = regex.exec(header);
        if (result !== null) {
            params[result[1]] = result[2];
        }
    }
    while (result !== null);
    return params;
}

/*
Parses 401/407 server response and extracts digest params.
*/
AuthCalc.prototype.updateServerResponse = function(xhr) {
	if (!xhr || xhr.readyState < 2) { //HEADERS_RECEIVED
		console.error("No XHR / no headers ready at XHR");
		return;
	}
	
	//There could be multiple WWW-Authenticate headers with challenges for different auth types.
	//In theory they can even be merged into a single header but no one supports that.
	var headers = xhr.getAllResponseHeaders().trim().split(/[\r\n]+/);
	var challenges = {};
	for(let i=0; i<headers.length; i++) {
		let parts = headers[i].split(': ');
		let name = parts.shift().toLowerCase();
		let value = parts.join(': ');
		if (name == this.WWW_AUTHENTICATE.toLowerCase()) {
			let params = this.parseWWWAuthenticateHeader(value);
			if (!(null in params))
				continue;
			params[null] = params[null].toLowerCase();
			challenges[params[null]] = params;
		}
	}
	
	if (challenges.length <= 0) {
		//These fn days servers need to Access-Control-Expose-Headers this header too.
		console.error('No "'+this.WWW_AUTHENTICATE+'" headers in server response');
		return;
	}
	
	//Choose the authentication method. Digest is preferred
	if (('basic' in challenges) && (this.authType=='basic'))
		this.AUTH_PARAMS = challenges['basic'];
	if (('digest' in challenges) && (!this.authType || (this.authType=='basic') || (this.authType=='digest')))
		this.AUTH_PARAMS = challenges['digest'];
	else if (('basic' in challenges) && !this.authType)
		this.AUTH_PARAMS = challenges['basic'];
	else {
		console.error('No allowed authentication challenges in server response. All challenges: ', challenges);
		return;
	}
	
	//Reset all the authentication methods
    this.nonce_count = 1;
}


/*
If Digest authentication succeeds, the username and HA1 are stored here,
where they are used for future requests.
*/
AuthCalc.prototype.AUTH_HA1 = null;
AuthCalc.prototype.AUTH_USERNAME = null;

AuthCalc.prototype.generateCnonce = function() {
    var cnonceChars = 'abcdef0123456789';
    var cnonce = '';
    for (var i = 0; i < 8; i++) {
        var randNum = Math.floor(Math.random() * cnonceChars.length);
        cnonce += cnonceChars.substr(randNum, 1);
    }
    return cnonce;
}

/*
Constructs an authorization header for the next request.
Returns null if there's no challenge available.
*/
AuthCalc.prototype.createAuthorizationHeaderDigest = function(req) {
	var params = this.AUTH_PARAMS;
	if (!params)
		return null; //no challenge data yet

    var qop = params.qop;
    var clientQop = 'auth';
    if (qop !== undefined && qop.toLowerCase() === 'auth-int')
        clientQop = 'auth-int';

    //HA1 Calculation
    if (this.AUTH_HA1 == null) {
		let auth = this.getCredentials();
		if (!auth || (!auth.username && !auth.password))
			return null; //no credentials supplied
		this.AUTH_USERNAME = auth.username;
		this.AUTH_HA1 = CryptoJS.MD5(auth.username+':'+params.realm+':'+auth.password);
    }
    
	//If the algorithm is md5-sess we should further MD5 this:
    //  TRUE_HA1 = MD5(MD5(username:realm:password):nonce:cnonce) = MD5(STORED_HA1:nonce:cnonce)
    var ha1;
	var cnonce;
    var algorithm = params.algorithm;
    if (algorithm !== undefined && algorithm.toLowerCase() === 'md5-sess') {
        cnonce = this.generateCnonce();
        ha1 = CryptoJS.MD5(this.AUTH_HA1 + ':' + params.nonce + ':' + cnonce);
	} else
		ha1 = this.AUTH_HA1;

    //HA2 Calculation
    var ha2, response;
    if (clientQop === 'auth-int') {
        var body = req.data ? req.data : '';
        ha2 = CryptoJS.MD5(req.type + ':' + req.url + ':' + CryptoJS.MD5(body));
    }
    else {
        ha2 = CryptoJS.MD5(req.type + ':' + req.url);
    }

    //Response Calculation
    var response, nc;
    if (params.qop === undefined) {
        response = CryptoJS.MD5(ha1 + ':' + params.nonce + ':' + ha2);
    }
    else {
        if (cnonce === undefined)
            //Cnonce may have been generated already for MD5-sess algorithm
            cnonce = this.generateCnonce();
        nc = this.nonce_count.toString(16).padStart(8, '0'); //00000001
        this.nonce_count += 1;
        response = CryptoJS.MD5(ha1 + ':' + params.nonce + ':' 
                + nc + ':' + cnonce + ':' + clientQop + ':' + ha2);
    }

    var sb = [];
    sb.push('Digest username="', this.AUTH_USERNAME, '",');
    sb.push('realm="', params.realm, '",');
    sb.push('nonce="', params.nonce, '",');
    sb.push('uri="', req.url, '",');
    sb.push('qop=', clientQop, ',');
    if (nc !== undefined) {
        sb.push('nc=', nc, ',');
    }
    if (cnonce !== undefined) {
        sb.push('cnonce="', cnonce, '",');
    }
    if (params.opaque !== undefined) {
        sb.push('opaque="', params.opaque, '",');
    }
    sb.push('response="', response, '"');
    return sb.join('');
}

AuthCalc.prototype.createAuthorizationHeaderBasic = function(req) {
	let auth = this.getCredentials();
	if (!auth || (!auth.username && !auth.password))
		return null; //no credentials supplied
	return "Basic " + btoa(auth.username+":"+auth.password);
}

/*
Call to sign each request.
Request must be an Object() with at least these params:
  req.url		URL being requested
  req.type		HTTP method (GET, PUT, and so on)
  req.data		Request data.
*/
AuthCalc.prototype.sign = function(xhr, req) {
	var params = this.AUTH_PARAMS;
	var header = null;
	
	if (params && (params[null]=='digest'))
		header = this.createAuthorizationHeaderDigest(req, params);
	else
	//If basic auth is preferred, we can create authorization header even without the challenge
	if ((params && (params[null]=='basic')) || (this.authType=='basic'))
		header = this.createAuthorizationHeaderBasic(req);
	
	if (header) {
		//console.log('AuthCalc: Authorization: '+header);
		xhr.setRequestHeader('Authorization', header);
	}
}
