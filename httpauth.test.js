import { AuthCalc } from './httpauth';

test('AuthCalc', () => {
	let calc = new AuthCalc('username', 'password');
	//Just check that everything doesn't crash for now
	
	let req = {
		url: 'http://example.org',
		type: 'GET',
		data: 'Example request data',
	};
	
	//Basic header is always available
	let basic = calc.createAuthorizationHeaderBasic(req);
	expect(basic).toBeDefined();
	expect(typeof basic).toBe('string');
	expect(basic.startsWith('Basic')).toBe(true);
	
	//Digest header unavailable until challenge set
	expect(calc.createAuthorizationHeaderDigest(req)).toBeFalsy();
	
	//Set the challenge
	calc.AUTH_PARAMS = {
		realm: "example.org",
		nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		//optional: qop, algorithm, opaque
	};
	let digest = calc.createAuthorizationHeaderDigest(req);
	expect(typeof digest).toBe('string');
	expect(digest.startsWith('Digest')).toBe(true);
});