var assert = require('assert');
var TokenGenerator = require('./index');

function error(err) {
  throw new Error(err || 'Error!');
}

var trainingData = [
  { input: { userAgent: 1,    language: 1, referer: 1, requestData: 0 }, output: { integrity: 1 } },
  { input: { userAgent: 0,    language: 0, referer: 0, requestData: 1 }, output: { integrity: 0.001 } }
];

var generator = new TokenGenerator(trainingData, 'test', 'localhost', 'localhost');

generator.create({
  httpVersion: '1.1',
  acceptEncoding: 'gzip, deflate',
  contentType: 'application/json',
  connection: 'keep-alive',
  remoteFamily: 'IPv4',
  remotePort: '443',
  userAgent: 'Mozilla/5.0 (Windows NT 6.1) Gecko/20100101 Firefox/43.0',
  acceptLanguage: 'en-US',
  referer: 'http://localhost',
  remoteAddress: '127.0.0.1'
}, 'testResourceId', '1.0', function(token, resourceId) {
  // Confirm the token was made correctly
  assert.strictEqual(token.length > 330, true);
  assert.strictEqual(token.slice(0, 50), 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZGVudGlma');
  assert.strictEqual(resourceId.length, 64);

  generator.decode(token, function(decoded) {
    // Confirm the token can be decoded
    assert.strictEqual(decoded.identifier, resourceId);
    assert.strictEqual(decoded.iat, parseInt(Date.now() / 1000, 10));
    assert.strictEqual(decoded.aud, 'localhost');
    assert.strictEqual(decoded.iss, 'localhost');
    assert.strictEqual(decoded.properties.version, '1.0');
    assert.strictEqual(decoded.properties.integrity > 0.85, true);

    generator.train(1, 1, 1, 0.5, 0.5);
  }, error);
}, error);

