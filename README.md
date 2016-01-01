# janus-token
Stores REST resource identifiers and HTTP header data integrity score into JSON Web Tokens.

## Installation

``npm install janus-token``

## API

### constructor(trainingData, jwtSecret, jwtIssuer, jwtAudience, jwtAlgorithm, delimit, botMatch, browserMatch, languageMatch, idealRequestChain)

TBD

### create(request, resourceId, version, done, error)

TBD

### decode(token, next, error)

TBD

### compare(integrity, request, done, error)

TBD

### calculate(request, done, error)

TBD

### extractHeaders(request)

TBD

### train(userAgent, language, referer, requestData, integrity)

TBD

## Examples

```javascript
var TokenGenerator = require('./index');

var trainingData = [
  { input: { userAgent: 1,    language: 1, referer: 1, requestData: 0 }, output: { integrity: 1 } }
];

var generator = new TokenGenerator(trainingData, 'test', 'localhost', 'localhost');

// Adds more training data to the generator
generator.train(0, 0, 0, 1, 0.001);

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
    console.log(token);
    console.log(resourceId);
  
    generator.decode(token, function(decoded) {
    console.log(decoded);
  }, error);
}, error);
```