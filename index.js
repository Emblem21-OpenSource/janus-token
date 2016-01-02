var levenshtein = require('fast-levenshtein');
var brain = require('brain');
var url = require('url');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var uuid = require('uuid');

var blank = '';
var defaultDelimit = '✰';
var defaultBotMatch = /bot|crawler|link|spider|spyder|phantom/gi;
var defaultBrowserMatch = /chrome|msie|safari|mozilla|opera/gi;
var defaultLanguageMatch = /[a-zA-Z]{2,4}\-?/;
var defaultIdealRequestChain = '1.1✰gzip, deflate✰application/json✰keep-alive✰IPv4✰443✰';

/**
 * Compares user agent data against a structural integrity test.
 * @param   agent         String    Agent string.
 * @param   botMatch      RegExp    Regular expression of phrases that bots would have in their agent data.
 * @param   browserMatch  RegExp    Regular expression of phrases that valid browsers would identify with.
 * @return                Number    Percentage of checks failed
 */
function userAgentTest(agent, botMatch, browserMatch) {
  if(agent === undefined || agent === null || agent.trim() === '') {
    return 0;
  }

  return (
    ((agent.search(botMatch) === -1) & 1) + 
    ((agent.search(browserMatch) !== -1) & 1) +
    ((agent.indexOf('.') !== -1) & 1) + 
    ((agent.indexOf('(') !== -1) & 1) +
    ((agent.indexOf(')') !== -1) & 1) + 
    ((agent.indexOf('/') !== -1) & 1)) / 6;
}

/**
 * Compares language data against a structural integrity test.
 * @param   language        String    Language string.
 * @param   languageMatch   RegExp    Regular expression of languages that a valid browser would use.
 * @param                   Boolean   Did the test pass?
 */
function evaluateLanguage(language, languageMatch) {
  if(language === undefined || language === null || language.trim() === '') {
    return 0;
  }

  return (language.search(languageMatch) !== -1) & 1;
}

/**
 * Compares referer data against a structural integrity test.
 * @param   referer   String    Referer string.
 * @param             Boolean   Did the test pass?
 */
function evaluateReferer(referer) {
  if(referer === undefined || referer === null || referer.trim() === '') {
    return 0;
  }

  var parts = url.parse(referer);
  return ((parts.protocol === 'http:' || parts.protocol === 'https:') && parts.slashes && parts.auth === null && parts.host !== null && parts.port === null) & 1;
}

/**
 * Creates a JSON Web Token
 * @param   identifier  String    Resource hash identifier.
 * @param   properties  Object    Object of custom properties to add to the token.
 * @param   config      Object    JWT Configuration
 * ^param   secret      String    Secret to use with the token encoding
 * ^param   algorithm   String    The algorithm to use for token encoding (Defaults to HS256)
 * ^param   issuer      String    Website the token was generated at
 * ^param   audience    String    Website audience the token
 */
function createToken(identifier, properties, config) {
    return jwt.sign({
      identifier: identifier,
      properties: properties || {}
    }, config.secret, config);
}

/**
 * Token generator factory constructor
 * @param   trainingData        Array<Object>   An array of input/output objects to train the neural network with.  (Review the train method to get the expected structure of each element in the array)
 * @param   jwtSecret           String          Secret to use with the token encoding
 * @param   jwtIssuer           String          Website the token was generated at
 * @param   jwtAudience         String          Website audience the token
 * @param   jwtAlgorithm        String          The algorithm to use for token encoding (Defaults to HS256)
 * @param   delimit             String          The delimiter used within the idealRequestChain (Defaults to ✰)
 * @param   botMatch            RegExp          Regular expression of phrases that bots would have in their agent data.
 * @param   browserMatch        RegExp          Regular expression of phrases that valid browsers would identify with.
 * @param   languageMatch       RegExp          Regular expression of languages that a valid browser would use.
 * @param   idealRequestChain   String          A string of headers, separated by the delimiter, that the processed request headers will be compared against.  (Defaults to 1.1✰gzip, deflate✰application/json✰keep-alive✰IPv4✰443✰)
 */
function TokenGenerator(trainingData, jwtSecret, jwtIssuer, jwtAudience, jwtAlgorithm, delimit, botMatch, browserMatch, languageMatch, idealRequestChain) {

  this.jwtConfig = {
    secret: jwtSecret,
    algorithm: jwtAlgorithm || 'HS256',
    issuer: jwtIssuer,
    audience: jwtAudience
  };

  this.delimit = delimit || defaultDelimit;
  this.botMatch = botMatch || defaultBotMatch;
  this.browserMatch = browserMatch || defaultBrowserMatch;
  this.languageMatch = languageMatch || defaultLanguageMatch;
  this.idealRequestChain = idealRequestChain || defaultIdealRequestChain;
  this.trainingData = trainingData || [];
}

/**
 * Generates a token for resources based on a user's HTTP headers
 * @param     request         Object      The headers of the request to compare against
 * ^param     httpVersion     String      The HTTP version in the header (Ex.: 1.1)
 * ^param     acceptEncoding  String      The accept-encoding HTTP header (Ex.: gzip, deflate)
 * ^param     contentType     String      The content-type HTTP header (Ex.: application/json)
 * ^param     connection      String      The connection HTTP header (Ex.: keep-alive)
 * ^param     remoteFamily    String      The type of TCP/IP connection (Ex.: IPv4, IPv6)
 * ^param     remotePort      String      The port of the connection
 * ^param     userAgent       String      The user-agent HTTP header (Ex.: Mozilla/5.0 (Windows NT 6.1) Gecko/20100101 Firefox/43.0)
 * ^param     acceptLanguage  String      The accept-language HTTP header (Ex.: en-US)
 * ^param     referer         String      The referer HTTP header (Ex.: http://www.janusengine.com)
 * ^param     remoteAddress   String      The IP address of the connect (Ex.: 127.0.0.1)
 * @param     resourceId      Mixed       The identifier of a resource
 * @param     version         String      The version of the generated token
 * @param     done            Function    The callback to to fire when the creation succeeds
 * ^argument  integrity       Float       The integrity score
 * @param     error           Function    The callback to fire when the creation fails
 * ^argument  err             String      The error message
 */
TokenGenerator.prototype.create = function(request, resourceId, properties, version, done, error) {
  var time = Date.now();
  var self = this;

  if(!properties) {
    properties = {};
  }

  this.calculate(request, function(result) {
    // Generate pepper
    var ip = request.remoteAddress;
    var pepper = 1;
    for(var i = 0, len = ip.length; i<len; i++) {
      pepper *= ip.charCodeAt(i);
    }

    resourceId = crypto.createHash('sha256').update(resourceId + pepper + ip + uuid.v4({
      rng: uuid.nodeRNG
    })).digest('hex');

    properties.version = version;
    properties.integrity = result;

    done(createToken(resourceId, properties, self.jwtConfig), resourceId);
  }, error);
};

/**
 * Decodes a token.
 * @param     token     String    The token
 * @param     done            Function    The callback to to fire when the creation succeeds
 * ^argument  decoded         Object      The decoded token
 * ^^param    identifier      String      The identifier of a resource
 * ^^param    properties:     Object      An object of properties
 * ^^^param   version:        String      The version of the token
 * ^^^param   integrity       Float       The integrity score of the token
 * ^^param    iat             Number      Token issued at in seconds
 * ^^param    aud             String      Website audience the token
 * ^^param    iss             String      Website the token was generated at
 * @param     error           Function    The callback to fire when the creation fails
 * ^argument  err             String      The error message
 */
TokenGenerator.prototype.decode = function(token, next, error) {
  jwt.verify(token, this.jwtConfig.secret, this.jwtConfig, function (err, decoded) {
    if (err || !decoded.identifier) {
      return error(err || !decoded.identifier);
    }
    return next(decoded);
  });
};

/**
 * Compares if initial browser data integrity is within range of current browser data integrity.
 * @param     integrity       Float       The integrity of a token
 * @param     request         Object      The headers of the request to compare against
 * ^param     httpVersion     String      The HTTP version in the header (Ex.: 1.1)
 * ^param     acceptEncoding  String      The accept-encoding HTTP header (Ex.: gzip, deflate)
 * ^param     contentType     String      The content-type HTTP header (Ex.: application/json)
 * ^param     connection      String      The connection HTTP header (Ex.: keep-alive)
 * ^param     remoteFamily    String      The type of TCP/IP connection (Ex.: IPv4, IPv6)
 * ^param     remotePort      String      The port of the connection
 * ^param     userAgent       String      The user-agent HTTP header (Ex.: Mozilla/5.0 (Windows NT 6.1) Gecko/20100101 Firefox/43.0)
 * ^param     acceptLanguage  String      The accept-language HTTP header (Ex.: en-US)
 * ^param     referer         String      The referer HTTP header (Ex.: http://www.janusengine.com)
 * ^param     remoteAddress   String      The IP address of the connect (Ex.: 127.0.0.1)
 * @param     done            Function    The callback to fire when the comparison is done
 * ^argument  integrity       Boolean     Is the calculated integrity of the request within the range of the token's integrity?
 * @param     error           Function    The callback to fire when the comparison fails
 * ^argument  err             String      The error message
 */
TokenGenerator.prototype.compare = function(integrity, request, done, error) {
  this.calculate(request, function(result) {
    done(Math.abs(integrity - result) < 0.05);
  }, error);
};

/**
 * Calculates the integrity score of the request
 * @param     request         Object      The headers of the request to compare against
 * ^param     httpVersion     String      The HTTP version in the header (Ex.: 1.1)
 * ^param     acceptEncoding  String      The accept-encoding HTTP header (Ex.: gzip, deflate)
 * ^param     contentType     String      The content-type HTTP header (Ex.: application/json)
 * ^param     connection      String      The connection HTTP header (Ex.: keep-alive)
 * ^param     remoteFamily    String      The type of TCP/IP connection (Ex.: IPv4, IPv6)
 * ^param     remotePort      String      The port of the connection
 * ^param     userAgent       String      The user-agent HTTP header (Ex.: Mozilla/5.0 (Windows NT 6.1) Gecko/20100101 Firefox/43.0)
 * ^param     acceptLanguage  String      The accept-language HTTP header (Ex.: en-US)
 * ^param     referer         String      The referer HTTP header (Ex.: http://www.janusengine.com)
 * ^param     remoteAddress   String      The IP address of the connect (Ex.: 127.0.0.1)
 * @param     done            Function    The callback to fire when the comparison is done
 * ^argument  integrity       Float       The integrity score
 * @param     error           Function    The callback to fire when the comparison fails
 * ^argument  err             String      The error message
 */
TokenGenerator.prototype.calculate = function(request, done, error) {
  var net = new brain.NeuralNetwork();

  net.train(this.trainingData);

  var chain = (request.httpVersion ? request.httpVersion.substr(0, 5) : blank) + this.delimit + 
              (request.acceptEncoding ? request.acceptEncoding.substr(0, 32) : blank) + this.delimit + 
              (request.contentType ? request.contentType.substr(0, 32) : blank) + this.delimit + 
              (request.connection ? request.connection.substr(0, 16) : blank) + this.delimit + 
              request.remoteFamily + this.delimit + 
              request.remotePort + this.delimit;

  levenshtein.getAsync(this.idealRequestChain, chain, function(err, distance) {
    if(err) {
      return error(err);
    }

    var data = {
      userAgent: userAgentTest(request.userAgent, this.botMatch, this.browserMatch),
      language: evaluateLanguage(request.acceptLanguage, this.languageMatch),
      referer: evaluateReferer(request.referer),
      requestData: distance / chain.length
    };

    return done(net.run(data).integrity);
  });
};

/**
 * Converts an Express HTTP Request Object into valid input for the Token Generator
 * @param     request         Object      The HTTP Request object
 * ^param     httpVersion     String      The HTTP version in the header (Ex.: 1.1)
 * ^param     headers         Object      The headers object
 * ^^param    acceptEncoding  String      The accept-encoding HTTP header (Ex.: gzip, deflate)
 * ^^param    contentType     String      The content-type HTTP header (Ex.: application/json)
 * ^^param    userAgent       String      The user-agent HTTP header (Ex.: Mozilla/5.0 (Windows NT 6.1) Gecko/20100101 Firefox/43.0)
 * ^^param    connection      String      The connection HTTP header (Ex.: keep-alive)
 * ^^param    acceptLanguage  String      The accept-language HTTP header (Ex.: en-US)
 * ^^param    referer         String      The referer HTTP header (Ex.: http://www.janusengine.com)
 * ^param     connection      Object      The connection object
 * ^^param    remoteFamily    String      The type of TCP/IP connection (Ex.: IPv4, IPv6)
 * ^^param    remotePort      String      The port of the connection
 * ^^param    remoteAddress   String      The IP address of the connect (Ex.: 127.0.0.1)
 * @returns                   Object      A header object
 */
TokenGenerator.prototype.extractHeaders = function(request) {
  return {
    httpVersion: request.httpVersion,
    acceptEncoding: request.headers['accept-encoding'],
    contentType: request.headers['content-type'],
    connection: request.headers.connection,
    remoteFamily: request.connection.remoteFamily,
    remotePort: request.connection.remotePort,
    userAgent: request.headers['user-agent'],
    acceptLanguage: request.headers['accept-language'],
    referer: request.headers['referer'],
    remoteAddress: request.connection.remoteAddress
  };
};

/**
 * Trains the token generator to refine the integrity score calculation
 * @param   userAgent     Float     The user agent score (0 = failure, 1 = all tests pass)
 * @param   language      Float     The language score (0 = failure, 1 = all tests pass)
 * @param   referer       Float     The referer score (0 = failure, 1 = all tests pass)
 * @param   requestData   Float     The user agent score (0 = request data matches ideal, 1 = 100% differences between request data and ideal)
 * @param   integrity     Float     The integrity score
 */
TokenGenerator.prototype.train = function(userAgent, language, referer, requestData, integrity) {
  this.trainingData.push({
    input: {
      userAgent: userAgent,
      language: language,
      referer: referer,
      requestData: requestData
    },
    output: { integrity: integrity}
  });
};

module.exports = TokenGenerator;