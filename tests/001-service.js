/*
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */

'use strict';

var bedrock = require('bedrock');
var config = bedrock.config;
var request = require('request');
request = request.defaults({json: true});

var identityService = config.server.baseUri + config['identity-rest'].basePath;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

describe('identity-service', function() {
  it.only('should accept a get', function(done) {
    // console.log(config['identity-rest'].keys[0].privateKey.privateKeyPem);
    // console.log(config['identity-rest'].keys[0].privateKey.publicKey);
    var privateKeyPem =
      config['identity-rest'].keys[0].privateKey.privateKeyPem;
    var publicKeyId = config['identity-rest'].keys[0].privateKey.publicKey;
    sendRequest(
      {
        url: identityService,
        method: 'GET',
        privateKeyPem: privateKeyPem,
        publicKeyId: publicKeyId
      },
      function(err, res, body) {
        console.log('BODY', body);
        done(err);
      }
    );
  });
});

function sendRequest(options, callback) {
  var url = options.url;
  var reqBody = options.identity || null;
  var privateKeyPem = options.privateKeyPem;
  var publicKeyId = options.publicKeyId;
  var reqMethod = options.method;

  var requestOptions = {
    method: reqMethod,
    url: url,
    json: true,
    httpSignature: {
      key: privateKeyPem,
      keyId: publicKeyId,
      headers: ['date', 'host', 'request-line']
    }
  };

  if(reqBody) {
    requestOptions.body = reqBody;
  }

  request(requestOptions, callback);
}
