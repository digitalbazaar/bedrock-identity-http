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

  it('should accept a get request for a slug', function(done) {
    sendRequest(
      {
        url: identityService + '/' + config['identity-rest'].test.testUser,
        method: 'GET'
      },
      function(err, res, body) {
        should.not.exist(err);
        body.should.be.an('object');
        should.exist(body.label);
        body.label.should.be.a('string');
        body.label.should.equal(config['identity-rest'].test.testUser);
        done();
      }
    );
  });

  it('should respond 404-NotFound on an unknown slug', function(done) {
    sendRequest(
      {
        url: identityService + '/unknownUser',
        method: 'GET'
      },
      function(err, res, body) {
        should.not.exist(err);
        res.statusCode.should.equal(404);
        body.should.be.an('object');
        should.exist(body.type);
        body.type.should.be.a('string');
        body.type.should.equal('NotFound');
        done();
      }
    );
  });

  it.skip('should accept request with an httpSignature', function(done) {
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

  it.only('should create a new identity', function(done) {
    // console.log(config['identity-rest'].keys[0].privateKey.privateKeyPem);
    // console.log(config['identity-rest'].keys[0].privateKey.publicKey);
    var privateKeyPem =
      config['identity-rest'].keys[0].privateKey.privateKeyPem;
    var publicKeyId = config['identity-rest'].keys[0].privateKey.publicKey;
    sendRequest(
      {
        url: identityService,
        method: 'POST',
        identity: createIdentity('Abcdefg'),
        privateKeyPem: privateKeyPem,
        publicKeyId: publicKeyId
      },
      function(err, res, body) {
        // console.log('BODY', body.details.errors);
        console.log('RETURNED BODY', body);
        done(err);
      }
    );
  });
});

function sendRequest(options, callback) {
  var url = options.url;
  var reqBody = options.identity || null;
  var privateKeyPem = options.privateKeyPem || null;
  var publicKeyId = options.publicKeyId || null;
  var reqMethod = options.method;

  var requestOptions = {
    method: reqMethod,
    url: url,
    json: true
  };

  if(privateKeyPem) {
    requestOptions.httpSignature = {
      key: privateKeyPem,
      keyId: publicKeyId,
      headers: ['date', 'host', 'request-line']
    };
  }

  if(reqBody) {
    requestOptions.body = reqBody;
  }

  request(requestOptions, callback);
}

function createIdentity(userName) {
  var newIdentity = {
    //id: identityService + '/' + userName,
    type: 'Identity',
    sysSlug: userName,
    label: userName,
    email: userName + '@bedrock.dev',
    sysPassword: 'password',
    sysPublic: ['label', 'url', 'description'],
    url: config.server.baseUri,
    description: userName
  };
  return newIdentity;
}
