/*
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */
/* globals after, before, describe, it, require, should */
/* jshint node: true */

'use strict';

var async = require('async');
var bedrock = require('bedrock');
var config = bedrock.config;
var request = require('request');
var uuid = require('node-uuid');
request = request.defaults({json: true});

var identityService = config.server.baseUri + config['identity-http'].basePath;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

describe('identity-service', function() {

  describe('unauthenticated requests', function() {
    it('should accept a request for a slug', function(done) {
      sendRequest(
        {
          url: identityService + '/' +
            config['identity-http'].test.users.registered.name,
          method: 'GET'
        },
        function(err, res, body) {
          should.not.exist(err);
          should.exist(body);
          body.should.be.an('object');
          should.exist(body.label);
          body.label.should.be.a('string');
          body.label.should.equal(
            config['identity-http'].test.users.registered.name);
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
  });

  describe('authenticated requests', function() {

    it('should accept a get request for a slug', function(done) {
      var privateKeyPem =
        config['identity-http'].test.users.admin.keys.privateKey.privateKeyPem;
      var publicKeyId =
        config['identity-http'].test.users.admin.keys.privateKey.publicKey;
      sendRequest(
        {
          url: identityService + '/' +
            config['identity-http'].test.users.registered.name,
          method: 'GET',
          privateKeyPem: privateKeyPem,
          publicKeyId: publicKeyId
        },
        function(err, res, body) {
          should.not.exist(err);
          should.exist(body);
          body.should.be.an('object');
          should.exist(body.label);
          body.label.should.be.a('string');
          body.label.should.equal(
            config['identity-http'].test.users.registered.name);
          done(err);
        }
      );
    });

    it('should create and lookup a new identity', function(done) {
      var userId = uuid.v4();
      var privateKeyPem =
        config['identity-http'].test.users.admin.keys.privateKey.privateKeyPem;
      var publicKeyId =
        config['identity-http'].test.users.admin.keys.privateKey.publicKey;
      async.waterfall([
        function(callback) {
          sendRequest(
            {
              url: identityService,
              method: 'POST',
              identity: createIdentity(userId),
              privateKeyPem: privateKeyPem,
              publicKeyId: publicKeyId
            }, callback);
        },
        function(res, body, callback) {
          res.statusCode.should.equal(201);
          should.exist(body);
          body.should.be.an('object');
          should.exist(body.id);
          body.id.should.be.a('string');
          sendRequest(
            {
              url: body.id,
              method: 'GET'
            }, callback);
        },
        function(res, body, callback) {
          should.exist(body);
          body.should.be.an('object');
          should.exist(body.label);
          body.label.should.be.a('string');
          body.label.should.equal(userId);
          callback();
        }
      ], function(err) {
        should.not.exist(err);
        done();
      });
    });

    it('should return 409 on a duplicate identity', function(done) {
      var userId = uuid.v4();
      var privateKeyPem =
        config['identity-http'].test.users.admin.keys.privateKey.privateKeyPem;
      var publicKeyId =
        config['identity-http'].test.users.admin.keys.privateKey.publicKey;
      async.waterfall([
        function(callback) {
          sendRequest(
            {
              url: identityService,
              method: 'POST',
              identity: createIdentity(userId),
              privateKeyPem: privateKeyPem,
              publicKeyId: publicKeyId
            }, callback);
        },
        function(res, body, callback) {
          res.statusCode.should.equal(201);
          sendRequest(
            {
              url: identityService,
              method: 'POST',
              identity: createIdentity(userId),
              privateKeyPem: privateKeyPem,
              publicKeyId: publicKeyId
            }, callback);
        },
        function(res, body, callback) {
          res.statusCode.should.equal(409);
          should.exist(body);
          body.should.be.an('object');
          should.exist(body.type);
          body.type.should.be.a('string');
          body.type.should.equal('DuplicateIdentity');
          should.exist(body.details);
          body.details.should.be.an('object');
          should.exist(body.details.identity);
          body.details.identity.should.be.a('string');
          callback();
        }
      ], function(err) {
        should.not.exist(err);
        done();
      });
    });
  });

  it('should reject a malformed identity');

});

describe('admin users should update any identity', function() {
  // console.log(config['identity-http'].test.users.admin);
  var userId = uuid.v4();
  var idUrl = null;
  var privateKeyPem =
    config['identity-http'].test.users.admin.keys.privateKey.privateKeyPem;
  var publicKeyId =
    config['identity-http'].test.users.admin.keys.privateKey.publicKey;

  before(function(done) {
    sendRequest(
      {
        url: identityService,
        method: 'POST',
        identity: createIdentity(userId),
        privateKeyPem: privateKeyPem,
        publicKeyId: publicKeyId
      }, function(err, res, body) {
        idUrl = body.id;
        done();
      });
  });

  it('should update an identities label', function(done) {
    var newData = uuid.v4();
    async.waterfall([
      function(callback) {
        sendRequest(
          {
            url: idUrl,
            method: 'POST',
            identity: {id: idUrl, label: newData},
            privateKeyPem: privateKeyPem,
            publicKeyId: publicKeyId
          }, callback);
      },
      function(res, body, callback) {
        res.statusCode.should.equal(204);
        sendRequest(
          {
            url: idUrl,
            method: 'GET'
          }, callback);
      },
      function(res, body, callback) {
        should.exist(body);
        body.should.be.an('object');
        should.exist(body.label);
        body.label.should.be.a('string');
        body.label.should.equal(newData);
        callback();
      }
    ], function(err) {
      should.not.exist(err);
      done();
    });
  });

  it('should update an identities description', function(done) {
    var newData = uuid.v4();
    async.waterfall([
      function(callback) {
        sendRequest(
          {
            url: idUrl,
            method: 'POST',
            identity: {id: idUrl, description: newData},
            privateKeyPem: privateKeyPem,
            publicKeyId: publicKeyId
          }, callback);
      },
      function(res, body, callback) {
        res.statusCode.should.equal(204);
        sendRequest(
          {
            url: idUrl,
            method: 'GET'
          }, callback);
      },
      function(res, body, callback) {
        should.exist(body);
        body.should.be.an('object');
        should.exist(body.label);
        body.description.should.be.a('string');
        body.description.should.equal(newData);
        callback();
      }
    ], function(err) {
      should.not.exist(err);
      done();
    });
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
