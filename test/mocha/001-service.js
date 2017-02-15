/*
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */
/* globals before, describe, it, require, should */
/* jshint node: true */

'use strict';

var async = require('async');
var bedrock = require('bedrock');
var config = bedrock.config;
var helpers = require('./helpers');
var mockData = require('./mock.data');
var request = require('request');
var uuid = require('uuid').v4;
request = request.defaults({json: true, strictSSL: false});

var identityService = config.server.baseUri + config['identity-http'].basePath;

describe('bedrock-identity-http', function() {
  before(function(done) {
    helpers.prepareDatabase({mockData: mockData}, done);
  });
  describe('identity-service', function() {
    describe('unauthenticated requests', function() {
      it('should accept a request for a slug with public label', done => {
        sendRequest(
          {
            url: mockData.identities.registered.identity.id,
            method: 'GET'
          },
          function(err, res, body) {
            should.not.exist(err);
            res.statusCode.should.equal(200);
            should.exist(body);
            body.should.be.an('object');
            should.exist(body.label);
            body.label.should.be.a('string');
            body.label.should.equal(
              mockData.identities.registered.identity.label);
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
      describe('admin user', function() {
        var actor = mockData.identities.adminUser;

        describe('GET request for all identities', function() {
          it('should include all identity data', function(done) {
            var privateKeyPem = actor.keys.privateKey.privateKeyPem;
            var publicKeyId = actor.keys.privateKey.publicKey;
            sendRequest({
              url: identityService,
              method: 'GET',
              privateKeyPem: privateKeyPem,
              publicKeyId: publicKeyId
            }, function(err, res, body) {
              should.not.exist(err);
              res.statusCode.should.equal(200);
              should.exist(body);
              body.should.be.an('array');
              body.should.have.length(2);
              var r = body.filter(function(i) {
                if(i.id === mockData.identities.registered.identity.id) {
                  return true;
                }
              })[0];
              r.label.should.equal(
                mockData.identities.registered.identity.label);
              r.sysSlug.should.equal(
                mockData.identities.registered.identity.sysSlug);
              r.email.should.equal(
                mockData.identities.registered.identity.email);
              r.url.should.equal(
                mockData.identities.registered.identity.url);
              r.type.should.equal('Identity');
              should.exist(r.sysResourceRole);
              done(err);
            });
          });
        });
        describe('POST to create new identity', function() {
          it('should reject a malformed identity');
          it('should create and lookup a new identity', function(done) {
            var userId = uuid();
            var privateKeyPem = actor.keys.privateKey.privateKeyPem;
            var publicKeyId = actor.keys.privateKey.publicKey;
            async.waterfall([
              function(callback) {
                sendRequest({
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

          it('should return 400 for invalid identity owner', function(done) {
            var actor = mockData.identities.registered;
            var userId = uuid();
            var privateKeyPem = actor.keys.privateKey.privateKeyPem;
            var publicKeyId = actor.keys.privateKey.publicKey;
            var group = createIdentity(userId);
            group.type = ['Identity', 'Group'];
            group.owner = mockData.identities.adminUser.identity.id;
            async.waterfall([
              function(callback) {
                sendRequest({
                  url: identityService,
                  method: 'POST',
                  identity: group,
                  privateKeyPem: privateKeyPem,
                  publicKeyId: publicKeyId
                }, callback);
              },
              function(res, body, callback) {
                res.statusCode.should.equal(400);
                should.exist(body);
                body.should.be.an('object');
                should.exist(body.type);
                body.type.should.equal('AddIdentityFailed');
                callback();
              }
            ], function(err) {
              should.not.exist(err);
              done();
            });
          });

          it('should return 409 on a duplicate identity', function(done) {
            var userId = uuid();
            var actor = mockData.identities.adminUser;
            var privateKeyPem = actor.keys.privateKey.privateKeyPem;
            var publicKeyId = actor.keys.privateKey.publicKey;
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
        }); // end POST request

        describe('should update any identity', function() {
          var actor = mockData.identities.adminUser;
          var userId = uuid();
          var idUrl = null;
          var privateKeyPem = actor.keys.privateKey.privateKeyPem;
          var publicKeyId = actor.keys.privateKey.publicKey;

          before(function(done) {
            sendRequest({
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
            var newData = uuid();
            async.waterfall([
              function(callback) {
                sendRequest({
                  url: idUrl,
                  method: 'PATCH',
                  identity: [{
                    changes: {label: newData},
                    op: 'updateIdentity'
                  }],
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
            var newData = uuid();
            async.waterfall([
              function(callback) {
                sendRequest({
                  url: idUrl,
                  method: 'PATCH',
                  identity: [{
                    changes: {description: newData},
                    op: 'updateIdentity'
                  }],
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
        }); // end admin user
        describe('registered user', function() {
          it('GET');
          it('POST');
          it('PATCH');
        });
      });
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
    // id: identityService + '/' + userName,
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
