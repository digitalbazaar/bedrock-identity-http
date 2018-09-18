/*
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const brTest = require('bedrock-test');
const config = bedrock.config;
const helpers = require('./helpers');
const jsonpatch = require('fast-json-patch');
const mockData = require('./mock.data');
let request = require('request');
const uuid = require('uuid/v4');
request = request.defaults({json: true, strictSSL: false});

const identityService = config.server.baseUri +
  config['identity-http'].basePath;

describe('bedrock-identity-http', function() {
  before(function(done) {
    helpers.prepareDatabase({mockData}, done);
  });
  describe('identity-service', function() {
    describe('unauthenticated requests', function() {
      it('should accept a request for a slug with public label', done => {
        sendRequest(
          {
            url: mockData.identities.registered.identity.id,
            method: 'GET'
          },
          (err, res, body) => {
            assertNoError(err);
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
            assertNoError(err);
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
        const actor = mockData.identities.adminUser;

        describe('GET request for all identities', function() {
          it('should include all identity data', function(done) {
            sendRequest({
              url: identityService,
              method: 'GET',
              authIdentity: actor,
            }, (err, res, body) => {
              assertNoError(err);
              res.statusCode.should.equal(200);
              should.exist(body);
              body.should.be.an('array');
              body.should.have.length(2);
              const r = body.filter(function(i) {
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
              done();
            });
          });
        });
        describe('POST to create new identity', function() {
          it('should reject a malformed identity');
          it('should create and lookup a new identity', done => {
            const userId = uuid();
            async.waterfall([
              function(callback) {
                sendRequest({
                  authIdentity: actor,
                  url: identityService,
                  method: 'POST',
                  identity: createIdentity(userId),
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
              assertNoError(err);
              done();
            });
          });

          it('should return 400 for invalid identity owner', function(done) {
            const actor = mockData.identities.registered;
            const userId = uuid();
            const privateKeyPem = actor.keys.privateKey.privateKeyPem;
            const publicKeyId = actor.keys.privateKey.publicKey;
            const group = createIdentity(userId);
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
                body.type.should.equal('NotAllowedError');
                callback();
              }
            ], function(err) {
              assertNoError(err);
              done();
            });
          });

          it('should return 409 on a duplicate identity', function(done) {
            const userId = uuid();
            const actor = mockData.identities.adminUser;
            async.waterfall([
              function(callback) {
                sendRequest(
                  {
                    authIdentity: actor,
                    url: identityService,
                    method: 'POST',
                    identity: createIdentity(userId),
                  }, callback);
              },
              function(res, body, callback) {
                res.statusCode.should.equal(201);
                sendRequest(
                  {
                    authIdentity: actor,
                    url: identityService,
                    method: 'POST',
                    identity: createIdentity(userId),
                  }, callback);
              },
              function(res, body, callback) {
                res.statusCode.should.equal(409);
                should.exist(body);
                body.should.be.an('object');
                should.exist(body.type);
                body.type.should.be.a('string');
                body.type.should.equal('DuplicateError');
                should.exist(body.details);
                body.details.should.be.an('object');
                should.exist(body.details.identity);
                body.details.identity.should.be.a('string');
                callback();
              }
            ], function(err) {
              assertNoError(err);
              done();
            });
          });
        }); // end POST request

        describe('should update any identity', function() {
          const actor = mockData.identities.adminUser;
          const userId = uuid();
          const groupId = uuid();
          let createdIdentity = null;
          let createdGroup = null;

          before(function(done) {
            const newIdentity = createIdentity(userId);
            newIdentity.sysResourceRole = [{
              sysRole: 'bedrock-identity-http.identity.registered',
              generateResource: 'id'
            }];
            async.auto({
              createIdentity: callback => {
                sendRequest({
                  authIdentity: actor,
                  url: identityService,
                  method: 'POST',
                  identity: newIdentity,
                }, function(err, res, body) {
                  res.statusCode.should.equal(201);
                  createdIdentity = body;
                  callback(err, createdIdentity);
                });
              },
              createGroup: ['createIdentity', (results, callback) => {
                const group = createIdentity(groupId);
                group.owner = actor.id;
                group.type = ['Identity', 'Group'];
                sendRequest({
                  authIdentity: actor,
                  url: identityService,
                  method: 'POST',
                  identity: group,
                }, function(err, res, body) {
                  createdGroup = body;
                  callback(err);
                });
              }]
            }, done);
          });

          it('should update an identities label', function(done) {
            const newData = uuid();
            const updatedIdentity = createdIdentity;
            const observer = jsonpatch.observe(updatedIdentity);
            updatedIdentity.label = newData;
            const patch = jsonpatch.generate(observer);
            jsonpatch.unobserve(updatedIdentity, observer);
            async.waterfall([
              function(callback) {
                sendRequest({
                  authIdentity: actor,
                  url: createdIdentity.id,
                  method: 'PATCH',
                  identity: {
                    patch,
                    sequence: 0
                  },
                }, callback);
              },
              function(res, body, callback) {
                res.statusCode.should.equal(204);
                sendRequest(
                  {
                    url: createdIdentity.id,
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
              assertNoError(err);
              done();
            });
          });

          it('should update an identities description', done => {
            const newData = uuid();
            const updatedIdentity = createdIdentity;
            const observer = jsonpatch.observe(updatedIdentity);
            updatedIdentity.description = newData;
            const patch = jsonpatch.generate(observer);
            jsonpatch.unobserve(updatedIdentity, observer);
            async.waterfall([
              function(callback) {
                sendRequest({
                  authIdentity: actor,
                  url: createdIdentity.id,
                  method: 'PATCH',
                  identity: {
                    patch,
                    sequence: 1
                  },
                }, callback);
              },
              function(res, body, callback) {
                res.statusCode.should.equal(204);
                sendRequest(
                  {
                    url: createdIdentity.id,
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
              assertNoError(err);
              done();
            });
          });

          // TODO: implement updateRoles API
          it.skip('should update an identities sysResourceRoles', done => {
            const updatedSysResourceRole = actor.identity.sysResourceRole;
            updatedSysResourceRole.push({
              sysRole: 'bedrock-identity-http.identity.manager',
              resource: [createdGroup.id]
            });
            async.waterfall([
              function(callback) {
                sendRequest({
                  authIdentity: actor,
                  url: actor.identity.id,
                  method: 'PATCH',
                  identity: [{
                    value: {
                      sysResourceRole: updatedSysResourceRole
                    },
                    op: 'add'
                  }],
                }, callback);
              },
              function(res, body, callback) {
                res.statusCode.should.equal(204);
                sendRequest(
                  {
                    authIdentity: actor,
                    url: actor.identity.id,
                    method: 'GET',
                  }, callback);
              },
              function(res, body, callback) {
                should.exist(body);
                body.should.be.an('object');
                should.exist(body.sysResourceRole);
                body.sysResourceRole.should.be.a('array');
                callback();
              }
            ], function(err) {
              assertNoError(err);
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
  const url = options.url;
  const reqBody = options.identity || null;
  const reqMethod = options.method;
  const authIdentity = options.authIdentity || null;

  const requestOptions = {
    method: reqMethod,
    url: url,
    json: true
  };

  if(reqBody) {
    requestOptions.body = reqBody;
  }
  async.auto({
    sign: callback => {
      if(!authIdentity) {
        return callback();
      }
      // mutates requestOptions
      brTest.helpers.createHttpSignatureRequest(
        {algorithm: 'rsa-sha256', identity: authIdentity, requestOptions},
        callback);
    },
    request: ['sign', (results, callback) => request(requestOptions, callback)]
  }, (err, results) => {
    if(err) {
      return callback(err);
    }
    const [res, body] = results.request;
    callback(err, res, body);
  });
}

function createIdentity(userName) {
  const newIdentity = {
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
