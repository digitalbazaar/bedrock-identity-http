/*
 * Copyright (c) 2012-2016 Digital Bazaar, Inc. All rights reserved.
 */
var async = require('async');
var bedrock = require('bedrock');
var brIdentity = require('bedrock-identity');
var brKey = require('bedrock-key');
var config = bedrock.config;
var database = require('bedrock-mongodb');
var uuid = require('uuid').v4;

var helpers = {};
module.exports = helpers;

helpers.createIdentity = function(userName) {
  var newIdentity = {
    id: config.server.baseUri + config['identity-http'].basePath +
      '/' + userName,
    type: 'Identity',
    sysSlug: userName,
    label: userName,
    email: userName + '@bedrock.dev',
    sysPassword: 'password',
    sysPublic: ['label'],
    sysResourceRole: [],
    sysStatus: 'active',
    url: config.server.baseUri,
    description: userName
  };
  return newIdentity;
};

helpers.createKeyPair = function(options) {
  var publicKey = options.publicKey;
  var privateKey = options.privateKey;
  var id = options.id || uuid();
  var keyId = config.server.baseUri + config.key.basePath + '/' + id;
  var ownerId = options.owner;
  var newKeyPair = {
    publicKey: {
      '@context': 'https://w3id.org/identity/v1',
      id: keyId,
      type: 'CryptographicKey',
      owner: ownerId,
      label: 'Signing Key 1',
      publicKeyPem: publicKey
    },
    privateKey: {
      type: 'CryptographicKey',
      owner: ownerId,
      label: 'Signing Key 1',
      publicKey: keyId,
      privateKeyPem: privateKey
    }
  };
  return newKeyPair;
};

helpers.prepareDatabase = function(options, callback) {
  async.series([
    function(callback) {
      helpers.removeCollections(callback);
    },
    function(callback) {
      insertTestData(options, callback);
    }
  ], function(err) {
    callback(err);
  });
};

helpers.removeCollections = function(callback) {
  var collectionNames = [
    'credentialProvider', 'identity', 'publicKey', 'eventLog'];
  database.openCollections(collectionNames, function() {
    async.each(collectionNames, function(collectionName, callback) {
      database.collections[collectionName].remove({}, callback);
    }, function(err) {
      callback(err);
    });
  });
};

// Insert identities and public keys used for testing into database
function insertTestData(options, done) {
  var mockData = options.mockData;
  async.forEachOf(mockData.identities, function(identity, key, callback) {
    async.parallel([
      function(callback) {
        brIdentity.insert(null, identity.identity, callback);
      },
      function(callback) {
        brKey.addPublicKey(null, identity.keys.publicKey, callback);
      }
    ], callback);
  }, function(err) {
    if(err) {
      if(!database.isDuplicateError(err)) {
        // duplicate error means test data is already loaded
        return done(err);
      }
    }
    done();
  });
}
