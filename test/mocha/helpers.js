/*
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const brIdentity = require('bedrock-identity');
const brKey = require('bedrock-key');
const config = bedrock.config;
const database = require('bedrock-mongodb');
const uuid = require('uuid/v4');

const helpers = {};
module.exports = helpers;

helpers.createIdentity = function(userName) {
  const newIdentity = {
    id: config.server.baseUri + config['identity-http'].basePath +
      '/' + userName,
    type: 'Identity',
    sysSlug: userName,
    label: userName,
    email: userName + '@bedrock.dev',
    sysPublic: ['label'],
    url: config.server.baseUri,
    description: userName
  };
  return newIdentity;
};

helpers.createKeyPair = function(options) {
  const publicKey = options.publicKey;
  const privateKey = options.privateKey;
  const id = options.id || uuid();
  const keyId = config.server.baseUri + config.key.basePath + '/' + id;
  const ownerId = options.owner;
  const newKeyPair = {
    publicKey: {
      '@context': 'https://w3id.org/identity/v1',
      id: keyId,
      type: 'RsaVerificationKey2018',
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
  const collectionNames = [
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
  const {identities} = options.mockData;
  async.forEachOf(identities, ({identity, keys, meta}, k, callback) => {
    async.parallel([
      callback => brIdentity.insert({actor: null, identity, meta}, callback),
      callback => brKey.addPublicKey(
        {actor: null, publicKey: keys.publicKey},
        callback),
    ], callback);
  }, function(err) {
    if(err) {
      if(err.name !== 'DuplicateError') {
        // duplicate error means test data is already loaded
        return done(err);
      }
    }
    done();
  });
}
