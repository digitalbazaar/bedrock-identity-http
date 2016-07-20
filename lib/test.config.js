/*
 * Copyright (c) 2012-2016 Digital Bazaar, Inc. All rights reserved.
 */

var config = require('bedrock').config;
var path = require('path');

require('./test.data');

// mongodb config
config.mongodb.name = 'bedrock_identity_rest_test';
config.mongodb.host = 'localhost';
config.mongodb.port = 27017;
config.mongodb.local.collection = 'bedrock_identity_rest_test';
// drop all collections on initialization
config.mongodb.dropCollections = {};
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

// tests
config.mocha.tests.push(path.join(__dirname, '..', 'tests'));
