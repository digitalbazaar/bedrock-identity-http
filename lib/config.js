/*
 * Bedrock Identity REST Module Configuration
 *
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */
var config = require('bedrock').config;
var path = require('path');
require('bedrock-validation');

config['identity-rest'] = {};
// root of identity endpoints
config['identity-rest'].basePath = '/i';

config['identity-rest'].defaults = {
  identity: {
    '@context': config.constants.IDENTITY_CONTEXT_V1_URL,
    type: 'Identity',
    sysStatus: 'active'
  }
};

config['identity-rest'].identities = [];
config['identity-rest'].keys = [];

// common validation schemas
config.validation.schema.paths.push(
  path.join(__dirname, '..', 'schemas')
);
