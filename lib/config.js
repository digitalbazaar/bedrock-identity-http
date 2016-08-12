/*
 * Bedrock Identity HTTP Module Configuration
 *
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */
var config = require('bedrock').config;
var path = require('path');
require('bedrock-validation');

config['identity-http'] = {};
// root of identity endpoints
config['identity-http'].basePath = '/i';

config['identity-http'].defaults = {
  identity: {
    '@context': config.constants.IDENTITY_CONTEXT_V1_URL,
    type: 'Identity',
    sysStatus: 'active'
  }
};

config['identity-http'].identities = [];
config['identity-http'].keys = [];

// common validation schemas
config.validation.schema.paths.push(
  path.join(__dirname, '..', 'schemas')
);

// documentation config
config.docs.categories[config['identity-http'].basePath] = 'Identity Services';
