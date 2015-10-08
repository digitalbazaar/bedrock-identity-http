/*
 * Bedrock Identity REST Module Configuration
 *
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */
var config = require('bedrock').config;

config['identity-rest'] = {};
// root of identity endpoints
config['identity-rest'].basePath = '/identity';

config['identity-rest'].defaults = {
  identity: {
    '@context': config.constants.IDENTITY_CONTEXT_V1_URL,
    type: 'Identity',
    sysStatus: 'active'
  }
};

config['identity-rest'].identities = [];
config['identity-rest'].keys = [];
