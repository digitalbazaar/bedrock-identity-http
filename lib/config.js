/*
 * Bedrock Identity HTTP Module Configuration
 *
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const path = require('path');

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

// common validation schemas
config.validation.schema.paths.push(
  path.join(__dirname, '..', 'schemas')
);

// documentation config
config.docs.categories[config['identity-http'].basePath] = 'Identity Services';
