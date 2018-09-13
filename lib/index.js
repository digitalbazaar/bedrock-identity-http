/*
 * Bedrock Identity HTTP module.
 *
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// module API
const api = {};
module.exports = api;

require('bedrock-docs');
require('bedrock-validation');

require('./config');

require('./services.identity');
