/*
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */
var bedrock = require('bedrock');
require('bedrock-express');
require('bedrock-requirejs');
require('bedrock-server');
require('../lib/api');

bedrock.start();
