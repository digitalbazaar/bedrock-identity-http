/*
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');

const schema = {
  title: 'Passcode',
  description: 'An auto-generated security code.',
  type: 'string',
  minLength: 8,
  maxLength: 8,
  errors: {
    invalid: 'The passcode must be 8 characters in length.',
    missing: 'Please enter a passcode.',
    masked: true
  }
};

module.exports = function(extend) {
  if(extend) {
    return bedrock.util.extend(true, bedrock.util.clone(schema), extend);
  }
  return schema;
};
