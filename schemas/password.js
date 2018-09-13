/*
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');

const schema = {
  title: 'Password',
  description: 'A secure phrase used to protect information.',
  type: 'string',
  minLength: 6,
  maxLength: 32,
  errors: {
    invalid: 'The password must be between 6 and 32 characters in length.',
    missing: 'Please enter a password.',
    mask: true
  }
};

module.exports = function(extend) {
  if(extend) {
    return bedrock.util.extend(true, bedrock.util.clone(schema), extend);
  }
  return schema;
};
