/*
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */

'use strict';

var bedrock = require('bedrock');
var config = bedrock.config;
var request = require('request');
request = request.defaults({json: true});

var identityService = config.server.baseUri + config['identity-rest'].basePath;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

describe('identity-service', function() {
  it('should accept a get', function(done) {
    request.get(
      {
        url: identityService
      },
      function(err, res, body) {
        console.log('BODY', body);
        done(err);
      }
    );
  });
});
