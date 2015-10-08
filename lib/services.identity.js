/*
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */
var async = require('async');
var bedrock = require('bedrock');
var bcrypt = require('bcrypt');
var config = bedrock.config;
var brIdentity = require('bedrock-identity');
var brPassport = require('bedrock-passport');
var BedrockError = bedrock.util.BedrockError;
var cors = require('cors');
var database = require('bedrock-mongodb');
var docs = require('bedrock-docs');
var validate = require('bedrock-validation').validate;
var ensureAuthenticated = brPassport.ensureAuthenticated;

bedrock.events.on('bedrock.test.configure', function() {
  // load test config
  require('./test.config');
});

bedrock.events.on('bedrock-mongodb.ready', function init(callback) {
  async.auto({
    openCollections: function(callback) {
      database.openCollections(['identity'], callback);
    },
    createIndexes: ['openCollections', function(callback) {
      database.createIndexes([{
        collection: 'identity',
        // TODO: move `sysSlug` to meta?
        fields: {'identity.sysSlug': 1},
        options: {unique: true, background: false}
      }, {
        collection: 'identity',
        fields: {'identity.email': 1},
        options: {unique: false, background: false}
      }], callback);
    }],
    createIdentities: ['createIndexes', function(callback) {
      // create identities, ignoring duplicate errors
      async.eachSeries(
        config['identity-rest'].identities,
        function(i, callback) {
          createIdentity(null, i, function(err) {
            if(err && database.isDuplicateError(err)) {
              err = null;
            }
            callback(err);
          });
        },
        callback);
    }],
    createKeys: ['createIdentities', function(callback) {
      // add keys, ignoring duplicate errors
      async.eachSeries(config['identity-rest'].keys, function(i, callback) {
        var publicKey = i.publicKey;
        var privateKey = i.privateKey || null;
        brIdentity.addPublicKey(null, publicKey, privateKey, function(err) {
          if(err && database.isDuplicateError(err)) {
            err = null;
          }
          callback(err);
        });
      }, callback);
    }]
  }, function(err) {
    callback(err);
  });
});

// add routes
bedrock.events.on('bedrock-express.configure.routes', function(app) {
  var basePath = bedrock.config['identity-rest'].basePath;
  var idPath = basePath;

  app.post(basePath,
    ensureAuthenticated,
    validate({query: 'services.identity.postIdentitiesQuery'}),
    validate('services.identity.postIdentities'),
    function(req, res, next) {
      // do identity credentials query
      if(req.query.action === 'query') {
        return _getCredentials(req, res, next);
      }

      // do create identity
      var identity = {};
      identity['@context'] = bedrock.config.constants.IDENTITY_CONTEXT_V1_URL;
      // TODO: allow DID to be specified (if `id` is present, ensure it is
      // validated as a DID w/a validator fix above; only add a local `id` if
      // no `id` (DID) was given)
      identity.id = auth.createIdentityId(req.body.sysSlug);
      identity.type = req.body.type || 'Identity';
      identity.sysSlug = req.body.sysSlug;
      identity.label = req.body.label;

      // conditional values only set if present
      if(req.body.description) {
        identity.description = req.body.description;
      }
      if(req.body.image) {
        identity.image = req.body.image;
      }
      if(req.body.sysGravatarType) {
        identity.sysGravatarType = req.body.sysGravatarType;
      }
      if(req.body.sysImageType) {
        identity.sysImageType = req.body.sysImageType;
      }
      if(req.body.sysPublic) {
        identity.sysPublic = req.body.sysPublic;
      }
      if(req.body.url) {
        identity.url = req.body.url;
      }

      // add identity
      auth.createIdentity(
        req.user.identity, identity, function(err) {
        if(err) {
          if(database.isDuplicateError(err)) {
            return next(new BedrockError(
              'The identity is a duplicate and could not be added.',
              'DuplicateIdentity', {
                identity: identity.id,
                httpStatusCode: 409,
                'public': true
              }));
          }
          return next(new BedrockError(
            'The identity could not be added.',
            'AddIdentityFailed', {
              httpStatusCode: 400,
              'public': true
            }, err));
        }
        // return identity
        res.set('Location', identity.id);
        res.status(201).json(identity);
      });
    });
  docs.annotate.post(basePath, {
    displayName: 'Managing Identity',
    description: 'Create a new identity on the system.',
    securedBy: ['cookie', 'hs1'],
    schema: 'services.identity.postIdentities',
    querySchema: 'services.identity.postIdentitiesQuery',
    responses: {
      201: 'Identity creation was successful. The Location header will ' +
        'contain the URL identifier for the identity.',
      400: 'The identity was rejected. ' +
        'Error details will be included in the response body.',
      409: 'The identity was rejected because it is a duplicate.'
    }
  });

  app.get(basePath,
    ensureAuthenticated,
    validate({query: 'services.identity.getIdentitiesQuery'}),
    function(req, res, next) {
      if(req.query.service === 'add-key') {
        // logged in at this point, redirect to keys page and preserve query
        var urlObj = url.parse(req.originalUrl);
        urlObj.pathname = util.format(
          '%s/%s/keys',
          urlObj.pathname,
          req.user.identity.sysSlug);
        var redirUrl = url.format(urlObj);
        res.redirect(307, redirUrl);
        return;
      }

      res.send(404);
      /*
      // TODO: get identities that current identity is a memberOf? (orgs?)
      // FIXME: use .auto instead?
      async.waterfall([
        function(callback) {
          brIdentity.get(req.user.identity, req.user.identity.id, callback);
        },
        function(identity, identityMeta, callback) {
          // get all related identities
          _getIdentities(req, function(err, identities) {
            callback(err, identity, identityMeta, identities);
          });
        }
      ], function(err) {
        if(err) {
          next(err);
        }
      });
      */
    });
  docs.annotate.get(basePath, {
    description: 'Discover the endpoint of a particular identity service. ' +
      'This method is typically used by a 3rd party website that wants to ' +
      'perform operations on an unknown identity, like adding a public key, ' +
      'but does not know the exact service URL for the operation.' +
      'Valid actions include \'query\', and valid services include ' +
      '\'add-key\'.',
    securedBy: ['cookie', 'hs1'],
    querySchema: 'services.identity.getIdentitiesQuery',
    responses: {
      307: 'A redirect to the location of the actual service.',
      404: 'The request did not result in an action.'
    }
  });

  app.post(idPath,
    ensureAuthenticated,
    validate('services.identity.postIdentity'),
    function(req, res, next) {
      async.auto({
        getId: auth.getIdentityIdFromUrl.bind(null, req),
        update: ['getId', function(callback, results) {
          // check id matches
          if(req.body.id !== results.getId) {
            return callback(new BedrockError(
              'Identity mismatch.',
              'IdentityMismatch', {
                identity: results.getId,
                httpStatusCode: 400,
                'public': true
              }));
          }

          var identity = {id: results.getId};

          // conditional values only set if preset
          if(req.body.description) {
            identity.description = req.body.description;
          }
          if(req.body.image) {
            identity.image = req.body.image;
          }
          if(req.body.label) {
            identity.label = req.body.label;
          }
          if(req.body.sysGravatarType) {
            identity.sysGravatarType = req.body.sysGravatarType;
          }
          if(req.body.sysImageType) {
            identity.sysImageType = req.body.sysImageType;
          }
          if(req.body.sysPublic) {
            identity.sysPublic = req.body.sysPublic;
          }
          if(req.body.sysSigningKey) {
            identity.sysSigningKey = req.body.sysSigningKey;
          }
          if(req.body.url) {
            identity.url = req.body.url;
          }

          // FIXME: allow changes to identity type?
          /*
          //identity.type = req.body.type;
          */

          // TODO: replace/implement/reimplement `updateIdentity`
          // update identity
          brIdentity.updateIdentity(req.user.identity, identity, callback);
        }]
      }, function(err) {
        if(err) {
          return next(err);
        }
        res.status(204).end();
      });
    });
  docs.annotate.post(idPath, {
    description: 'Update an existing identity on the system.',
    securedBy: ['cookie', 'hs1'],
    schema: 'services.identity.postIdentity',
    responses: {
      204: 'The identity was updates successfully.',
      400: 'The provided identity did not match any in the database.'
    }
  });

  // authentication not required
  app.options(idPath, cors());
  app.get(idPath, cors(), function(req, res, next) {
    // FIXME: refactor this ... just put data into the identity like how
    // it is returned when application/ld+json is accepted?
    var data = {};

    // FIXME: optimize this
    async.auto({
      getId: auth.getIdentityIdFromUrl.bind(null, req),
      getIdentity: ['getId', function(callback, results) {
        // get identity without permission check
        brIdentity.get(null, results.getId, function(err, identity, meta) {
          if(err) {
            return callback(err);
          }
          data.privateIdentity = identity;

          // determine if requestor is the identity
          var isIdentity = (req.isAuthenticated() &&
            identity.id === req.user.identity.id);
          if(isIdentity) {
            data.identity = identity;
          } else {
            // only include public info
            data.publicIdentity = {
              '@context': bedrock.config.constants.IDENTITY_CONTEXT_V1_URL,
              id: identity.id,
              type: identity.type
            };
            identity.sysPublic.forEach(function(field) {
              data.publicIdentity[field] = identity[field];
            });
            data.identity = data.publicIdentity;
          }
          data.identityMeta = meta;
          callback();
        });
      }],
      getKeys: ['getId', function(callback, results) {
        // get identity's keys
        brIdentity.getPublicKeys(results.getId, function(err, records) {
          callback(err, records);
        });
      }],
      getActiveKeys: ['getKeys', function(callback, results) {
        var keys = data.keys = [];
        results.getKeys.forEach(function(record) {
          var key = record.publicKey;
          if(key.sysStatus === 'active') {
            keys.push(key);
          }
        });
        callback(null);
      }]
    }, function(err) {
      if(err) {
        return next(err);
      }

      function ldjson() {
        // build identity w/embedded keys
        var identity = data.identity;
        for(var i = 0; i < data.keys.length; ++i) {
          var key = data.keys[i];
          delete key['@context'];
          delete key.publicKeyPem;
          delete key.sysStatus;
          jsonld.addValue(identity, 'publicKey', key);
        }
        res.json(identity);
      }
      res.format({
        'application/ld+json': ldjson,
        json: ldjson,
        html: function() {
          res.render('identity.html', data.vars);
        }
      });
      return;
    });
  });
  docs.annotate.get(idPath, {
    description: 'Retrieve an existing identity on the system.',
    securedBy: ['null', 'cookie', 'hs1'],
    responses: {
      200: {
        'application/ld+json': {
          example: 'examples/get.identity.jsonld'
        }
      },
      404: 'The identity was not found on the system.'
    }
  });
});

/**
 * Creates a local (non-DID) Identity ID from the given name.
 *
 * @param name the short identity name (slug).
 *
 * @return the local (non-DID) Identity ID for the Identity.
 */
var createIdentityId = function(name) {
  return util.format('%s%s/%s',
    bedrock.config.server.baseUri,
    bedrock.config.idp.identityBasePath,
    encodeURIComponent(name));
};

/**
 * Creates a new Identity. The Identity must contain `id`.
 *
 * @param actor the Identity performing the action.
 * @param identity the Identity containing at least the minimum required data.
 * @param callback(err, record) called once the operation completes.
 */
var createIdentity = function(actor, identity, callback) {
  // TODO: move password/passcode to meta
  async.auto({
    checkDuplicate: function(callback) {
      // check for a duplicate to prevent generating password hashes
      database.collections.identity.findOne(
        {'identity.sysSlug': identity.sysSlug}, {'identity.sysSlug': true},
        function(err, record) {
          if(err) {
            return callback(err);
          }
          if(record) {
            // simulate duplicate identity error
            err = new Error('Duplicate Identity.');
            err.name = 'MongoError';
            err.code = 11000;
            return callback(err);
          }
          callback();
        });
    },
    setDefaults: ['checkDuplicate', function(callback) {
      var defaults = bedrock.util.clone(config['identity-rest'].defaults);

      // add identity defaults
      identity = bedrock.util.extend(
        {}, defaults.identity, bedrock.util.clone(identity));

      // create identity ID from slug if not present
      if(!('id' in identity)) {
        identity.id = createIdentityId(identity.sysSlug);
      }

      /* Note: If the identity doesn't have a password, generate a fake one
      for them (that will not be known by anyone). This simplifies the code
      path for verifying passwords. */
      if(!('sysPassword' in identity)) {
        identity.sysPassword = _generatePasscode();
      }

      callback();
    }],
    generatePasscode: ['checkDuplicate', function(callback) {
      // generate new random passcode for identity
      callback(null, _generatePasscode());
    }],
    hashPassword: ['checkDuplicate', function(callback) {
      if(identity.sysHashedPassword === true) {
        // password already hashed
        delete identity.sysHashedPassword;
        return callback(null, identity.sysPassword);
      }
      createPasswordHash(identity.sysPassword, callback);
    }],
    hashPasscode: ['generatePasscode', function(callback, results) {
      if(identity.sysHashedPasscode === true) {
        // passcode already hashed
        delete identity.sysHashedPasscode;
        return callback(null, identity.sysPasscode);
      }
      createPasswordHash(results.generatePasscode, callback);
    }],
    insert: ['hashPassword', 'hashPasscode', function(callback, results) {
      // store hash results
      identity.sysPassword = results.hashPassword;
      identity.sysPasscode = results.hashPasscode;

      // insert the identity
      var now = Date.now();
      var record = {
        id: database.hash(identity.id),
        meta: {
          created: now,
          updated: now
        },
        identity: identity
      };
      brIdentity.insert(null, identity, function(err, record) {
        if(err) {
          return callback(err);
        }
        // return unhashed passcode in record
        record.identity.sysPasscode = results.generatePasscode;
        callback(null, record);
      });
    }]
  }, function(err, results) {
    callback(err, results.insert);
  });
};

/**
 * Creates a password hash that can be stored and later used to verify a
 * password at a later point in time.
 *
 * @param password the password to hash.
 * @param callback(err, hash) called once the operation completes.
 */
var createPasswordHash = function(password, callback) {
  bcrypt.genSalt(function(err, salt) {
    if(err) {
      return callback(err);
    }
    bcrypt.hash(password, salt, function(err, hash) {
      callback(err, 'bcrypt:' + hash);
    });
  });
};

// static passcode character set
var CHARSET = (
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');

/**
 * Generates a passcode for resetting a password. This passcode must be
 * stored using a password hash in the database.
 *
 * @return the generated passcode.
 */
function _generatePasscode() {
  // passcodes are 8 chars long
  var rval = '';
  for(var i = 0; i < 8; ++i) {
    rval += CHARSET.charAt(parseInt(Math.random() * (CHARSET.length - 1), 10));
  }
  return rval;
}
