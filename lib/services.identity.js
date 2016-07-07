/*
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */
var _ = require('lodash');
var async = require('async');
var bedrock = require('bedrock');
var config = bedrock.config;
var brKey = require('bedrock-key');
var brIdentity = require('bedrock-identity');
var brPassport = require('bedrock-passport');
var brPermission = require('bedrock-permission');
var BedrockError = bedrock.util.BedrockError;
var cors = require('cors');
var database = require('bedrock-mongodb');
var docs = require('bedrock-docs');
var jsonld = require('jsonld');
var validate = require('bedrock-validation').validate;
var ensureAuthenticated = brPassport.ensureAuthenticated;
var util = require('util');

// module permissions
var PERMISSIONS = config.permission.permissions;

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
        brKey.addPublicKey(null, publicKey, privateKey, function(err) {
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

bedrock.events.on('bedrock-identity.postInsert', function(e) {
  if(e.actor) {
    bedrock.events.emit('bedrock-identity-rest.created', e);
    return;
  }
  bedrock.events.emit('bedrock-identity-rest.joined', e);
});

// add routes
bedrock.events.on('bedrock-express.configure.routes', function(app) {
  var basePath = bedrock.config['identity-rest'].basePath;
  var idPath = basePath + '/:identity';

  app.post(basePath,
    ensureAuthenticated,
    //validate({query: 'services.identity.postIdentitiesQuery'}),
    //validate('services.identity.postIdentities'),
    function(req, res, next) {
      // do identity credentials query
      // FIXME: this should be removed if not needed
      /*
      if(req.query.action === 'query') {
        return _getCredentials(req, res, next);
      }
      */

      // do create identity
      var identity = {};
      identity['@context'] = bedrock.config.constants.IDENTITY_CONTEXT_V1_URL;
      // TODO: allow DID to be specified (if `id` is present, ensure it is
      // validated as a DID w/a validator fix above; only add a local `id` if
      // no `id` (DID) was given)
      identity.id = createIdentityId(req.body.sysSlug);
      identity.type = req.body.type || 'Identity';
      identity.sysSlug = req.body.sysSlug;
      identity.label = req.body.label;
      identity.sysResourceRole = req.body.sysResourceRole || [];
      identity.sysStatus = req.body.sysStatus || 'active';

      // conditional values only set if present
      if(req.body.description) {
        identity.description = req.body.description;
      }
      if(req.body.email) {
        identity.email = req.body.email;
      }
      if(req.body.generatePasscode) {
        identity.generatePasscode = true;
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
      if(req.body.sysPassword) {
        identity.sysPassword = req.body.sysPassword;
      }
      if(req.body.sysPublic) {
        identity.sysPublic = req.body.sysPublic;
      }
      if(req.body.url) {
        identity.url = req.body.url;
      }
      // add identity
      createIdentity(req.user.identity, identity, function(err, result) {
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
        res.set('Location', result.identity.id);
        res.status(201).json(result.identity);
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
      // TODO: support URL query parameters
      var q = {
        'identity.sysStatus': 'active'
      };
      brIdentity.getAll(req.user.identity, q, function(err, records) {
        if(err) {
          return next(err);
        }
        res.json(_.map(records, 'identity'));
      });

      /*
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
      */
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
    description: 'Get a list of all identities on the system. ' +
    'The information provided will depend on the permissions of the actor.',
    securedBy: ['cookie', 'hs1'],
    querySchema: 'services.identity.getIdentitiesQuery',
    responses: {
      200: 'A list of identities.',
      404: 'The request did not result in an action.'
    }
  });

  // FIXME: create validation schema
  app.patch(
    idPath,
    ensureAuthenticated,
    // validate('services.identity.patchIdentity'),
    function(req, res, next) {
      var updateOperations = req.body.filter(function(o) {
        return o.op == 'updateIdentity';
      }).map(function(o) {
        return o.changes;
      });
      async.eachSeries(updateOperations, function(operation, callback) {
        updateIdentity(req, operation, callback);
      }, function(err) {
        if(err) {
          return next(err);
        }
        res.sendStatus(204);
      });
    });
  docs.annotate.patch(idPath, {
    description: 'Update an existing identity on the system.',
    securedBy: ['cookie', 'hs1'],
    schema: 'services.identity.patchIdentity',
    responses: {
      204: 'The identity was updated successfully.',
      400: 'The provided identity did not match any in the database.'
    }
  });

  // FIXME: remove entirely? replaced by patch method
  /*
  app.post(
    idPath,
    ensureAuthenticated,
    // validate('services.identity.postIdentity'),
    updateIdentity
  );
  docs.annotate.post(idPath, {
    description: 'Update an existing identity on the system.',
    securedBy: ['cookie', 'hs1'],
    schema: 'services.identity.postIdentity',
    responses: {
      204: 'The identity was updates successfully.',
      400: 'The provided identity did not match any in the database.'
    }
  });*/

  // authentication not required
  app.options(idPath, cors());
  app.get(idPath, cors(), function(req, res, next) {
    // FIXME: refactor this ... just put data into the identity like how
    // it is returned when application/ld+json is accepted?
    var data = {};

    // FIXME: optimize this
    async.auto({
      getId: getIdentityIdFromUrl.bind(null, req),
      checkPermission: ['getId', function(callback, results) {
        if(req.isAuthenticated() && 'identity' in req.user) {
          return brPermission.checkPermission(
            req.user.identity, PERMISSIONS.IDENTITY_ACCESS,
            {resource: results.getId}, function(err, result) {
              return callback(null, !err);
            });
        }
        callback(null, false);
      }],
      getIdentity: ['getId', function(callback, results) {
        // get identity without permission check
        brIdentity.get(null, results.getId, function(err, identity, meta) {
          if(err) {
            return callback(err);
          }
          callback(null, {identity: identity, meta: meta});
        });
      }],
      processIdentity: ['getIdentity', 'checkPermission',
        function(callback, results) {
        var identity = results.getIdentity.identity;
        var meta = results.getIdentity.meta;
        if(results.checkPermission) {
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
      }],
      getKeys: ['getId', function(callback, results) {
        // get identity's keys
        brKey.getPublicKeys(results.getId, function(err, records) {
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
          next('route');
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

  app.delete(idPath, ensureAuthenticated, function(req, res, next) {
    var identityId = createIdentityId(req.params.identity);
    brIdentity.setStatus(
      req.user.identity, identityId, 'deleted', function(err) {
      if(err) {
        return next(err);
      }
      res.sendStatus(204);
    });
  });

  // TODO: endpoint for batch update operations, needs fix-up and tests
  app.patch(basePath,
    ensureAuthenticated,
    function(req, res, next) {
      var operations = req.body;
      var deleteOperations = operations.filter(function(operation) {
        return operation.op === 'delete';
      });
      var updateOperations = operations.filter(function(operation) {
        return operation.op === 'update';
      });
      var updateRoleOperations = operations.filter(function(operation) {
        return operation.op === 'updateRoles';
      });

      async.auto({
        delete: function(callback) {
          return callback(new BedrockError(
            'Bulk delete operations not implemented.', 'NotImplemented',
            {httpStatusCode: 400, 'public': true}
          ));
        },
        update: function(callback) {
          return callback(new BedrockError(
            'Bulk update operations not implemented.', 'NotImplemented',
            {httpStatusCode: 400, 'public': true}
          ));
        },
        updateRoles: function(callback) {
          if(updateRoleOperations.length === 0) {
            return callback();
          }
          async.each(updateRoleOperations, function(operation, callback) {
            brIdentity.setRoles(
              req.user.identity, operation.identity, callback);
          }, callback);
        }
      }, function(err) {
        if(err) {
          return next(err);
        }
        res.sendStatus(204);
      });
    });
});

/**
 * Creates a local (non-DID) Identity ID from the given name.
 *
 * @param name the short identity name (slug).
 *
 * @return the local (non-DID) Identity ID for the Identity.
 */
function createIdentityId(name) {
  return util.format('%s%s/%s',
    bedrock.config.server.baseUri,
    bedrock.config['identity-rest'].basePath,
    encodeURIComponent(name));
}

/**
 * Creates a new Identity. The Identity must contain `id`.
 *
 * @param actor the Identity performing the action.
 * @param identity the Identity containing at least the minimum required data.
 * @param callback(err, record) called once the operation completes.
 */
function createIdentity(actor, identity, callback) {
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
      // create identity ID from slug if not present
      if(!('id' in identity)) {
        identity.id = createIdentityId(identity.sysSlug);
      }
      // create sysPublic if not present
      if(!('sysPublic' in identity)) {
        identity.sysPublic = [];
      }

      // if using a 'did:', add resource role for local id
      if(identity.id.indexOf('did:') === 0) {
        identity.sysResourceRole = identity.sysResourceRole || [];
        identity.sysResourceRole.push({
          sysRole: 'identity.registered',
          resource: [createIdentityId(identity.sysSlug)]
        });
      }
      callback();
    }],
    insert: ['setDefaults', function(callback, results) {
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
      brIdentity.insert(actor, identity, function(err, record) {
        if(err) {
          return callback(err);
        }
        callback(null, record);
      });
    }]
  }, function(err, results) {
    callback(err, results.insert);
  });
}

/**
 * Gets an IdentityID from the URL parameters in the given request. In the
 * common case, the authenticated user for the request can be used to obtain
 * the ID without an extra database hit.
 *
 * @param req the request.
 * @param callback(err, identityId) called once the operation completes.
 */
function getIdentityIdFromUrl(req, callback) {
  // TODO: determine if this function's usage anywhere leaks DID information
  // through its slug

  // if slug from URL matches authenticated user (common case), then
  // use its ID
  var slug = req.params.identity;
  if(req.isAuthenticated() && req.user.identity.sysSlug === slug) {
    return callback(null, req.user.identity.id);
  }
  resolveIdentitySlug(slug, {error: true}, callback);
}

/**
 * Gets the Identity ID that matches the given identity name (ID or slug). The
 * Identity ID will be null if none is found. If a full identity ID is passed,
 * it will be passed back in the callback if it is valid.
 *
 * @param name the identity name (ID or slug).
 * @param [options] the options to use:
 *          [error] pass a `NotFound` error to the callback if the ID
 *            could not be found.
 * @param callback(err, identityId) called once the operation completes.
 */
function resolveIdentitySlug(name, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  database.collections.identity.findOne(
    {$or: [{id: database.hash(name)}, {'identity.sysSlug': name}]},
    {'identity.id': true},
    function(err, result) {
      if(!err) {
        if(result) {
          result = result.identity.id;
        } else if(options.error) {
          err = new BedrockError(
            'Identity not found.', 'NotFound', {
            httpStatusCode: 404,
            public: true
          });
        }
      }
      callback(err, result);
    });
}

function updateIdentity(req, operation, callback) {
  async.auto({
    getId: getIdentityIdFromUrl.bind(null, req),
    updateRoles: ['getId', function(callback, results) {
      // Updating roles requires elevated permissions.  Attempt to update roles
      // first and if that fails then fail the entire update operation.
      if(!operation.sysResourceRole) {
        return callback();
      }
      var identity = {
        id: results.getId,
        sysResourceRole: operation.sysResourceRole
      };
      brIdentity.setRoles(req.user.identity, identity, callback);
    }],
    update: ['updateRoles', function(callback, results) {
      var identity = {};
      identity = constructIdentity(operation, config.identity.fields);
      identity.id = results.getId;
      // FIXME: allow changes to identity type?
      /*
      //identity.type = req.body.type;
      */
      brIdentity.update(req.user.identity, identity, callback);
    }]
  }, function(err) {
    callback(err);
  });
}

function constructIdentity(fromIdentity, fields) {
  var constructedIdentity = {identity: {}};
  fromIdentity = {identity: fromIdentity};
  for(var i = 0; i < fields.length; ++i) {
    var field = fields[i];
    var value = _.get(fromIdentity, field, null);
    if(value) {
      _.set(constructedIdentity, field, value);
    }
  }
  return constructedIdentity.identity;
}

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
  // static passcode character set
  var CHARSET = (
    '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');
  var passcodeLength = 40;
  var rval = '';
  for(var i = 0; i < passcodeLength; ++i) {
    rval += CHARSET.charAt(parseInt(Math.random() * (CHARSET.length - 1), 10));
  }
  return rval;
}
