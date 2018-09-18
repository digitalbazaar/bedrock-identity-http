/*
 * Copyright (c) 2015-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _ = require('lodash');
const async = require('async');
const bedrock = require('bedrock');
const {config} = bedrock;
const brKey = require('bedrock-key');
const brIdentity = require('bedrock-identity');
const brPassport = require('bedrock-passport');
const brPermission = require('bedrock-permission');
const {BedrockError} = bedrock.util;
const cors = require('cors');
const database = require('bedrock-mongodb');
const docs = require('bedrock-docs');
const jsonld = require('jsonld');
const {validate} = require('bedrock-validation');
const {ensureAuthenticated, optionallyAuthenticated} = brPassport;
const util = require('util');
require('bedrock-express');

// module permissions
const PERMISSIONS = config.permission.permissions;

bedrock.events.on('bedrock-mongodb.ready', function init(callback) {
  async.auto({
    openCollections: callback => {
      database.openCollections(['identity'], callback);
    },
    createIndexes: ['openCollections', (results, callback) => {
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
  }, err => {
    callback(err);
  });
});

bedrock.events.on('bedrock-identity.postInsert', e => {
  if(e.actor) {
    bedrock.events.emit('bedrock-identity-http.created', e);
    return;
  }
  bedrock.events.emit('bedrock-identity-http.joined', e);
});

// add routes
bedrock.events.on('bedrock-express.configure.routes', app => {
  const basePath = bedrock.config['identity-http'].basePath;
  const idPath = basePath + '/:identity';

  app.post(basePath,
    ensureAuthenticated,
    // validate({query: 'services.identity.postIdentitiesQuery'}),
    // validate('services.identity.postIdentities'),
    (req, res, next) => {
      const {actor} = req.user;
      // do identity credentials query
      // FIXME: this should be removed if not needed
      /*
      if(req.query.action === 'query') {
        return _getCredentials(req, res, next);
      }
      */

      // do create identity
      const identity = {};
      identity['@context'] = bedrock.config.constants.IDENTITY_CONTEXT_V1_URL;
      // TODO: allow DID to be specified (if `id` is present, ensure it is
      // validated as a DID w/a validator fix above; only add a local `id` if
      // no `id` (DID) was given)
      identity.id = createIdentityId(req.body.sysSlug);
      identity.type = req.body.type || 'Identity';
      identity.sysSlug = req.body.sysSlug;
      identity.label = req.body.label;

      const meta = {};
      meta.sysResourceRole = req.body.sysResourceRole || [];
      meta.status = req.body.sysStatus || 'active';

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
      if(req.body.owner) {
        identity.owner = req.body.owner;
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
      _createIdentity({actor, identity, meta}, (err, result) => {
        if(err) {
          if(database.isDuplicateError(err)) {
            return next(new BedrockError(
              'The identity is a duplicate and could not be added.',
              'DuplicateError', {
                identity: identity.id,
                httpStatusCode: 409,
                'public': true
              }));
          }
          return next(err);
        }
        // return identity
        res.location(result.identity.id).status(201).json(result.identity);
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
    (req, res, next) => {
      const {actor} = req.user;
      // TODO: support URL query parameters
      const query = {
        'meta.status': 'active'
      };
      brIdentity.getAll({actor, query}, (err, records) => {
        if(err) {
          return next(err);
        }
        res.json(_.map(records, 'identity'));
      });

      /*
      if(req.query.service === 'add-key') {
        // logged in at this point, redirect to keys page and preserve query
        const urlObj = url.parse(req.originalUrl);
        urlObj.pathname = util.format(
          '%s/%s/keys',
          urlObj.pathname,
          req.user.identity.sysSlug);
        const redirUrl = url.format(urlObj);
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
    (req, res, next) => {
      const {actor} = req.user;
      async.auto({
        getId: getIdentityIdFromUrl.bind(null, req),
        applyUpdate: ['getId', (results, callback) => {
          const {patch, sequence} = req.body;
          brIdentity.update(
            {actor, id: results.getId, patch, sequence}, callback);
        }],
      }, err => err ? next(err) : res.status(204).end());
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
  app.get(idPath, optionallyAuthenticated, cors(), (req, res, next) => {
    // FIXME: refactor this ... just put data into the identity like how
    // it is returned when application/ld+json is accepted?
    const data = {};

    // FIXME: optimize this
    async.auto({
      getId: getIdentityIdFromUrl.bind(null, req),
      checkPermission: ['getId', (results, callback) => {
        if(req.isAuthenticated() && 'identity' in req.user) {
          return brPermission.checkPermission(
            req.user.identity, PERMISSIONS.IDENTITY_ACCESS,
            {resource: results.getId}, err => {
              return callback(null, !err);
            });
        }
        callback(null, false);
      }],
      getIdentity: ['getId', (results, callback) => {
        // get identity without permission check
        brIdentity.get(
          {actor: null, id: results.getId}, (err, i) => {
            if(err) {
              return callback(err);
            }
            callback(null, {identity: i.identity, meta: i.meta});
          });
      }],
      processIdentity: ['getIdentity', 'checkPermission',
        (results, callback) => {
          const identity = results.getIdentity.identity;
          const meta = results.getIdentity.meta;
          if(results.checkPermission) {
            data.identity = identity;
          } else {
            // only include public info
            data.publicIdentity = {
              '@context': bedrock.config.constants.IDENTITY_CONTEXT_V1_URL,
              id: identity.id,
              type: identity.type
            };
            identity.sysPublic.forEach(field => {
              data.publicIdentity[field] = identity[field];
            });
            data.identity = data.publicIdentity;
          }
          data.identityMeta = meta;
          callback();
        }],
      getKeys: ['getId', (results, callback) => {
        // get identity's keys
        brKey.getPublicKeys({id: results.getId}, callback);
      }],
      getActiveKeys: ['getKeys', (results, callback) => {
        const keys = data.keys = [];
        results.getKeys.forEach(record => {
          const key = record.publicKey;
          if(key.sysStatus === 'active') {
            keys.push(key);
          }
        });
        callback(null);
      }]
    }, err => {
      if(err) {
        return next(err);
      }

      function ldjson() {
        // build identity w/embedded keys
        const identity = data.identity;
        for(let i = 0; i < data.keys.length; ++i) {
          const key = data.keys[i];
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
        html: () => {
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

  app.delete(idPath, ensureAuthenticated, (req, res, next) => {
    const identityId = createIdentityId(req.params.identity);
    brIdentity.setStatus(req.user.identity, identityId, 'deleted', err => {
      if(err) {
        return next(err);
      }
      res.status(204).end();
    });
  });

  app.delete(basePath,
    ensureAuthenticated,
    validate({query: 'services.identity.deleteIdentityParams'}),
    (req, res, next) => {
      brIdentity.setStatus(req.user.identity, req.query.id, 'deleted', err => {
        if(err) {
          return next(err);
        }
        res.status(204).end();
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
    bedrock.config['identity-http'].basePath,
    encodeURIComponent(name));
}

/**
 * Creates a new Identity. The Identity must contain `id`.
 *
 * @param actor the Identity performing the action.
 * @param identity the Identity containing at least the minimum required data.
 * @param callback(err, record) called once the operation completes.
 */
function _createIdentity({actor, identity, meta}, callback) {
  async.auto({
    checkDuplicate: callback => {
      // check for a duplicate to prevent generating password hashes
      database.collections.identity.findOne(
        {'identity.sysSlug': identity.sysSlug}, {'identity.sysSlug': true},
        (err, record) => {
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
    setDefaults: ['checkDuplicate', (results, callback) => {
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
        meta.sysResourceRole = meta.sysResourceRole || [];
        meta.sysResourceRole.push({
          sysRole: 'identity.registered',
          resource: [createIdentityId(identity.sysSlug)]
        });
      }
      callback();
    }],
    insert: ['setDefaults', (results, callback) => {
      brIdentity.insert({actor, identity, meta}, callback);
    }]
  }, (err, results) => {
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
  const slug = req.params.identity;
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
    (err, result) => {
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

bedrock.events.on('bedrock-views.vars.get', addViewVars);

function addViewVars(req, vars, callback) {
  vars['identity-http'] = {};
  vars['identity-http'].basePath = bedrock.config['identity-http'].basePath;
  vars['identity-http'].baseUri = vars.baseUri + vars['identity-http'].basePath;

  callback();
}
