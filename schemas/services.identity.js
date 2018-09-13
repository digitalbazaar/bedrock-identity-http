/*
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {schemas} = require('bedrock-validation');

// FIXME: this schema is not being used.
// const sysImageType = {
//   type: 'string',
//   enum: ['url', 'gravatar']
// };

// FIXME: this schema is not being used.
// const sysGravatarType = {
//   type: 'string',
//   enum: ['gravatar', 'mm', 'identicon', 'monsterid', 'wavatar', 'retro']
// };

// FIXME: this schema is not being used.
// const sysPublic = {
//   title: 'Identity Property Visibility',
//   description: 'A list of Identity properties that are publicly visible.',
//   type: 'array',
//   uniqueItems: true,
//   items: {
//     type: 'string',
//     enum: [
//       'description',
//       'email',
//       'image',
//       'label',
//       'url'
//     ]
//   },
//   errors: {
//     invalid: 'Only "description", "email", "image", "label", and "url" ' +
//       'are permitted.',
//     missing: 'Please enter the properties that should be publicly visible.'
//   }
// };

const deleteIdentityParams = {
  title: 'Delete Identity with Parameters',
  type: 'object',
  properties: {
    id: schemas.identifier()
  },
  additionalProperties: false
};

// FIXME: this schema is not being used.
// const postIdentity = {
//   title: 'Post Identity',
//   required: ['@context', 'id'],
//   type: 'object',
//   properties: {
//     '@context': schemas.jsonldContext(constants.IDENTITY_CONTEXT_V1_URL),
//     id: schemas.identifier(),
//     description: schemas.description(),
//     image: schemas.url(),
//     label: schemas.label(),
//     url: schemas.url(),
//     sysImageType: sysImageType,
//     sysGravatarType: sysGravatarType,
//     sysPublic: sysPublic,
//     sysSigningKey: schemas.identifier()
//   },
//   additionalProperties: false
// };

const getIdentitiesQuery = {
  title: 'Get Identities Query',
  type: 'object',
  properties: {
    service: {
      type: 'string',
      enum: ['add-key']
    },
    'public-key-label': schemas.label(),
    'public-key': schemas.publicKeyPem(),
    'registration-callback': schemas.url(),
    'response-nonce': schemas.nonce(),
  }
};

const postIdentitiesQuery = {
  title: 'Post Identities Query',
  type: 'object',
  properties: {
    action: {
      type: 'string',
      enum: ['query']
    },
    authorize: {
      type: 'string',
      enum: ['true']
    },
    credentials: {
      type: 'string',
      enum: ['true', 'false']
    },
    domain: {
      type: 'string',
      minLength: 1,
      maxLength: 100
    },
    callback: {
      type: schemas.url()
    }
  }
};

// FIXME: this schema is not being used.
// const postIdentities = {
//   title: 'Post Identities',
//   description: 'Identity credentials query or Identity creation',
//   oneOf: [{
//     title: 'Identity Query',
//     description: 'Query Identity credentials',
//     required: ['query'],
//     type: 'object',
//     properties: {
//       query: {
//         type: 'string'
//       }
//     },
//     additionalProperties: false
//   }, {
//     title: 'Create Identity',
//     description: 'Create an Identity',
//     required: [
//       '@context',
//       'email',
//       'label',
//       'sysSlug',
//       'type',
//     ],
//     type: 'object',
//     properties: {
//       '@context': schemas.jsonldContext(constants.IDENTITY_CONTEXT_V1_URL),
//       id: schemas.identifier(),
//       type: {
//         type: 'string',
//         enum: ['Identity']
//       },
//       sysSlug: schemas.slug(),
//       label: schemas.label(),
//       image: schemas.url(),
//       email: schemas.email(),
//       sysPassword: schemas.password(),
//       url: schemas.url({required: false}),
//       description: schemas.description({required: false}),
//       sysImageType: sysImageType,
//       sysGravatarType: sysGravatarType,
//       sysPublic: sysPublic
//     },
//     additionalProperties: false
//   }]
// };

// FIXME: this schema is not being used.
// const postPreferences = {
//   title: 'Post Preferences',
//   type: 'object',
//   properties: {
//     '@context': schemas.jsonldContext(constants.IDENTITY_CONTEXT_V1_URL),
//     type: schemas.jsonldType('IdentityPreferences'),
//     publicKey: {
//       required: false,
//       type: [{
//         // IRI only
//         type: 'string'
//       }, {
//         // label+pem
//         type: 'object',
//         properties: {
//           label: schemas.label(),
//           publicKeyPem: schemas.publicKeyPem()
//         }
//       }]
//     }
//   },
//   additionalProperties: false
// };

// FIXME: this schema is not being used.
// const postEmailVerify = {
//   title: 'Verify email',
//   description: 'Verify an email address.',
//   type: 'object',
//   properties: {
//     sysPasscode: schemas.passcode()
//   },
//   additionalProperties: false
// };

module.exports.deleteIdentityParams = () => deleteIdentityParams;

// module.exports.postIdentity = function() {
//   return postIdentity;
// };

module.exports.getIdentitiesQuery = () => getIdentitiesQuery;

module.exports.postIdentitiesQuery = () => postIdentitiesQuery;

// module.exports.postIdentities = function() {
//   return postIdentities;
// };
// module.exports.postPreferences = function() {
//   return postPreferences;
// };
// module.exports.postEmailVerify = function() {
//   return postEmailVerify;
// };
