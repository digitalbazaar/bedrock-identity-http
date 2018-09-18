/*
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */

const config = require('bedrock').config;
const path = require('path');

// tests
config.mocha.tests.push(path.join(__dirname, 'mocha'));

// mongodb config
config.mongodb.name = 'bedrock_identity_http_test';
config.mongodb.host = 'localhost';
config.mongodb.port = 27017;
config.mongodb.local.collection = 'bedrock_identity_http_test';
// drop all collections on initialization
config.mongodb.dropCollections = {};
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

const permissions = config.permission.permissions;
const roles = config.permission.roles;

roles['bedrock-identity-http.identity.administrator'] = {
  id: 'bedrock-identity-http.identity.administrator',
  label: 'Identity Administrator',
  comment: 'Role for identity administrators.',
  sysPermission: [
    permissions.IDENTITY_ACCESS.id,
    permissions.IDENTITY_INSERT.id,
    permissions.IDENTITY_UPDATE.id,
    permissions.IDENTITY_REMOVE.id,
    permissions.IDENTITY_CAPABILITY_DELEGATE.id,
    permissions.PUBLIC_KEY_CREATE.id,
    permissions.PUBLIC_KEY_REMOVE.id
  ]
};
roles['bedrock-identity-http.identity.manager'] = {
  id: 'bedrock-identity-http.identity.manager',
  label: 'Identity Manager',
  comment: 'Role for identity managers.',
  sysPermission: [
    permissions.IDENTITY_ACCESS.id,
    permissions.IDENTITY_INSERT.id,
    permissions.IDENTITY_UPDATE.id,
    permissions.IDENTITY_CAPABILITY_DELEGATE.id,
    permissions.PUBLIC_KEY_CREATE.id,
    permissions.PUBLIC_KEY_REMOVE.id
  ]
};

// admin role contains all permissions
roles['bedrock-identity-http.admin'] = {
  id: 'bedrock-identity-http.admin',
  label: 'Administrator',
  comment: 'Role for System Administrator.',
  sysPermission: [].concat(
    roles['bedrock-identity-http.identity.administrator'].sysPermission)
};

// default registered identity role (contains all permissions for a regular
// identity)
roles['bedrock-identity-http.identity.registered'] = {
  id: 'bedrock-identity-http.identity.registered',
  label: 'Registered Identity',
  comment: 'Role for registered identities.',
  sysPermission: [].concat(
    roles['bedrock-identity-http.identity.manager'].sysPermission)
};
