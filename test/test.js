/*
 * Copyright (c) 2015-2016 Digital Bazaar, Inc. All rights reserved.
 */
var bedrock = require('bedrock');
var config = bedrock.config;
require('bedrock-express');
require('bedrock-requirejs');
require('bedrock-server');
require('../lib');

var permissions = config.permission.permissions;
var roles = config.permission.roles;

roles['bedrock-identity-http.identity.administrator'] = {
  id: 'bedrock-identity-http.identity.administrator',
  label: 'Identity Administrator',
  comment: 'Role for identity administrators.',
  sysPermission: [
    permissions.IDENTITY_ADMIN.id,
    permissions.IDENTITY_ACCESS.id,
    permissions.IDENTITY_INSERT.id,
    permissions.IDENTITY_EDIT.id,
    permissions.IDENTITY_REMOVE.id,
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
    permissions.IDENTITY_EDIT.id,
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

bedrock.start();
