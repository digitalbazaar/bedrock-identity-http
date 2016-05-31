/*
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */
var bedrock = require('bedrock');
var config = bedrock.config;
require('bedrock-express');
require('bedrock-requirejs');
require('bedrock-server');
require('../lib/api');

var permissions = config.permission.permissions;
var roles = config.permission.roles;

roles['identity.admin'] = {
  id: 'identity.administrator',
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
roles['identity.manager'] = {
  id: 'identity.manager',
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
roles['admin'] = {
  id: 'admin',
  label: 'Administrator',
  comment: 'Role for System Administrator.',
  sysPermission: [].concat(roles['identity.admin'].sysPermission)
};

// default registered identity role (contains all permissions for a regular
// identity)
roles['identity.registered'] = {
  id: 'identity.registered',
  label: 'Registered Identity',
  comment: 'Role for registered identities.',
  sysPermission: [].concat(roles['identity.manager'].sysPermission)
};

bedrock.start();
