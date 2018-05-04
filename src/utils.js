// @flow

import crypto from 'crypto';
import crypt3 from './crypt3';
import md5 from 'apache-md5';
import bcrypt from 'bcryptjs';
import * as locker from '@verdaccio/file-locking';

// this function neither unlocks file nor closes it
// it'll have to be done manually later
export function lockAndRead(name: string, cb: Function): void {
  locker.readFile(name, { lock: true }, (err, res) => {
    if (err) {
      return cb(err);
    }

    return cb(null, res);
  });
}

// close and unlock file
export function unlockFile(name: string, cb: Function): void {
  locker.unlockFile(name, cb);
}

/**
 * parseHTPasswd - convert htpasswd lines to object.
 * @param {string} input
 * @returns {object}
 */
export function parseHTPasswd(input: string): Object {
  return input.split('\n').reduce((result, line) => {
    const args = line.split(':', 3);
    if (args.length > 1) result[args[0]] = args[1];
    return result;
  }, {});
}

/**
 * verifyPassword - matches password and it's hash.
 * @param {string} passwd
 * @param {string} hash
 * @returns {boolean}
 */
export function verifyPassword(passwd: string, hash: string): boolean {
  if (hash.match(/^\$2(a|b|y)\$/)) {
    return bcrypt.compareSync(passwd, hash);
  } else if (hash.indexOf('{PLAIN}') === 0) {
    return passwd === hash.substr(7);
  } else if (hash.indexOf('{SHA}') === 0) {
    return (
      crypto
        .createHash('sha1')
        .update(passwd, 'binary')
        .digest('base64') === hash.substr(5)
    );
  }
  // for backwards compatibility, first check md5 then check crypt3
  return md5(passwd, hash) === hash || crypt3(passwd, hash) === hash;
}

/**
 * addUserToHTPasswd - Generate a htpasswd format for .htpasswd
 * @param {string} body
 * @param {string} user
 * @param {string} passwd
 * @returns {string}
 */
export function addUserToHTPasswd(
  body: string,
  user: string,
  passwd: string
): string {
  if (user !== encodeURIComponent(user)) {
    const err = Error('username should not contain non-uri-safe characters');

    // $FlowFixMe
    err.status = 409;
    throw err;
  }

  if (crypt3) {
    passwd = crypt3(passwd);
  } else {
    passwd =
      '{SHA}' +
      crypto
        .createHash('sha1')
        .update(passwd, 'binary')
        .digest('base64');
  }
  let comment = 'autocreated ' + new Date().toJSON();
  let newline = `${user}:${passwd}:${comment}\n`;

  if (body.length && body[body.length - 1] !== '\n') {
    newline = '\n' + newline;
  }
  return body + newline;
}

/**
 * Sanity check for a user
 * @param {string} user
 * @param {object} users
 * @param {number} maxUsers
 * @returns {object}
 */
export function sanityCheck(
  user: string,
  password: string,
  verifyFn: Function,
  users: {},
  maxUsers: number
) {
  let err;
  let hash;

  // check for user or password
  if (!user || !password) {
    err = Error('username and password is required');
    // $FlowFixMe
    err.status = 400;
    return err;
  }

  hash = users[user];

  if (hash) {
    const auth = verifyFn(password, hash);
    if (auth) {
      err = Error('username is already registered');
      // $FlowFixMe
      err.status = 409;
      return err;
    }
    err = Error('unauthorized access');
    // $FlowFixMe
    err.status = 401;
    return err;
  } else if (Object.keys(users).length >= maxUsers) {
    err = Error('maximum amount of users reached');
    // $FlowFixMe
    err.status = 403;
    return err;
  }

  return null;
}

/**
 * parseHTgroup - convert htgroup lines to object.
 * htgroup format is groupname separated from list of users by colon.
 * list of users is space separated
 * Ex: mygroup: user1 user2 user3
 *
 * @param {string} input
 * @returns {object}
 */
export function parseHTgroup(input: string): Object {
  return input.split('\n').reduce((result, line) => {
    const args = line.split(':', 2);
    let groupName = args[0];
    let groupUsers;

    if (args.length > 1) {
      // split users
      groupUsers = args[1].split(' ');
    } else {
      // group has no users in it
      groupUsers = [];
    }

    result[groupName] = groupUsers;

    return result;
  }, {});
}

/**
 * Serializes our group objects file into lines to write to .htgroup
 *
 * @param {object} groupsObj
 * @returns {string}
 */
export function serializeHTgroups(groupsObj: {
  [groupName: string]: Array<string>
}): string {
  let body = '';
  for (const groupName of Object.keys(groupsObj)) {
    const groupUsers = groupsObj[groupName];
    body += `${groupName}: ${groupUsers.join(' ')}`;
  }
  return body;
}

/**
 * addUserToHTGroup - Add user to group in .htgroup
 * @param {object} groupsObj
 * @param {string} user
 * @param {Array<string>} groups
 * @returns {boolean} - was groupsObj modified
 */
export function addUserToHTGroup(
  groupsObj: Object,
  user: string,
  groups: Array<string>
): boolean {
  if (user !== encodeURIComponent(user)) {
    const err = Error('username should not contain non-uri-safe characters');

    // $FlowFixMe
    err.status = 409;
    throw err;
  }

  let groupsModified = false;
  groups.forEach(groupName => {
    // check if each user is already in group
    let groupUsers = groupsObj[groupName];
    if (!groupUsers.includes(user)) {
      // add user
      groupUsers.push(user);
      groupsModified = true;
    }
  });

  return groupsModified;
}

/**
 * Always include user in its groups.
 *
 * @param {object} groupsObj
 * @param {string} user
 * @returns {Array<string>} - all groups this user belongs to
 */
export function getGroupsForUser(
  groupsObj: { [groupName: string]: Array<string> },
  user: string
): Array<string> {
  // user always at least includes group with its own name
  let userGroups = [user];

  for (const groupName of Object.keys(groupsObj)) {
    const groupUsers = groupsObj[groupName];
    if (groupUsers.includes(user)) {
      userGroups.push(groupName);
    }
  }

  return userGroups;
}

/**
 *
 * @param {string | Array<string>} groups
 * @returns {Array<string>}
 */
export function sanityCheckGroups(
  groups: string | Array<string>
): Array<string> {
  let groupsArr: Array<string>;

  if (!groups) {
    // log warning (?)
    groupsArr = [];
  } else if (typeof groups === 'string') {
    // treat string as space separated listing of groups
    groupsArr = groups.split(' ');
  } else if (Array.isArray(groups)) {
    groupsArr = [];
    groups.forEach(group => {
      if (typeof group !== 'string') {
        // log warning
        return;
      }
      groupsArr.push(group);
    });
  } else {
    // should log warning
    groupsArr = [];
  }

  return groupsArr;
}
