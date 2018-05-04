// @flow

import fs from 'fs';
import Path from 'path';
import type { Config, Logger } from '@verdaccio/types';
import {
  verifyPassword,
  lockAndRead,
  unlockFile,
  parseHTPasswd,
  addUserToHTPasswd,
  sanityCheck,
  parseHTgroup,
  serializeHTgroups,
  addUserToHTGroup,
  getGroupsForUser,
  sanityCheckGroups
} from './utils';

/**
 * HTPasswd - Verdaccio auth class
 */
export default class HTPasswd {
  /**
   *
   * @param {*} config htpasswd file
   * @param {object} stuff config.yaml in object from
   * @param {Config} stuff.config
   * @param {Logger} stuff.logger
   */
  // flow types
  users: {};
  groups: {};
  stuff: {};
  config: {};
  verdaccioConfig: {};
  maxUsers: number;
  path: string;
  groupPath: string;
  logger: {};
  lastTime: any;
  lastTimeGroup: any;
  // constructor
  constructor(
    config: {
      file: string,
      group_file: string,
      max_users: number
    },
    stuff: {
      config: Config,
      logger: Logger
    }
  ) {
    this.users = {};
    this.groups = {};

    // config for this module
    this.config = config;
    this.stuff = stuff;

    // verdaccio logger
    this.logger = stuff.logger;

    // verdaccio main config object
    this.verdaccioConfig = stuff.config;

    // all this "verdaccio_config" stuff is for b/w compatibility only
    this.maxUsers = config.max_users ? config.max_users : Infinity;

    this.lastTime = null;
    this.lastTimeGroup = null;

    let { file, group_file } = config;

    if (!file) {
      file = this.verdaccioConfig.users_file;
    }

    if (!file) {
      throw new Error('should specify "file" in config');
    }
    if (!group_file) {
      throw new Error('should specify "groupFile" in config');
    }

    let selfPath = this.verdaccioConfig['self_path'];
    this.path = Path.resolve(Path.dirname(selfPath), file);
    this.groupPath = Path.resolve(Path.dirname(selfPath), group_file);
  }

  /**
   * authenticate - Authenticate user.
   * @param {string} user
   * @param {string} password
   * @param {function} cb
   * @returns {function}
   */
  authenticate(user: string, password: string, cb: Function) {
    this.reload(err => {
      if (err) {
        return cb(err.code === 'ENOENT' ? null : err);
      }

      let userHash = this.users[user];
      if (!userHash) {
        return cb(null, false);
      }
      if (!verifyPassword(password, userHash)) {
        return cb(null, false);
      }

      // authentication succeeded!
      // return all usergroups this user has access to;
      this.reloadGroups(err => {
        if (err) {
          return cb(err.code === 'ENOENT' ? null : err);
        }

        return cb(null, getGroupsForUser(this.groups, user));
      });
    });
  }

  /**
   * Add user
   * 1. lock file for writing (other processes can still read)
   * 2. reload .htpasswd
   * 3. write new data into .htpasswd.tmp
   * 4. move .htpasswd.tmp to .htpasswd
   * 5. reload .htpasswd
   * 6. unlock file
   *
   * @param {string} user
   * @param {string} password
   * @param {function} realCb
   * @returns {function}
   */
  adduser(user: string, password: string, realCb: Function) {
    let sanity = sanityCheck(
      user,
      password,
      verifyPassword,
      this.users,
      this.maxUsers
    );

    // preliminary checks, just to ensure that file won't be reloaded if it's
    // not needed
    if (sanity) {
      return realCb(sanity, false);
    }

    lockAndRead(this.path, (err, res) => {
      let locked = false;

      // callback that cleans up lock first
      const cb = err => {
        if (locked) {
          unlockFile(this.path, () => {
            // ignore any error from the unlock
            realCb(err, !err);
          });
        } else {
          realCb(err, !err);
        }
      };

      if (!err) {
        locked = true;
      }

      // ignore ENOENT errors, we'll just create .htpasswd in that case
      if (err && err.code !== 'ENOENT') return cb(err);

      let body = (res || '').toString('utf8');
      this.users = parseHTPasswd(body);

      // real checks, to prevent race conditions
      // parsing users after reading file.
      sanity = sanityCheck(
        user,
        password,
        verifyPassword,
        this.users,
        this.maxUsers
      );

      if (sanity) {
        return cb(sanity);
      }

      try {
        body = addUserToHTPasswd(body, user, password);
      } catch (err) {
        return cb(err);
      }

      fs.writeFile(this.path, body, err => {
        if (err) {
          return cb(err);
        }
        this.reload(() => {
          cb(null);
        });
      });
    });
  }

  /**
   * Add groups for user.
   *
   * @param {string} user
   * @param {string | Array<string>} groups
   * @param {function} realCb
   * @returns {function}
   */
  addusergroups(
    user: string,
    groups: string | Array<string>,
    realCb: Function
  ) {
    let groupsArr: Array<string> = sanityCheckGroups(groups);

    if (groupsArr.length === 0) {
      // nothing to do
      return;
    }

    // else lock and write to file, same as htpasswd
    lockAndRead(this.groupPath, (err, res) => {
      let locked = false;

      // callback that cleans up lock first
      const cb = err => {
        if (locked) {
          unlockFile(this.groupPath, () => {
            // ignore any error from the unlock
            realCb(err, !err);
          });
        } else {
          realCb(err, !err);
        }
      };

      if (!err) {
        locked = true;
      }

      // ignore ENOENT errors, we'll just create .htpasswd in that case
      if (err && err.code !== 'ENOENT') return cb(err);

      let body = (res || '').toString('utf8');
      this.groups = parseHTgroup(body);

      let groupsModified = false;
      try {
        groupsModified = addUserToHTGroup(this.groups, user, groupsArr);
      } catch (err) {
        return cb(err);
      }

      if (groupsModified) {
        body = serializeHTgroups(this.groups);
        fs.writeFile(this.groupPath, body, err => {
          if (err) {
            return cb(err);
          }
          this.reloadGroups(() => {
            cb(null);
          });
        });
      } else {
        // no need to write to file
        cb(null);
      }
    });
  }

  /**
   * Reload users
   * @param {function} callback
   */
  reload(callback: Function) {
    fs.stat(this.path, (err, stats) => {
      if (err) {
        return callback(err);
      }
      if (this.lastTime === stats.mtime) {
        return callback();
      }

      this.lastTime = stats.mtime;

      fs.readFile(this.path, 'utf8', (err, buffer) => {
        if (err) {
          return callback(err);
        }

        Object.assign(this.users, parseHTPasswd(buffer));
        callback();
      });
    });
  }

  /**
   * Reload groups
   * @param {function} callback
   */
  reloadGroups(callback: Function) {
    fs.stat(this.groupPath, (err, stats) => {
      if (err) {
        return callback(err);
      }
      if (this.lastTimeGroup === stats.mtime) {
        return callback();
      }

      this.lastTimeGroup = stats.mtime;

      fs.readFile(this.groupPath, 'utf8', (err, buffer) => {
        if (err) {
          return callback(err);
        }

        Object.assign(this.groups, parseHTgroup(buffer));
        callback();
      });
    });
  }
}
