import HTPasswd from './htpasswd';

/**
 * A new instance of HTPasswd class.
 * @param {object} config
 * @param {object} stuff
 * @returns {object}
 */
function HTPasswdWrapper(config, stuff) {
  return new HTPasswd(config, stuff);
}

export default HTPasswdWrapper;

// necessary for verdaccio 2.x to be happy when loading plugin
// uncomment when 3.x release, but remember will break 2.x
module.exports = HTPasswdWrapper;
