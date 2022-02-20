const crypto = require('crypto');
var base64Utils = require('./bcrypt/util/base64.js');
var impl = require('./bcrypt/impl.js');
var constants = require('./bcrypt/constants.js');
var BCRYPT_SALT_LEN = constants.BCRYPT_SALT_LEN;
var GENSALT_DEFAULT_LOG2_ROUNDS = constants.GENSALT_DEFAULT_LOG2_ROUNDS;

function Bcrypt() {}

/**
 * Synchronously generates a salt.
 * @param {number=} rounds Number of rounds to use, defaults to 10 if omitted
 * @returns {string} Resulting salt
 * @throws {TypeError} If a random fallback is required but not set
 */
Bcrypt.prototype.genSaltSync = function(rounds) {
    !rounds && (rounds = GENSALT_DEFAULT_LOG2_ROUNDS);
    if (typeof rounds !== 'number') {
        throw TypeError("Illegal arguments: "+(typeof rounds)+", "+(typeof seed_length));
    }
    (rounds < 4) && (rounds = 4);
    (rounds > 31) && (rounds = 31);
    rounds = ((rounds < 10) && '0' || '') + rounds;

    return `$2a$${rounds}$${base64Utils.encode(crypto.randomBytes(BCRYPT_SALT_LEN), BCRYPT_SALT_LEN)}`;
};

/**
 * Asynchronously generates a salt.
 * @param {(number|function(Error, string=))=} rounds Number of rounds to use, defaults to 10 if omitted
 * @param {(number|function(Error, string=))=} seed_length Not supported.
 * @param {function(Error, string=)=} callback Callback receiving the error, if any, and the resulting salt
 * @returns {!Promise} If `callback` has been omitted
 * @throws {Error} If `callback` is present but not a function
 */
Bcrypt.prototype.genSalt = async function(rounds) {
    return this.genSaltSync(rounds);
};

/**
 * Synchronously generates a hash for the given string.
 * @param {string} s String to hash
 * @param {(number|string)=} salt Salt length to generate or salt to use, default to 10
 * @returns {string} Resulting hash
 */
Bcrypt.prototype.hashSync = function(s, salt) {
    if (typeof salt === 'undefined')
        salt = GENSALT_DEFAULT_LOG2_ROUNDS;
    if (typeof salt === 'number')
        salt = this.genSaltSync(salt);
    if (typeof s !== 'string' || typeof salt !== 'string')
        throw TypeError("Illegal arguments: "+(typeof s)+', '+(typeof salt));
    return impl.hash(s, salt);
};

/**
 * Asynchronously generates a hash for the given string.
 * @param {string} s String to hash
 * @param {number|string} salt Salt length to generate or salt to use
 * @param {function(Error, string=)=} callback Callback receiving the error, if any, and the resulting hash
 * @param {function(number)=} progressCallback Callback successively called with the percentage of rounds completed
 *  (0.0 - 1.0), maximally once per `MAX_EXECUTION_TIME = 100` ms.
 * @returns {!Promise} If `callback` has been omitted
 * @throws {Error} If `callback` is present but not a function
 */
Bcrypt.prototype.hash = function(s, salt, callback, progressCallback) {
    var self = this;

    function _async(callback) {
        if (typeof s === 'string' && typeof salt === 'number')
            self.genSalt(salt, function(err, salt) {
                impl.hash(s, salt, callback, progressCallback);
            });
        else if (typeof s === 'string' && typeof salt === 'string')
            impl.hash(s, salt, callback, progressCallback);
        else
            process.nextTick(callback.bind(this, TypeError("Illegal arguments: "+(typeof s)+', '+(typeof salt))));
    }

    if (callback) {
        if (typeof callback !== 'function')
            throw TypeError("Illegal callback: "+typeof(callback));
        _async(callback);
    } else
        return new Promise(function(resolve, reject) {
            _async(function(err, res) {
                if (err) {
                    reject(err);
                    return;
                }
                resolve(res);
            });
        });
};

/**
 * Synchronously tests a string against a hash.
 * @param {string} s String to compare
 * @param {string} hash Hash to test against
 * @returns {boolean} true if matching, otherwise false
 * @throws {Error} If an argument is illegal
 */
Bcrypt.prototype.compareSync = function(s, hash) {
    if (typeof s !== "string" || typeof hash !== "string")
        throw TypeError("Illegal arguments: "+(typeof s)+', '+(typeof hash));
    if (hash.length !== 60)
        return false;
    return crypto.timingSafeEqual(Buffer.from(this.hashSync(s, hash.substr(0, hash.length-31))), Buffer.from(hash));
};

/**
 * Asynchronously compares the given data against the given hash.
 * @param {string} s Data to compare
 * @param {string} hash Data to be compared to
 * @param {function(Error, boolean)=} callback Callback receiving the error, if any, otherwise the result
 * @param {function(number)=} progressCallback Callback successively called with the percentage of rounds completed
 *  (0.0 - 1.0), maximally once per `MAX_EXECUTION_TIME = 100` ms.
 * @returns {!Promise} If `callback` has been omitted
 * @throws {Error} If `callback` is present but not a function
 */
Bcrypt.prototype.compare = function(s, hash, callback, progressCallback) {
    var self = this;

    function _async(callback) {
        if (typeof s !== "string" || typeof hash !== "string") {
            process.nextTick(callback.bind(this, TypeError("Illegal arguments: "+(typeof s)+', '+(typeof hash))));
            return;
        }
        if (hash.length !== 60) {
            process.nextTick(callback.bind(this, null, false));
            return;
        }
        self.hash(s, hash.substr(0, 29), function(err, comp) {
            if (err)
                callback(err);
            else
                callback(null, crypto.timingSafeEqual(Buffer.from(comp), Buffer.from(hash)));
        }, progressCallback);
    }

    if (callback) {
        if (typeof callback !== 'function')
            throw TypeError("Illegal callback: "+typeof(callback));
        _async(callback);
    } else
        return new Promise(function(resolve, reject) {
            _async(function(err, res) {
                if (err) {
                    reject(err);
                    return;
                }
                resolve(res);
            });
        });
};

/**
 * Gets the number of rounds used to encrypt the specified hash.
 * @param {string} hash Hash to extract the used number of rounds from
 * @returns {number} Number of rounds used
 * @throws {Error} If `hash` is not a string
 */
Bcrypt.prototype.getRounds = function(hash) {
    if (typeof hash !== "string") {
        throw TypeError("Illegal arguments: " + (typeof hash));
    }
    return ~~(hash[4] + hash[5]);
};

/**
 * Gets the salt portion from a hash. Does not validate the hash.
 * @param {string} hash Hash to extract the salt from
 * @returns {string} Extracted salt part
 * @throws {Error} If `hash` is not a string or otherwise invalid
 */
Bcrypt.prototype.getSalt = function(hash) {
    if (typeof hash !== 'string')
        throw TypeError("Illegal arguments: "+(typeof hash));
    if (hash.length !== 60)
        throw TypeError("Illegal hash length: "+hash.length+" != 60");
    return hash.substring(0, 29);
};

//? include("bcrypt/util.js");

//? include("bcrypt/impl.js");

/**
 * Encodes a byte array to base64 with up to len bytes of input, using the custom bcrypt alphabet.
 * @function
 * @param {!Array.<number>} b Byte array
 * @param {number} len Maximum input length
 * @returns {string}
 */
Bcrypt.prototype.encodeBase64 = base64Utils.encode;

/**
 * Decodes a base64 encoded string to up to len bytes of output, using the custom bcrypt alphabet.
 * @function
 * @param {string} s String to decode
 * @param {number} len Maximum output length
 * @returns {!Array.<number>}
 */
Bcrypt.prototype.decodeBase64 = base64Utils.decode;

module.exports = new Bcrypt();
