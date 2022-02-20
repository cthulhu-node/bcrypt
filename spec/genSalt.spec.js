const { describe, it } = require('mocha');
const assert = require('assert');
const bcrypt = require('../lib/bcrypt');

describe('genSalt', () => {
    it('genSalt', async () => {
        const salt = await bcrypt.genSalt(10);
        assert.ok(salt);
        assert.ok(typeof salt === 'string');
        assert.ok(salt.length !== 0);
        assert.ok(salt.length === 29)
    });
});