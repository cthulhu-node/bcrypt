const { describe, it } = require('mocha');
const assert = require('assert');
const bcrypt = require('../lib/bcrypt');

describe('getRounds', () => {
    it('getRounds', () => {
        const rounds = bcrypt.getRounds('$2a$12$0kdgu4H1rjsNkd67g/YfvOdwCBlv2.DLR7G3jyANY2Lo3Lm62N6o6');
        assert.ok(typeof rounds === 'number');
        assert.ok(rounds === 12);
    });
});