const { describe, it } = require('mocha');
const assert = require('assert');
const bcrypt = require('../lib/bcrypt');

describe('compare', () => {
    it('compare valid', async () => {
        const result = await bcrypt.compare('test', '$2a$12$0kdgu4H1rjsNkd67g/YfvOdwCBlv2.DLR7G3jyANY2Lo3Lm62N6o6');
        assert.ok(typeof result === 'boolean');
        assert.ok(result);
    });
    it('compare invalid', async () => {
        const result = await bcrypt.compare('test', '$2a$12$0kdgu4H1rjsNkd67g/YfvOdwCBlv2.XLR7G3jyANY2Lo3Lm62N6o6');
        assert.ok(typeof result === 'boolean');
        assert.ok(!result);
    });
});
