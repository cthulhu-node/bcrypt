"use strict";

const bcrypt = require('./lib/bcrypt');
const Benchmark = require('benchmark');

const suite = new Benchmark.Suite();

suite.add('hashSync', function () {
    bcrypt.hashSync("Password", 10);
});
suite.add('hash', {
    'defer': true,
    'fn': function (deferred) {
        // avoid test inlining
        suite.name;
        bcrypt.hash("Password", 10).then(() => deferred.resolve());
    }
});
suite.on('cycle', function (event) { console.log(String(event.target)); })

suite.run({ async: true })
