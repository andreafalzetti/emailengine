'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const { Writable } = require('node:stream');
const pathlib = require('node:path');
const { execFileSync } = require('node:child_process');
const pino = require('pino');
const { REDACTED_LOG_KEYS } = require('../lib/consts');
const { headerRedactionPaths } = require('../lib/logger-consts');

const ROOT = pathlib.join(__dirname, '..');

// The logger instances in lib/logger.js and workers/api.js are created with this list, so a key
// missing from it is a secret in the log stream; these cases pin the ones that carry credentials.
test('REDACTED_LOG_KEYS', async t => {
    const lines = [];
    const logger = pino(
        { redact: REDACTED_LOG_KEYS },
        new Writable({
            write(chunk, encoding, callback) {
                lines.push(chunk.toString());
                callback();
            }
        })
    );

    t.beforeEach(() => {
        lines.length = 0;
    });

    await t.test('a URL parse error does not log the URL it rejected', () => {
        let err;
        try {
            // only the parser's exception is under test
            // eslint-disable-next-line no-new
            new URL('socks5://user:s3cret@proxy.example.com:99999');
        } catch (parseError) {
            err = parseError;
        }
        assert.ok(err, 'the port is out of range, so the parser must have refused the URL');

        logger.error({ msg: 'Failed to create HTTP proxy agent', err });

        assert.equal(lines.length, 1);
        assert.ok(lines[0].includes('Invalid URL'), 'the error message is kept');
        assert.ok(!lines[0].includes('s3cret'), 'the credential must not reach the log');
    });

    await t.test('request credentials are redacted', () => {
        logger.info({ msg: 'request', req: { headers: { authorization: 'Bearer top-secret', cookie: 'ee=abc' }, query: { access_token: 'tok-secret' } } });

        assert.equal(lines.length, 1);
        assert.ok(!lines[0].includes('top-secret'));
        assert.ok(!lines[0].includes('ee=abc'));
        assert.ok(!lines[0].includes('tok-secret'));
    });
});

test('headerRedactionPaths', async t => {
    await t.test('nothing set adds nothing', () => {
        assert.deepEqual(headerRedactionPaths(undefined), []);
        assert.deepEqual(headerRedactionPaths(''), []);
        assert.deepEqual(headerRedactionPaths(' , '), []);
    });

    await t.test('names are trimmed, lowercased and deduplicated', () => {
        // Node reports incoming header names in lower case, so that is the key the path has to name
        assert.deepEqual(headerRedactionPaths(' X-Proxy-Auth , x-proxy-auth,X-Api-Key '), ['req.headers["x-proxy-auth"]', 'req.headers["x-api-key"]']);
    });

    await t.test('a name that is not a header name stops the start', () => {
        // Each name becomes a pino path. Skipping a bad one would leave the operator believing a
        // credential is masked while it is written to the log in full.
        for (const value of ['x proxy', 'x-proxy-auth;', 'x"]', 'x-proxy-auth,a.b[0]']) {
            assert.throws(() => headerRedactionPaths(value), /EENGINE_LOG_REDACT_HEADERS: entry \d+ is not a valid HTTP header name/, value);
        }
    });

    await t.test('the error does not repeat the value', () => {
        // A header written with its value is the likeliest mistake, and the value is the secret
        assert.throws(
            () => headerRedactionPaths('x-api-key, X-Proxy-Auth: proxy-shared-secret'),
            err => err.message.includes('entry 2') && !err.message.includes('proxy-shared-secret')
        );
    });

    await t.test('every name the header grammar allows is a working path', () => {
        // The tchar set includes quote, backtick and pipe, which have to survive pino's path compiler
        for (const name of ['x-proxy-auth', "a'b", 'a`b', 'a|b', 'a!#$%&*+.^_~b']) {
            const lines = [];
            const logger = pino({ redact: headerRedactionPaths(name) }, { write: line => lines.push(line) });
            logger.info({ req: { headers: { [name]: 'header-secret', other: 'kept' } } });
            assert.ok(!lines[0].includes('header-secret'), name);
            assert.ok(lines[0].includes('kept'), name);
        }
    });
});

// The root logger and the API request logger are both built from REDACTED_LOG_KEYS as their module
// loads, and the list is read from the environment once. These run in a child process so the variable
// is in place before anything loads, in both orders a worker can load the two modules in.
test('EENGINE_LOG_REDACT_HEADERS reaches the root logger', async t => {
    const probe = first =>
        execFileSync(
            process.execPath,
            [
                '-e',
                `require('./lib/${first}'); require('./lib/logger').info({ msg: 'probe', req: { headers: { 'x-proxy-auth': 'header-secret', other: 'kept' } } });`
            ],
            {
                cwd: ROOT,
                encoding: 'utf-8',
                env: {
                    PATH: process.env.PATH,
                    HOME: process.env.HOME,
                    NODE_ENV: 'test',
                    // lib/load-env.js would otherwise load the developer's own .env
                    EE_ENV_LOADED: 'true',
                    EENGINE_LOG_REDACT_HEADERS: 'X-Proxy-Auth'
                }
            }
        );

    for (const first of ['consts', 'logger']) {
        await t.test(`with lib/${first}.js loaded first`, () => {
            const output = probe(first);
            assert.ok(output.includes('"x-proxy-auth":"[Redacted]"'), output);
            assert.ok(output.includes('"other":"kept"'), output);
            assert.ok(!output.includes('header-secret'));
        });
    }
});
