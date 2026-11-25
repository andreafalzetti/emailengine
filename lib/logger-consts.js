'use strict';

// The constants lib/logger.js needs, in a module that requires nothing but the dependency-free
// lib/load-env.js. lib/consts.js reads its own environment variables through lib/read-env-value.js,
// which logs through lib/logger.js, so a logger that required lib/consts.js was a require cycle, and
// read-env-value had to defer every log line by a tick to get around it. lib/consts.js re-exports
// both, so other callers are unchanged.
//
// For the same reason EENGINE_LOG_REDACT_HEADERS is read from process.env here and not through
// readEnvValue(): the helper's file branch loads lib/logger.js, which would get this module half
// loaded and build the root logger with no redaction at all. The main process resolves every
// `<KEY>_FILE` into process.env before it starts the logger, and worker threads inherit that.

// lib/consts.js requires this module before it loads .env, so the variable below has to be loaded here
require('./load-env').loadEnvOnce();

// Transient network error codes that indicate a retry-worthy connection failure
const TRANSIENT_NETWORK_CODES = new Set([
    'ENOTFOUND',
    'EAI_AGAIN',
    'ETIMEDOUT',
    'ECONNRESET',
    'ECONNREFUSED',
    // no route to the host, such as an IPv6 address on a host without IPv6 connectivity
    'ENETUNREACH',
    'EHOSTUNREACH',
    'UND_ERR_SOCKET',
    'UND_ERR_CONNECT_TIMEOUT',
    'UND_ERR_HEADERS_TIMEOUT',
    // a response body that stalled mid-transfer
    'UND_ERR_BODY_TIMEOUT'
]);

// Applied by lib/logger.js to the root logger, so every worker inherits it. A logged joi
// ValidationError carries the full submitted payload in `_original` and the offending value in
// each detail context, and `rawPacket` is a TLS-error field that can carry an unparsed
// credential frame - without these a failed validation writes plaintext passwords, OAuth2
// client secrets and access tokens into the log, the per-account log store and Sentry.
// `req.query.access_token` is here because the api-token scheme accepts the credential as a
// query argument, and the request logger (lib/hapi-request-logger.js) logs the parsed query
// object with every request - so a client using that form wrote a live token into this
// instance's own request log. The serialized `req.url` is the pathname only
// (pino-std-serializers reports `req.path`), so the credential reaches the log through the
// query object and nowhere else.
const REDACTED_LOG_KEYS = [
    'req.headers.authorization',
    'req.headers.cookie',
    'req.query.access_token',
    'err.rawPacket',
    'err._original',
    'err.details[*].context.value',
    // the WHATWG URL parser attaches the string it rejected, and a stored proxy or webhook URL
    // carries its credentials inline
    'err.input'
];

// An HTTP header field name (RFC 9110 token), lowercased the way Node reports incoming headers. The
// check is strict because each name becomes a pino redaction path, and a name that is not a path
// pino understands would fail the logger, or worse, redact something else.
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/;

/**
 * Builds the redaction paths for the request headers an operator names in EENGINE_LOG_REDACT_HEADERS.
 *
 * Authorization and Cookie are always redacted. This is for the credentials a deployment adds in front
 * of EmailEngine, such as a shared-secret header that a reverse proxy or WAF requires, which the
 * request logger would otherwise write with every API request.
 *
 * @param {string} [value] Comma-separated header names; case and surrounding whitespace are ignored
 * @returns {string[]} One `req.headers["<name>"]` path per distinct name
 * @throws {Error} When a name is not a valid header name, so a typo stops the start instead of
 *     leaving the header in the log
 */
function headerRedactionPaths(value) {
    const names = new Set();
    const entries = (value || '').split(',');
    for (let i = 0; i < entries.length; i++) {
        const name = entries[i].trim().toLowerCase();
        if (!name) {
            continue;
        }
        if (!HEADER_NAME.test(name)) {
            // The entry itself is not quoted: one written as `Name: value` would put the very
            // credential this exists to hide into the startup error
            throw new Error(
                `EENGINE_LOG_REDACT_HEADERS: entry ${i + 1} is not a valid HTTP header name (expected names such as X-Proxy-Auth, separated by commas)`
            );
        }
        names.add(name);
    }
    return [...names].map(name => `req.headers["${name}"]`);
}

REDACTED_LOG_KEYS.push(...headerRedactionPaths(process.env.EENGINE_LOG_REDACT_HEADERS));

module.exports = { REDACTED_LOG_KEYS, TRANSIENT_NETWORK_CODES, headerRedactionPaths };
