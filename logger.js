/**
 * logger.js — structured JSON logger for Elite Hardware POS
 *
 * Replaces scattered console.error/console.log calls with a consistent
 * structured format that can be ingested by log aggregators (Papertrail,
 * Logtail, Datadog, etc.) or simply grepped in production.
 *
 * Usage:
 *   const log = require('./logger');
 *   log.info('Sale recorded', { saleId, amount });
 *   log.warn('Low stock', { item, stock });
 *   log.error('DB error', err, { route: '/api/sell' });
 */

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN_LEVEL = LEVELS[process.env.LOG_LEVEL] ?? LEVELS.info;

function write(level, message, errOrMeta, meta = {}) {
    if (LEVELS[level] < MIN_LEVEL) return;

    // Allow log.error('msg', err) or log.error('msg', err, { extra })
    // or log.info('msg', { extra }) with no error
    let errorInfo = null;
    let extraMeta = meta;

    if (errOrMeta instanceof Error) {
        errorInfo = { message: errOrMeta.message, stack: errOrMeta.stack };
    } else if (errOrMeta && typeof errOrMeta === 'object') {
        extraMeta = errOrMeta;
    }

    const entry = {
        ts:      new Date().toISOString(),
        level,
        message,
        ...extraMeta,
        ...(errorInfo ? { error: errorInfo } : {}),
    };

    const line = JSON.stringify(entry);
    if (level === 'error' || level === 'warn') {
        process.stderr.write(line + '\n');
    } else {
        process.stdout.write(line + '\n');
    }
}

// Express request logger middleware — call app.use(log.middleware) in server.js
function middleware(req, res, next) {
    const start = Date.now();
    res.on('finish', () => {
        const ms = Date.now() - start;
        const level = res.statusCode >= 500 ? 'error'
                    : res.statusCode >= 400 ? 'warn'
                    : 'info';
        write(level, 'HTTP', null, {
            method: req.method,
            path:   req.path,
            status: res.statusCode,
            ms,
            ip:     req.ip,
        });
    });
    next();
}

module.exports = {
    debug:      (msg, meta, extra) => write('debug', msg, meta, extra),
    info:       (msg, meta, extra) => write('info',  msg, meta, extra),
    warn:       (msg, meta, extra) => write('warn',  msg, meta, extra),
    error:      (msg, err,  extra) => write('error', msg, err,  extra),
    middleware,
};
