/**
 * validate.js — input sanitization helpers for Elite Hardware POS
 *
 * Provides:
 *   sanitize(value)        — strips PostgREST operator chars from free-text inputs
 *   validateBody(schema)   — express middleware: validates req.body fields
 *   validateQuery(schema)  — express middleware: validates req.query fields
 *
 * Schema format:
 *   {
 *     fieldName: { type: 'string'|'number'|'boolean', required: bool, min, max, enum: [] }
 *   }
 */

/**
 * Strip characters that have special meaning in PostgREST filter strings.
 * This prevents injection through .or(), .ilike(), .eq() string interpolation.
 * Characters removed: ( ) , " ' \ and PostgREST operators like .eq. .ilike. etc.
 */
function sanitize(value) {
    if (value === null || value === undefined) return value;
    if (typeof value !== 'string') return value;
    // Remove PostgREST operator injection chars
    return value
        .replace(/[(),"'\\]/g, '')   // structural chars used in filter strings
        .replace(/\.(eq|neq|lt|lte|gt|gte|like|ilike|in|is|fts|cs|cd)\./gi, ' ') // operator injection
        .trim();
}

/**
 * Sanitize all string fields in req.query in-place.
 * Call as app.use(sanitizeQuery) or per-router.
 */
function sanitizeQuery(req, _res, next) {
    for (const key of Object.keys(req.query)) {
        if (typeof req.query[key] === 'string') {
            req.query[key] = sanitize(req.query[key]);
        }
    }
    next();
}

/**
 * Validate and coerce req.body against a schema.
 * Returns 400 with a clear message on failure.
 *
 * Example:
 *   router.post('/api/sell',
 *     validateBody({ itemId: { type:'number', required:true }, quantity: { type:'number', required:true, min:1 } }),
 *     handler
 *   );
 */
function validateBody(schema) {
    return (req, res, next) => {
        const errors = [];
        for (const [field, rules] of Object.entries(schema)) {
            const raw = req.body[field];
            // Required check
            if (rules.required && (raw === undefined || raw === null || raw === '')) {
                errors.push(`"${field}" is required.`);
                continue;
            }
            if (raw === undefined || raw === null || raw === '') continue; // optional, skip

            // Type coercion & checking
            if (rules.type === 'number') {
                const num = Number(raw);
                if (isNaN(num)) { errors.push(`"${field}" must be a number.`); continue; }
                if (rules.min !== undefined && num < rules.min) errors.push(`"${field}" must be at least ${rules.min}.`);
                if (rules.max !== undefined && num > rules.max) errors.push(`"${field}" must be at most ${rules.max}.`);
                req.body[field] = num;
            } else if (rules.type === 'string') {
                const str = String(raw).trim();
                if (rules.minLen && str.length < rules.minLen) errors.push(`"${field}" must be at least ${rules.minLen} characters.`);
                if (rules.maxLen && str.length > rules.maxLen) errors.push(`"${field}" must be at most ${rules.maxLen} characters.`);
                if (rules.enum && !rules.enum.includes(str)) errors.push(`"${field}" must be one of: ${rules.enum.join(', ')}.`);
                if (rules.pattern && !rules.pattern.test(str)) errors.push(`"${field}" has invalid format.`);
                req.body[field] = str;
            } else if (rules.type === 'boolean') {
                req.body[field] = raw === true || raw === 'true' || raw === 1 || raw === '1';
            }
        }
        if (errors.length) {
            return res.status(400).json({ success: false, message: errors.join(' ') });
        }
        next();
    };
}

/**
 * Validate req.query fields against a schema (same format as validateBody).
 */
function validateQuery(schema) {
    return (req, res, next) => {
        const errors = [];
        for (const [field, rules] of Object.entries(schema)) {
            const raw = req.query[field];
            if (rules.required && (raw === undefined || raw === null || raw === '')) {
                errors.push(`Query param "${field}" is required.`);
                continue;
            }
            if (raw === undefined || raw === null || raw === '') continue;

            if (rules.type === 'number') {
                const num = Number(raw);
                if (isNaN(num)) { errors.push(`Query param "${field}" must be a number.`); continue; }
                if (rules.min !== undefined && num < rules.min) errors.push(`"${field}" must be >= ${rules.min}.`);
                if (rules.max !== undefined && num > rules.max) errors.push(`"${field}" must be <= ${rules.max}.`);
                req.query[field] = num;
            } else if (rules.type === 'string') {
                const str = String(raw).trim();
                if (rules.enum && !rules.enum.includes(str)) errors.push(`"${field}" must be one of: ${rules.enum.join(', ')}.`);
                req.query[field] = str;
            }
        }
        if (errors.length) {
            return res.status(400).json({ success: false, message: errors.join(' ') });
        }
        next();
    };
}

module.exports = { sanitize, sanitizeQuery, validateBody, validateQuery };
