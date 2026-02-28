/**
 * ============================================================
 * NUESA BIU API SERVER - ORGANIZED VERSION
 * ============================================================
 * 
 * Production-ready Express.js server for NUESA BIU (Benson Idahosa University)
 * with comprehensive security, caching, logging, and database features.
 * 
 * @author NUESA BIU Team
 * @version 1.0.0
 * @license MIT
 */

// ============================================================
// SECTION 1: ENVIRONMENT & CORE DEPENDENCIES
// ============================================================

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const winston = require('winston');
const xss = require('xss-clean');
const hpp = require('hpp');
const morgan = require('morgan');
const timeout = require('connect-timeout');
const mime = require('mime-types');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const uuid = require('uuid');
const Joi = require('joi');
const csrf = require('csurf');
const Redis = require('ioredis');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// ============================================================
// SECTION 2: CONFIGURATION & VALIDATION
// ============================================================

const REQUIRED_ENV_VARS = [
    'JWT_SECRET',
    'SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY'
];

const missingEnvVars = REQUIRED_ENV_VARS.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
    console.error('❌ ERROR: Missing required environment variables:', missingEnvVars.join(', '));
    process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const IS_PRODUCTION = NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024;
const MAX_REQUEST_SIZE = process.env.MAX_REQUEST_SIZE || '10mb';

// ============================================================
// SECTION 3: DATABASE & CACHE SETUP
// ============================================================

// Redis Setup
let redis = null;
if (process.env.REDIS_URL) {
    try {
        redis = new Redis(process.env.REDIS_URL, {
            maxRetriesPerRequest: 3,
            retryStrategy: (times) => Math.min(times * 50, 2000),
            enableReadyCheck: true,
            lazyConnect: true
        });
        
        redis.on('connect', () => console.log('✅ Redis connected successfully'));
        redis.on('error', (err) => console.warn('⚠️ Redis connection error:', err.message));
    } catch (error) {
        console.warn('⚠️ Redis connection failed, using in-memory cache:', error.message);
    }
}

// Supabase Setup
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false
    },
    db: {
        schema: 'public',
        pool: {
            max: 20,
            idleTimeoutMillis: 30000
        }
    },
    global: {
        headers: {
            'x-application-name': 'nuesa-biu-api',
            'x-version': '1.0.0'
        }
    }
});

// ============================================================
// SECTION 4: CUSTOM ERROR CLASSES
// ============================================================

class DatabaseError extends Error {
    constructor(message, code, table, operation) {
        super(message);
        this.name = 'DatabaseError';
        this.code = code;
        this.table = table;
        this.operation = operation;
        this.timestamp = new Date();
        this.statusCode = 400;
    }
}

class ValidationError extends Error {
    constructor(message, errors = []) {
        super(message);
        this.name = 'ValidationError';
        this.errors = errors;
        this.statusCode = 400;
    }
}

class NotFoundError extends Error {
    constructor(resource) {
        super(`${resource} not found`);
        this.name = 'NotFoundError';
        this.statusCode = 404;
    }
}

class AuthError extends Error {
    constructor(message, code = 'AUTH_ERROR') {
        super(message);
        this.name = 'AuthError';
        this.code = code;
        this.statusCode = 401;
    }
}

class ForbiddenError extends Error {
    constructor(message = 'Access denied') {
        super(message);
        this.name = 'ForbiddenError';
        this.statusCode = 403;
    }
}

// ============================================================
// SECTION 5: DATABASE SERVICE LAYER
// ============================================================

class DatabaseService {
    constructor(supabase) {
        this.supabase = supabase;
        this.queryCount = 0;
        this.queryTimes = [];
    }

    async query(operation, table, options = {}) {
        const startTime = Date.now();
        this.queryCount++;

        try {
            const {
                data = null,
                select = '*',
                where = {},
                order = {},
                limit = null,
                offset = 0,
                count = false
            } = options;

            let query;

            switch (operation) {
                case 'select':
                    query = this.supabase.from(table).select(select, count ? { count: 'exact' } : {});
                    break;
                case 'insert':
                    query = this.supabase.from(table).insert(data).select(select);
                    break;
                case 'update':
                    query = this.supabase.from(table).update(data).select(select);
                    break;
                case 'upsert':
                    query = this.supabase.from(table).upsert(data).select(select);
                    break;
                case 'delete':
                    query = this.supabase.from(table).delete().select(select);
                    break;
                default:
                    throw new Error(`Unknown operation: ${operation}`);
            }

            if (where && Object.keys(where).length > 0) {
                for (const [key, value] of Object.entries(where)) {
                    if (Array.isArray(value)) {
                        query = query.in(key, value);
                    } else if (typeof value === 'object' && value.operator) {
                        switch (value.operator) {
                            case 'like': query = query.like(key, value.value); break;
                            case 'ilike': query = query.ilike(key, value.value); break;
                            case 'gt': query = query.gt(key, value.value); break;
                            case 'lt': query = query.lt(key, value.value); break;
                            case 'gte': query = query.gte(key, value.value); break;
                            case 'lte': query = query.lte(key, value.value); break;
                            case 'neq': query = query.neq(key, value.value); break;
                            case 'contains': query = query.contains(key, value.value); break;
                            case 'overlaps': query = query.overlaps(key, value.value); break;
                            case 'isNull': query = query.is(key, null); break;
                            default: query = query.eq(key, value.value);
                        }
                    } else if (value !== undefined && value !== null) {
                        query = query.eq(key, value);
                    }
                }
            }

            if (order.column) {
                query = query.order(order.column, {
                    ascending: order.ascending !== false,
                    nullsFirst: order.nullsFirst || false
                });
            }

            if (limit && operation === 'select') {
                query = query.range(offset, offset + limit - 1);
            }

            const result = await query;
            const queryTime = Date.now() - startTime;
            this.queryTimes.push(queryTime);
            if (this.queryTimes.length > 100) this.queryTimes.shift();

            if (result.error) {
                throw new DatabaseError(result.error.message, result.error.code, table, operation);
            }

            return {
                data: result.data || [],
                count: result.count,
                status: 'success',
                queryTime
            };
        } catch (error) {
            console.error(`Database ${operation} error on table ${table}:`, error);
            throw error;
        }
    }

    getStats() {
        const avgQueryTime = this.queryTimes.length > 0 
            ? this.queryTimes.reduce((a, b) => a + b, 0) / this.queryTimes.length 
            : 0;
        
        return {
            totalQueries: this.queryCount,
            averageQueryTime: Math.round(avgQueryTime) + 'ms',
            recentQueryTimes: this.queryTimes.slice(-10)
        };
    }
}

const db = new DatabaseService(supabase);

// ============================================================
// SECTION 6: LOGGING SYSTEM
// ============================================================

const LOG_DIR = 'logs';
if (!fsSync.existsSync(LOG_DIR)) {
    fsSync.mkdirSync(LOG_DIR, { recursive: true });
}

const logger = winston.createLogger({
    level: IS_PRODUCTION ? 'info' : 'debug',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'nuesa-biu-api', environment: NODE_ENV },
    transports: [
        new winston.transports.File({
            filename: `${LOG_DIR}/error.log`,
            level: 'error',
            maxsize: 10 * 1024 * 1024,
            maxFiles: 10,
            tailable: true
        }),
        new winston.transports.File({
            filename: `${LOG_DIR}/combined.log`,
            maxsize: 20 * 1024 * 1024,
            maxFiles: 10,
            tailable: true
        }),
        new winston.transports.File({
            filename: `${LOG_DIR}/audit.log`,
            level: 'info',
            maxsize: 10 * 1024 * 1024,
            maxFiles: 5,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.printf(({ timestamp, level, message, ...meta }) => {
                    return JSON.stringify({ timestamp, level, message, ...meta });
                })
            )
        })
    ]
});

if (!IS_PRODUCTION) {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.timestamp(),
            winston.format.printf(({ timestamp, level, message, ...meta }) => {
                const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
                return `${timestamp} ${level}: ${message}${metaStr}`;
            })
        )
    }));
}

// ============================================================
// SECTION 7: CACHE MANAGEMENT
// ============================================================

class LRUCache {
    constructor(maxSize = 100, ttl = 300000) {
        this.cache = new Map();
        this.maxSize = maxSize;
        this.ttl = ttl;
        this.hits = 0;
        this.misses = 0;
    }

    set(key, value, customTTL = null) {
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }

        this.cache.set(key, {
            value,
            expiry: Date.now() + (customTTL || this.ttl),
            accessed: Date.now()
        });
    }

    get(key) {
        const item = this.cache.get(key);
        if (!item) {
            this.misses++;
            return null;
        }

        if (Date.now() > item.expiry) {
            this.cache.delete(key);
            this.misses++;
            return null;
        }

        item.accessed = Date.now();
        this.hits++;
        return item.value;
    }

    delete(key) {
        return this.cache.delete(key);
    }

    clear() {
        this.cache.clear();
        this.hits = 0;
        this.misses = 0;
    }

    getStats() {
        const hitRate = this.hits + this.misses > 0 ? this.hits / (this.hits + this.misses) : 0;
        return {
            size: this.cache.size,
            maxSize: this.maxSize,
            hits: this.hits,
            misses: this.misses,
            hitRate: Math.round(hitRate * 100) + '%',
            ttl: this.ttl
        };
    }
}

class CacheManager {
    constructor() {
        this.caches = new Map();
        this.redis = redis;
    }

    getCache(name, options = {}) {
        if (!this.caches.has(name)) {
            this.caches.set(name, new LRUCache(options.maxSize || 100, options.ttl || 300000));
        }
        return this.caches.get(name);
    }

    async get(key) {
        if (this.redis) {
            const value = await this.redis.get(key);
            if (value) return JSON.parse(value);
            return null;
        }
        return this.caches.get('default')?.get(key) || null;
    }

    async set(key, value, ttl = 300000) {
        if (this.redis) {
            await this.redis.set(key, JSON.stringify(value), 'PX', ttl);
        } else {
            if (!this.caches.has('default')) {
                this.caches.set('default', new LRUCache(100, ttl));
            }
            this.caches.get('default').set(key, value, ttl);
        }
    }

    async delete(key) {
        if (this.redis) {
            await this.redis.del(key);
        } else {
            this.caches.forEach(cache => cache.delete(key));
        }
    }

    async invalidate(pattern) {
        if (this.redis) {
            const keys = await this.redis.keys(pattern);
            if (keys.length > 0) await this.redis.del(...keys);
        } else {
            this.caches.forEach((cache, cacheName) => {
                if (cacheName.match(pattern)) cache.clear();
            });
        }
    }

    async invalidateByTags(tags) {
        for (const tag of tags) {
            await this.invalidate(`tag:${tag}:*`);
        }
    }

    clearAll() {
        if (this.redis) {
            this.redis.flushdb();
        } else {
            this.caches.forEach(cache => cache.clear());
        }
    }

    getStats() {
        const stats = {};
        this.caches.forEach((cache, name) => {
            stats[name] = cache.getStats();
        });
        if (this.redis) stats.redis = { connected: true };
        return stats;
    }
}

const cacheManager = new CacheManager();
const userCache = cacheManager.getCache('users', { maxSize: 200, ttl: 300000 });
const dataCache = cacheManager.getCache('data', { maxSize: 100, ttl: 60000 });

// ============================================================
// SECTION 8: SECURITY MIDDLEWARE SETUP
// ============================================================

app.set('trust proxy', 1);

// Request ID Middleware
app.use((req, res, next) => {
    req.id = uuid.v4();
    res.setHeader('X-Request-ID', req.id);
    next();
});

// Security Headers
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});

// Compression
app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

// Helmet with custom CSP
const CSP_DIRECTIVES = {
    defaultSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:", "blob:"],
    connectSrc: ["'self'", supabaseUrl, "https://*.supabase.co"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"]
};

if (process.env.FRONTEND_URL) {
    CSP_DIRECTIVES.connectSrc.push(process.env.FRONTEND_URL);
}

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CSRF Protection (except API routes)
const csrfProtection = csrf({ cookie: true });
app.use('/portal', (req, res, next) => {
    if (req.path === '/login') return next();
    csrfProtection(req, res, next);
});

// XSS & HPP Protection
app.use(xss());
app.use(hpp({ whitelist: ['page', 'limit', 'sort', 'fields'] }));

// CORS Configuration
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(origin => origin.trim())
    .filter(origin => origin.length > 0);

if (process.env.FRONTEND_URL && !ALLOWED_ORIGINS.includes(process.env.FRONTEND_URL)) {
    ALLOWED_ORIGINS.push(process.env.FRONTEND_URL);
}

ALLOWED_ORIGINS.push('https://nuesa-biu-pjp0.onrender.com');
ALLOWED_ORIGINS.push('https://www.nuesa-biu-pjp0.onrender.com');

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (!IS_PRODUCTION) return callback(null, true);
        if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            logger.warn(`Blocked by CORS: ${origin}`, { allowedOrigins: ALLOWED_ORIGINS });
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
    allowedHeaders: [
        'Content-Type', 'Authorization', 'Accept', 'Origin', 
        'X-Requested-With', 'X-API-Key', 'X-Total-Count', 
        'X-Page-Count', 'X-CSRF-Token'
    ],
    exposedHeaders: [
        'X-Total-Count', 'X-Page-Count', 'X-RateLimit-Limit',
        'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'X-Request-ID'
    ],
    maxAge: 86400,
    preflightContinue: false,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.use(cookieParser());

// Body Parsing
app.use(express.json({
    limit: MAX_REQUEST_SIZE,
    verify: (req, res, buf, encoding) => { req.rawBody = buf; }
}));

app.use(express.urlencoded({
    extended: true,
    limit: MAX_REQUEST_SIZE,
    parameterLimit: 100
}));

// Request Logging
const morganFormat = IS_PRODUCTION ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
    stream: { write: (message) => logger.http(message.trim()) },
    skip: (req, res) => req.path === '/api/health' && req.method === 'GET'
}));

// Timeout Handling
app.use(timeout('30s'));
app.use((req, res, next) => {
    if (req.timedout) {
        logger.error('Request timeout', {
            requestId: req.id, url: req.url, method: req.method,
            ip: req.ip, userId: req.user?.id
        });
        return res.status(503).json({
            status: 'error', code: 'TIMEOUT',
            message: 'Request timeout. Please try again.'
        });
    }
    next();
});

// Response Time Tracking
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info('Request completed', {
            requestId: req.id, method: req.method, url: req.url,
            status: res.statusCode, duration: `${duration}ms`, userId: req.user?.id
        });
    });
    next();
});

// ============================================================
// SECTION 9: RATE LIMITING & CACHE MIDDLEWARE
// ============================================================

const createRateLimiter = (max, windowMs = 15 * 60 * 1000, message = 'Too many requests') => {
    return rateLimit({
        windowMs, max,
        message: { status: 'error', code: 'TOO_MANY_REQUESTS', message },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip,
        handler: (req, res) => {
            logger.warn('Rate limit exceeded', {
                requestId: req.id, ip: req.ip, url: req.url, method: req.method
            });
            res.status(429).json({
                status: 'error', code: 'TOO_MANY_REQUESTS', message
            });
        }
    });
};

// Apply rate limits
app.use('/api/auth/login', createRateLimiter(10, 15 * 60 * 1000, 'Too many login attempts'));
app.use('/api/admin/login', createRateLimiter(10, 15 * 60 * 1000, 'Too many admin login attempts'));
app.use('/api/contact/submit', createRateLimiter(10, 15 * 60 * 1000, 'Too many contact form submissions'));
app.use('/api/', createRateLimiter(200, 15 * 60 * 1000));

// Cache Middleware
const cacheMiddleware = (duration = 60, tags = []) => {
    return async (req, res, next) => {
        if (req.method !== 'GET' || req.headers.authorization) return next();

        const key = `cache:${req.originalUrl || req.url}`;
        
        try {
            const cachedResponse = await cacheManager.get(key);
            if (cachedResponse) return res.json(cachedResponse);

            const originalSend = res.json;
            res.json = async function (body) {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    await cacheManager.set(key, body, duration * 1000);
                    if (tags.length > 0) {
                        for (const tag of tags) {
                            await cacheManager.set(`tag:${tag}:${key}`, true, duration * 1000);
                        }
                    }
                }
                originalSend.call(this, body);
            };
            next();
        } catch (error) {
            logger.error('Cache middleware error:', { requestId: req.id, error: error.message });
            next();
        }
    };
};

// ============================================================
// SECTION 10: ACCOUNT LOCKOUT SYSTEM
// ============================================================

const loginAttempts = new Map();

async function checkLoginAttempts(identifier) {
    const attempts = loginAttempts.get(identifier) || { count: 0, lockedUntil: null };
    
    if (attempts.lockedUntil && attempts.lockedUntil > Date.now()) {
        throw new AuthError('Account temporarily locked. Try again later.', 'ACCOUNT_LOCKED');
    }
    
    if (attempts.lockedUntil && attempts.lockedUntil <= Date.now()) {
        loginAttempts.delete(identifier);
        return;
    }
    
    return attempts;
}

async function recordFailedAttempt(identifier) {
    const attempts = loginAttempts.get(identifier) || { count: 0, lockedUntil: null };
    attempts.count += 1;
    
    if (attempts.count >= 5) {
        attempts.lockedUntil = Date.now() + 15 * 60 * 1000;
        attempts.count = 0;
        logger.warn('Account locked due to multiple failed attempts', { identifier });
    }
    
    loginAttempts.set(identifier, attempts);
}

async function resetLoginAttempts(identifier) {
    loginAttempts.delete(identifier);
}

// ============================================================
// SECTION 11: FILE UPLOAD CONFIGURATION
// ============================================================

const UPLOAD_DIRS = {
    images: './uploads/images',
    resources: './uploads/resources',
    profiles: './uploads/profiles',
    temp: './uploads/temp'
};

Object.values(UPLOAD_DIRS).forEach(dir => {
    if (!fsSync.existsSync(dir)) {
        fsSync.mkdirSync(dir, { recursive: true });
        logger.info(`Created upload directory: ${dir}`);
    }
});

const storage = multer.diskStorage({
    destination: async function (req, file, cb) {
        try {
            const type = file.fieldname;
            let subDir = '';

            if (type.includes('profile') || type.includes('avatar')) {
                subDir = 'profiles';
            } else if (type.includes('image') || /\.(jpg|jpeg|png|gif|webp)$/i.test(file.originalname)) {
                subDir = 'images';
            } else {
                subDir = 'resources';
            }

            const destDir = path.join(UPLOAD_DIRS[subDir], new Date().toISOString().split('T')[0]);
            await fs.mkdir(destDir, { recursive: true });
            cb(null, destDir);
        } catch (error) {
            cb(error);
        }
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
        const ext = path.extname(file.originalname).toLowerCase();
        const safeName = path.basename(file.originalname, ext)
            .replace(/[^a-zA-Z0-9_-]/g, '_')
            .substring(0, 50);
        cb(null, `${safeName}-${uniqueSuffix}${ext}`);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedMimeTypes = {
        'image/jpeg': ['.jpg', '.jpeg'],
        'image/png': ['.png'],
        'image/gif': ['.gif'],
        'image/webp': ['.webp'],
        'application/pdf': ['.pdf'],
        'application/msword': ['.doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
        'text/plain': ['.txt'],
        'application/zip': ['.zip'],
        'application/x-rar-compressed': ['.rar']
    };

    const allowedExts = Object.values(allowedMimeTypes).flat();
    const ext = path.extname(file.originalname).toLowerCase();

    if (!allowedMimeTypes[file.mimetype] || !allowedExts.includes(ext)) {
        return cb(new Error(`File type ${file.mimetype} with extension ${ext} is not allowed`), false);
    }

    cb(null, true);
};

const upload = multer({
    storage: storage,
    limits: { fileSize: MAX_FILE_SIZE, files: 5 },
    fileFilter: fileFilter
});

// ============================================================
// SECTION 12: VALIDATION SCHEMAS
// ============================================================

const schemas = {
    login: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(8).required(),
        rememberMe: Joi.boolean()
    }),
    
    register: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(8).required(),
        full_name: Joi.string().min(2).max(100).required(),
        department: Joi.string().optional(),
        role: Joi.string().valid('member', 'editor', 'admin').default('member')
    }),
    
    createUser: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(8).required(),
        full_name: Joi.string().min(2).max(100).required(),
        department: Joi.string().optional(),
        role: Joi.string().valid('member', 'editor', 'admin').default('member'),
        is_active: Joi.boolean().default(true)
    }),
    
    updateUser: Joi.object({
        full_name: Joi.string().min(2).max(100).optional(),
        department: Joi.string().optional(),
        role: Joi.string().valid('member', 'editor', 'admin').optional(),
        is_active: Joi.boolean().optional(),
        password: Joi.string().min(8).optional()
    }),
    
    changePassword: Joi.object({
        currentPassword: Joi.string().required(),
        newPassword: Joi.string().min(8).required()
    }),
    
    createMember: Joi.object({
        full_name: Joi.string().required(),
        position: Joi.string().required(),
        department: Joi.string().optional(),
        level: Joi.string().optional(),
        email: Joi.string().email().optional(),
        phone: Joi.string().optional(),
        bio: Joi.string().optional(),
        committee: Joi.string().optional(),
        display_order: Joi.number().integer().default(0),
        status: Joi.string().valid('active', 'inactive', 'alumni').default('active'),
        social_links: Joi.object().default({})
    }),
    
    contactForm: Joi.object({
        name: Joi.string().min(2).max(100).required(),
        email: Joi.string().email().required(),
        message: Joi.string().min(10).max(1000).required(),
        subject: Joi.string().max(200).optional()
    }),
    
    article: Joi.object({
        title: Joi.string().required(),
        slug: Joi.string().optional(),
        content: Joi.string().required(),
        excerpt: Joi.string().optional(),
        author: Joi.string().optional(),
        category: Joi.string().optional(),
        tags: Joi.array().items(Joi.string()).default([]),
        status: Joi.string().valid('draft', 'published').default('draft'),
        is_published: Joi.boolean().default(false),
        published_at: Joi.date().optional()
    })
};

const validate = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) throw new ValidationError('Validation failed', error.details);
        next();
    };
};

// ============================================================
// SECTION 13: AUTHENTICATION SERVICE
// ============================================================

class AuthService {
    constructor() {
        this.secret = JWT_SECRET;
        this.expire = JWT_EXPIRE;
    }

    generateToken(payload) {
        return jwt.sign(payload, this.secret, {
            expiresIn: this.expire,
            issuer: 'nuesa-biu-api',
            audience: 'nuesa-biu-client',
            jwtid: uuid.v4()
        });
    }

    verifyToken(token) {
        try {
            return jwt.verify(token, this.secret, {
                issuer: ['nuesa-biu-api'],
                audience: ['nuesa-biu-client']
            });
        } catch (error) {
            throw new AuthError('Invalid token', error.name);
        }
    }

    async authenticateUser(email, password) {
        try {
            await checkLoginAttempts(email.toLowerCase());

            const result = await db.query('select', 'users', {
                where: { email: email.toLowerCase().trim() },
                select: 'id, email, password_hash, full_name, role, department, is_active, created_at, last_login'
            });

            if (result.data.length === 0) {
                await recordFailedAttempt(email.toLowerCase());
                throw new AuthError('Invalid credentials');
            }

            const user = result.data[0];

            if (!user.is_active) throw new AuthError('Account is deactivated');

            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                await recordFailedAttempt(email.toLowerCase());
                throw new AuthError('Invalid credentials');
            }

            await resetLoginAttempts(email.toLowerCase());

            await db.query('update', 'users', {
                data: { last_login: new Date() },
                where: { id: user.id }
            });

            logger.info('User logged in successfully', { userId: user.id, email: user.email });

            return this.createUserResponse(user);
        } catch (error) {
            throw error;
        }
    }

    createUserResponse(user) {
        return {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            department: user.department,
            isActive: user.is_active,
            createdAt: user.created_at,
            lastLogin: user.last_login
        };
    }

    createTokenPayload(user) {
        return {
            userId: user.id,
            email: user.email,
            role: user.role,
            fullName: user.full_name
        };
    }
}

const authService = new AuthService();

// ============================================================
// SECTION 14: AUTHENTICATION MIDDLEWARE
// ============================================================

const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new AuthError('Access token required', 'TOKEN_REQUIRED');
        }

        const token = authHeader.split(' ')[1];
        const decoded = authService.verifyToken(token);

        const cacheKey = `user:${decoded.userId}`;
        const cachedUser = await cacheManager.get(cacheKey);

        if (cachedUser) {
            req.user = cachedUser;
            req.token = token;
            return next();
        }

        const result = await db.query('select', 'users', {
            where: { id: decoded.userId },
            select: 'id, email, full_name, role, department, is_active, created_at, last_login'
        });

        if (result.data.length === 0) throw new AuthError('User not found', 'USER_NOT_FOUND');

        const user = authService.createUserResponse(result.data[0]);

        if (!user.isActive) throw new AuthError('Account deactivated', 'ACCOUNT_DEACTIVATED');

        await cacheManager.set(cacheKey, user, 300000);
        req.user = user;
        req.token = token;

        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ status: 'error', code: 'TOKEN_EXPIRED', message: 'Token expired' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ status: 'error', code: 'INVALID_TOKEN', message: 'Invalid token' });
        }

        logger.error('Authentication error:', { requestId: req.id, error: error.message });
        res.status(error.statusCode || 401).json({
            status: 'error', code: error.code || 'AUTH_FAILED',
            message: error.message || 'Authentication failed'
        });
    }
};

const requireRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) throw new AuthError('Authentication required', 'AUTH_REQUIRED');
        if (!roles.includes(req.user.role)) {
            throw new ForbiddenError(`Required roles: ${roles.join(', ')}`);
        }
        next();
    };
};

const requirePermission = (permission) => {
    const permissions = {
        admin: ['manage_users', 'manage_content', 'manage_settings', 'view_all'],
        editor: ['manage_content', 'view_all'],
        member: ['view_content']
    };

    return (req, res, next) => {
        if (!req.user) throw new AuthError('Authentication required', 'AUTH_REQUIRED');
        const userPermissions = permissions[req.user.role] || [];
        if (!userPermissions.includes(permission)) {
            throw new ForbiddenError(`Required permission: ${permission}`);
        }
        next();
    };
};

// ============================================================
// SECTION 15: DATABASE INITIALIZATION
// ============================================================

async function initializeDatabase() {
    try {
        const { error } = await supabase.from('users').select('count').limit(1);
        if (error) throw new Error(`Database connection failed: ${error.message}`);

        logger.info('Database connected successfully');
        await createDefaultAdmin();
        await createDefaultTables();
        logger.info('Database initialization complete');
    } catch (error) {
        logger.error('Database initialization failed:', error);
        throw error;
    }
}

async function createDefaultAdmin() {
    try {
        const adminEmail = process.env.ADMIN_EMAIL;
        if (!adminEmail) {
            logger.warn('ADMIN_EMAIL not set, skipping admin creation');
            return;
        }

        const result = await db.query('select', 'users', {
            where: { email: adminEmail },
            select: 'id'
        });

        if (result.data.length === 0) {
            const adminPassword = process.env.ADMIN_PASSWORD;
            if (!adminPassword) {
                logger.warn('ADMIN_PASSWORD not set, skipping admin creation');
                return;
            }

            const hashedPassword = await bcrypt.hash(adminPassword, 12);
            const adminData = {
                email: adminEmail,
                password_hash: hashedPassword,
                full_name: process.env.ADMIN_FULL_NAME || 'System Administrator',
                role: 'admin',
                department: process.env.ADMIN_DEPARTMENT || 'Computer Engineering',
                username: process.env.ADMIN_USERNAME || 'admin',
                is_active: true,
                created_at: new Date(),
                updated_at: new Date()
            };

            await db.query('insert', 'users', { data: adminData });
            logger.info(`Admin user created: ${adminEmail}`);
        } else {
            logger.info('Admin user already exists');
        }
    } catch (error) {
        logger.error('Could not create admin user:', error);
    }
}

async function createDefaultTables() {
    logger.info('Checking database tables...');
}

// ============================================================
// SECTION 16: ROUTE HANDLERS
// ============================================================

// --- 16.1 AUTHENTICATION ROUTES (Regular Users) ---

const authRouter = express.Router();

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: User login
 *     tags: [Authentication]
 */
authRouter.post('/login', validate(schemas.login), async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;
        const user = await authService.authenticateUser(email, password);
        const tokenPayload = authService.createTokenPayload(user);
        const token = authService.generateToken(tokenPayload);

        await cacheManager.set(`user:${user.id}`, user, rememberMe ? 604800000 : 300000);

        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: 'strict',
            maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
            path: '/',
            domain: IS_PRODUCTION ? new URL(process.env.FRONTEND_URL || '').hostname : undefined
        });

        res.json({
            status: 'success',
            data: { user, token, expiresIn: JWT_EXPIRE },
            message: 'Login successful'
        });
    } catch (error) {
        logger.error('Login failed:', { email: req.body.email, error: error.message });
        res.status(error.statusCode || 500).json({
            status: 'error', code: error.code || 'LOGIN_FAILED', message: error.message || 'Login failed'
        });
    }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: User logout
 *     tags: [Authentication]
 */
authRouter.post('/logout', verifyToken, async (req, res) => {
    try {
        await cacheManager.delete(`user:${req.user.id}`);
        await cacheManager.invalidate('data:*');
        res.clearCookie('auth_token');
        res.json({ status: 'success', message: 'Logged out successfully' });
    } catch (error) {
        logger.error('Logout error:', error);
        res.status(500).json({ status: 'error', message: 'Logout failed' });
    }
});

/**
 * @swagger
 * /api/auth/verify:
 *   get:
 *     summary: Verify token validity
 *     tags: [Authentication]
 */
authRouter.get('/verify', verifyToken, async (req, res) => {
    res.json({ status: 'success', data: req.user, message: 'Token is valid' });
});

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     tags: [Authentication]
 */
authRouter.post('/refresh', verifyToken, async (req, res) => {
    try {
        const newToken = authService.generateToken(authService.createTokenPayload(req.user));
        res.json({
            status: 'success',
            data: { token: newToken, expiresIn: JWT_EXPIRE },
            message: 'Token refreshed successfully'
        });
    } catch (error) {
        logger.error('Token refresh error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to refresh token' });
    }
});

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Authentication]
 */
authRouter.post('/forgot-password', validate(Joi.object({ email: Joi.string().email().required() })), async (req, res) => {
    try {
        logger.info('Password reset requested', { email: req.body.email });
        res.json({
            status: 'success',
            message: 'If an account exists with this email, you will receive a reset link'
        });
    } catch (error) {
        logger.error('Forgot password error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to process request' });
    }
});

app.use('/api/auth', authRouter);

// --- 16.2 ADMIN AUTHENTICATION (Single Endpoint) ---

/**
 * @swagger
 * /api/admin/login:
 *   post:
 *     summary: Admin login (single endpoint for admin portal)
 *     tags: [Admin Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: { type: string, format: email }
 *               password: { type: string }
 *               rememberMe: { type: boolean }
 *     responses:
 *       200: { description: Login successful }
 *       401: { description: Invalid credentials or not admin }
 *       403: { description: Access denied - not admin role }
 */
app.post('/api/admin/login', createRateLimiter(10, 15 * 60 * 1000), validate(schemas.login), async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;

        // Check login attempts
        await checkLoginAttempts(email.toLowerCase());

        // Fetch user
        const result = await db.query('select', 'users', {
            where: { email: email.toLowerCase().trim() },
            select: 'id, email, password_hash, full_name, role, department, is_active, created_at, last_login'
        });

        if (result.data.length === 0) {
            await recordFailedAttempt(email.toLowerCase());
            logger.warn('Admin login failed - user not found', { email });
            return res.status(401).json({
                status: 'error',
                code: 'INVALID_CREDENTIALS',
                message: 'Invalid email or password'
            });
        }

        const user = result.data[0];

        // STRICT ADMIN CHECK - Only admins can use this endpoint
        if (user.role !== 'admin') {
            logger.warn('Admin login failed - not admin', { email, role: user.role });
            return res.status(403).json({
                status: 'error',
                code: 'FORBIDDEN',
                message: 'Access denied. Admin privileges required.'
            });
        }

        if (!user.is_active) {
            logger.warn('Admin login failed - account deactivated', { email });
            return res.status(401).json({
                status: 'error',
                code: 'ACCOUNT_DEACTIVATED',
                message: 'Your account has been deactivated'
            });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            await recordFailedAttempt(email.toLowerCase());
            logger.warn('Admin login failed - invalid password', { email });
            return res.status(401).json({
                status: 'error',
                code: 'INVALID_CREDENTIALS',
                message: 'Invalid email or password'
            });
        }

        // Reset login attempts
        await resetLoginAttempts(email.toLowerCase());

        // Update last login
        await db.query('update', 'users', {
            data: { last_login: new Date() },
            where: { id: user.id }
        });

        // Create response
        const userResponse = authService.createUserResponse(user);
        const tokenPayload = authService.createTokenPayload(user);
        const token = authService.generateToken(tokenPayload);

        // Set cookie
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: 'strict',
            maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
            path: '/'
        });

        // Cache user
        await cacheManager.set(`user:${user.id}`, userResponse, rememberMe ? 604800000 : 300000);

        logger.info('Admin logged in successfully', { 
            requestId: req.id, userId: user.id, email: user.email 
        });

        res.json({
            status: 'success',
            data: {
                user: userResponse,
                token,
                expiresIn: JWT_EXPIRE
            },
            message: 'Admin login successful'
        });

    } catch (error) {
        logger.error('Admin login error:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            code: 'SERVER_ERROR',
            message: 'Login failed. Please try again.'
        });
    }
});

/**
 * @swagger
 * /api/admin/logout:
 *   post:
 *     summary: Admin logout
 *     tags: [Admin Authentication]
 */
app.post('/api/admin/logout', verifyToken, async (req, res) => {
    try {
        await cacheManager.delete(`user:${req.user.id}`);
        res.clearCookie('auth_token');
        logger.info('Admin logged out', { requestId: req.id, userId: req.user.id });
        res.json({ status: 'success', message: 'Logged out successfully' });
    } catch (error) {
        logger.error('Admin logout error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Logout failed' });
    }
});

/**
 * @swagger
 * /api/admin/session:
 *   get:
 *     summary: Check admin session
 *     tags: [Admin Authentication]
 */
app.get('/api/admin/session', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                status: 'error', code: 'FORBIDDEN', message: 'Not authorized'
            });
        }
        res.json({ status: 'success', data: req.user, message: 'Session valid' });
    } catch (error) {
        logger.error('Session check error:', { requestId: req.id, error: error.message });
        res.status(401).json({
            status: 'error', code: 'INVALID_SESSION', message: 'No valid session'
        });
    }
});

// --- 16.3 PUBLIC ROUTES ---

/**
 * @swagger
 * /api/contact/submit:
 *   post:
 *     summary: Submit contact form
 *     tags: [Public]
 */
app.post('/api/contact/submit', createRateLimiter(10), validate(schemas.contactForm), async (req, res) => {
    try {
        const { name, email, message, subject } = req.body;
        logger.info('Contact form submitted', { 
            requestId: req.id, name, email, subject: subject || 'No subject' 
        });
        res.json({
            status: 'success',
            message: 'Thank you for your message! We will get back to you soon.'
        });
    } catch (error) {
        logger.error('Contact form error:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error', message: 'Failed to submit form. Please try again later.'
        });
    }
});

// --- 16.4 USER MANAGEMENT ROUTES ---

const userRouter = express.Router();

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all users (admin only)
 *     tags: [Users]
 */
userRouter.get('/', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const { page = 1, limit = 20, role, department, search, sort = 'created_at', order = 'desc' } = req.query;
        const offset = (page - 1) * limit;
        let where = {};

        if (role && role !== 'all') where.role = role;
        if (department && department !== 'all') where.department = department;
        if (search) where.full_name = { operator: 'ilike', value: `%${search}%` };

        const [usersResult, totalResult] = await Promise.all([
            db.query('select', 'users', {
                where,
                select: 'id, email, full_name, role, department, is_active, created_at, updated_at, last_login',
                order: { column: sort, ascending: order === 'asc' },
                limit: parseInt(limit),
                offset: parseInt(offset)
            }),
            db.query('select', 'users', { where, count: true })
        ]);

        res.setHeader('X-Total-Count', totalResult.count || 0);
        res.setHeader('X-Page-Count', Math.ceil((totalResult.count || 0) / limit));

        res.json({
            status: 'success',
            data: usersResult.data,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: totalResult.count || 0,
                pages: Math.ceil((totalResult.count || 0) / limit),
                hasMore: (parseInt(page) * parseInt(limit)) < (totalResult.count || 0)
            }
        });
    } catch (error) {
        logger.error('Error fetching users:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch users' });
    }
});

/**
 * @swagger
 * /api/users:
 *   post:
 *     summary: Create new user (admin only)
 *     tags: [Users]
 */
userRouter.post('/', verifyToken, requireRole('admin'), validate(schemas.createUser), async (req, res) => {
    try {
        const { email, password, full_name, department, role = 'member', is_active = true } = req.body;

        const existing = await db.query('select', 'users', {
            where: { email: email.toLowerCase() },
            select: 'id'
        });

        if (existing.data.length > 0) throw new ValidationError('User with this email already exists');

        const hashedPassword = await bcrypt.hash(password, 12);
        const username = email.split('@')[0].toLowerCase();

        const userData = {
            email: email.toLowerCase(),
            password_hash: hashedPassword,
            full_name: full_name.trim(),
            username,
            department: department || null,
            role,
            is_active,
            created_at: new Date(),
            updated_at: new Date()
        };

        const result = await db.query('insert', 'users', { data: userData });
        const user = authService.createUserResponse(result.data[0]);

        logger.info('User created', { requestId: req.id, userId: user.id, createdBy: req.user.id });

        res.status(201).json({ status: 'success', data: user, message: 'User created successfully' });
    } catch (error) {
        logger.error('Error creating user:', { requestId: req.id, error: error.message });
        if (error instanceof ValidationError) {
            return res.status(400).json({ status: 'error', code: 'VALIDATION_ERROR', message: error.message });
        }
        res.status(500).json({ status: 'error', message: 'Failed to create user' });
    }
});

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get user by ID
 *     tags: [Users]
 */
userRouter.get('/:id', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
            throw new ForbiddenError('Access denied');
        }

        const result = await db.query('select', 'users', {
            where: { id: req.params.id },
            select: 'id, email, full_name, role, department, is_active, created_at, updated_at, last_login, profile_picture'
        });

        if (result.data.length === 0) throw new NotFoundError('User');

        res.json({ status: 'success', data: authService.createUserResponse(result.data[0]) });
    } catch (error) {
        logger.error('Error fetching user:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        if (error instanceof ForbiddenError) return res.status(403).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch user' });
    }
});

/**
 * @swagger
 * /api/users/{id}:
 *   put:
 *     summary: Update user
 *     tags: [Users]
 */
userRouter.put('/:id', verifyToken, validate(schemas.updateUser), async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
            throw new ForbiddenError('Access denied');
        }

        const { full_name, department, role, is_active, password } = req.body;
        const updateData = { updated_at: new Date() };

        if (full_name) updateData.full_name = full_name.trim();
        if (department !== undefined) updateData.department = department;

        if (req.user.role === 'admin') {
            if (role !== undefined) updateData.role = role;
            if (is_active !== undefined) updateData.is_active = is_active;
        }

        if (password) updateData.password_hash = await bcrypt.hash(password, 12);

        const cleanUpdateData = Object.fromEntries(
            Object.entries(updateData).filter(([_, v]) => v !== undefined)
        );

        const result = await db.query('update', 'users', {
            data: cleanUpdateData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) throw new NotFoundError('User');

        await cacheManager.delete(`user:${req.params.id}`);
        await cacheManager.invalidate('data:*');

        if (req.user.id === req.params.id) req.user = authService.createUserResponse(result.data[0]);

        logger.info('User updated', { requestId: req.id, userId: req.params.id, updatedBy: req.user.id });

        res.json({
            status: 'success',
            data: authService.createUserResponse(result.data[0]),
            message: 'User updated successfully'
        });
    } catch (error) {
        logger.error('Error updating user:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        if (error instanceof ForbiddenError) return res.status(403).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update user' });
    }
});

/**
 * @swagger
 * /api/users/{id}:
 *   delete:
 *     summary: Delete user (admin only)
 *     tags: [Users]
 */
userRouter.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        if (req.params.id === req.user.id) throw new ValidationError('Cannot delete your own account');

        const result = await db.query('delete', 'users', { where: { id: req.params.id } });
        if (result.data.length === 0) throw new NotFoundError('User');

        await cacheManager.delete(`user:${req.params.id}`);
        await cacheManager.invalidate('data:*');

        logger.info('User deleted', { requestId: req.id, userId: req.params.id, deletedBy: req.user.id });

        res.json({ status: 'success', message: 'User deleted successfully' });
    } catch (error) {
        logger.error('Error deleting user:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        if (error instanceof ValidationError) return res.status(400).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete user' });
    }
});

app.use('/api/users', userRouter);

// --- 16.5 PROFILE ROUTES ---

/**
 * @swagger
 * /api/profile:
 *   get:
 *     summary: Get current user profile
 *     tags: [Profile]
 */
app.get('/api/profile', verifyToken, async (req, res) => {
    res.json({ status: 'success', data: req.user });
});

/**
 * @swagger
 * /api/profile:
 *   put:
 *     summary: Update current user profile
 *     tags: [Profile]
 */
app.put('/api/profile', verifyToken, validate(Joi.object({ 
    full_name: Joi.string().min(2).max(100).required(),
    department: Joi.string().optional()
})), async (req, res) => {
    try {
        const { full_name, department } = req.body;
        const updateData = {
            full_name: full_name.trim(),
            department: department || null,
            updated_at: new Date()
        };

        const result = await db.query('update', 'users', {
            data: updateData,
            where: { id: req.user.id }
        });

        const updatedUser = authService.createUserResponse(result.data[0]);
        await cacheManager.set(`user:${req.user.id}`, updatedUser, 300000);
        req.user = updatedUser;

        res.json({ status: 'success', data: updatedUser, message: 'Profile updated successfully' });
    } catch (error) {
        logger.error('Error updating profile:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update profile' });
    }
});

/**
 * @swagger
 * /api/profile/password:
 *   put:
 *     summary: Change user password
 *     tags: [Profile]
 */
app.put('/api/profile/password', verifyToken, validate(schemas.changePassword), async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        const result = await db.query('select', 'users', {
            where: { id: req.user.id },
            select: 'password_hash'
        });

        const validPassword = await bcrypt.compare(currentPassword, result.data[0].password_hash);
        if (!validPassword) throw new ValidationError('Current password is incorrect');

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        await db.query('update', 'users', {
            data: { password_hash: hashedPassword, updated_at: new Date() },
            where: { id: req.user.id }
        });

        logger.info('Password updated', { requestId: req.id, userId: req.user.id });
        res.json({ status: 'success', message: 'Password updated successfully' });
    } catch (error) {
        logger.error('Error updating password:', { requestId: req.id, error: error.message });
        if (error instanceof ValidationError) return res.status(400).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update password' });
    }
});

// --- 16.6 ADMIN DASHBOARD ROUTES ---

const adminRouter = express.Router();
adminRouter.use(verifyToken);
adminRouter.use(requireRole('admin'));

/**
 * @swagger
 * /api/admin/stats:
 *   get:
 *     summary: Get dashboard statistics
 *     tags: [Admin]
 */
adminRouter.get('/stats', async (req, res) => {
    try {
        const [users, members, events, resources, articles] = await Promise.allSettled([
            db.query('select', 'users', { count: true }),
            db.query('select', 'executive_members', { count: true }),
            db.query('select', 'biu_events', { count: true }),
            db.query('select', 'resources', { count: true }),
            db.query('select', 'articles', { count: true })
        ]);

        res.json({
            status: 'success',
            data: {
                users: users.status === 'fulfilled' ? users.value.count || 0 : 0,
                members: members.status === 'fulfilled' ? members.value.count || 0 : 0,
                events: events.status === 'fulfilled' ? events.value.count || 0 : 0,
                resources: resources.status === 'fulfilled' ? resources.value.count || 0 : 0,
                articles: articles.status === 'fulfilled' ? articles.value.count || 0 : 0,
                uptime: process.uptime(),
                environment: NODE_ENV
            }
        });
    } catch (error) {
        logger.error('Admin stats error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch statistics' });
    }
});

/**
 * @swagger
 * /api/admin/members:
 *   get:
 *     summary: Get all members (with filtering)
 *     tags: [Admin]
 */
adminRouter.get('/members', async (req, res) => {
    try {
        const { status, committee, search } = req.query;
        let where = {};

        if (status && status !== 'all') where.status = status;
        if (committee && committee !== 'all') where.committee = committee;
        if (search) where.full_name = { operator: 'ilike', value: `%${search}%` };

        const result = await db.query('select', 'executive_members', {
            where,
            order: { column: 'display_order', ascending: true }
        });

        res.json({ status: 'success', data: result.data });
    } catch (error) {
        logger.error('Admin members error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch members' });
    }
});

/**
 * @swagger
 * /api/admin/members/{id}:
 *   get:
 *     summary: Get member by ID
 *     tags: [Admin]
 */
adminRouter.get('/members/:id', async (req, res) => {
    try {
        const result = await db.query('select', 'executive_members', { where: { id: req.params.id } });
        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Member not found' });
        }
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Admin member fetch error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch member' });
    }
});

/**
 * @swagger
 * /api/admin/members:
 *   post:
 *     summary: Create member
 *     tags: [Admin]
 */
adminRouter.post('/members', upload.single('profile_image'), async (req, res) => {
    try {
        const memberData = JSON.parse(req.body.data || '{}');
        const { full_name, position, department, level, email, phone, bio, committee, display_order, status, social_links } = memberData;

        const newMember = {
            full_name: full_name?.trim(),
            position: position?.trim(),
            department: department?.trim() || null,
            level: level || null,
            email: email?.toLowerCase().trim() || null,
            phone: phone?.trim() || null,
            bio: bio?.trim() || null,
            committee: committee?.trim() || null,
            display_order: display_order || 0,
            status: status || 'active',
            social_links: social_links || {},
            created_at: new Date(),
            updated_at: new Date()
        };

        if (req.file) newMember.profile_image = `/uploads/${req.file.filename}`;

        const result = await db.query('insert', 'executive_members', { data: newMember });
        await cacheManager.invalidateByTags(['members']);

        logger.info('Admin created member', { requestId: req.id, memberId: result.data[0].id });

        res.status(201).json({ status: 'success', data: result.data[0], message: 'Member created successfully' });
    } catch (error) {
        logger.error('Admin create member error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to create member' });
    }
});

/**
 * @swagger
 * /api/admin/members/{id}:
 *   put:
 *     summary: Update member
 *     tags: [Admin]
 */
adminRouter.put('/members/:id', upload.single('profile_image'), async (req, res) => {
    try {
        const memberData = JSON.parse(req.body.data || '{}');
        const updateData = {
            full_name: memberData.full_name?.trim(),
            position: memberData.position?.trim(),
            department: memberData.department?.trim(),
            level: memberData.level,
            email: memberData.email?.toLowerCase().trim(),
            phone: memberData.phone?.trim(),
            bio: memberData.bio?.trim(),
            committee: memberData.committee?.trim(),
            display_order: memberData.display_order,
            status: memberData.status,
            social_links: memberData.social_links,
            updated_at: new Date()
        };

        Object.keys(updateData).forEach(key => 
            updateData[key] === undefined && delete updateData[key]
        );

        if (req.file) updateData.profile_image = `/uploads/${req.file.filename}`;

        const result = await db.query('update', 'executive_members', {
            data: updateData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Member not found' });
        }

        await cacheManager.invalidateByTags(['members']);
        res.json({ status: 'success', data: result.data[0], message: 'Member updated successfully' });
    } catch (error) {
        logger.error('Admin update member error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update member' });
    }
});

/**
 * @swagger
 * /api/admin/members/{id}:
 *   delete:
 *     summary: Delete member
 *     tags: [Admin]
 */
adminRouter.delete('/members/:id', async (req, res) => {
    try {
        const result = await db.query('delete', 'executive_members', { where: { id: req.params.id } });
        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Member not found' });
        }
        await cacheManager.invalidateByTags(['members']);
        res.json({ status: 'success', message: 'Member deleted successfully' });
    } catch (error) {
        logger.error('Admin delete member error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete member' });
    }
});

/**
 * @swagger
 * /api/admin/events:
 *   get:
 *     summary: Get all events
 *     tags: [Admin]
 */
adminRouter.get('/events', async (req, res) => {
    try {
        const { status, category } = req.query;
        let where = {};

        if (status && status !== 'all') where.status = status;
        if (category && category !== 'all') where.category = category;

        const result = await db.query('select', 'biu_events', {
            where,
            order: { column: 'date', ascending: true }
        });

        res.json({ status: 'success', data: result.data });
    } catch (error) {
        logger.error('Admin events error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch events' });
    }
});

/**
 * @swagger
 * /api/admin/events:
 *   post:
 *     summary: Create event
 *     tags: [Admin]
 */
adminRouter.post('/events', async (req, res) => {
    try {
        const { title, description, date, start_time, end_time, location, category, organizer, max_participants, status } = req.body;

        const eventData = {
            title: title?.trim(),
            description: description?.trim(),
            date,
            start_time,
            end_time,
            location: location?.trim(),
            category: category?.trim(),
            organizer: organizer?.trim(),
            max_participants: max_participants ? parseInt(max_participants) : null,
            status: status || 'upcoming',
            created_at: new Date(),
            updated_at: new Date()
        };

        const result = await db.query('insert', 'biu_events', { data: eventData });
        await cacheManager.invalidateByTags(['biu_events']);

        res.status(201).json({ status: 'success', data: result.data[0], message: 'Event created successfully' });
    } catch (error) {
        logger.error('Admin create event error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to create event' });
    }
});

/**
 * @swagger
 * /api/admin/events/{id}:
 *   put:
 *     summary: Update event
 *     tags: [Admin]
 */
adminRouter.put('/events/:id', async (req, res) => {
    try {
        const { title, description, date, start_time, end_time, location, category, organizer, max_participants, status } = req.body;

        const updateData = {
            title: title?.trim(),
            description: description?.trim(),
            date,
            start_time,
            end_time,
            location: location?.trim(),
            category: category?.trim(),
            organizer: organizer?.trim(),
            max_participants: max_participants ? parseInt(max_participants) : null,
            status,
            updated_at: new Date()
        };

        Object.keys(updateData).forEach(key => 
            updateData[key] === undefined && delete updateData[key]
        );

        const result = await db.query('update', 'biu_events', {
            data: updateData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Event not found' });
        }

        await cacheManager.invalidateByTags(['biu_events']);
        res.json({ status: 'success', data: result.data[0], message: 'Event updated successfully' });
    } catch (error) {
        logger.error('Admin update event error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update event' });
    }
});

/**
 * @swagger
 * /api/admin/events/{id}:
 *   delete:
 *     summary: Delete event
 *     tags: [Admin]
 */
adminRouter.delete('/events/:id', async (req, res) => {
    try {
        const result = await db.query('delete', 'biu_events', { where: { id: req.params.id } });
        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Event not found' });
        }
        await cacheManager.invalidateByTags(['biu_events']);
        res.json({ status: 'success', message: 'Event deleted successfully' });
    } catch (error) {
        logger.error('Admin delete event error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete event' });
    }
});

/**
 * @swagger
 * /api/admin/resources:
 *   get:
 *     summary: Get all resources
 *     tags: [Admin]
 */
adminRouter.get('/resources', async (req, res) => {
    try {
        const { category, department } = req.query;
        let where = {};

        if (category && category !== 'all') where.category = category;
        if (department && department !== 'all') where.department = department;

        const result = await db.query('select', 'resources', {
            where,
            order: { column: 'created_at', ascending: false }
        });

        res.json({ status: 'success', data: result.data });
    } catch (error) {
        logger.error('Admin resources error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch resources' });
    }
});

/**
 * @swagger
 * /api/admin/resources:
 *   post:
 *     summary: Upload resource
 *     tags: [Admin]
 */
adminRouter.post('/resources', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ status: 'error', message: 'No file uploaded' });
        }

        const resourceData = JSON.parse(req.body.data || '{}');

        const newResource = {
            title: resourceData.title?.trim(),
            category: resourceData.category?.trim(),
            description: resourceData.description?.trim(),
            department: resourceData.department?.trim(),
            course_code: resourceData.course_code?.trim(),
            year: resourceData.year,
            level: resourceData.level ? parseInt(resourceData.level) : null,
            file_url: `/uploads/${req.file.filename}`,
            file_size: req.file.size,
            file_type: req.file.mimetype,
            download_count: 0,
            uploaded_by: req.user.id,
            created_at: new Date()
        };

        const result = await db.query('insert', 'resources', { data: newResource });
        await cacheManager.invalidateByTags(['resources']);

        res.status(201).json({ status: 'success', data: result.data[0], message: 'Resource uploaded successfully' });
    } catch (error) {
        logger.error('Admin upload resource error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to upload resource' });
    }
});

/**
 * @swagger
 * /api/admin/resources/{id}:
 *   delete:
 *     summary: Delete resource
 *     tags: [Admin]
 */
adminRouter.delete('/resources/:id', async (req, res) => {
    try {
        const result = await db.query('delete', 'resources', { where: { id: req.params.id } });
        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Resource not found' });
        }
        await cacheManager.invalidateByTags(['resources']);
        res.json({ status: 'success', message: 'Resource deleted successfully' });
    } catch (error) {
        logger.error('Admin delete resource error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete resource' });
    }
});

/**
 * @swagger
 * /api/admin/messages:
 *   get:
 *     summary: Get all messages (from contact form)
 *     tags: [Admin]
 */
adminRouter.get('/messages', async (req, res) => {
    try {
        const result = await db.query('select', 'contact_messages', {
            order: { column: 'created_at', ascending: false }
        });
        res.json({ status: 'success', data: result.data });
    } catch (error) {
        logger.error('Admin messages error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch messages' });
    }
});

/**
 * @swagger
 * /api/admin/messages/{id}/read:
 *   put:
 *     summary: Mark message as read
 *     tags: [Admin]
 */
adminRouter.put('/messages/:id/read', async (req, res) => {
    try {
        await db.query('update', 'contact_messages', {
            data: { is_read: true, read_at: new Date() },
            where: { id: req.params.id }
        });
        res.json({ status: 'success', message: 'Message marked as read' });
    } catch (error) {
        logger.error('Admin mark message read error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update message' });
    }
});

/**
 * @swagger
 * /api/admin/messages/{id}:
 *   delete:
 *     summary: Delete message
 *     tags: [Admin]
 */
adminRouter.delete('/messages/:id', async (req, res) => {
    try {
        await db.query('delete', 'contact_messages', { where: { id: req.params.id } });
        res.json({ status: 'success', message: 'Message deleted successfully' });
    } catch (error) {
        logger.error('Admin delete message error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete message' });
    }
});

/**
 * @swagger
 * /api/admin/upload:
 *   post:
 *     summary: File upload (generic)
 *     tags: [Admin]
 */
adminRouter.post('/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ status: 'error', message: 'No file uploaded' });
        }

        const fileInfo = {
            filename: req.file.filename,
            originalname: req.file.originalname,
            mimetype: req.file.mimetype,
            size: req.file.size,
            url: `/uploads/${req.file.filename}`,
            uploaded_at: new Date()
        };

        res.json({ status: 'success', data: fileInfo, message: 'File uploaded successfully' });
    } catch (error) {
        logger.error('Admin upload error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to upload file' });
    }
});

app.use('/api/admin', adminRouter);

// --- 16.7 MEMBERS ROUTES (Public) ---

const memberRouter = express.Router();

/**
 * @swagger
 * /api/members:
 *   get:
 *     summary: Get all executive members
 *     tags: [Members]
 */
memberRouter.get('/', cacheMiddleware(120, ['members']), async (req, res) => {
    try {
        const { committee, status = 'active', sort = 'display_order', order = 'asc' } = req.query;
        let where = { status };
        if (committee && committee !== 'all') where.committee = committee;

        const result = await db.query('select', 'executive_members', {
            where,
            order: { column: sort, ascending: order === 'asc' }
        });

        res.json({
            status: 'success',
            data: result.data,
            count: result.data.length
        });
    } catch (error) {
        logger.error('Error fetching members:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch members' });
    }
});

/**
 * @swagger
 * /api/members/{id}:
 *   get:
 *     summary: Get member by ID
 *     tags: [Members]
 */
memberRouter.get('/:id', cacheMiddleware(300, ['members']), async (req, res) => {
    try {
        const result = await db.query('select', 'executive_members', { where: { id: req.params.id } });
        if (result.data.length === 0) throw new NotFoundError('Member');

        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Error fetching member:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch member' });
    }
});

/**
 * @swagger
 * /api/members:
 *   post:
 *     summary: Create new member (admin/editor only)
 *     tags: [Members]
 */
memberRouter.post('/', verifyToken, requireRole('admin', 'editor'), upload.single('profile_image'), validate(schemas.createMember), async (req, res) => {
    try {
        const { full_name, position, department, level, email, phone, bio, committee, display_order, status, social_links } = req.body;

        const memberData = {
            full_name: full_name.trim(),
            position: position.trim(),
            department: department ? department.trim() : null,
            level: level ? level.trim() : null,
            email: email ? email.toLowerCase().trim() : null,
            phone: phone ? phone.trim() : null,
            bio: bio ? bio.trim() : null,
            committee: committee ? committee.trim() : null,
            display_order: display_order || 0,
            status: status || 'active',
            social_links: social_links ? (typeof social_links === 'string' ? JSON.parse(social_links) : social_links) : {},
            created_at: new Date(),
            updated_at: new Date()
        };

        if (req.file) memberData.profile_image = `/uploads/${req.file.filename}`;

        const result = await db.query('insert', 'executive_members', { data: memberData });
        await cacheManager.invalidateByTags(['members']);

        logger.info('Member created', { requestId: req.id, memberId: result.data[0].id, createdBy: req.user.id });

        res.status(201).json({ status: 'success', data: result.data[0], message: 'Member created successfully' });
    } catch (error) {
        logger.error('Error creating member:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to create member' });
    }
});

/**
 * @swagger
 * /api/members/{id}:
 *   put:
 *     summary: Update member
 *     tags: [Members]
 */
memberRouter.put('/:id', verifyToken, requireRole('admin', 'editor'), upload.single('profile_image'), async (req, res) => {
    try {
        const memberData = {};
        const fields = ['full_name', 'position', 'department', 'level', 'email', 'phone', 'bio', 'committee', 'display_order', 'status'];

        fields.forEach(field => {
            if (req.body[field] !== undefined) {
                memberData[field] = typeof req.body[field] === 'string' ? req.body[field].trim() : req.body[field];
            }
        });

        if (req.body.social_links) {
            memberData.social_links = typeof req.body.social_links === 'string' 
                ? JSON.parse(req.body.social_links) 
                : req.body.social_links;
        }

        if (req.file) memberData.profile_image = `/uploads/${req.file.filename}`;
        memberData.updated_at = new Date();

        const result = await db.query('update', 'executive_members', {
            data: memberData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) throw new NotFoundError('Member');

        await cacheManager.invalidateByTags(['members']);
        logger.info('Member updated', { requestId: req.id, memberId: req.params.id, updatedBy: req.user.id });

        res.json({ status: 'success', data: result.data[0], message: 'Member updated successfully' });
    } catch (error) {
        logger.error('Error updating member:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update member' });
    }
});

/**
 * @swagger
 * /api/members/{id}:
 *   delete:
 *     summary: Delete member (admin/editor only)
 *     tags: [Members]
 */
memberRouter.delete('/:id', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    try {
        const result = await db.query('delete', 'executive_members', { where: { id: req.params.id } });
        if (result.data.length === 0) throw new NotFoundError('Member');

        await cacheManager.invalidateByTags(['members']);
        logger.info('Member deleted', { requestId: req.id, memberId: req.params.id, deletedBy: req.user.id });

        res.json({ status: 'success', message: 'Member deleted successfully' });
    } catch (error) {
        logger.error('Error deleting member:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete member' });
    }
});

app.use('/api/members', memberRouter);

// --- 16.8 EVENTS ROUTES ---

const eventRouter = express.Router();

eventRouter.get('/test', (req, res) => {
    console.log('📡 [TEST] Test route hit at:', new Date().toISOString());
    res.json({ 
        message: 'Event router test route works',
        timestamp: new Date().toISOString(),
        requestId: req.id 
    });
});

/**
 * @swagger
 * /api/events:
 *   get:
 *     summary: Get all events
 *     tags: [Events]
 */
eventRouter.get('/', cacheMiddleware(120, ['biu_events']), async (req, res) => {
    console.log('📡 [3] GET /api/events called at:', new Date().toISOString());
    console.log('📡 [3a] Query params:', req.query);
    console.log('📡 [3b] Request ID:', req.id);
    
    try {
        const { status = 'upcoming', category, limit = 50 } = req.query;
        console.log('📡 [4] Building where clause with:', { status, category, limit });
        
        let where = {};
        if (status !== 'all') where.status = status;
        if (category && category !== 'all') where.category = category;

        console.log('📡 [5] Final where clause:', where);
        console.log('📡 [6] Executing database query on biu_events table...');

        const result = await db.query('select', 'biu_events', {
            where,
            order: { column: 'date', ascending: status === 'past' ? false : true },
            limit: parseInt(limit)
        });

        console.log(`📡 [7] Query returned ${result.data.length} events`);
        
        if (result.data.length > 0) {
            console.log('📡 [8] First event:', {
                id: result.data[0].id,
                title: result.data[0].title,
                date: result.data[0].date,
                category: result.data[0].category
            });
        } else {
            console.log('📡 [8] No events found in biu_events table');
        }

        res.json({
            status: 'success',
            data: result.data,
            count: result.data.length,
            message: result.data.length === 0 ? 'No events found' : undefined
        });
        
        console.log('✅ [10] Response sent successfully with', result.data.length, 'events');
        
    } catch (error) {
        console.error('❌ [ERROR] Events API error:', {
            message: error.message,
            code: error.code,
            stack: error.stack,
            name: error.name
        });
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch events',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/events/{id}:
 *   get:
 *     summary: Get event by ID
 *     tags: [Events]
 */
eventRouter.get('/:id', cacheMiddleware(300, ['biu_events']), async (req, res) => {
    console.log(`📡 GET /api/events/${req.params.id} called`);
    
    try {
        const result = await db.query('select', 'biu_events', { where: { id: req.params.id } });

        if (result.data.length === 0) {
            console.log(`📡 Event with id ${req.params.id} not found`);
            return res.status(404).json({ status: 'error', message: 'Event not found' });
        }

        console.log(`📡 Event found:`, result.data[0].title);
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        console.error('❌ Error fetching event:', error.message);
        res.status(500).json({ status: 'error', message: 'Failed to fetch event', debug: error.message });
    }
});

/**
 * @swagger
 * /api/events/status/upcoming:
 *   get:
 *     summary: Get upcoming events
 *     tags: [Events]
 */
eventRouter.get('/status/upcoming', cacheMiddleware(60, ['biu_events']), async (req, res) => {
    console.log('📡 GET /api/events/status/upcoming called');
    
    try {
        const result = await db.query('select', 'biu_events', {
            where: { status: 'upcoming' },
            order: { column: 'date', ascending: true }
        });

        console.log(`📡 Found ${result.data.length} upcoming events`);
        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        console.error('❌ Error fetching upcoming events:', error.message);
        res.status(500).json({ status: 'error', message: 'Failed to fetch upcoming events' });
    }
});

/**
 * @swagger
 * /api/events/status/past:
 *   get:
 *     summary: Get past events
 *     tags: [Events]
 */
eventRouter.get('/status/past', cacheMiddleware(300, ['biu_events']), async (req, res) => {
    console.log('📡 GET /api/events/status/past called');
    
    try {
        const result = await db.query('select', 'biu_events', {
            where: { status: 'past' },
            order: { column: 'date', ascending: false }
        });

        console.log(`📡 Found ${result.data.length} past events`);
        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        console.error('❌ Error fetching past events:', error.message);
        res.status(500).json({ status: 'error', message: 'Failed to fetch past events' });
    }
});

/**
 * @swagger
 * /api/events/category/{category}:
 *   get:
 *     summary: Get events by category
 *     tags: [Events]
 */
eventRouter.get('/category/:category', cacheMiddleware(120, ['biu_events']), async (req, res) => {
    console.log(`📡 GET /api/events/category/${req.params.category} called`);
    
    try {
        const result = await db.query('select', 'biu_events', {
            where: { category: req.params.category },
            order: { column: 'date', ascending: true }
        });

        console.log(`📡 Found ${result.data.length} events in category ${req.params.category}`);
        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        console.error('❌ Error fetching events by category:', error.message);
        res.status(500).json({ status: 'error', message: 'Failed to fetch events' });
    }
});

/**
 * @swagger
 * /api/events:
 *   post:
 *     summary: Create new event (admin/editor only)
 *     tags: [Events]
 */
eventRouter.post('/', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    console.log('📡 POST /api/events called');
    console.log('📡 Request body:', req.body);
    
    try {
        const { title, date, description, category, start_time, end_time, location, organizer, max_participants, status = 'upcoming' } = req.body;

        if (!title || !date) throw new ValidationError('Title and date are required');

        let formattedDate = date;
        if (typeof date === 'string' && date.includes('/')) {
            const [day, month, year] = date.split('/');
            formattedDate = `${year}-${month}-${day}`;
            console.log('📡 Date formatted:', formattedDate);
        }

        const eventData = {
            title: title.trim(),
            date: formattedDate,
            description: description || null,
            category: category || null,
            start_time: start_time || null,
            end_time: end_time || null,
            location: location || null,
            organizer: organizer || null,
            max_participants: max_participants ? parseInt(max_participants) : null,
            status,
            created_at: new Date(),
            updated_at: new Date()
        };

        console.log('📡 Inserting event data into biu_events:', eventData);

        const result = await db.query('insert', 'biu_events', { data: eventData });

        console.log('✅ Event created with ID:', result.data[0].id);

        await cacheManager.invalidateByTags(['biu_events']);

        res.status(201).json({ status: 'success', data: result.data[0], message: 'Event created successfully' });
    } catch (error) {
        console.error('❌ Error creating event:', error.message);
        if (error instanceof ValidationError) return res.status(400).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to create event', debug: error.message });
    }
});

/**
 * @swagger
 * /api/events/{id}:
 *   put:
 *     summary: Update event (admin/editor only)
 *     tags: [Events]
 */
eventRouter.put('/:id', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    console.log(`📡 PUT /api/events/${req.params.id} called`);
    console.log('📡 Update data:', req.body);
    
    try {
        const allowedFields = ['title', 'date', 'description', 'category', 'start_time', 'end_time', 'location', 'organizer', 'max_participants', 'status'];
        const updateData = {};

        allowedFields.forEach(field => {
            if (req.body[field] !== undefined) {
                if (field === 'date' && req.body[field] && typeof req.body[field] === 'string' && req.body[field].includes('/')) {
                    const [day, month, year] = req.body[field].split('/');
                    updateData[field] = `${year}-${month}-${day}`;
                } else if (field === 'max_participants' && req.body[field]) {
                    updateData[field] = parseInt(req.body[field]);
                } else if (typeof req.body[field] === 'string') {
                    updateData[field] = req.body[field].trim();
                } else {
                    updateData[field] = req.body[field];
                }
            }
        });

        if (Object.keys(updateData).length === 0) throw new ValidationError('No fields to update');
        updateData.updated_at = new Date();

        console.log('📡 Executing update on biu_events with:', updateData);

        const result = await db.query('update', 'biu_events', {  
            data: updateData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            console.log(`📡 Event ${req.params.id} not found`);
            return res.status(404).json({ status: 'error', message: 'Event not found' });
        }

        console.log('✅ Event updated:', result.data[0].id);

        await cacheManager.invalidateByTags(['biu_events']);

        res.json({ status: 'success', data: result.data[0], message: 'Event updated successfully' });
    } catch (error) {
        console.error('❌ Error updating event:', error.message);
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        if (error instanceof ValidationError) return res.status(400).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update event' });
    }
});

/**
 * @swagger
 * /api/events/{id}:
 *   delete:
 *     summary: Delete event (admin only)
 *     tags: [Events]
 */
eventRouter.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    console.log(`📡 DELETE /api/events/${req.params.id} called`);
    
    try {
        const result = await db.query('delete', 'biu_events', { where: { id: req.params.id } });

        if (result.data.length === 0) {
            console.log(`📡 Event ${req.params.id} not found`);
            return res.status(404).json({ status: 'error', message: 'Event not found' });
        }

        console.log('✅ Event deleted:', req.params.id);

        await cacheManager.invalidateByTags(['biu_events']);

        res.json({ status: 'success', message: 'Event deleted successfully' });
    } catch (error) {
        console.error('❌ Error deleting event:', error.message);
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete event' });
    }
});

app.use('/api/events', eventRouter);
console.log('✅ [12] /api/events router registered');

// --- 16.9 RESOURCES ROUTES ---

const resourceRouter = express.Router();

resourceRouter.get('/test', (req, res) => {
    console.log('📡 [TEST] Resources test route hit at:', new Date().toISOString());
    res.json({ 
        message: 'Resources router test route works',
        timestamp: new Date().toISOString(),
        requestId: req.id 
    });
});

/**
 * @swagger
 * /api/resources:
 *   get:
 *     summary: Get all resources
 *     tags: [Resources]
 */
resourceRouter.get('/', cacheMiddleware(120, ['resources']), async (req, res) => {
    console.log('📡 [R3] GET /api/resources called at:', new Date().toISOString());
    console.log('📡 [R3a] Query params:', req.query);
    console.log('📡 [R3b] Request ID:', req.id);
    
    try {
        const { category, department, level, course_code, year, semester, limit = 50 } = req.query;

        console.log('📡 [R4] Building where clause with filters:', { 
            category, department, level, course_code, year, semester, limit 
        });
        
        let where = {};
        if (category && category !== 'all') where.category = category;
        if (department && department !== 'all') where.department = department;
        if (level) where.level = parseInt(level);
        if (course_code && course_code !== 'all') where.course_code = course_code;
        if (year && year !== 'all') where.year = year;
        if (semester && semester !== 'all') where.semester = semester;

        console.log('📡 [R5] Final where clause:', where);
        console.log('📡 [R6] Executing database query on resources table...');

        const result = await db.query('select', 'resources', {
            where,
            order: { column: 'created_at', ascending: false },
            limit: parseInt(limit)
        });

        console.log(`📡 [R7] Query returned ${result.data.length} resources`);
        
        if (result.data.length > 0) {
            console.log('📡 [R8] First resource:', {
                id: result.data[0].id,
                title: result.data[0].title,
                category: result.data[0].category,
                department: result.data[0].department
            });
        } else {
            console.log('📡 [R8] No resources found');
        }

        res.json({ status: 'success', data: result.data, count: result.data.length });
        console.log('✅ [R10] Resources response sent successfully');
        
    } catch (error) {
        console.error('❌ [R-ERROR] Resources API error:', {
            message: error.message,
            code: error.code,
            stack: error.stack,
            name: error.name
        });
        
        if (error.message && error.message.includes('relation') && error.message.includes('does not exist')) {
            console.error('❌ [R-DB ERROR] Resources table does not exist!');
            return res.status(500).json({
                status: 'error',
                message: 'Resources table not found in database',
                debug: 'Please create the resources table in Supabase'
            });
        }
        
        logger.error('Error fetching resources:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch resources', debug: error.message });
    }
});

/**
 * @swagger
 * /api/resources/past-questions:
 *   get:
 *     summary: Get past questions (legacy endpoint)
 *     tags: [Resources]
 */
resourceRouter.get('/past-questions', cacheMiddleware(120, ['resources']), async (req, res) => {
    console.log('📡 [R11] GET /api/resources/past-questions called');
    console.log('📡 [R11a] Query params:', req.query);
    
    try {
        const { department, level, course_code, year, semester, limit = 50 } = req.query;

        console.log('📡 [R12] Building past questions where clause');
        
        let where = { category: 'past-question' };
        console.log('📡 [R12a] Base category filter: past-question');
        
        if (department && department !== 'all') where.department = department;
        if (level) where.level = parseInt(level);
        if (course_code && course_code !== 'all') where.course_code = course_code;
        if (year && year !== 'all') where.year = year;
        if (semester && semester !== 'all') where.semester = semester;

        console.log('📡 [R13] Final where clause for past questions:', where);
        console.log('📡 [R14] Executing past questions query...');

        const result = await db.query('select', 'resources', {
            where,
            order: { column: 'year', ascending: false },
            limit: parseInt(limit)
        });

        console.log(`📡 [R15] Past questions query returned ${result.data.length} results`);
        
        if (result.data.length > 0) {
            console.log('📡 [R16] First past question:', {
                id: result.data[0].id,
                title: result.data[0].title,
                course_code: result.data[0].course_code,
                year: result.data[0].year
            });
        }

        res.json({ status: 'success', data: result.data, count: result.data.length });
        console.log('✅ [R17] Past questions response sent');
        
    } catch (error) {
        console.error('❌ [R-ERROR] Past questions API error:', error.message);
        logger.error('Error fetching past questions:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch past questions', debug: error.message });
    }
});

/**
 * @swagger
 * /api/resources/{id}:
 *   get:
 *     summary: Get resource by ID
 *     tags: [Resources]
 */
resourceRouter.get('/:id', cacheMiddleware(300, ['resources']), async (req, res) => {
    console.log(`📡 [R18] GET /api/resources/${req.params.id} called`);
    
    try {
        console.log('📡 [R19] Querying for resource ID:', req.params.id);
        
        const result = await db.query('select', 'resources', { where: { id: req.params.id } });

        if (result.data.length === 0) {
            console.log(`📡 [R20] Resource with id ${req.params.id} not found`);
            return res.status(404).json({ status: 'error', message: 'Resource not found' });
        }

        console.log(`📡 [R21] Resource found:`, result.data[0].title);
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        console.error('❌ [R-ERROR] Error fetching resource:', error.message);
        logger.error('Error fetching resource:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch resource', debug: error.message });
    }
});

/**
 * @swagger
 * /api/resources:
 *   post:
 *     summary: Create new resource (admin/editor only)
 *     tags: [Resources]
 */
resourceRouter.post('/', verifyToken, requireRole('admin', 'editor'), upload.single('file'), async (req, res) => {
    console.log('📡 [R22] POST /api/resources called');
    console.log('📡 [R22a] Request body:', req.body);
    console.log('📡 [R22b] File uploaded:', req.file ? {
        filename: req.file.filename,
        size: req.file.size,
        mimetype: req.file.mimetype
    } : 'No file');
    
    try {
        const { title, category, description, department, level, course_code, course_title, year, semester, file_type, file_size } = req.body;

        if (!title || !category) {
            console.log('❌ [R23] Validation failed: missing title or category');
            throw new ValidationError('Title and category are required');
        }

        const resourceData = {
            title: title.trim(),
            category: category.trim(),
            description: description || null,
            department: department || null,
            level: level ? parseInt(level) : null,
            course_code: course_code || null,
            course_title: course_title || null,
            year: year || null,
            semester: semester || null,
            file_type: file_type || null,
            file_size: file_size ? parseInt(file_size) : null,
            download_count: 0,
            uploaded_by: req.user.id,
            created_at: new Date()
        };

        console.log('📡 [R24] Prepared resource data:', resourceData);

        if (req.file) {
            resourceData.file_url = `/uploads/${req.file.filename}`;
            resourceData.file_size = req.file.size;
            resourceData.file_type = req.file.mimetype;
            console.log('📡 [R25] File data added:', {
                file_url: resourceData.file_url,
                file_size: resourceData.file_size,
                file_type: resourceData.file_type
            });
        }

        console.log('📡 [R26] Inserting resource into database...');
        const result = await db.query('insert', 'resources', { data: resourceData });

        console.log('✅ [R27] Resource created with ID:', result.data[0].id);

        await cacheManager.invalidateByTags(['resources']);

        logger.info('Resource created', { requestId: req.id, resourceId: result.data[0].id, createdBy: req.user.id });

        res.status(201).json({ status: 'success', data: result.data[0], message: 'Resource created successfully' });
    } catch (error) {
        console.error('❌ [R-ERROR] Error creating resource:', error.message);
        logger.error('Error creating resource:', { requestId: req.id, error: error.message });
        if (error instanceof ValidationError) return res.status(400).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to create resource', debug: error.message });
    }
});

/**
 * @swagger
 * /api/resources/{id}:
 *   put:
 *     summary: Update resource (admin/editor only)
 *     tags: [Resources]
 */
resourceRouter.put('/:id', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    console.log(`📡 [R28] PUT /api/resources/${req.params.id} called`);
    console.log('📡 [R28a] Update data:', req.body);
    
    try {
        const allowedFields = ['title', 'category', 'description', 'department', 'level', 'course_code', 'course_title', 'year', 'semester', 'file_type', 'file_size', 'file_url'];
        const updateData = {};

        allowedFields.forEach(field => {
            if (req.body[field] !== undefined) {
                if (field === 'level' || field === 'file_size') {
                    updateData[field] = parseInt(req.body[field]);
                    console.log(`📡 [R29] Parsed ${field} as integer:`, updateData[field]);
                } else if (typeof req.body[field] === 'string') {
                    updateData[field] = req.body[field].trim();
                    console.log(`📡 [R29a] Processed ${field} as string:`, updateData[field]);
                } else {
                    updateData[field] = req.body[field];
                    console.log(`📡 [R29b] Processed ${field}:`, updateData[field]);
                }
            }
        });

        if (Object.keys(updateData).length === 0) {
            console.log('❌ [R30] No fields to update');
            throw new ValidationError('No fields to update');
        }

        updateData.updated_at = new Date();

        console.log('📡 [R31] Executing update with:', updateData);

        const result = await db.query('update', 'resources', {
            data: updateData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            console.log(`📡 [R32] Resource ${req.params.id} not found`);
            return res.status(404).json({ status: 'error', message: 'Resource not found' });
        }

        console.log('✅ [R33] Resource updated:', result.data[0].id);

        await cacheManager.invalidateByTags(['resources']);

        logger.info('Resource updated', { requestId: req.id, resourceId: req.params.id, updatedBy: req.user.id });

        res.json({ status: 'success', data: result.data[0], message: 'Resource updated successfully' });
    } catch (error) {
        console.error('❌ [R-ERROR] Error updating resource:', error.message);
        logger.error('Error updating resource:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        if (error instanceof ValidationError) return res.status(400).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update resource', debug: error.message });
    }
});

/**
 * @swagger
 * /api/resources/{id}:
 *   delete:
 *     summary: Delete resource (admin only)
 *     tags: [Resources]
 */
resourceRouter.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    console.log(`📡 [R34] DELETE /api/resources/${req.params.id} called`);
    
    try {
        console.log('📡 [R35] Deleting resource:', req.params.id);
        
        const result = await db.query('delete', 'resources', { where: { id: req.params.id } });

        if (result.data.length === 0) {
            console.log(`📡 [R36] Resource ${req.params.id} not found`);
            return res.status(404).json({ status: 'error', message: 'Resource not found' });
        }

        console.log('✅ [R37] Resource deleted:', req.params.id);

        await cacheManager.invalidateByTags(['resources']);

        logger.info('Resource deleted', { requestId: req.id, resourceId: req.params.id, deletedBy: req.user.id });

        res.json({ status: 'success', message: 'Resource deleted successfully' });
    } catch (error) {
        console.error('❌ [R-ERROR] Error deleting resource:', error.message);
        logger.error('Error deleting resource:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete resource', debug: error.message });
    }
});

/**
 * @swagger
 * /api/resources/{id}/download:
 *   post:
 *     summary: Increment download count for resource
 *     tags: [Resources]
 */
resourceRouter.post('/:id/download', async (req, res) => {
    console.log(`📡 [R38] POST /api/resources/${req.params.id}/download called`);
    
    try {
        console.log('📡 [R39] Getting current download count for resource:', req.params.id);
        
        const getResult = await db.query('select', 'resources', {
            where: { id: req.params.id },
            select: 'download_count'
        });

        if (getResult.data.length === 0) {
            console.log(`📡 [R40] Resource ${req.params.id} not found`);
            return res.status(404).json({ status: 'error', message: 'Resource not found' });
        }

        const currentCount = getResult.data[0].download_count || 0;
        console.log(`📡 [R41] Current download count: ${currentCount}`);
        
        const newCount = currentCount + 1;
        console.log(`📡 [R42] Updating to: ${newCount}`);
        
        await db.query('update', 'resources', {
            data: { download_count: newCount, updated_at: new Date() },
            where: { id: req.params.id }
        });

        console.log('✅ [R43] Download count updated');

        res.json({ status: 'success', data: { download_count: newCount }, message: 'Download count updated' });
    } catch (error) {
        console.error('❌ [R-ERROR] Error updating download count:', error.message);
        logger.error('Error updating download count:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update download count', debug: error.message });
    }
});

/**
 * @swagger
 * /api/resources/meta/categories:
 *   get:
 *     summary: Get unique resource categories
 *     tags: [Resources]
 */
resourceRouter.get('/meta/categories', async (req, res) => {
    console.log('📡 [R44] GET /api/resources/meta/categories called');
    
    try {
        const result = await db.query('select', 'resources', {
            select: 'DISTINCT category',
            where: { category: { operator: 'isNull', value: false } }
        });
        
        const categories = result.data.map(item => item.category).filter(Boolean);
        console.log(`📡 [R45] Found ${categories.length} unique categories`);
        
        res.json({ status: 'success', data: categories });
    } catch (error) {
        console.error('❌ [R-ERROR] Error fetching categories:', error.message);
        logger.error('Error fetching categories:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch categories' });
    }
});

/**
 * @swagger
 * /api/resources/meta/departments:
 *   get:
 *     summary: Get unique resource departments
 *     tags: [Resources]
 */
resourceRouter.get('/meta/departments', async (req, res) => {
    console.log('📡 [R46] GET /api/resources/meta/departments called');
    
    try {
        const result = await db.query('select', 'resources', {
            select: 'DISTINCT department',
            where: { department: { operator: 'isNull', value: false } }
        });
        
        const departments = result.data.map(item => item.department).filter(Boolean);
        console.log(`📡 [R47] Found ${departments.length} unique departments`);
        
        res.json({ status: 'success', data: departments });
    } catch (error) {
        console.error('❌ [R-ERROR] Error fetching departments:', error.message);
        logger.error('Error fetching departments:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch departments' });
    }
});

/**
 * @swagger
 * /api/resources/meta/courses:
 *   get:
 *     summary: Get unique course codes with titles
 *     tags: [Resources]
 */
resourceRouter.get('/meta/courses', async (req, res) => {
    console.log('📡 [R48] GET /api/resources/meta/courses called');
    console.log('📡 [R48a] Query params:', req.query);
    
    try {
        const { department } = req.query;
        
        let where = { course_code: { operator: 'isNull', value: false } };
        if (department) {
            where.department = department;
            console.log('📡 [R49] Filtering by department:', department);
        }
        
        const result = await db.query('select', 'resources', {
            select: 'DISTINCT course_code, course_title',
            where
        });
        
        console.log(`📡 [R50] Found ${result.data.length} unique courses`);
        
        res.json({ status: 'success', data: result.data });
    } catch (error) {
        console.error('❌ [R-ERROR] Error fetching courses:', error.message);
        logger.error('Error fetching courses:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch courses' });
    }
});

app.use('/api/resources', resourceRouter);
console.log('✅ [R52] /api/resources router registered');

// --- 16.10 ARTICLES/NEWS ROUTES ---

const articleRouter = express.Router();

/**
 * @swagger
 * /api/articles:
 *   get:
 *     summary: Get all published articles
 *     tags: [Articles]
 */
articleRouter.get('/', cacheMiddleware(120, ['articles']), async (req, res) => {
    try {
        const { category, tag, limit = 50, page = 1, sort = 'published_at', order = 'desc' } = req.query;
        const offset = (page - 1) * limit;
        
        let where = { status: 'published', is_published: true };
        if (category && category !== 'all') where.category = category;
        if (tag) where.tags = { operator: 'contains', value: [tag] };

        const [articles, totalCount] = await Promise.all([
            db.query('select', 'articles', {
                where,
                order: { column: sort, ascending: order === 'asc' },
                limit: parseInt(limit),
                offset: parseInt(offset)
            }),
            db.query('select', 'articles', { where, count: true })
        ]);

        res.setHeader('X-Total-Count', totalCount.count || 0);
        res.setHeader('X-Page-Count', Math.ceil((totalCount.count || 0) / limit));

        res.json({
            status: 'success',
            data: articles.data,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: totalCount.count || 0,
                pages: Math.ceil((totalCount.count || 0) / limit)
            }
        });
    } catch (error) {
        logger.error('Error fetching articles:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch articles' });
    }
});

/**
 * @swagger
 * /api/articles/{identifier}:
 *   get:
 *     summary: Get article by ID or slug
 *     tags: [Articles]
 */
articleRouter.get('/:identifier', cacheMiddleware(300, ['articles']), async (req, res) => {
    try {
        const { identifier } = req.params;
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identifier);
        
        let where = { status: 'published', is_published: true };
        if (isUUID) where.uuid = identifier;
        else where.slug = identifier;

        const result = await db.query('select', 'articles', { where });
        if (result.data.length === 0) throw new NotFoundError('Article');

        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Error fetching article:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch article' });
    }
});

/**
 * @swagger
 * /api/articles/category/{category}:
 *   get:
 *     summary: Get articles by category
 *     tags: [Articles]
 */
articleRouter.get('/category/:category', cacheMiddleware(120, ['articles']), async (req, res) => {
    try {
        const result = await db.query('select', 'articles', {
            where: { category: req.params.category, status: 'published', is_published: true },
            order: { column: 'published_at', ascending: false }
        });

        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        logger.error('Error fetching articles by category:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch articles' });
    }
});

/**
 * @swagger
 * /api/articles:
 *   post:
 *     summary: Create new article (admin/editor only)
 *     tags: [Articles]
 */
articleRouter.post('/', verifyToken, requireRole('admin', 'editor'), validate(schemas.article), async (req, res) => {
    try {
        const { title, slug, content, excerpt, author, category, tags, status, is_published, published_at } = req.body;

        let articleSlug = slug;
        if (!articleSlug) {
            articleSlug = title.toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-').replace(/--+/g, '-').trim();
        }

        const existing = await db.query('select', 'articles', { where: { slug: articleSlug } });
        if (existing.data.length > 0) articleSlug = `${articleSlug}-${Date.now()}`;

        const articleData = {
            uuid: uuid.v4(),
            title: title.trim(),
            slug: articleSlug,
            content,
            excerpt: excerpt || null,
            author: author || req.user.fullName || 'NUESA BIU',
            category: category || null,
            tags: tags || [],
            status: status || 'draft',
            is_published: is_published || false,
            published_at: published_at || (is_published ? new Date() : null),
            created_at: new Date(),
            updated_at: new Date()
        };

        const result = await db.query('insert', 'articles', { data: articleData });
        await cacheManager.invalidateByTags(['articles']);

        logger.info('Article created', { requestId: req.id, articleId: result.data[0].uuid, createdBy: req.user.id });

        res.status(201).json({ status: 'success', data: result.data[0], message: 'Article created successfully' });
    } catch (error) {
        logger.error('Error creating article:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to create article' });
    }
});

/**
 * @swagger
 * /api/articles/{uuid}:
 *   put:
 *     summary: Update article (admin/editor only)
 *     tags: [Articles]
 */
articleRouter.put('/:uuid', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    try {
        const allowedFields = ['title', 'slug', 'content', 'excerpt', 'author', 'category', 'tags', 'status', 'is_published', 'published_at'];
        const updateData = {};

        allowedFields.forEach(field => {
            if (req.body[field] !== undefined) updateData[field] = req.body[field];
        });

        if (Object.keys(updateData).length === 0) throw new ValidationError('No fields to update');
        updateData.updated_at = new Date();

        const result = await db.query('update', 'articles', {
            data: updateData,
            where: { uuid: req.params.uuid }
        });

        if (result.data.length === 0) throw new NotFoundError('Article');

        await cacheManager.invalidateByTags(['articles']);

        logger.info('Article updated', { requestId: req.id, articleId: req.params.uuid, updatedBy: req.user.id });

        res.json({ status: 'success', data: result.data[0], message: 'Article updated successfully' });
    } catch (error) {
        logger.error('Error updating article:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update article' });
    }
});

/**
 * @swagger
 * /api/articles/{uuid}:
 *   delete:
 *     summary: Delete article (admin only)
 *     tags: [Articles]
 */
articleRouter.delete('/:uuid', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const result = await db.query('delete', 'articles', { where: { uuid: req.params.uuid } });
        if (result.data.length === 0) throw new NotFoundError('Article');

        await cacheManager.invalidateByTags(['articles']);

        logger.info('Article deleted', { requestId: req.id, articleId: req.params.uuid, deletedBy: req.user.id });

        res.json({ status: 'success', message: 'Article deleted successfully' });
    } catch (error) {
        logger.error('Error deleting article:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete article' });
    }
});

/**
 * @swagger
 * /api/articles/meta/categories:
 *   get:
 *     summary: Get unique article categories
 *     tags: [Articles]
 */
articleRouter.get('/meta/categories', async (req, res) => {
    try {
        const result = await db.query('select', 'articles', {
            select: 'DISTINCT category',
            where: { category: { operator: 'isNull', value: false }, status: 'published', is_published: true }
        });
        
        const categories = result.data.map(item => item.category).filter(Boolean);
        res.json({ status: 'success', data: categories });
    } catch (error) {
        logger.error('Error fetching categories:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch categories' });
    }
});

/**
 * @swagger
 * /api/articles/meta/tags:
 *   get:
 *     summary: Get unique article tags
 *     tags: [Articles]
 */
articleRouter.get('/meta/tags', async (req, res) => {
    try {
        const result = await db.query('select', 'articles', {
            select: 'tags',
            where: { tags: { operator: 'isNull', value: false }, status: 'published', is_published: true }
        });
        
        const allTags = result.data.flatMap(item => item.tags || []).filter(Boolean);
        const uniqueTags = [...new Set(allTags)];
        
        res.json({ status: 'success', data: uniqueTags });
    } catch (error) {
        logger.error('Error fetching tags:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch tags' });
    }
});

app.use('/api/articles', articleRouter);
app.use('/api/news', articleRouter);
console.log('✅ Articles/News router registered at /api/articles and /api/news');

// --- 16.11 FILE MANAGEMENT ROUTES ---

/**
 * @swagger
 * /api/upload:
 *   post:
 *     summary: Upload a file (admin/editor only)
 *     tags: [Files]
 */
app.post('/api/upload', verifyToken, requireRole('admin', 'editor'), upload.single('file'), async (req, res) => {
    try {
        if (!req.file) throw new ValidationError('No file uploaded');

        const fileInfo = {
            filename: req.file.filename,
            originalname: req.file.originalname,
            mimetype: req.file.mimetype,
            size: req.file.size,
            path: `/uploads/${req.file.filename}`,
            url: `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`,
            uploadedBy: req.user.id,
            uploadedAt: new Date()
        };

        logger.info('File uploaded', { requestId: req.id, filename: req.file.filename, size: req.file.size, uploadedBy: req.user.id });

        res.json({ status: 'success', data: fileInfo, message: 'File uploaded successfully' });
    } catch (error) {
        logger.error('Error uploading file:', { requestId: req.id, error: error.message });
        if (error instanceof ValidationError) return res.status(400).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to upload file' });
    }
});

/**
 * @swagger
 * /api/upload/{filename}:
 *   delete:
 *     summary: Delete a file (admin only)
 *     tags: [Files]
 */
app.delete('/api/upload/:filename', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const filePath = path.join(__dirname, 'uploads', req.params.filename);
        await fs.access(filePath);
        await fs.unlink(filePath);

        logger.info('File deleted', { requestId: req.id, filename: req.params.filename, deletedBy: req.user.id });

        res.json({ status: 'success', message: 'File deleted successfully' });
    } catch (error) {
        logger.error('Error deleting file:', { requestId: req.id, error: error.message });
        if (error.code === 'ENOENT') return res.status(404).json({ status: 'error', message: 'File not found' });
        res.status(500).json({ status: 'error', message: 'Failed to delete file' });
    }
});

// ============================================================
// SECTION 17: STATIC FILES & PAGES
// ============================================================

// Serve uploaded files
app.use('/uploads', compression(), express.static(path.join(__dirname, 'uploads'), {
    maxAge: IS_PRODUCTION ? '30d' : '0',
    setHeaders: (res, filePath) => {
        const ext = path.extname(filePath).toLowerCase();
        const mimeType = mime.lookup(ext) || 'application/octet-stream';

        if (ext.match(/\.(jpg|jpeg|png|gif|webp|svg)$/)) {
            res.setHeader('Content-Disposition', 'inline');
            res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
        } else {
            res.setHeader('Content-Disposition', 'attachment');
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }

        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Content-Type', mimeType);
    }
}));

// Public pages
const publicDir = path.join(__dirname, 'public');
const publicExists = fsSync.existsSync(publicDir);

if (publicExists) {
    app.use(express.static(publicDir, {
        maxAge: '1d',
        setHeaders: (res, filePath) => {
            res.setHeader('X-Content-Type-Options', 'nosniff');
            if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'public, max-age=3600');
        }
    }));
    
    const publicRoutes = {
        '/': 'index.html',
        '/index.html': 'index.html',
        '/about': 'about.html',
        '/about.html': 'about.html',
        '/events': 'event.html',
        '/event.html': 'event.html',
        '/members': 'member.html',
        '/member.html': 'member.html',
        '/resources': 'resources.html',
        '/resources.html': 'resources.html',
        '/news': 'news.html',
        '/news.html': 'news.html',
        '/contact': 'contacts.html',
        '/contacts.html': 'contacts.html'
    };
    
    Object.entries(publicRoutes).forEach(([route, file]) => {
        app.get(route, (req, res) => {
            res.sendFile(path.join(publicDir, file));
        });
    });
    
    console.log('✅ Public pages served from /public folder');
} else {
    console.log('⚠️ Public folder not found at:', publicDir);
}

// Admin panel
const adminDir = path.join(__dirname, 'admin');
if (fsSync.existsSync(adminDir)) {
    app.use('/admin', express.static(adminDir, {
        maxAge: IS_PRODUCTION ? '1h' : '0',
        setHeaders: (res, filePath) => {
            res.setHeader('X-Content-Type-Options', 'nosniff');
        }
    }));

    app.get('/admin/adlog.html', (req, res) => {
        res.sendFile(path.join(adminDir, 'adlog.html'));
    });

    app.get('/admin', (req, res) => {
        res.redirect('/admin/dashboard');
    });

    app.get('/admin/dashboard', (req, res) => {
        res.sendFile(path.join(adminDir, 'dash.html'));
    });

    console.log('✅ Admin panel routes registered at /admin/*');
} else {
    console.log('⚠️ Admin directory not found at:', adminDir);
}

// ============================================================
// SECTION 18: API DOCUMENTATION
// ============================================================

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'NUESA BIU API',
            version: '1.0.0',
            description: 'API documentation for NUESA BIU application',
            contact: { name: 'NUESA BIU', email: process.env.ADMIN_EMAIL }
        },
        servers: [{
            url: IS_PRODUCTION ? 'https://nuesa-biu-pjp0.onrender.com' : `http://localhost:${PORT}`,
            description: IS_PRODUCTION ? 'Production server' : 'Development server'
        }],
        components: {
            securitySchemes: {
                bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }
            }
        }
    },
    apis: ['./server.js'],
};

const swaggerSpecs = swaggerJsdoc(swaggerOptions);
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs));

// ============================================================
// SECTION 19: SYSTEM ENDPOINTS
// ============================================================

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function checkDatabase() {
    try {
        const start = Date.now();
        await db.query('select', 'users', { limit: 1 });
        const responseTime = Date.now() - start;
        return { status: 'healthy', responseTime: `${responseTime}ms` };
    } catch (error) {
        return { status: 'unhealthy', error: error.message };
    }
}

async function checkCache() {
    try {
        if (redis) {
            await redis.ping();
            return { status: 'healthy', type: 'redis' };
        } else {
            return { status: 'healthy', type: 'memory', size: cacheManager.getStats() };
        }
    } catch (error) {
        return { status: 'unhealthy', error: error.message };
    }
}

async function checkDiskSpace() {
    try {
        if (process.platform !== 'win32') {
            const { stdout } = await execPromise('df -k . | tail -1');
            const parts = stdout.trim().split(/\s+/);
            const used = parseInt(parts[2]) * 1024;
            const available = parseInt(parts[3]) * 1024;
            const total = used + available;
            
            return {
                status: 'healthy',
                total: formatBytes(total),
                used: formatBytes(used),
                available: formatBytes(available),
                usagePercent: Math.round((used / total) * 100) + '%'
            };
        }
        return { status: 'healthy', message: 'Disk check not available on Windows' };
    } catch (error) {
        return { status: 'unknown', error: error.message };
    }
}

function checkMemory() {
    const memory = process.memoryUsage();
    return {
        status: 'healthy',
        rss: formatBytes(memory.rss),
        heapTotal: formatBytes(memory.heapTotal),
        heapUsed: formatBytes(memory.heapUsed),
        external: formatBytes(memory.external)
    };
}

async function getRequestCount() { return 0; }
async function getEndpointStats() { return {}; }
async function getStatusStats() { return {}; }
async function getAvgResponseTime() { return '0ms'; }
async function getP95ResponseTime() { return '0ms'; }

/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Health check endpoint
 *     tags: [System]
 */
app.get('/api/health', async (req, res) => {
    try {
        const dbStatus = await checkDatabase();
        res.status(200).json({
            status: 'healthy',
            database: dbStatus,
            uptime: process.uptime(),
            timestamp: new Date().toISOString(),
            version: '1.0.0'
        });
    } catch (error) {
        res.status(200).json({
            status: 'degraded',
            message: 'Partial service disruption',
            timestamp: new Date().toISOString()
        });
    }
});

/**
 * @swagger
 * /api/ping:
 *   get:
 *     summary: Simple ping endpoint
 *     tags: [System]
 */
app.get('/api/ping', (req, res) => {
    res.json({
        status: 'success',
        message: 'pong',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        requestId: req.id
    });
});

/**
 * @swagger
 * /api/metrics:
 *   get:
 *     summary: Get system metrics (admin only)
 *     tags: [System]
 */
app.get('/api/metrics', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const metrics = {
            requests: {
                total: await getRequestCount(),
                byEndpoint: await getEndpointStats(),
                byStatus: await getStatusStats()
            },
            performance: {
                averageResponseTime: await getAvgResponseTime(),
                p95ResponseTime: await getP95ResponseTime()
            },
            database: db.getStats(),
            cache: cacheManager.getStats(),
            system: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage()
            }
        };
        
        res.json({
            status: 'success',
            data: metrics,
            timestamp: new Date().toISOString(),
            requestId: req.id
        });
    } catch (error) {
        logger.error('Error fetching metrics:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch metrics' });
    }
});

/**
 * @swagger
 * /api/stats:
 *   get:
 *     summary: Get basic statistics (admin only)
 *     tags: [System]
 */
app.get('/api/stats', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const [users, members, cacheStats] = await Promise.all([
            db.query('select', 'users', { count: true }),
            db.query('select', 'executive_members', { count: true }),
            Promise.resolve(cacheManager.getStats())
        ]);

        res.json({
            status: 'success',
            data: {
                users: users.count || 0,
                members: members.count || 0,
                cache: cacheStats,
                uptime: process.uptime(),
                environment: NODE_ENV
            },
            requestId: req.id
        });
    } catch (error) {
        logger.error('Error fetching stats:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch statistics' });
    }
});

/**
 * Root API endpoint
 */
app.get('/api', (req, res) => {
    res.json({
        message: 'NUESA BIU API Server',
        version: '1.0.0',
        environment: NODE_ENV,
        status: 'operational',
        timestamp: new Date().toISOString(),
        documentation: `${req.protocol}://${req.get('host')}/api/docs`,
        endpoints: {
            auth: '/api/auth',
            adminAuth: '/api/admin/login',
            users: '/api/users',
            members: '/api/members',
            events: '/api/events',
            resources: '/api/resources',
            articles: '/api/articles',
            profile: '/api/profile',
            health: '/api/health',
            stats: '/api/stats',
            metrics: '/api/metrics',
            contact: '/api/contact/submit',
            docs: '/api/docs'
        },
        requestId: req.id
    });
});

// ============================================================
// SECTION 20: DEBUG ENDPOINTS (Development Only)
// ============================================================

if (!IS_PRODUCTION) {
    app.get('/api/debug/env', (req, res) => {
        res.json({
            admin_email: process.env.ADMIN_EMAIL ? '✓ Set' : '✗ Missing',
            admin_password: process.env.ADMIN_PASSWORD ? '✓ Set' : '✗ Missing',
            jwt_secret: process.env.JWT_SECRET ? '✓ Set' : '✗ Missing',
            supabase_url: process.env.SUPABASE_URL ? '✓ Set' : '✗ Missing',
            supabase_key: process.env.SUPABASE_SERVICE_ROLE_KEY ? '✓ Set' : '✗ Missing',
            node_env: process.env.NODE_ENV,
            redis: process.env.REDIS_URL ? '✓ Set' : '✗ Missing',
            requestId: req.id
        });
    });

    app.get('/api/debug/db', async (req, res) => {
        try {
            const result = await db.query('select', 'users', { limit: 1 });
            res.json({
                status: 'connected',
                message: 'Database connection successful',
                data: result.data,
                stats: db.getStats(),
                requestId: req.id
            });
        } catch (error) {
            res.status(500).json({
                status: 'error',
                message: error.message,
                code: error.code,
                requestId: req.id
            });
        }
    });

    app.get('/api/debug/admin-paths', (req, res) => {
        const paths = {
            __dirname: __dirname,
            cwd: process.cwd(),
            adminDir: path.join(__dirname, 'admin'),
            adminDirCwd: path.join(process.cwd(), 'admin'),
        };
        
        const exists = {
            adminDir: fsSync.existsSync(paths.adminDir),
            adminDirCwd: fsSync.existsSync(paths.adminDirCwd),
            adlogInAdmin: fsSync.existsSync(path.join(__dirname, 'admin', 'adlog.html')),
            adlogInCwd: fsSync.existsSync(path.join(process.cwd(), 'admin', 'adlog.html')),
        };
        
        const files = {};
        if (exists.adminDir) files.adminDir = fsSync.readdirSync(paths.adminDir);
        if (exists.adminDirCwd) files.adminDirCwd = fsSync.readdirSync(paths.adminDirCwd);
        
        res.json({ paths, exists, files });
    });

    app.get('/api/debug/test', (req, res) => {
        res.json({ 
            message: 'Debug endpoint working',
            timestamp: new Date().toISOString(),
            requestId: req.id 
        });
    });
}

// ============================================================
// SECTION 21: ERROR HANDLING
// ============================================================

app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({
            status: 'error',
            code: 'ROUTE_NOT_FOUND',
            message: `Route ${req.method} ${req.url} not found`,
            timestamp: new Date().toISOString(),
            requestId: req.id
        });
    }
    
    const notFoundPage = path.join(publicDir, '404.html');
    if (publicExists && fsSync.existsSync(notFoundPage)) {
        res.status(404).sendFile(notFoundPage);
    } else {
        res.status(404).json({ status: 'error', message: 'Page not found', requestId: req.id });
    }
});

app.use((err, req, res, next) => {
    logger.error('Unhandled error:', {
        requestId: req.id,
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userId: req.user?.id,
        body: req.body
    });

    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                status: 'error',
                code: 'FILE_TOO_LARGE',
                message: `File size too large. Maximum size is ${MAX_FILE_SIZE} bytes.`,
                requestId: req.id
            });
        }
        return res.status(400).json({
            status: 'error',
            code: 'UPLOAD_ERROR',
            message: `File upload error: ${err.message}`,
            requestId: req.id
        });
    }

    if (err instanceof DatabaseError) {
        return res.status(400).json({
            status: 'error',
            code: 'DATABASE_ERROR',
            message: `Database error: ${err.message}`,
            requestId: req.id
        });
    }

    if (err instanceof AuthError) {
        return res.status(err.statusCode || 401).json({
            status: 'error',
            code: err.code,
            message: err.message,
            requestId: req.id
        });
    }

    if (err instanceof ValidationError) {
        return res.status(400).json({
            status: 'error',
            code: 'VALIDATION_ERROR',
            message: err.message,
            errors: err.errors,
            requestId: req.id
        });
    }

    if (err instanceof NotFoundError) {
        return res.status(404).json({
            status: 'error',
            code: 'NOT_FOUND',
            message: err.message,
            requestId: req.id
        });
    }

    if (err instanceof ForbiddenError) {
        return res.status(403).json({
            status: 'error',
            code: 'FORBIDDEN',
            message: err.message,
            requestId: req.id
        });
    }

    const message = IS_PRODUCTION ? 'Internal server error' : err.message;
    const statusCode = err.statusCode || 500;

    res.status(statusCode).json({
        status: 'error',
        code: 'INTERNAL_ERROR',
        message: message,
        ...(!IS_PRODUCTION && { stack: err.stack, details: err.message }),
        requestId: req.id
    });
});

// ============================================================
// SECTION 22: PROCESS HANDLERS
// ============================================================

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', {
        reason: reason.message || reason,
        stack: reason.stack,
        promise: promise
    });
    if (IS_PRODUCTION) logger.error('Unhandled rejection in production, continuing...');
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', { error: error.message, stack: error.stack });
    if (IS_PRODUCTION) {
        setTimeout(() => process.exit(1), 1000);
    }
});

process.on('SIGTERM', () => {
    logger.info('SIGTERM received, starting graceful shutdown');
    setTimeout(() => process.exit(0), 1000);
});

process.on('SIGINT', () => {
    logger.info('SIGINT received, starting graceful shutdown');
    setTimeout(() => process.exit(0), 1000);
});

// ============================================================
// SECTION 23: SERVER STARTUP
// ============================================================

async function startServer() {
    try {
        await initializeDatabase();

        app.listen(PORT, '0.0.0.0', () => {
            console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║     🚀 NUESA BIU API Server Started Successfully!                 ║
╠═══════════════════════════════════════════════════════════════════╣
║ 📡 Port: ${PORT}                                                ║
║ 🌍 Environment: ${NODE_ENV}                                     ║
║ 🗄️  Database: Supabase                                          ║
║ 💾 Cache: ${redis ? 'Redis' : 'In-Memory'}                      ║
║ 🔗 API URL: ${BASE_URL}                            ║
║ 🌐 Frontend: ${process.env.FRONTEND_URL || 'Not set'}           ║
║ 🔒 JWT: ${JWT_SECRET ? 'Set ✓' : 'Missing ✗'}                  ║
║ 👑 Admin: ${process.env.ADMIN_EMAIL || 'Not configured'}        ║
║ 📚 API Docs: ${BASE_URL}/api/docs                 ║
║ 🔐 Admin Login: ${BASE_URL}/api/admin/login       ║
╚═══════════════════════════════════════════════════════════════════╝
            `);

            logger.info(`Server started on port ${PORT} in ${NODE_ENV} mode`);
        });
    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();