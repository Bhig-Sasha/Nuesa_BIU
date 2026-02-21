/**
 * ============================================================
 * NUESA BIU API SERVER
 * ============================================================
 * 
 * Production-ready Express.js server for NUESA BIU (Baze University)
 * with comprehensive security, caching, logging, and database features.
 * 
 * @author NUESA BIU Team
 * @version 1.0.0
 * @license MIT
 */

// ============================================================
// ENVIRONMENT CONFIGURATION
// ============================================================
require('dotenv').config();

// ============================================================
// CORE DEPENDENCIES
// ============================================================
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
// ENVIRONMENT VALIDATION
// ============================================================

/**
 * Required environment variables for the application to run
 * @type {string[]}
 */
const REQUIRED_ENV_VARS = [
    'JWT_SECRET',
    'SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY'
];

/**
 * Validate that all required environment variables are present
 * Exit process with error if any are missing
 */
const missingEnvVars = REQUIRED_ENV_VARS.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
    console.error('❌ ERROR: Missing required environment variables:', missingEnvVars.join(', '));
    process.exit(1);
}

// ============================================================
// APPLICATION CONFIGURATION
// ============================================================

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const IS_PRODUCTION = NODE_ENV === 'production';

// Security Configuration
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';
const JWT_ADMIN_EXPIRE = process.env.JWT_ADMIN_EXPIRE || '8h';

// File Upload Configuration
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024; // 10MB default
const MAX_REQUEST_SIZE = process.env.MAX_REQUEST_SIZE || '10mb';

// ============================================================
// REDIS CACHE SETUP (Optional)
// ============================================================

/**
 * Redis client instance for distributed caching
 * Falls back to null if Redis is not configured
 * @type {Redis|null}
 */
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

// ============================================================
// SUPABASE DATABASE SETUP
// ============================================================

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

/**
 * Supabase client instance configured for server-side operations
 * Uses service role key for administrative access
 */
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
// CUSTOM ERROR CLASSES
// ============================================================

/**
 * Database operation error with additional context
 */
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

/**
 * Validation error for request data
 */
class ValidationError extends Error {
    constructor(message, errors = []) {
        super(message);
        this.name = 'ValidationError';
        this.errors = errors;
        this.statusCode = 400;
    }
}

/**
 * Resource not found error
 */
class NotFoundError extends Error {
    constructor(resource) {
        super(`${resource} not found`);
        this.name = 'NotFoundError';
        this.statusCode = 404;
    }
}

/**
 * Authentication error
 */
class AuthError extends Error {
    constructor(message, code = 'AUTH_ERROR') {
        super(message);
        this.name = 'AuthError';
        this.code = code;
        this.statusCode = 401;
    }
}

/**
 * Authorization error (insufficient permissions)
 */
class ForbiddenError extends Error {
    constructor(message = 'Access denied') {
        super(message);
        this.name = 'ForbiddenError';
        this.statusCode = 403;
    }
}

// ============================================================
// DATABASE SERVICE LAYER
// ============================================================

/**
 * Enhanced database service with query monitoring and advanced filtering
 * Provides abstraction over Supabase client with additional features
 */
class DatabaseService {
    constructor(supabase) {
        this.supabase = supabase;
        this.queryCount = 0;
        this.queryTimes = [];
    }

    /**
     * Execute a database query with enhanced features
     * @param {string} operation - Query type: 'select', 'insert', 'update', 'upsert', 'delete'
     * @param {string} table - Database table name
     * @param {Object} options - Query options
     * @param {Object} options.data - Data for insert/update operations
     * @param {string} options.select - Fields to select
     * @param {Object} options.where - Filter conditions with operators
     * @param {Object} options.order - Sorting configuration
     * @param {number} options.limit - Maximum records to return
     * @param {number} options.offset - Pagination offset
     * @param {boolean} options.count - Whether to return total count
     * @returns {Promise<Object>} Query result with metadata
     * @throws {DatabaseError} When query fails
     */
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

            // Build base query based on operation
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

            // Apply filters with enhanced operators
            if (where && Object.keys(where).length > 0) {
                for (const [key, value] of Object.entries(where)) {
                    if (Array.isArray(value)) {
                        query = query.in(key, value);
                    } else if (typeof value === 'object' && value.operator) {
                        switch (value.operator) {
                            case 'like':
                                query = query.like(key, value.value);
                                break;
                            case 'ilike':
                                query = query.ilike(key, value.value);
                                break;
                            case 'gt':
                                query = query.gt(key, value.value);
                                break;
                            case 'lt':
                                query = query.lt(key, value.value);
                                break;
                            case 'gte':
                                query = query.gte(key, value.value);
                                break;
                            case 'lte':
                                query = query.lte(key, value.value);
                                break;
                            case 'neq':
                                query = query.neq(key, value.value);
                                break;
                            case 'contains':
                                query = query.contains(key, value.value);
                                break;
                            case 'overlaps':
                                query = query.overlaps(key, value.value);
                                break;
                            case 'isNull':
                                query = query.is(key, null);
                                break;
                            default:
                                query = query.eq(key, value.value);
                        }
                    } else if (value !== undefined && value !== null) {
                        query = query.eq(key, value);
                    }
                }
            }

            // Apply ordering
            if (order.column) {
                query = query.order(order.column, {
                    ascending: order.ascending !== false,
                    nullsFirst: order.nullsFirst || false
                });
            }

            // Apply pagination
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

    /**
     * Get database performance statistics
     * @returns {Object} Query statistics
     */
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
// LOGGING SYSTEM
// ============================================================

/**
 * Create log directory if it doesn't exist
 */
const LOG_DIR = 'logs';
if (!fsSync.existsSync(LOG_DIR)) {
    fsSync.mkdirSync(LOG_DIR, { recursive: true });
}

/**
 * Winston logger instance with multiple transports
 * - error.log: Only error-level logs
 * - combined.log: All logs
 * - audit.log: Security and audit events
 * - Console: Development logging with colors
 */
const logger = winston.createLogger({
    level: IS_PRODUCTION ? 'info' : 'debug',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'nuesa-biu-api', environment: NODE_ENV },
    transports: [
        // Error logs
        new winston.transports.File({
            filename: `${LOG_DIR}/error.log`,
            level: 'error',
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 10,
            tailable: true
        }),
        // Combined logs
        new winston.transports.File({
            filename: `${LOG_DIR}/combined.log`,
            maxsize: 20 * 1024 * 1024, // 20MB
            maxFiles: 10,
            tailable: true
        }),
        // Audit logs for security events
        new winston.transports.File({
            filename: `${LOG_DIR}/audit.log`,
            level: 'info',
            maxsize: 10 * 1024 * 1024,
            maxFiles: 5,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.printf(({ timestamp, level, message, ...meta }) => {
                    return JSON.stringify({
                        timestamp,
                        level,
                        message,
                        ...meta
                    });
                })
            )
        })
    ]
});

// Console transport for development
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
// CACHE MANAGEMENT SYSTEM
// ============================================================

/**
 * LRU Cache implementation with TTL support
 */
class LRUCache {
    constructor(maxSize = 100, ttl = 300000) {
        this.cache = new Map();
        this.maxSize = maxSize;
        this.ttl = ttl;
        this.hits = 0;
        this.misses = 0;
    }

    /**
     * Set a value in cache with optional custom TTL
     * @param {string} key - Cache key
     * @param {*} value - Value to cache
     * @param {number} customTTL - Custom TTL in milliseconds
     */
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

    /**
     * Get a value from cache
     * @param {string} key - Cache key
     * @returns {*} Cached value or null if not found/expired
     */
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

    /**
     * Delete a key from cache
     * @param {string} key - Cache key
     * @returns {boolean} True if key was deleted
     */
    delete(key) {
        return this.cache.delete(key);
    }

    /**
     * Clear all cache entries
     */
    clear() {
        this.cache.clear();
        this.hits = 0;
        this.misses = 0;
    }

    /**
     * Get cache statistics
     * @returns {Object} Cache stats
     */
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

/**
 * Centralized cache manager with Redis support
 */
class CacheManager {
    constructor() {
        this.caches = new Map();
        this.redis = redis;
    }

    /**
     * Get or create a named cache
     * @param {string} name - Cache name
     * @param {Object} options - Cache options
     * @returns {LRUCache} Cache instance
     */
    getCache(name, options = {}) {
        if (!this.caches.has(name)) {
            this.caches.set(name, new LRUCache(options.maxSize || 100, options.ttl || 300000));
        }
        return this.caches.get(name);
    }

    /**
     * Get value from cache (Redis if available, otherwise memory)
     * @param {string} key - Cache key
     * @returns {Promise<*>} Cached value or null
     */
    async get(key) {
        if (this.redis) {
            const value = await this.redis.get(key);
            if (value) {
                return JSON.parse(value);
            }
            return null;
        }
        return this.caches.get('default')?.get(key) || null;
    }

    /**
     * Set value in cache
     * @param {string} key - Cache key
     * @param {*} value - Value to cache
     * @param {number} ttl - TTL in milliseconds
     */
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

    /**
     * Delete a key from cache
     * @param {string} key - Cache key
     */
    async delete(key) {
        if (this.redis) {
            await this.redis.del(key);
        } else {
            this.caches.forEach(cache => cache.delete(key));
        }
    }

    /**
     * Invalidate all keys matching a pattern
     * @param {string} pattern - Key pattern (e.g., 'user:*')
     */
    async invalidate(pattern) {
        if (this.redis) {
            const keys = await this.redis.keys(pattern);
            if (keys.length > 0) {
                await this.redis.del(...keys);
            }
        } else {
            this.caches.forEach((cache, cacheName) => {
                if (cacheName.match(pattern)) {
                    cache.clear();
                }
            });
        }
    }

    /**
     * Invalidate cache entries by tags
     * @param {string[]} tags - Tags to invalidate
     */
    async invalidateByTags(tags) {
        for (const tag of tags) {
            await this.invalidate(`tag:${tag}:*`);
        }
    }

    /**
     * Clear all caches
     */
    clearAll() {
        if (this.redis) {
            this.redis.flushdb();
        } else {
            this.caches.forEach(cache => cache.clear());
        }
    }

    /**
     * Get cache statistics
     * @returns {Object} Cache stats by name
     */
    getStats() {
        const stats = {};
        this.caches.forEach((cache, name) => {
            stats[name] = cache.getStats();
        });
        if (this.redis) {
            stats.redis = { connected: true };
        }
        return stats;
    }
}

const cacheManager = new CacheManager();
const userCache = cacheManager.getCache('users', { maxSize: 200, ttl: 300000 });
const dataCache = cacheManager.getCache('data', { maxSize: 100, ttl: 60000 });

// ============================================================
// REQUEST ID MIDDLEWARE
// ============================================================

/**
 * Generate unique ID for each request and set response header
 */
app.use((req, res, next) => {
    req.id = uuid.v4();
    res.setHeader('X-Request-ID', req.id);
    next();
});

// ============================================================
// SECURITY HEADERS MIDDLEWARE
// ============================================================

/**
 * Set security headers for all responses
 */
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});

// ============================================================
// ENHANCED MIDDLEWARE STACK
// ============================================================

app.set('trust proxy', 1);

/**
 * Compression middleware
 * Compress response bodies for all requests except those with x-no-compression header
 */
app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

/**
 * Helmet security configuration with custom CSP
 */
const CSP_DIRECTIVES = {
    defaultSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:", "blob:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"]
};

// Add allowed origins to connectSrc if they exist
if (supabaseUrl) {
    CSP_DIRECTIVES.connectSrc.push(supabaseUrl);
}

if (process.env.FRONTEND_URL) {
    CSP_DIRECTIVES.connectSrc.push(process.env.FRONTEND_URL);
}

// Add Supabase wildcard
CSP_DIRECTIVES.connectSrc.push("https://*.supabase.co");

app.use(
    helmet({
        contentSecurityPolicy: false, // Disabled for now, would need proper configuration
        crossOriginEmbedderPolicy: false,
        crossOriginResourcePolicy: { policy: "cross-origin" }
    })
);

/**
 * CSRF Protection (except for API routes)
 */
const csrfProtection = csrf({ cookie: true });
app.use('/portal', (req, res, next) => {
    if (req.path === '/login') {
        return next();
    }
    csrfProtection(req, res, next);
});

/**
 * XSS protection middleware
 */
app.use(xss());

/**
 * HTTP Parameter Pollution protection
 */
app.use(hpp({
    whitelist: ['page', 'limit', 'sort', 'fields']
}));

/**
 * Enhanced CORS configuration
 */
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(origin => origin.trim())
    .filter(origin => origin.length > 0);

// Add FRONTEND_URL if set
if (process.env.FRONTEND_URL && !ALLOWED_ORIGINS.includes(process.env.FRONTEND_URL)) {
    ALLOWED_ORIGINS.push(process.env.FRONTEND_URL);
}

// Add production domains
ALLOWED_ORIGINS.push('https://nuesa-biu.vercel.app');
ALLOWED_ORIGINS.push('https://www.nuesa-biu.vercel.app');

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) {
            return callback(null, true);
        }

        if (!IS_PRODUCTION) {
            return callback(null, true);
        }

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
        'Content-Type',
        'Authorization',
        'Accept',
        'Origin',
        'X-Requested-With',
        'X-API-Key',
        'X-Total-Count',
        'X-Page-Count',
        'X-CSRF-Token'
    ],
    exposedHeaders: [
        'X-Total-Count',
        'X-Page-Count',
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset',
        'X-Request-ID'
    ],
    maxAge: 86400,
    preflightContinue: false,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

/**
 * Cookie parser middleware
 */
app.use(cookieParser());

/**
 * Enhanced request parsing with raw body capture
 */
app.use(express.json({
    limit: MAX_REQUEST_SIZE,
    verify: (req, res, buf, encoding) => {
        req.rawBody = buf;
    }
}));

app.use(express.urlencoded({
    extended: true,
    limit: MAX_REQUEST_SIZE,
    parameterLimit: 100
}));

/**
 * Request logging with Morgan
 */
const morganFormat = IS_PRODUCTION ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
    stream: {
        write: (message) => logger.http(message.trim())
    },
    skip: (req, res) => req.path === '/api/health' && req.method === 'GET'
}));

/**
 * Request timeout middleware
 */
app.use(timeout('30s'));
app.use(haltOnTimedout);

/**
 * Handle request timeouts
 */
function haltOnTimedout(req, res, next) {
    if (req.timedout) {
        logger.error('Request timeout', {
            requestId: req.id,
            url: req.url,
            method: req.method,
            ip: req.ip,
            userId: req.user?.id
        });
        res.status(503).json({
            status: 'error',
            code: 'TIMEOUT',
            message: 'Request timeout. Please try again.'
        });
    } else {
        next();
    }
}

/**
 * Create rate limiter with configurable options
 * @param {number} max - Maximum requests per window
 * @param {number} windowMs - Time window in milliseconds
 * @param {string} message - Error message
 * @returns {Function} Rate limiter middleware
 */
const createRateLimiter = (max, windowMs = 15 * 60 * 1000, message = 'Too many requests') => {
    return rateLimit({
        windowMs,
        max,
        message: {
            status: 'error',
            code: 'TOO_MANY_REQUESTS',
            message
        },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        keyGenerator: (req) => {
            return req.headers['x-forwarded-for'] || req.ip;
        },
        handler: (req, res) => {
            logger.warn('Rate limit exceeded', {
                requestId: req.id,
                ip: req.ip,
                url: req.url,
                method: req.method
            });
            res.status(429).json({
                status: 'error',
                code: 'TOO_MANY_REQUESTS',
                message
            });
        }
    });
};

/**
 * Apply rate limiting to specific routes
 */
app.use('/api/auth/login', createRateLimiter(10, 15 * 60 * 1000, 'Too many login attempts'));
app.use('/api/admin/login', createRateLimiter(5, 15 * 60 * 1000, 'Too many admin login attempts'));
app.use('/api/contact/submit', createRateLimiter(10, 15 * 60 * 1000, 'Too many contact form submissions'));
app.use('/api/', createRateLimiter(200, 15 * 60 * 1000));

/**
 * Cache middleware with tag support
 * @param {number} duration - Cache duration in seconds
 * @param {string[]} tags - Cache tags for invalidation
 * @returns {Function} Cache middleware
 */
const cacheMiddleware = (duration = 60, tags = []) => {
    return async (req, res, next) => {
        if (req.method !== 'GET' || req.headers.authorization) {
            return next();
        }

        const key = `cache:${req.originalUrl || req.url}`;
        
        try {
            const cachedResponse = await cacheManager.get(key);

            if (cachedResponse) {
                return res.json(cachedResponse);
            }

            const originalSend = res.json;
            res.json = async function (body) {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    await cacheManager.set(key, body, duration * 1000);
                    
                    // Set cache tags for invalidation
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

/**
 * Response time tracking middleware
 */
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info('Request completed', {
            requestId: req.id,
            method: req.method,
            url: req.url,
            status: res.statusCode,
            duration: `${duration}ms`,
            userId: req.user?.id
        });
    });
    next();
});

// ============================================================
// ACCOUNT LOCKOUT SYSTEM
// ============================================================

/**
 * In-memory store for login attempts
 * In production, this should be replaced with Redis
 */
const loginAttempts = new Map();

/**
 * Check if an account is locked due to too many failed attempts
 * @param {string} identifier - Email or user identifier
 * @throws {AuthError} If account is locked
 */
async function checkLoginAttempts(identifier) {
    const attempts = loginAttempts.get(identifier) || { count: 0, lockedUntil: null };
    
    // Check if locked
    if (attempts.lockedUntil && attempts.lockedUntil > Date.now()) {
        throw new AuthError('Account temporarily locked. Try again later.', 'ACCOUNT_LOCKED');
    }
    
    // Reset if lock expired
    if (attempts.lockedUntil && attempts.lockedUntil <= Date.now()) {
        loginAttempts.delete(identifier);
        return;
    }
    
    return attempts;
}

/**
 * Record a failed login attempt
 * @param {string} identifier - Email or user identifier
 */
async function recordFailedAttempt(identifier) {
    const attempts = loginAttempts.get(identifier) || { count: 0, lockedUntil: null };
    attempts.count += 1;
    
    // Lock after 5 failed attempts
    if (attempts.count >= 5) {
        attempts.lockedUntil = Date.now() + 15 * 60 * 1000; // 15 minutes
        attempts.count = 0;
        logger.warn('Account locked due to multiple failed attempts', { identifier });
    }
    
    loginAttempts.set(identifier, attempts);
}

/**
 * Reset login attempts on successful login
 * @param {string} identifier - Email or user identifier
 */
async function resetLoginAttempts(identifier) {
    loginAttempts.delete(identifier);
}

// ============================================================
// FILE UPLOAD CONFIGURATION
// ============================================================

/**
 * Upload directories configuration
 */
const UPLOAD_DIRS = {
    images: './uploads/images',
    resources: './uploads/resources',
    profiles: './uploads/profiles',
    temp: './uploads/temp'
};

// Create upload directories
Object.values(UPLOAD_DIRS).forEach(dir => {
    if (!fsSync.existsSync(dir)) {
        fsSync.mkdirSync(dir, { recursive: true });
        logger.info(`Created upload directory: ${dir}`);
    }
});

/**
 * Enhanced storage configuration for multer
 */
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

/**
 * File filter with enhanced validation
 */
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

/**
 * Multer upload instance with configuration
 */
const upload = multer({
    storage: storage,
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 5
    },
    fileFilter: fileFilter
});

// ============================================================
// VALIDATION SCHEMAS
// ============================================================

/**
 * Joi validation schemas for request data
 */
const schemas = {
    // Authentication schemas
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
    
    // User management schemas
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
    
    // Member management schemas
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
    
    // Contact form schema
    contactForm: Joi.object({
        name: Joi.string().min(2).max(100).required(),
        email: Joi.string().email().required(),
        message: Joi.string().min(10).max(1000).required(),
        subject: Joi.string().max(200).optional()
    }),
    
    // Article schema
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

/**
 * Validation middleware factory
 * @param {Joi.Schema} schema - Joi validation schema
 * @returns {Function} Express middleware
 */
const validate = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            throw new ValidationError('Validation failed', error.details);
        }
        next();
    };
};

// ============================================================
// AUTHENTICATION SERVICE
// ============================================================

/**
 * Authentication service handling JWT and user authentication
 */
class AuthService {
    constructor() {
        this.secret = JWT_SECRET;
        this.expire = JWT_EXPIRE;
        this.adminExpire = JWT_ADMIN_EXPIRE;
    }

    /**
     * Generate JWT token for regular users
     * @param {Object} payload - Token payload
     * @returns {string} JWT token
     */
    generateToken(payload) {
        return jwt.sign(payload, this.secret, {
            expiresIn: this.expire,
            issuer: 'nuesa-biu-api',
            audience: 'nuesa-biu-client',
            jwtid: uuid.v4()
        });
    }

    /**
     * Generate JWT token for admin users
     * @param {Object} payload - Token payload
     * @returns {string} JWT token
     */
    generateAdminToken(payload) {
        return jwt.sign(payload, this.secret, {
            expiresIn: this.adminExpire,
            issuer: 'nuesa-biu-system',
            audience: 'nuesa-biu-admin',
            jwtid: uuid.v4()
        });
    }

    /**
     * Verify and decode JWT token
     * @param {string} token - JWT token
     * @returns {Object} Decoded payload
     * @throws {AuthError} If token is invalid
     */
    verifyToken(token) {
        try {
            return jwt.verify(token, this.secret, {
                issuer: ['nuesa-biu-api', 'nuesa-biu-system'],
                audience: ['nuesa-biu-client', 'nuesa-biu-admin']
            });
        } catch (error) {
            throw new AuthError('Invalid token', error.name);
        }
    }

    /**
     * Authenticate user with email and password
     * @param {string} email - User email
     * @param {string} password - User password
     * @returns {Promise<Object>} User object without sensitive data
     * @throws {AuthError} If authentication fails
     */
    async authenticateUser(email, password) {
        try {
            // Check login attempts
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

            if (!user.is_active) {
                throw new AuthError('Account is deactivated');
            }

            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                await recordFailedAttempt(email.toLowerCase());
                throw new AuthError('Invalid credentials');
            }

            // Reset login attempts on success
            await resetLoginAttempts(email.toLowerCase());

            // Update last login
            await db.query('update', 'users', {
                data: { last_login: new Date() },
                where: { id: user.id }
            });

            // Log successful login
            logger.info('User logged in successfully', { userId: user.id, email: user.email });

            return this.createUserResponse(user);
        } catch (error) {
            throw error;
        }
    }

    /**
     * Create user response object (remove sensitive data)
     * @param {Object} user - Raw user object from database
     * @returns {Object} Sanitized user object
     */
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

    /**
     * Create token payload from user
     * @param {Object} user - User object
     * @returns {Object} Token payload
     */
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
// ADMIN AUTHENTICATION MIDDLEWARE
// ============================================================

/**
 * Check admin session from cookies or headers
 * Sets req.isAdmin and req.admin if authenticated
 */
const checkAdminSessionEnhanced = async (req, res, next) => {
    try {
        // Check multiple token sources
        const token = req.cookies?.admin_session || 
                     req.cookies?.auth_token ||
                     req.headers['x-access-token'] ||
                     req.headers['authorization']?.replace('Bearer ', '');
        
        if (!token) {
            req.isAdmin = false;
            req.admin = null;
            return next();
        }
        
        let decoded;
        try {
            // Try to verify as admin token first
            decoded = jwt.verify(token, JWT_SECRET, {
                issuer: 'nuesa-biu-system',
                audience: 'nuesa-biu-admin'
            });
        } catch (e) {
            // If not admin token, try regular token
            try {
                decoded = jwt.verify(token, JWT_SECRET);
            } catch (e2) {
                req.isAdmin = false;
                req.admin = null;
                return next();
            }
        }
        
        // Get user from database
        const result = await db.query('select', 'users', {
            where: { id: decoded.userId },
            select: 'id, email, full_name, role, is_active, last_login'
        });
        
        if (result.data.length === 0 || !result.data[0].is_active) {
            // Clear cookies safely
            const clearAdminCookie = () => {
                const cookieOptions = {
                    httpOnly: true,
                    secure: IS_PRODUCTION,
                    sameSite: 'none',
                    maxAge: 8 * 60 * 60 * 1000,
                    path: '/'
                };
                
                if (IS_PRODUCTION && process.env.FRONTEND_URL) {
                    try {
                        const frontendUrl = new URL(process.env.FRONTEND_URL);
                        cookieOptions.domain = frontendUrl.hostname;
                    } catch (error) {
                        logger.warn('Invalid FRONTEND_URL for cookie clearing:', error);
                    }
                }
                
                res.clearCookie('admin_token', cookieOptions);
                res.clearCookie('admin_session', cookieOptions);
            };
            
            clearAdminCookie();
            req.isAdmin = false;
            req.admin = null;
            return next();
        }
        
        const user = result.data[0];
        
        // Check if user has admin role
        if (user.role === 'admin') {
            req.admin = user;
            req.isAdmin = true;
        } else {
            req.isAdmin = false;
            req.admin = null;
        }
        
        next();
    } catch (error) {
        req.isAdmin = false;
        req.admin = null;
        next();
    }
};

// Apply enhanced session check to all routes
app.use(checkAdminSessionEnhanced);

// ============================================================
// USER AUTHENTICATION MIDDLEWARE
// ============================================================

/**
 * Verify JWT token and attach user to request
 */
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

        if (result.data.length === 0) {
            throw new AuthError('User not found', 'USER_NOT_FOUND');
        }

        const user = authService.createUserResponse(result.data[0]);

        if (!user.isActive) {
            throw new AuthError('Account deactivated', 'ACCOUNT_DEACTIVATED');
        }

        await cacheManager.set(cacheKey, user, 300000);
        req.user = user;
        req.token = token;

        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                status: 'error',
                code: 'TOKEN_EXPIRED',
                message: 'Token expired'
            });
        }

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                status: 'error',
                code: 'INVALID_TOKEN',
                message: 'Invalid token'
            });
        }

        logger.error('Authentication error:', { requestId: req.id, error: error.message });
        res.status(error.statusCode || 401).json({
            status: 'error',
            code: error.code || 'AUTH_FAILED',
            message: error.message || 'Authentication failed'
        });
    }
};

/**
 * Require specific roles for access
 * @param {...string} roles - Allowed roles
 * @returns {Function} Middleware
 */
const requireRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            throw new AuthError('Authentication required', 'AUTH_REQUIRED');
        }

        if (!roles.includes(req.user.role)) {
            throw new ForbiddenError(`Required roles: ${roles.join(', ')}`);
        }

        next();
    };
};

/**
 * Require specific permission
 * @param {string} permission - Required permission
 * @returns {Function} Middleware
 */
const requirePermission = (permission) => {
    const permissions = {
        admin: ['manage_users', 'manage_content', 'manage_settings', 'view_all'],
        editor: ['manage_content', 'view_all'],
        member: ['view_content']
    };

    return (req, res, next) => {
        if (!req.user) {
            throw new AuthError('Authentication required', 'AUTH_REQUIRED');
        }

        const userPermissions = permissions[req.user.role] || [];
        if (!userPermissions.includes(permission)) {
            throw new ForbiddenError(`Required permission: ${permission}`);
        }

        next();
    };
};

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

/**
 * Initialize database connection and create default admin
 */
async function initializeDatabase() {
    try {
        // Test database connection
        const { error } = await supabase.from('users').select('count').limit(1);

        if (error) {
            throw new Error(`Database connection failed: ${error.message}`);
        }

        logger.info('Database connected successfully');

        await createDefaultAdmin();
        await createDefaultTables();

        logger.info('Database initialization complete');
    } catch (error) {
        logger.error('Database initialization failed:', error);
        throw error;
    }
}

/**
 * Create default admin user if it doesn't exist
 */
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

/**
 * Check database tables (tables should be created via migrations)
 */
async function createDefaultTables() {
    logger.info('Checking database tables...');
}

// ============================================================
// AUTHENTICATION ROUTES
// ============================================================

const authRouter = express.Router();

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: User login
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 8
 *               rememberMe:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 */
authRouter.post('/login', validate(schemas.login), async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;

        const user = await authService.authenticateUser(email, password);
        const tokenPayload = authService.createTokenPayload(user);
        const token = authService.generateToken(tokenPayload);

        await cacheManager.set(`user:${user.id}`, user, rememberMe ? 604800000 : 300000);

        // Set secure cookie
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
            data: {
                user,
                token,
                expiresIn: JWT_EXPIRE
            },
            message: 'Login successful'
        });
    } catch (error) {
        logger.error('Login failed:', { email: req.body.email, error: error.message });

        res.status(error.statusCode || 500).json({
            status: 'error',
            code: error.code || 'LOGIN_FAILED',
            message: error.message || 'Login failed'
        });
    }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: User logout
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 */
authRouter.post('/logout', verifyToken, async (req, res) => {
    try {
        await cacheManager.delete(`user:${req.user.id}`);
        await cacheManager.invalidate('data:*');

        res.clearCookie('auth_token');

        res.json({
            status: 'success',
            message: 'Logged out successfully'
        });
    } catch (error) {
        logger.error('Logout error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Logout failed'
        });
    }
});

/**
 * @swagger
 * /api/auth/verify:
 *   get:
 *     summary: Verify token validity
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token is valid
 *       401:
 *         description: Invalid or expired token
 */
authRouter.get('/verify', verifyToken, async (req, res) => {
    res.json({
        status: 'success',
        data: req.user,
        message: 'Token is valid'
    });
});

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 */
authRouter.post('/refresh', verifyToken, async (req, res) => {
    try {
        const newToken = authService.generateToken(
            authService.createTokenPayload(req.user)
        );

        res.json({
            status: 'success',
            data: {
                token: newToken,
                expiresIn: JWT_EXPIRE
            },
            message: 'Token refreshed successfully'
        });
    } catch (error) {
        logger.error('Token refresh error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to refresh token'
        });
    }
});

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Reset email sent if account exists
 */
authRouter.post('/forgot-password', validate(Joi.object({ email: Joi.string().email().required() })), async (req, res) => {
    try {
        const { email } = req.body;

        // In production, send reset email
        logger.info('Password reset requested', { email });

        res.json({
            status: 'success',
            message: 'If an account exists with this email, you will receive a reset link'
        });
    } catch (error) {
        logger.error('Forgot password error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to process request'
        });
    }
});

app.use('/api/auth', authRouter);

// ============================================================
// ADMIN AUTHENTICATION HANDLER - FIXED & IMPROVED
// ============================================================

async function adminLoginHandler(req, res) {
    const requestId = req.id || 'unknown';
    console.log('\n🔐 ========== ADMIN LOGIN DEBUG ==========');
    console.log('Request ID:', requestId);
    console.log('Request body:', req.body);
    console.log('Email:', req.body?.email);
    console.log('Password provided:', !!req.body?.password);
    console.log('Content-Type:', req.headers['content-type']);
    
    try {
        const { email, password, rememberMe } = req.body;

        // STEP 1: Validate input
        console.log('\n📌 STEP 1: Validating input...');
        if (!email || !password) {
            console.log('❌ Missing email or password');
            return res.status(400).json({
                status: 'error',
                code: 'MISSING_FIELDS',
                message: 'Email and password are required'
            });
        }
        
        // Sanitize email
        const sanitizedEmail = email.toLowerCase().trim();
        console.log('✅ Input validation passed');
        console.log('Sanitized email:', sanitizedEmail);

        // STEP 2: Check login attempts
        console.log('\n📌 STEP 2: Checking login attempts...');
        try {
            await checkLoginAttempts(sanitizedEmail);
            console.log('✅ Login attempts check passed');
        } catch (error) {
            console.log('❌ Account locked:', error.message);
            return res.status(429).json({
                status: 'error',
                code: 'ACCOUNT_LOCKED',
                message: 'Too many failed attempts. Account temporarily locked.'
            });
        }

        // STEP 3: Find user directly with Supabase (bypass db.query for debugging)
        console.log('\n📌 STEP 3: Looking up user in database...');
        
        const { data: users, error: userError } = await supabase
            .from('users')
            .select('id, email, password_hash, full_name, role, department, is_active, created_at, last_login')
            .eq('email', sanitizedEmail)
            .limit(1);

        if (userError) {
            console.error('❌ Database error:', userError);
            return res.status(500).json({
                status: 'error',
                code: 'DATABASE_ERROR',
                message: 'Database error occurred'
            });
        }

        console.log('Query result:', {
            dataLength: users?.length || 0,
            hasError: !!userError
        });

        if (!users || users.length === 0) {
            console.log('❌ User not found');
            await recordFailedAttempt(sanitizedEmail);
            return res.status(401).json({
                status: 'error',
                code: 'INVALID_CREDENTIALS',
                message: 'Invalid email or password'
            });
        }

        const user = users[0];
        console.log('✅ User found:', { 
            id: user.id, 
            role: user.role, 
            is_active: user.is_active,
            hash_exists: !!user.password_hash,
            hash_length: user.password_hash?.length
        });

        // STEP 4: Check if account is active
        console.log('\n📌 STEP 4: Checking account status...');
        if (!user.is_active) {
            console.log('❌ Account inactive');
            return res.status(401).json({
                status: 'error',
                code: 'ACCOUNT_INACTIVE',
                message: 'Account is deactivated'
            });
        }
        console.log('✅ Account is active');

        // STEP 5: Check if user has admin role
        console.log('\n📌 STEP 5: Checking admin role...');
        console.log('User role:', user.role);
        if (user.role !== 'admin') {
            console.log('❌ Not admin - role is:', user.role);
            await recordFailedAttempt(sanitizedEmail);
            return res.status(401).json({
                status: 'error',
                code: 'INVALID_CREDENTIALS',
                message: 'Invalid email or password'
            });
        }
        console.log('✅ User is admin');

        // STEP 6: Verify password
        console.log('\n📌 STEP 6: Verifying password...');
        console.log('Hash from DB:', user.password_hash ? user.password_hash.substring(0, 20) + '...' : 'No hash');
        
        let validPassword = false;
        try {
            validPassword = await bcrypt.compare(password, user.password_hash);
        } catch (bcryptError) {
            console.error('❌ Bcrypt error:', bcryptError.message);
            return res.status(500).json({
                status: 'error',
                code: 'PASSWORD_VERIFICATION_FAILED',
                message: 'Password verification failed'
            });
        }
        
        console.log('Password valid:', validPassword);
        
        if (!validPassword) {
            console.log('❌ Invalid password');
            await recordFailedAttempt(sanitizedEmail);
            return res.status(401).json({
                status: 'error',
                code: 'INVALID_CREDENTIALS',
                message: 'Invalid email or password'
            });
        }
        console.log('✅ Password verified');

        // STEP 7: Reset login attempts
        console.log('\n📌 STEP 7: Resetting login attempts...');
        await resetLoginAttempts(sanitizedEmail);
        console.log('✅ Login attempts reset');

        // STEP 8: Update last login
        console.log('\n📌 STEP 8: Updating last_login...');
        try {
            await supabase
                .from('users')
                .update({ last_login: new Date().toISOString() })
                .eq('id', user.id);
            console.log('✅ Last login updated');
        } catch (updateError) {
            console.log('⚠️ Failed to update last login (non-critical):', updateError.message);
        }

        // STEP 9: Create token
        console.log('\n📌 STEP 9: Generating JWT token...');
        
        if (!process.env.JWT_SECRET) {
            console.error('❌ JWT_SECRET is not set!');
            return res.status(500).json({
                status: 'error',
                code: 'SERVER_CONFIG_ERROR',
                message: 'Server configuration error'
            });
        }
        
        const tokenPayload = {
            userId: user.id,
            email: user.email,
            role: user.role,
            fullName: user.full_name
        };
        
        console.log('Token payload created');
        console.log('JWT_SECRET exists:', !!process.env.JWT_SECRET);
        
        // Generate token directly (bypass authService for debugging)
        const token = jwt.sign(
            tokenPayload,
            process.env.JWT_SECRET,
            {
                expiresIn: rememberMe ? '7d' : '8h',
                issuer: 'nuesa-biu-system',
                audience: 'nuesa-biu-admin',
                jwtid: uuid.v4()
            }
        );
        
        console.log('✅ Token generated (length: ' + token.length + ')');

        // STEP 10: Set cookie
        console.log('\n📌 STEP 10: Setting cookies...');
        const isProduction = process.env.NODE_ENV === 'production';
        
        const cookieOptions = {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'none' : 'lax',
            maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 8 * 60 * 60 * 1000,
            path: '/'
        };
        
        // Only set domain if in production and FRONTEND_URL is valid
        if (isProduction && process.env.FRONTEND_URL) {
            try {
                const frontendUrl = new URL(process.env.FRONTEND_URL);
                // Don't set domain for localhost
                if (!frontendUrl.hostname.includes('localhost') && !frontendUrl.hostname.includes('127.0.0.1')) {
                    cookieOptions.domain = frontendUrl.hostname;
                    console.log('Cookie domain set to:', frontendUrl.hostname);
                }
            } catch (error) {
                console.warn('Could not parse FRONTEND_URL:', error.message);
            }
        }
        
        // Set both admin_session and auth_token for compatibility
        res.cookie('admin_session', token, cookieOptions);
        res.cookie('auth_token', token, cookieOptions);
        
        console.log('✅ Cookies set: admin_session and auth_token');

        // STEP 11: Prepare response
        console.log('\n📌 STEP 11: Preparing response...');
        const userResponse = {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            department: user.department,
            lastLogin: user.last_login,
            isActive: user.is_active
        };

        console.log('✅ Login successful for:', user.email);
        console.log('========== DEBUG END ==========\n');
        
        // Return success response
        return res.status(200).json({
            status: 'success',
            data: {
                user: userResponse,
                token: token
            },
            message: 'Login successful'
        });

    } catch (error) {
        console.error('\n❌ ADMIN LOGIN ERROR:', {
            message: error.message,
            stack: error.stack,
            name: error.name,
            code: error.code
        });
        console.log('========== DEBUG END (WITH ERROR) ==========\n');
        
        // Don't expose internal errors in production
        const isProduction = process.env.NODE_ENV === 'production';
        
        return res.status(500).json({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Login failed. Please try again.',
            ...(!isProduction && { debug: error.message, stack: error.stack })
        });
    }
}

// ============================================================
// FIXED: ADMIN ROUTES
// ============================================================

/**
 * Admin login endpoint - Single source of truth
 */
app.post('/admin/login', createRateLimiter(5, 15 * 60 * 1000, 'Too many admin login attempts'), adminLoginHandler);

/**
 * API admin login endpoint (redirects to main handler)
 */
app.post('/api/admin/login', createRateLimiter(5, 15 * 60 * 1000, 'Too many admin login attempts'), (req, res, next) => {
    // Just pass through to the same handler
    adminLoginHandler(req, res);
});


// ============================================================
// SIMPLE ADMIN LOGIN - WORKS WITH YOUR FRONTEND
// ============================================================

app.post('/api/admin-login', express.json(), async (req, res) => {
    console.log('\n🔐 ADMIN LOGIN ATTEMPT:', {
        email: req.body?.email,
        timestamp: new Date().toISOString()
    });
    
    try {
        const { email, password } = req.body;

        // Basic validation
        if (!email || !password) {
            return res.status(400).json({
                status: 'error',
                message: 'Email and password are required'
            });
        }

        // Find user in database
        const { data: users, error } = await supabase
            .from('users')
            .select('id, email, password_hash, full_name, role, is_active')
            .eq('email', email.toLowerCase().trim())
            .limit(1);

        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({
                status: 'error',
                message: 'Database error occurred'
            });
        }

        // Check if user exists
        if (!users || users.length === 0) {
            console.log('❌ User not found:', email);
            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password'
            });
        }

        const user = users[0];

        // Check if user is active
        if (!user.is_active) {
            console.log('❌ Account inactive:', email);
            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password'
            });
        }

        // Check if user has admin role
        if (user.role !== 'admin') {
            console.log('❌ Not admin - role is:', user.role);
            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password'
            });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            console.log('❌ Invalid password for:', email);
            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password'
            });
        }

        console.log('✅ Password verified for:', email);

        // Generate JWT token
        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email, 
                role: user.role,
                fullName: user.full_name 
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Update last login (don't wait for it)
        supabase
            .from('users')
            .update({ last_login: new Date().toISOString() })
            .eq('id', user.id)
            .then()
            .catch(err => console.log('Last login update failed:', err.message));

        // Set cookie for session
        const isProduction = process.env.NODE_ENV === 'production';
        
        res.cookie('admin_session', token, {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'none' : 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/'
        });

        console.log('✅ Login successful for:', user.email);

        // Return success response
        res.status(200).json({
            status: 'success',
            data: {
                user: {
                    id: user.id,
                    email: user.email,
                    fullName: user.full_name,
                    role: user.role
                },
                token: token
            },
            message: 'Login successful'
        });

    } catch (error) {
        console.error('❌ Admin login error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Login failed. Please try again.'
        });
    }
});

// ============================================================
// FIXED: CREATE DEFAULT ADMIN FUNCTION
// ============================================================

/**
 * Create default admin user if it doesn't exist
 */
async function createDefaultAdmin() {
    try {
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@nuesa-biu.com';

        if (!adminEmail) {
            logger.warn('ADMIN_EMAIL not set, skipping admin creation');
            return;
        }

        const result = await db.query('select', 'users', {
            where: { email: adminEmail },
            select: 'id'
        });

        if (result.data.length === 0) {
            const adminPassword = process.env.ADMIN_PASSWORD || 'Admin@123456';

            if (!adminPassword) {
                logger.warn('ADMIN_PASSWORD not set, skipping admin creation');
                return;
            }

            const hashedPassword = await bcrypt.hash(adminPassword, 12);

            const adminData = {
                email: adminEmail.toLowerCase(),
                password_hash: hashedPassword,
                full_name: process.env.ADMIN_FULL_NAME || 'System Administrator',
                role: 'admin',  // This is critical - must be 'admin'
                department: process.env.ADMIN_DEPARTMENT || 'Administration',
                username: (adminEmail.split('@')[0]).toLowerCase(),
                is_active: true,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };

            await db.query('insert', 'users', { data: adminData });
            logger.info(`✅ Admin user created: ${adminEmail} with role 'admin'`);
            console.log(`✅ Default admin created - Email: ${adminEmail}, Password: ${adminPassword}`);
        } else {
            logger.info('Admin user already exists');
            
            // Ensure existing admin has correct role
            const adminCheck = await db.query('select', 'users', {
                where: { email: adminEmail },
                select: 'id, role'
            });
            
            if (adminCheck.data.length > 0 && adminCheck.data[0].role !== 'admin') {
                logger.info(`Updating existing user ${adminEmail} to admin role`);
                await db.query('update', 'users', {
                    data: { role: 'admin', updated_at: new Date().toISOString() },
                    where: { email: adminEmail }
                });
                console.log(`✅ Updated ${adminEmail} to admin role`);
            }
        }
    } catch (error) {
        logger.error('Could not create admin user:', error);
    }
}

// ============================================================
// ADD THIS DEBUG ENDPOINT TO CHECK USERS (Development only)
// ============================================================

if (!IS_PRODUCTION) {
    app.get('/api/debug/users', async (req, res) => {
        try {
            const result = await db.query('select', 'users', {
                select: 'id, email, full_name, role, is_active, created_at',
                limit: 10
            });
            
            res.json({
                status: 'success',
                data: result.data,
                count: result.data.length
            });
        } catch (error) {
            res.status(500).json({
                status: 'error',
                message: error.message
            });
        }
    });
    
    app.get('/api/debug/check-admin/:email', async (req, res) => {
        try {
            const email = req.params.email;
            const result = await db.query('select', 'users', {
                where: { email: email.toLowerCase() },
                select: 'id, email, full_name, role, is_active'
            });
            
            if (result.data.length === 0) {
                return res.json({
                    status: 'error',
                    message: 'User not found',
                    email: email
                });
            }
            
            const user = result.data[0];
            const isAdmin = user.role === 'admin';
            
            res.json({
                status: 'success',
                data: user,
                isAdmin: isAdmin,
                canAccessAdmin: isAdmin && user.is_active,
                message: isAdmin ? 'User can access admin panel' : 'User needs role="admin" to access admin panel'
            });
        } catch (error) {
            res.status(500).json({
                status: 'error',
                message: error.message
            });
        }
    });
}

// ============================================================
// FIXED: ADMIN SESSION VERIFICATION
// ============================================================

/**
 * Admin session verification
 */
app.get('/api/admin/session', async (req, res) => {
    try {
        const token = req.cookies?.admin_session;
        
        if (!token) {
            return res.status(401).json({
                status: 'error',
                code: 'NO_SESSION',
                message: 'No active session'
            });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET, {
                issuer: 'nuesa-biu-system',
                audience: 'nuesa-biu-admin'
            });
        } catch (e) {
            return res.status(401).json({
                status: 'error',
                code: 'INVALID_TOKEN',
                message: 'Session expired or invalid'
            });
        }

        // Get user from database
        const result = await db.query('select', 'users', {
            where: { id: decoded.userId },
            select: 'id, email, full_name, role, is_active, last_login'
        });

        if (result.data.length === 0 || !result.data[0].is_active) {
            return res.status(401).json({
                status: 'error',
                code: 'USER_NOT_FOUND',
                message: 'User not found or deactivated'
            });
        }

        const user = result.data[0];
        
        // Check if user has admin role
        if (user.role !== 'admin') {
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_FAILED',
                message: 'Access denied - Admin only'
            });
        }

        const userResponse = {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            lastLogin: user.last_login,
            isActive: user.is_active
        };

        res.json({
            status: 'success',
            data: userResponse,
            message: 'Session is valid'
        });

    } catch (error) {
        logger.error('Session verification error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Session verification failed'
        });
    }
});

// ============================================================
// ADMIN ROUTES
// ============================================================

/**
 * Admin login endpoint
 */
app.post('/api/admin/login', createRateLimiter(10), adminLoginHandler);
app.post('/admin/login', createRateLimiter(5), adminLoginHandler);

/**
 * Admin logout endpoint
 */
app.post('/api/admin/logout', async (req, res) => {
    try {
        const cookieOptions = {
            path: '/'
        };
        
        if (IS_PRODUCTION && process.env.FRONTEND_URL) {
            try {
                const frontendUrl = new URL(process.env.FRONTEND_URL);
                cookieOptions.domain = frontendUrl.hostname;
            } catch (error) {
                logger.warn('Invalid FRONTEND_URL for cookie clearing:', error);
            }
        }
        
        res.clearCookie('admin_session', cookieOptions);

        res.json({
            status: 'success',
            message: 'Logged out successfully'
        });
    } catch (error) {
        logger.error('Admin logout error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Logout failed'
        });
    }
});

/**
 * Admin session verification
 */
app.get('/api/admin/session', async (req, res) => {
    try {
        const token = req.cookies?.admin_session;
        
        if (!token) {
            return res.status(401).json({
                status: 'error',
                code: 'NO_SESSION',
                message: 'No active session'
            });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET, {
                issuer: 'nuesa-biu-system',
                audience: 'nuesa-biu-admin'
            });
        } catch (e) {
            return res.status(401).json({
                status: 'error',
                code: 'INVALID_TOKEN',
                message: 'Session expired or invalid'
            });
        }

        // Get user from database
        const result = await db.query('select', 'users', {
            where: { id: decoded.userId },
            select: 'id, email, full_name, role, is_active, last_login'
        });

        if (result.data.length === 0 || !result.data[0].is_active) {
            return res.status(401).json({
                status: 'error',
                code: 'USER_NOT_FOUND',
                message: 'User not found or deactivated'
            });
        }

        const user = result.data[0];
        
        if (user.role !== 'admin') {
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_FAILED',
                message: 'Invalid credentials'
            });
        }

        const userResponse = {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            lastLogin: user.last_login
        };

        res.json({
            status: 'success',
            data: userResponse,
            message: 'Session is valid'
        });

    } catch (error) {
        logger.error('Session verification error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Session verification failed'
        });
    }
});

/**
 * Admin CSRF token endpoint
 */
app.get('/api/admin/csrf-token', csrfProtection, (req, res) => {
    res.json({
        status: 'success',
        csrfToken: req.csrfToken()
    });
});

// Add this temporary endpoint
app.get('/api/debug/check-admin/:email', async (req, res) => {
    try {
        const email = req.params.email;
        const result = await db.query('select', 'users', {
            where: { email: email.toLowerCase() },
            select: 'id, email, full_name, role, is_active'
        });
        
        if (result.data.length === 0) {
            return res.json({
                status: 'error',
                message: 'User not found',
                email: email
            });
        }
        
        const user = result.data[0];
        res.json({
            status: 'success',
            data: user,
            isAdmin: user.role === 'admin',
            canLogin: user.role === 'admin' && user.is_active
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: error.message
        });
    }
});

// ============================================================
// PUBLIC CONTACT FORM ENDPOINT
// ============================================================

/**
 * @swagger
 * /api/contact/submit:
 *   post:
 *     summary: Submit contact form
 *     tags: [Public]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - message
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               message:
 *                 type: string
 *               subject:
 *                 type: string
 *     responses:
 *       200:
 *         description: Form submitted successfully
 */
app.post('/api/contact/submit', createRateLimiter(10), validate(schemas.contactForm), async (req, res) => {
    try {
        const { name, email, message, subject } = req.body;

        // Here you would typically:
        // 1. Save to database
        // 2. Send email notification
        // 3. Trigger any workflow

        logger.info('Contact form submitted', { 
            requestId: req.id,
            name, 
            email, 
            subject: subject || 'No subject' 
        });

        res.json({
            status: 'success',
            message: 'Thank you for your message! We will get back to you soon.'
        });

    } catch (error) {
        logger.error('Contact form error:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to submit form. Please try again later.'
        });
    }
});

// ============================================================
// USER MANAGEMENT ROUTES
// ============================================================

const userRouter = express.Router();

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all users (admin only)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *       - in: query
 *         name: role
 *         schema:
 *           type: string
 *       - in: query
 *         name: department
 *         schema:
 *           type: string
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of users
 */
userRouter.get('/', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            role,
            department,
            search,
            sort = 'created_at',
            order = 'desc'
        } = req.query;

        const offset = (page - 1) * limit;

        let where = {};
        if (role && role !== 'all') where.role = role;
        if (department && department !== 'all') where.department = department;
        if (search) {
            where = {
                ...where,
                full_name: { operator: 'ilike', value: `%${search}%` }
            };
        }

        const [usersResult, totalResult] = await Promise.all([
            db.query('select', 'users', {
                where,
                select: 'id, email, full_name, role, department, is_active, created_at, updated_at, last_login',
                order: { column: sort, ascending: order === 'asc' },
                limit: parseInt(limit),
                offset: parseInt(offset)
            }),
            db.query('select', 'users', {
                where,
                count: true
            })
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
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch users'
        });
    }
});

/**
 * @swagger
 * /api/users:
 *   post:
 *     summary: Create new user (admin only)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateUser'
 *     responses:
 *       201:
 *         description: User created successfully
 */
userRouter.post('/', verifyToken, requireRole('admin'), validate(schemas.createUser), async (req, res) => {
    try {
        const {
            email,
            password,
            full_name,
            department,
            role = 'member',
            is_active = true
        } = req.body;

        // Check existing user
        const existing = await db.query('select', 'users', {
            where: { email: email.toLowerCase() },
            select: 'id'
        });

        if (existing.data.length > 0) {
            throw new ValidationError('User with this email already exists');
        }

        // Create user
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

        res.status(201).json({
            status: 'success',
            data: user,
            message: 'User created successfully'
        });
    } catch (error) {
        logger.error('Error creating user:', { requestId: req.id, error: error.message });
        
        if (error instanceof ValidationError) {
            return res.status(400).json({
                status: 'error',
                code: 'VALIDATION_ERROR',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to create user'
        });
    }
});

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get user by ID
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User details
 *       403:
 *         description: Access denied
 *       404:
 *         description: User not found
 */
userRouter.get('/:id', verifyToken, async (req, res) => {
    try {
        // Users can view their own profile, admins can view any
        if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
            throw new ForbiddenError('Access denied');
        }

        const result = await db.query('select', 'users', {
            where: { id: req.params.id },
            select: 'id, email, full_name, role, department, is_active, created_at, updated_at, last_login, profile_picture'
        });

        if (result.data.length === 0) {
            throw new NotFoundError('User');
        }

        res.json({
            status: 'success',
            data: authService.createUserResponse(result.data[0])
        });
    } catch (error) {
        logger.error('Error fetching user:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        if (error instanceof ForbiddenError) {
            return res.status(403).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch user'
        });
    }
});

/**
 * @swagger
 * /api/users/{id}:
 *   put:
 *     summary: Update user
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateUser'
 *     responses:
 *       200:
 *         description: User updated successfully
 */
userRouter.put('/:id', verifyToken, validate(schemas.updateUser), async (req, res) => {
    try {
        // Check permissions
        if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
            throw new ForbiddenError('Access denied');
        }

        const {
            full_name,
            department,
            role,
            is_active,
            password
        } = req.body;

        // Admins can update role and status
        const updateData = {
            full_name: full_name ? full_name.trim() : undefined,
            department: department !== undefined ? department : undefined,
            updated_at: new Date()
        };

        if (req.user.role === 'admin') {
            if (role !== undefined) updateData.role = role;
            if (is_active !== undefined) updateData.is_active = is_active;
        }

        if (password) {
            updateData.password_hash = await bcrypt.hash(password, 12);
        }

        const cleanUpdateData = Object.fromEntries(
            Object.entries(updateData).filter(([_, v]) => v !== undefined)
        );

        const result = await db.query('update', 'users', {
            data: cleanUpdateData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            throw new NotFoundError('User');
        }

        // Clear caches
        await cacheManager.delete(`user:${req.params.id}`);
        await cacheManager.invalidate('data:*');

        if (req.user.id === req.params.id) {
            req.user = authService.createUserResponse(result.data[0]);
        }

        logger.info('User updated', { requestId: req.id, userId: req.params.id, updatedBy: req.user.id });

        res.json({
            status: 'success',
            data: authService.createUserResponse(result.data[0]),
            message: 'User updated successfully'
        });
    } catch (error) {
        logger.error('Error updating user:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        if (error instanceof ForbiddenError) {
            return res.status(403).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to update user'
        });
    }
});

/**
 * @swagger
 * /api/users/{id}:
 *   delete:
 *     summary: Delete user (admin only)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User deleted successfully
 */
userRouter.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        if (req.params.id === req.user.id) {
            throw new ValidationError('Cannot delete your own account');
        }

        const result = await db.query('delete', 'users', {
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            throw new NotFoundError('User');
        }

        await cacheManager.delete(`user:${req.params.id}`);
        await cacheManager.invalidate('data:*');

        logger.info('User deleted', { requestId: req.id, userId: req.params.id, deletedBy: req.user.id });

        res.json({
            status: 'success',
            message: 'User deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting user:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        if (error instanceof ValidationError) {
            return res.status(400).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to delete user'
        });
    }
});

app.use('/api/users', userRouter);

// ============================================================
// PROFILE ROUTES
// ============================================================

/**
 * @swagger
 * /api/profile:
 *   get:
 *     summary: Get current user profile
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile
 */
app.get('/api/profile', verifyToken, async (req, res) => {
    res.json({
        status: 'success',
        data: req.user
    });
});

/**
 * @swagger
 * /api/profile:
 *   put:
 *     summary: Update current user profile
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               full_name:
 *                 type: string
 *               department:
 *                 type: string
 *     responses:
 *       200:
 *         description: Profile updated successfully
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

        res.json({
            status: 'success',
            data: updatedUser,
            message: 'Profile updated successfully'
        });
    } catch (error) {
        logger.error('Error updating profile:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to update profile'
        });
    }
});

/**
 * @swagger
 * /api/profile/password:
 *   put:
 *     summary: Change user password
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *                 minLength: 8
 *     responses:
 *       200:
 *         description: Password updated successfully
 */
app.put('/api/profile/password', verifyToken, validate(schemas.changePassword), async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        // Verify current password
        const result = await db.query('select', 'users', {
            where: { id: req.user.id },
            select: 'password_hash'
        });

        const validPassword = await bcrypt.compare(currentPassword, result.data[0].password_hash);
        if (!validPassword) {
            throw new ValidationError('Current password is incorrect');
        }

        // Update password
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        await db.query('update', 'users', {
            data: { password_hash: hashedPassword, updated_at: new Date() },
            where: { id: req.user.id }
        });

        logger.info('Password updated', { requestId: req.id, userId: req.user.id });

        res.json({
            status: 'success',
            message: 'Password updated successfully'
        });
    } catch (error) {
        logger.error('Error updating password:', { requestId: req.id, error: error.message });
        
        if (error instanceof ValidationError) {
            return res.status(400).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to update password'
        });
    }
});

// ============================================================
// EXECUTIVE MEMBERS ROUTES
// ============================================================

const memberRouter = express.Router();

/**
 * @swagger
 * /api/members:
 *   get:
 *     summary: Get all executive members
 *     tags: [Members]
 *     parameters:
 *       - in: query
 *         name: committee
 *         schema:
 *           type: string
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [active, inactive, alumni]
 *       - in: query
 *         name: sort
 *         schema:
 *           type: string
 *       - in: query
 *         name: order
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *     responses:
 *       200:
 *         description: List of members
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
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch members'
        });
    }
});

/**
 * @swagger
 * /api/members/{id}:
 *   get:
 *     summary: Get member by ID
 *     tags: [Members]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Member details
 *       404:
 *         description: Member not found
 */
memberRouter.get('/:id', cacheMiddleware(300, ['members']), async (req, res) => {
    try {
        const result = await db.query('select', 'executive_members', {
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            throw new NotFoundError('Member');
        }

        res.json({
            status: 'success',
            data: result.data[0]
        });
    } catch (error) {
        logger.error('Error fetching member:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch member'
        });
    }
});

/**
 * @swagger
 * /api/members:
 *   post:
 *     summary: Create new member (admin/editor only)
 *     tags: [Members]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - full_name
 *               - position
 *             properties:
 *               full_name:
 *                 type: string
 *               position:
 *                 type: string
 *               department:
 *                 type: string
 *               level:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               bio:
 *                 type: string
 *               committee:
 *                 type: string
 *               display_order:
 *                 type: integer
 *               status:
 *                 type: string
 *                 enum: [active, inactive, alumni]
 *               profile_image:
 *                 type: string
 *                 format: binary
 *     responses:
 *       201:
 *         description: Member created successfully
 */
memberRouter.post('/', verifyToken, requireRole('admin', 'editor'), upload.single('profile_image'), validate(schemas.createMember), async (req, res) => {
    try {
        const {
            full_name, position, department, level, email, phone,
            bio, committee, display_order, status, social_links
        } = req.body;

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

        if (req.file) {
            memberData.profile_image = `/uploads/${req.file.filename}`;
        }

        const result = await db.query('insert', 'executive_members', { data: memberData });

        await cacheManager.invalidateByTags(['members']);

        logger.info('Member created', { requestId: req.id, memberId: result.data[0].id, createdBy: req.user.id });

        res.status(201).json({
            status: 'success',
            data: result.data[0],
            message: 'Member created successfully'
        });
    } catch (error) {
        logger.error('Error creating member:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to create member'
        });
    }
});

/**
 * @swagger
 * /api/members/{id}:
 *   put:
 *     summary: Update member
 *     tags: [Members]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               full_name:
 *                 type: string
 *               position:
 *                 type: string
 *               department:
 *                 type: string
 *               level:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               bio:
 *                 type: string
 *               committee:
 *                 type: string
 *               display_order:
 *                 type: integer
 *               status:
 *                 type: string
 *               profile_image:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: Member updated successfully
 */
memberRouter.put('/:id', verifyToken, requireRole('admin', 'editor'), upload.single('profile_image'), async (req, res) => {
    try {
        const memberData = {};
        const fields = ['full_name', 'position', 'department', 'level', 'email', 'phone', 'bio', 'committee', 'display_order', 'status'];

        fields.forEach(field => {
            if (req.body[field] !== undefined) {
                if (typeof req.body[field] === 'string') {
                    memberData[field] = req.body[field].trim();
                } else {
                    memberData[field] = req.body[field];
                }
            }
        });

        if (req.body.social_links) {
            memberData.social_links = typeof req.body.social_links === 'string' 
                ? JSON.parse(req.body.social_links) 
                : req.body.social_links;
        }

        if (req.file) {
            memberData.profile_image = `/uploads/${req.file.filename}`;
        }

        memberData.updated_at = new Date();

        const result = await db.query('update', 'executive_members', {
            data: memberData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            throw new NotFoundError('Member');
        }

        await cacheManager.invalidateByTags(['members']);

        logger.info('Member updated', { requestId: req.id, memberId: req.params.id, updatedBy: req.user.id });

        res.json({
            status: 'success',
            data: result.data[0],
            message: 'Member updated successfully'
        });
    } catch (error) {
        logger.error('Error updating member:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to update member'
        });
    }
});

/**
 * @swagger
 * /api/members/{id}:
 *   delete:
 *     summary: Delete member (admin/editor only)
 *     tags: [Members]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Member deleted successfully
 */
memberRouter.delete('/:id', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    try {
        const result = await db.query('delete', 'executive_members', {
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            throw new NotFoundError('Member');
        }

        await cacheManager.invalidateByTags(['members']);

        logger.info('Member deleted', { requestId: req.id, memberId: req.params.id, deletedBy: req.user.id });

        res.json({
            status: 'success',
            message: 'Member deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting member:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to delete member'
        });
    }
});

app.use('/api/members', memberRouter);

// ============================================================
// EVENTS ROUTES
// ============================================================

const eventRouter = express.Router();

/**
 * Test route for events router
 */
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
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [upcoming, past, all]
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of events
 */
eventRouter.get('/', cacheMiddleware(120, ['biu_events']), async (req, res) => {
    console.log('📡 [3] GET /api/events called at:', new Date().toISOString());
    console.log('📡 [3a] Query params:', req.query);
    console.log('📡 [3b] Request ID:', req.id);
    
    try {
        const { 
            status = 'upcoming',
            category,
            limit = 50
        } = req.query;

        console.log('📡 [4] Building where clause with:', { status, category, limit });
        
        let where = {};
        
        // Filter by status
        if (status !== 'all') {
            where.status = status;
        }
        
        // Filter by category if provided
        if (category && category !== 'all') {
            where.category = category;
        }

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
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Event details
 *       404:
 *         description: Event not found
 */
eventRouter.get('/:id', cacheMiddleware(300, ['biu_events']), async (req, res) => {
    console.log(`📡 GET /api/events/${req.params.id} called`);
    
    try {
        const result = await db.query('select', 'biu_events', {
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            console.log(`📡 Event with id ${req.params.id} not found`);
            return res.status(404).json({
                status: 'error',
                message: 'Event not found'
            });
        }

        console.log(`📡 Event found:`, result.data[0].title);
        res.json({
            status: 'success',
            data: result.data[0]
        });
    } catch (error) {
        console.error('❌ Error fetching event:', error.message);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch event',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/events/status/upcoming:
 *   get:
 *     summary: Get upcoming events
 *     tags: [Events]
 *     responses:
 *       200:
 *         description: List of upcoming events
 */
eventRouter.get('/status/upcoming', cacheMiddleware(60, ['biu_events']), async (req, res) => {
    console.log('📡 GET /api/events/status/upcoming called');
    
    try {
        const result = await db.query('select', 'biu_events', {
            where: { status: 'upcoming' },
            order: { column: 'date', ascending: true }
        });

        console.log(`📡 Found ${result.data.length} upcoming events`);
        res.json({
            status: 'success',
            data: result.data,
            count: result.data.length
        });
    } catch (error) {
        console.error('❌ Error fetching upcoming events:', error.message);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch upcoming events'
        });
    }
});

/**
 * @swagger
 * /api/events/status/past:
 *   get:
 *     summary: Get past events
 *     tags: [Events]
 *     responses:
 *       200:
 *         description: List of past events
 */
eventRouter.get('/status/past', cacheMiddleware(300, ['biu_events']), async (req, res) => {
    console.log('📡 GET /api/events/status/past called');
    
    try {
        const result = await db.query('select', 'biu_events', {
            where: { status: 'past' },
            order: { column: 'date', ascending: false }
        });

        console.log(`📡 Found ${result.data.length} past events`);
        res.json({
            status: 'success',
            data: result.data,
            count: result.data.length
        });
    } catch (error) {
        console.error('❌ Error fetching past events:', error.message);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch past events'
        });
    }
});

/**
 * @swagger
 * /api/events/category/{category}:
 *   get:
 *     summary: Get events by category
 *     tags: [Events]
 *     parameters:
 *       - in: path
 *         name: category
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of events in category
 */
eventRouter.get('/category/:category', cacheMiddleware(120, ['biu_events']), async (req, res) => {
    console.log(`📡 GET /api/events/category/${req.params.category} called`);
    
    try {
        const result = await db.query('select', 'biu_events', {
            where: { category: req.params.category },
            order: { column: 'date', ascending: true }
        });

        console.log(`📡 Found ${result.data.length} events in category ${req.params.category}`);
        res.json({
            status: 'success',
            data: result.data,
            count: result.data.length
        });
    } catch (error) {
        console.error('❌ Error fetching events by category:', error.message);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch events'
        });
    }
});

/**
 * @swagger
 * /api/events:
 *   post:
 *     summary: Create new event (admin/editor only)
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *               - date
 *             properties:
 *               title:
 *                 type: string
 *               date:
 *                 type: string
 *                 format: date
 *               description:
 *                 type: string
 *               category:
 *                 type: string
 *               start_time:
 *                 type: string
 *               end_time:
 *                 type: string
 *               location:
 *                 type: string
 *               organizer:
 *                 type: string
 *               max_participants:
 *                 type: integer
 *               status:
 *                 type: string
 *                 enum: [upcoming, ongoing, past, cancelled]
 *     responses:
 *       201:
 *         description: Event created successfully
 */
eventRouter.post('/', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    console.log('📡 POST /api/events called');
    console.log('📡 Request body:', req.body);
    
    try {
        const {
            title,
            date,
            description,
            category,
            start_time,
            end_time,
            location,
            organizer,
            max_participants,
            status = 'upcoming'
        } = req.body;

        // Validate required fields
        if (!title || !date) {
            throw new ValidationError('Title and date are required');
        }

        // Parse date from DD/MM/YYYY to ISO format for storage
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

        res.status(201).json({
            status: 'success',
            data: result.data[0],
            message: 'Event created successfully'
        });
    } catch (error) {
        console.error('❌ Error creating event:', error.message);
        
        if (error instanceof ValidationError) {
            return res.status(400).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to create event',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/events/{id}:
 *   put:
 *     summary: Update event (admin/editor only)
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               date:
 *                 type: string
 *               description:
 *                 type: string
 *               category:
 *                 type: string
 *               start_time:
 *                 type: string
 *               end_time:
 *                 type: string
 *               location:
 *                 type: string
 *               organizer:
 *                 type: string
 *               max_participants:
 *                 type: integer
 *               status:
 *                 type: string
 *     responses:
 *       200:
 *         description: Event updated successfully
 */
eventRouter.put('/:id', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    console.log(`📡 PUT /api/events/${req.params.id} called`);
    console.log('📡 Update data:', req.body);
    
    try {
        const allowedFields = [
            'title', 'date', 'description', 'category', 'start_time', 
            'end_time', 'location', 'organizer', 'max_participants', 'status'
        ];
        
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

        if (Object.keys(updateData).length === 0) {
            throw new ValidationError('No fields to update');
        }

        updateData.updated_at = new Date();

        console.log('📡 Executing update on biu_events with:', updateData);

        const result = await db.query('update', 'biu_events', {  
            data: updateData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            console.log(`📡 Event ${req.params.id} not found`);
            return res.status(404).json({
                status: 'error',
                message: 'Event not found'
            });
        }

        console.log('✅ Event updated:', result.data[0].id);

        await cacheManager.invalidateByTags(['biu_events']);

        res.json({
            status: 'success',
            data: result.data[0],
            message: 'Event updated successfully'
        });
    } catch (error) {
        console.error('❌ Error updating event:', error.message);
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        if (error instanceof ValidationError) {
            return res.status(400).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to update event'
        });
    }
});

/**
 * @swagger
 * /api/events/{id}:
 *   delete:
 *     summary: Delete event (admin only)
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Event deleted successfully
 */
eventRouter.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    console.log(`📡 DELETE /api/events/${req.params.id} called`);
    
    try {
        const result = await db.query('delete', 'biu_events', {
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            console.log(`📡 Event ${req.params.id} not found`);
            return res.status(404).json({
                status: 'error',
                message: 'Event not found'
            });
        }

        console.log('✅ Event deleted:', req.params.id);

        await cacheManager.invalidateByTags(['biu_events']);

        res.json({
            status: 'success',
            message: 'Event deleted successfully'
        });
    } catch (error) {
        console.error('❌ Error deleting event:', error.message);
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to delete event'
        });
    }
});

app.use('/api/events', eventRouter);
console.log('✅ [12] /api/events router registered');

// ============================================================
// RESOURCES ROUTES
// ============================================================

const resourceRouter = express.Router();

/**
 * Test route for resources router
 */
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
 *     parameters:
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *       - in: query
 *         name: department
 *         schema:
 *           type: string
 *       - in: query
 *         name: level
 *         schema:
 *           type: integer
 *       - in: query
 *         name: course_code
 *         schema:
 *           type: string
 *       - in: query
 *         name: year
 *         schema:
 *           type: string
 *       - in: query
 *         name: semester
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of resources
 */
resourceRouter.get('/', cacheMiddleware(120, ['resources']), async (req, res) => {
    console.log('📡 [R3] GET /api/resources called at:', new Date().toISOString());
    console.log('📡 [R3a] Query params:', req.query);
    console.log('📡 [R3b] Request ID:', req.id);
    
    try {
        const { 
            category,
            department,
            level,
            course_code,
            year,
            semester,
            limit = 50
        } = req.query;

        console.log('📡 [R4] Building where clause with filters:', { 
            category, department, level, course_code, year, semester, limit 
        });
        
        let where = {};
        
        // Apply filters based on query parameters
        if (category && category !== 'all') {
            where.category = category;
            console.log('📡 [R4a] Filter by category:', category);
        }
        
        if (department && department !== 'all') {
            where.department = department;
            console.log('📡 [R4b] Filter by department:', department);
        }
        
        if (level) {
            where.level = parseInt(level);
            console.log('📡 [R4c] Filter by level:', level);
        }
        
        if (course_code && course_code !== 'all') {
            where.course_code = course_code;
            console.log('📡 [R4d] Filter by course_code:', course_code);
        }
        
        if (year && year !== 'all') {
            where.year = year;
            console.log('📡 [R4e] Filter by year:', year);
        }
        
        if (semester && semester !== 'all') {
            where.semester = semester;
            console.log('📡 [R4f] Filter by semester:', semester);
        }

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

        res.json({
            status: 'success',
            data: result.data,
            count: result.data.length
        });
        
        console.log('✅ [R10] Resources response sent successfully');
        
    } catch (error) {
        console.error('❌ [R-ERROR] Resources API error:', {
            message: error.message,
            code: error.code,
            stack: error.stack,
            name: error.name
        });
        
        // Check for specific database errors
        if (error.message && error.message.includes('relation') && error.message.includes('does not exist')) {
            console.error('❌ [R-DB ERROR] Resources table does not exist!');
            return res.status(500).json({
                status: 'error',
                message: 'Resources table not found in database',
                debug: 'Please create the resources table in Supabase'
            });
        }
        
        logger.error('Error fetching resources:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch resources',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/resources/past-questions:
 *   get:
 *     summary: Get past questions (legacy endpoint)
 *     tags: [Resources]
 *     parameters:
 *       - in: query
 *         name: department
 *         schema:
 *           type: string
 *       - in: query
 *         name: level
 *         schema:
 *           type: integer
 *       - in: query
 *         name: course_code
 *         schema:
 *           type: string
 *       - in: query
 *         name: year
 *         schema:
 *           type: string
 *       - in: query
 *         name: semester
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of past questions
 */
resourceRouter.get('/past-questions', cacheMiddleware(120, ['resources']), async (req, res) => {
    console.log('📡 [R11] GET /api/resources/past-questions called');
    console.log('📡 [R11a] Query params:', req.query);
    
    try {
        const { 
            department,
            level,
            course_code,
            year,
            semester,
            limit = 50
        } = req.query;

        console.log('📡 [R12] Building past questions where clause');
        
        let where = { 
            category: 'past-question'
        };
        
        console.log('📡 [R12a] Base category filter: past-question');
        
        // Apply filters
        if (department && department !== 'all') {
            where.department = department;
            console.log('📡 [R12b] Filter by department:', department);
        }
        
        if (level) {
            where.level = parseInt(level);
            console.log('📡 [R12c] Filter by level:', level);
        }
        
        if (course_code && course_code !== 'all') {
            where.course_code = course_code;
            console.log('📡 [R12d] Filter by course_code:', course_code);
        }
        
        if (year && year !== 'all') {
            where.year = year;
            console.log('📡 [R12e] Filter by year:', year);
        }
        
        if (semester && semester !== 'all') {
            where.semester = semester;
            console.log('📡 [R12f] Filter by semester:', semester);
        }

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

        res.json({
            status: 'success',
            data: result.data,
            count: result.data.length
        });
        
        console.log('✅ [R17] Past questions response sent');
        
    } catch (error) {
        console.error('❌ [R-ERROR] Past questions API error:', error.message);
        logger.error('Error fetching past questions:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch past questions',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/resources/{id}:
 *   get:
 *     summary: Get resource by ID
 *     tags: [Resources]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Resource details
 *       404:
 *         description: Resource not found
 */
resourceRouter.get('/:id', cacheMiddleware(300, ['resources']), async (req, res) => {
    console.log(`📡 [R18] GET /api/resources/${req.params.id} called`);
    
    try {
        console.log('📡 [R19] Querying for resource ID:', req.params.id);
        
        const result = await db.query('select', 'resources', {
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            console.log(`📡 [R20] Resource with id ${req.params.id} not found`);
            return res.status(404).json({
                status: 'error',
                message: 'Resource not found'
            });
        }

        console.log(`📡 [R21] Resource found:`, result.data[0].title);
        res.json({
            status: 'success',
            data: result.data[0]
        });
    } catch (error) {
        console.error('❌ [R-ERROR] Error fetching resource:', error.message);
        logger.error('Error fetching resource:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch resource',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/resources:
 *   post:
 *     summary: Create new resource (admin/editor only)
 *     tags: [Resources]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *               - category
 *             properties:
 *               title:
 *                 type: string
 *               category:
 *                 type: string
 *               description:
 *                 type: string
 *               department:
 *                 type: string
 *               level:
 *                 type: integer
 *               course_code:
 *                 type: string
 *               course_title:
 *                 type: string
 *               year:
 *                 type: string
 *               semester:
 *                 type: string
 *               file:
 *                 type: string
 *                 format: binary
 *     responses:
 *       201:
 *         description: Resource created successfully
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
        const {
            title,
            category,
            description,
            department,
            level,
            course_code,
            course_title,
            year,
            semester,
            file_type,
            file_size
        } = req.body;

        // Validate required fields
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

        // If file was uploaded
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

        logger.info('Resource created', { 
            requestId: req.id, 
            resourceId: result.data[0].id, 
            createdBy: req.user.id 
        });

        res.status(201).json({
            status: 'success',
            data: result.data[0],
            message: 'Resource created successfully'
        });
    } catch (error) {
        console.error('❌ [R-ERROR] Error creating resource:', error.message);
        logger.error('Error creating resource:', { requestId: req.id, error: error.message });
        
        if (error instanceof ValidationError) {
            return res.status(400).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to create resource',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/resources/{id}:
 *   put:
 *     summary: Update resource (admin/editor only)
 *     tags: [Resources]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               category:
 *                 type: string
 *               description:
 *                 type: string
 *               department:
 *                 type: string
 *               level:
 *                 type: integer
 *               course_code:
 *                 type: string
 *               course_title:
 *                 type: string
 *               year:
 *                 type: string
 *               semester:
 *                 type: string
 *               file_url:
 *                 type: string
 *     responses:
 *       200:
 *         description: Resource updated successfully
 */
resourceRouter.put('/:id', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    console.log(`📡 [R28] PUT /api/resources/${req.params.id} called`);
    console.log('📡 [R28a] Update data:', req.body);
    
    try {
        const allowedFields = [
            'title', 'category', 'description', 'department', 'level',
            'course_code', 'course_title', 'year', 'semester', 
            'file_type', 'file_size', 'file_url'
        ];
        
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
            return res.status(404).json({
                status: 'error',
                message: 'Resource not found'
            });
        }

        console.log('✅ [R33] Resource updated:', result.data[0].id);

        await cacheManager.invalidateByTags(['resources']);

        logger.info('Resource updated', { 
            requestId: req.id, 
            resourceId: req.params.id, 
            updatedBy: req.user.id 
        });

        res.json({
            status: 'success',
            data: result.data[0],
            message: 'Resource updated successfully'
        });
    } catch (error) {
        console.error('❌ [R-ERROR] Error updating resource:', error.message);
        logger.error('Error updating resource:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        if (error instanceof ValidationError) {
            return res.status(400).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to update resource',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/resources/{id}:
 *   delete:
 *     summary: Delete resource (admin only)
 *     tags: [Resources]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Resource deleted successfully
 */
resourceRouter.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    console.log(`📡 [R34] DELETE /api/resources/${req.params.id} called`);
    
    try {
        console.log('📡 [R35] Deleting resource:', req.params.id);
        
        const result = await db.query('delete', 'resources', {
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            console.log(`📡 [R36] Resource ${req.params.id} not found`);
            return res.status(404).json({
                status: 'error',
                message: 'Resource not found'
            });
        }

        console.log('✅ [R37] Resource deleted:', req.params.id);

        await cacheManager.invalidateByTags(['resources']);

        logger.info('Resource deleted', { 
            requestId: req.id, 
            resourceId: req.params.id, 
            deletedBy: req.user.id 
        });

        res.json({
            status: 'success',
            message: 'Resource deleted successfully'
        });
    } catch (error) {
        console.error('❌ [R-ERROR] Error deleting resource:', error.message);
        logger.error('Error deleting resource:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to delete resource',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/resources/{id}/download:
 *   post:
 *     summary: Increment download count for resource
 *     tags: [Resources]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Download count updated
 */
resourceRouter.post('/:id/download', async (req, res) => {
    console.log(`📡 [R38] POST /api/resources/${req.params.id}/download called`);
    
    try {
        console.log('📡 [R39] Getting current download count for resource:', req.params.id);
        
        // First get current download count
        const getResult = await db.query('select', 'resources', {
            where: { id: req.params.id },
            select: 'download_count'
        });

        if (getResult.data.length === 0) {
            console.log(`📡 [R40] Resource ${req.params.id} not found`);
            return res.status(404).json({
                status: 'error',
                message: 'Resource not found'
            });
        }

        const currentCount = getResult.data[0].download_count || 0;
        console.log(`📡 [R41] Current download count: ${currentCount}`);
        
        // Update download count
        const newCount = currentCount + 1;
        console.log(`📡 [R42] Updating to: ${newCount}`);
        
        await db.query('update', 'resources', {
            data: { 
                download_count: newCount,
                updated_at: new Date()
            },
            where: { id: req.params.id }
        });

        console.log('✅ [R43] Download count updated');

        res.json({
            status: 'success',
            data: { download_count: newCount },
            message: 'Download count updated'
        });
    } catch (error) {
        console.error('❌ [R-ERROR] Error updating download count:', error.message);
        logger.error('Error updating download count:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to update download count',
            debug: error.message
        });
    }
});

/**
 * @swagger
 * /api/resources/meta/categories:
 *   get:
 *     summary: Get unique resource categories
 *     tags: [Resources]
 *     responses:
 *       200:
 *         description: List of categories
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
        
        res.json({
            status: 'success',
            data: categories
        });
    } catch (error) {
        console.error('❌ [R-ERROR] Error fetching categories:', error.message);
        logger.error('Error fetching categories:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch categories'
        });
    }
});

/**
 * @swagger
 * /api/resources/meta/departments:
 *   get:
 *     summary: Get unique resource departments
 *     tags: [Resources]
 *     responses:
 *       200:
 *         description: List of departments
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
        
        res.json({
            status: 'success',
            data: departments
        });
    } catch (error) {
        console.error('❌ [R-ERROR] Error fetching departments:', error.message);
        logger.error('Error fetching departments:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch departments'
        });
    }
});

/**
 * @swagger
 * /api/resources/meta/courses:
 *   get:
 *     summary: Get unique course codes with titles
 *     tags: [Resources]
 *     parameters:
 *       - in: query
 *         name: department
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of courses
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
        
        res.json({
            status: 'success',
            data: result.data
        });
    } catch (error) {
        console.error('❌ [R-ERROR] Error fetching courses:', error.message);
        logger.error('Error fetching courses:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch courses'
        });
    }
});

app.use('/api/resources', resourceRouter);
console.log('✅ [R52] /api/resources router registered');

// ============================================================
// ARTICLES/NEWS ROUTES
// ============================================================

const articleRouter = express.Router();

/**
 * @swagger
 * /api/articles:
 *   get:
 *     summary: Get all published articles
 *     tags: [Articles]
 *     parameters:
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *       - in: query
 *         name: tag
 *         schema:
 *           type: string
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *       - in: query
 *         name: sort
 *         schema:
 *           type: string
 *       - in: query
 *         name: order
 *         schema:
 *           type: string
 *           enum: [asc, desc]
 *     responses:
 *       200:
 *         description: List of articles
 */
articleRouter.get('/', cacheMiddleware(120, ['articles']), async (req, res) => {
    try {
        const { 
            category,
            tag,
            limit = 50,
            page = 1,
            sort = 'published_at',
            order = 'desc'
        } = req.query;

        const offset = (page - 1) * limit;
        
        let where = { 
            status: 'published',
            is_published: true 
        };
        
        if (category && category !== 'all') {
            where.category = category;
        }
        
        if (tag) {
            where.tags = { operator: 'contains', value: [tag] };
        }

        const [articles, totalCount] = await Promise.all([
            db.query('select', 'articles', {
                where,
                order: { column: sort, ascending: order === 'asc' },
                limit: parseInt(limit),
                offset: parseInt(offset)
            }),
            db.query('select', 'articles', {
                where,
                count: true
            })
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
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch articles'
        });
    }
});

/**
 * @swagger
 * /api/articles/{identifier}:
 *   get:
 *     summary: Get article by ID or slug
 *     tags: [Articles]
 *     parameters:
 *       - in: path
 *         name: identifier
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Article details
 *       404:
 *         description: Article not found
 */
articleRouter.get('/:identifier', cacheMiddleware(300, ['articles']), async (req, res) => {
    try {
        const { identifier } = req.params;
        
        // Check if identifier is UUID or slug
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identifier);
        
        let where = { status: 'published', is_published: true };
        if (isUUID) {
            where.uuid = identifier;
        } else {
            where.slug = identifier;
        }

        const result = await db.query('select', 'articles', { where });

        if (result.data.length === 0) {
            throw new NotFoundError('Article');
        }

        res.json({
            status: 'success',
            data: result.data[0]
        });
    } catch (error) {
        logger.error('Error fetching article:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch article'
        });
    }
});

/**
 * @swagger
 * /api/articles/category/{category}:
 *   get:
 *     summary: Get articles by category
 *     tags: [Articles]
 *     parameters:
 *       - in: path
 *         name: category
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of articles in category
 */
articleRouter.get('/category/:category', cacheMiddleware(120, ['articles']), async (req, res) => {
    try {
        const result = await db.query('select', 'articles', {
            where: { 
                category: req.params.category,
                status: 'published',
                is_published: true
            },
            order: { column: 'published_at', ascending: false }
        });

        res.json({
            status: 'success',
            data: result.data,
            count: result.data.length
        });
    } catch (error) {
        logger.error('Error fetching articles by category:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch articles'
        });
    }
});

/**
 * @swagger
 * /api/articles:
 *   post:
 *     summary: Create new article (admin/editor only)
 *     tags: [Articles]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Article'
 *     responses:
 *       201:
 *         description: Article created successfully
 */
articleRouter.post('/', verifyToken, requireRole('admin', 'editor'), validate(schemas.article), async (req, res) => {
    try {
        const {
            title, slug, content, excerpt, author,
            category, tags, status, is_published, published_at
        } = req.body;

        // Generate slug if not provided
        let articleSlug = slug;
        if (!articleSlug) {
            articleSlug = title
                .toLowerCase()
                .replace(/[^\w\s-]/g, '')
                .replace(/\s+/g, '-')
                .replace(/--+/g, '-')
                .trim();
        }

        // Check if slug exists
        const existing = await db.query('select', 'articles', {
            where: { slug: articleSlug }
        });

        if (existing.data.length > 0) {
            articleSlug = `${articleSlug}-${Date.now()}`;
        }

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

        logger.info('Article created', { 
            requestId: req.id, 
            articleId: result.data[0].uuid, 
            createdBy: req.user.id 
        });

        res.status(201).json({
            status: 'success',
            data: result.data[0],
            message: 'Article created successfully'
        });
    } catch (error) {
        logger.error('Error creating article:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to create article'
        });
    }
});

/**
 * @swagger
 * /api/articles/{uuid}:
 *   put:
 *     summary: Update article (admin/editor only)
 *     tags: [Articles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: uuid
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Article'
 *     responses:
 *       200:
 *         description: Article updated successfully
 */
articleRouter.put('/:uuid', verifyToken, requireRole('admin', 'editor'), async (req, res) => {
    try {
        const allowedFields = [
            'title', 'slug', 'content', 'excerpt', 'author',
            'category', 'tags', 'status', 'is_published', 'published_at'
        ];
        
        const updateData = {};
        allowedFields.forEach(field => {
            if (req.body[field] !== undefined) {
                updateData[field] = req.body[field];
            }
        });

        if (Object.keys(updateData).length === 0) {
            throw new ValidationError('No fields to update');
        }

        updateData.updated_at = new Date();

        const result = await db.query('update', 'articles', {
            data: updateData,
            where: { uuid: req.params.uuid }
        });

        if (result.data.length === 0) {
            throw new NotFoundError('Article');
        }

        await cacheManager.invalidateByTags(['articles']);

        logger.info('Article updated', { 
            requestId: req.id, 
            articleId: req.params.uuid, 
            updatedBy: req.user.id 
        });

        res.json({
            status: 'success',
            data: result.data[0],
            message: 'Article updated successfully'
        });
    } catch (error) {
        logger.error('Error updating article:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to update article'
        });
    }
});

/**
 * @swagger
 * /api/articles/{uuid}:
 *   delete:
 *     summary: Delete article (admin only)
 *     tags: [Articles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: uuid
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Article deleted successfully
 */
articleRouter.delete('/:uuid', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const result = await db.query('delete', 'articles', {
            where: { uuid: req.params.uuid }
        });

        if (result.data.length === 0) {
            throw new NotFoundError('Article');
        }

        await cacheManager.invalidateByTags(['articles']);

        logger.info('Article deleted', { 
            requestId: req.id, 
            articleId: req.params.uuid, 
            deletedBy: req.user.id 
        });

        res.json({
            status: 'success',
            message: 'Article deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting article:', { requestId: req.id, error: error.message });
        
        if (error instanceof NotFoundError) {
            return res.status(404).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to delete article'
        });
    }
});

/**
 * @swagger
 * /api/articles/meta/categories:
 *   get:
 *     summary: Get unique article categories
 *     tags: [Articles]
 *     responses:
 *       200:
 *         description: List of categories
 */
articleRouter.get('/meta/categories', async (req, res) => {
    try {
        const result = await db.query('select', 'articles', {
            select: 'DISTINCT category',
            where: { 
                category: { operator: 'isNull', value: false },
                status: 'published',
                is_published: true
            }
        });
        
        const categories = result.data.map(item => item.category).filter(Boolean);
        
        res.json({
            status: 'success',
            data: categories
        });
    } catch (error) {
        logger.error('Error fetching categories:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch categories'
        });
    }
});

/**
 * @swagger
 * /api/articles/meta/tags:
 *   get:
 *     summary: Get unique article tags
 *     tags: [Articles]
 *     responses:
 *       200:
 *         description: List of tags
 */
articleRouter.get('/meta/tags', async (req, res) => {
    try {
        const result = await db.query('select', 'articles', {
            select: 'tags',
            where: { 
                tags: { operator: 'isNull', value: false },
                status: 'published',
                is_published: true
            }
        });
        
        // Flatten and deduplicate tags
        const allTags = result.data
            .flatMap(item => item.tags || [])
            .filter(Boolean);
        
        const uniqueTags = [...new Set(allTags)];
        
        res.json({
            status: 'success',
            data: uniqueTags
        });
    } catch (error) {
        logger.error('Error fetching tags:', { requestId: req.id, error: error.message });
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch tags'
        });
    }
});

app.use('/api/articles', articleRouter);
app.use('/api/news', articleRouter); // Alias for backward compatibility
console.log('✅ Articles/News router registered at /api/articles and /api/news');

// ============================================================
// FILE MANAGEMENT ROUTES
// ============================================================

/**
 * @swagger
 * /api/upload:
 *   post:
 *     summary: Upload a file (admin/editor only)
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: File uploaded successfully
 */
app.post('/api/upload', verifyToken, requireRole('admin', 'editor'), upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            throw new ValidationError('No file uploaded');
        }

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

        logger.info('File uploaded', { 
            requestId: req.id, 
            filename: req.file.filename,
            size: req.file.size,
            uploadedBy: req.user.id 
        });

        res.json({
            status: 'success',
            data: fileInfo,
            message: 'File uploaded successfully'
        });
    } catch (error) {
        logger.error('Error uploading file:', { requestId: req.id, error: error.message });
        
        if (error instanceof ValidationError) {
            return res.status(400).json({
                status: 'error',
                message: error.message
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to upload file'
        });
    }
});

/**
 * @swagger
 * /api/upload/{filename}:
 *   delete:
 *     summary: Delete a file (admin only)
 *     tags: [Files]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: filename
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: File deleted successfully
 */
app.delete('/api/upload/:filename', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const filePath = path.join(__dirname, 'uploads', req.params.filename);

        await fs.access(filePath);
        await fs.unlink(filePath);

        logger.info('File deleted', { requestId: req.id, filename: req.params.filename, deletedBy: req.user.id });

        res.json({
            status: 'success',
            message: 'File deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting file:', { requestId: req.id, error: error.message });
        
        if (error.code === 'ENOENT') {
            return res.status(404).json({
                status: 'error',
                message: 'File not found'
            });
        }
        
        res.status(500).json({
            status: 'error',
            message: 'Failed to delete file'
        });
    }
});

// ============================================================
// STATIC FILES SERVING
// ============================================================

/**
 * Serve uploaded files with proper headers
 */
app.use('/uploads', compression(), express.static(path.join(__dirname, 'uploads'), {
    maxAge: IS_PRODUCTION ? '30d' : '0',
    setHeaders: (res, filePath) => {
        const ext = path.extname(filePath).toLowerCase();
        const mimeType = mime.lookup(ext) || 'application/octet-stream';

        // Security headers for files
        if (ext.match(/\.(jpg|jpeg|png|gif|webp|svg)$/)) {
            res.setHeader('Content-Disposition', 'inline');
        } else {
            res.setHeader('Content-Disposition', 'attachment');
        }

        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Content-Type', mimeType);

        // Cache control
        if (ext.match(/\.(jpg|jpeg|png|gif|webp|svg)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
        } else if (ext.match(/\.(pdf|docx|xlsx|pptx)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }
    }
}));

// ============================================================
// PUBLIC PAGES ROUTING
// ============================================================

const adminDir = path.join(__dirname, 'admin');
const publicDir = path.join(__dirname, 'public');
const adminExists = fsSync.existsSync(adminDir);
const publicExists = fsSync.existsSync(publicDir);

// Block direct access to any resources admin sub-path unless user is admin
app.all('/resources/admin*', (req, res, next) => {
    if (!req.isAdmin) {
        return res.status(404).send('Not found');
    }
    next();
});

// Serve static public files first
if (publicExists) {
    app.use(express.static(publicDir, {
        maxAge: '1d',
        setHeaders: (res, filePath) => {
            res.setHeader('X-Content-Type-Options', 'nosniff');
            if (filePath.endsWith('.html')) {
                res.setHeader('Cache-Control', 'public, max-age=3600');
            }
        }
    }));
    
    // Define explicit public routes
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
}

// ============================================================
// ADMIN INTERFACE ROUTING - FIXED
// ============================================================

if (adminExists) {
    console.log('✅ Admin folder found at:', adminDir);
    console.log('📄 Files in admin folder:', fsSync.readdirSync(adminDir));

    // 1. ADMIN LOGIN PAGE (GET)
    app.get('/admin/login', async (req, res) => {
        try {
            console.log('🔐 Serving admin login page');
            
            // If already admin, redirect to dashboard
            if (req.isAdmin) {
                return res.redirect('/admin/dashboard');
            }
            
            const loginPath = path.join(__dirname, 'admin', 'adlog.html');
            
            if (!fsSync.existsSync(loginPath)) {
                console.error('❌ Login file missing at:', loginPath);
                return res.status(500).send('Admin login page not found');
            }
            
            let loginHtml = await fs.readFile(loginPath, 'utf8');
            
            // Inject basic config
            const configScript = `
                <script>
                    window.API_BASE_URL = '${req.protocol}://${req.get('host')}';
                    console.log('✅ Admin login page loaded');
                </script>
            `;
            
            loginHtml = loginHtml.replace('</head>', configScript + '</head>');
            res.send(loginHtml);
            
        } catch (error) {
            console.error('❌ Error serving login page:', error);
            res.status(500).send('Error loading admin login page');
        }
    });

    // 2. ADMIN DASHBOARD (GET)
    app.get('/admin/dashboard', async (req, res) => {
        try {
            if (!req.isAdmin) {
                return res.redirect('/admin/login');
            }
            
            const dashPath = path.join(__dirname, 'admin', 'dash.html');
            
            if (!fsSync.existsSync(dashPath)) {
                return res.status(500).send('Dashboard not found');
            }
            
            let dashHtml = await fs.readFile(dashPath, 'utf8');
            
            const userData = {
                id: req.admin?.id,
                email: req.admin?.email,
                fullName: req.admin?.full_name || 'Admin',
                role: req.admin?.role
            };
            
            const configScript = `
                <script>
                    window.ADMIN_USER = ${JSON.stringify(userData)};
                    window.API_BASE_URL = '${req.protocol}://${req.get('host')}';
                </script>
            `;
            
            dashHtml = dashHtml.replace('</head>', configScript + '</head>');
            res.send(dashHtml);
            
        } catch (error) {
            console.error('Dashboard error:', error);
            res.status(500).send('Error loading dashboard');
        }
    });

    // 3. ADMIN LOGOUT (GET)
    app.get('/admin/logout', (req, res) => {
        res.clearCookie('admin_session', { path: '/' });
        res.clearCookie('auth_token', { path: '/' });
        res.redirect('/admin/login');
    });

    // 4. ADMIN STATUS CHECK (GET)
    app.get('/admin/status', (req, res) => {
        res.json({
            isAdmin: req.isAdmin || false,
            user: req.admin || null
        });
    });

    // 5. ADMIN ASSETS (GET)
    app.get('/admin/assets/:filename', (req, res) => {
        try {
            const { filename } = req.params;
            
            // Security: Only allow specific file types
            if (!filename.match(/\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf)$/i)) {
                return res.status(403).send('File type not allowed');
            }
            
            const filePath = path.join(adminDir, filename);
            
            if (fsSync.existsSync(filePath)) {
                res.sendFile(filePath);
            } else {
                res.status(404).send('File not found');
            }
        } catch (error) {
            res.status(500).send('Error serving asset');
        }
    });

    console.log('✅ Admin routes configured:');
    console.log('   • GET  /admin/login     - Login page');
    console.log('   • GET  /admin/dashboard  - Dashboard');
    console.log('   • GET  /admin/logout     - Logout');
    console.log('   • GET  /admin/status     - Status check');
    console.log('   • POST /api/admin/login  - Login API (already defined above)');

    // Add this debug code to your server.js or admin routes file
    console.log('Admin Email Check:', process.env.ADMIN_EMAIL);
    console.log('Admin Password Set:', process.env.ADMIN_PASSWORD ? 'Yes' : 'No');
    console.log('JWT Secret Set:', process.env.JWT_SECRET ? 'Yes' : 'No');
    
} else {
    console.log('⚠️ Admin folder not found at:', adminDir);
    console.log('⚠️ Please ensure admin folder contains: adlog.html and dash.html');
}

// ============================================================
// SWAGGER API DOCUMENTATION
// ============================================================

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'NUESA BIU API',
            version: '1.0.0',
            description: 'API documentation for NUESA BIU application',
            contact: {
                name: 'NUESA BIU',
                email: process.env.ADMIN_EMAIL
            }
        },
        servers: [
            {
                url: IS_PRODUCTION ? 'https://nuesa-biu-pjp0.onrender.com' : `http://localhost:${PORT}`,
                description: IS_PRODUCTION ? 'Production server' : 'Development server'
            }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ['./server.js'], // Path to the API docs
};

const swaggerSpecs = swaggerJsdoc(swaggerOptions);
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs));

// ============================================================
// SYSTEM ENDPOINTS
// ============================================================

/**
 * Helper function to format bytes to human-readable format
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Check database health
 */
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

/**
 * Check cache health
 */
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

/**
 * Check disk space
 */
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

/**
 * Check memory usage
 */
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

/**
 * Helper functions for metrics (simplified)
 */
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
 *     responses:
 *       200:
 *         description: Server health status
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
        res.status(200).json({ // Always return 200 for health checks
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
 *     responses:
 *       200:
 *         description: Returns pong
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
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System metrics
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
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch metrics'
        });
    }
});

/**
 * @swagger
 * /api/stats:
 *   get:
 *     summary: Get basic statistics (admin only)
 *     tags: [System]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System statistics
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
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch statistics'
        });
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
            admin: '/api/admin',
            users: '/api/users',
            members: '/api/members',
            events: '/api/events',
            resources: '/api/resources',
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
// DEBUG ENDPOINTS (Development Only)
// ============================================================

if (!IS_PRODUCTION) {
    /**
     * Debug: Show environment variables (masked)
     */
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

    /**
     * Debug: Test database connection
     */
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

    /**
     * Debug: Check admin paths
     */
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
        if (exists.adminDir) {
            files.adminDir = fsSync.readdirSync(paths.adminDir);
        }
        if (exists.adminDirCwd) {
            files.adminDirCwd = fsSync.readdirSync(paths.adminDirCwd);
        }
        
        res.json({ paths, exists, files });
    });

    /**
     * Debug: Simple test endpoint
     */
    app.get('/api/debug/test', (req, res) => {
        res.json({ 
            message: 'Debug endpoint working',
            timestamp: new Date().toISOString(),
            requestId: req.id 
        });
    });
}

// ============================================================
// 404 HANDLER
// ============================================================

app.use((req, res) => {
    // For API routes, return JSON
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({
            status: 'error',
            code: 'ROUTE_NOT_FOUND',
            message: `Route ${req.method} ${req.url} not found`,
            timestamp: new Date().toISOString(),
            requestId: req.id
        });
    }
    
    // For HTML routes, serve 404 page if exists, otherwise return JSON
    const notFoundPage = path.join(publicDir, '404.html');
    if (publicExists && fsSync.existsSync(notFoundPage)) {
        res.status(404).sendFile(notFoundPage);
    } else {
        res.status(404).json({
            status: 'error',
            message: 'Page not found',
            requestId: req.id
        });
    }
});

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

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

    // Multer errors
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

    // Database errors
    if (err instanceof DatabaseError) {
        return res.status(400).json({
            status: 'error',
            code: 'DATABASE_ERROR',
            message: `Database error: ${err.message}`,
            requestId: req.id
        });
    }

    // Authentication errors
    if (err instanceof AuthError) {
        return res.status(err.statusCode || 401).json({
            status: 'error',
            code: err.code,
            message: err.message,
            requestId: req.id
        });
    }

    // Validation errors
    if (err instanceof ValidationError) {
        return res.status(400).json({
            status: 'error',
            code: 'VALIDATION_ERROR',
            message: err.message,
            errors: err.errors,
            requestId: req.id
        });
    }

    // Not found errors
    if (err instanceof NotFoundError) {
        return res.status(404).json({
            status: 'error',
            code: 'NOT_FOUND',
            message: err.message,
            requestId: req.id
        });
    }

    // Forbidden errors
    if (err instanceof ForbiddenError) {
        return res.status(403).json({
            status: 'error',
            code: 'FORBIDDEN',
            message: err.message,
            requestId: req.id
        });
    }

    // Default error response
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
// PROCESS EVENT HANDLERS
// ============================================================

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', {
        reason: reason.message || reason,
        stack: reason.stack,
        promise: promise
    });

    if (IS_PRODUCTION) {
        logger.error('Unhandled rejection in production, continuing...');
    }
});

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', {
        error: error.message,
        stack: error.stack
    });

    if (IS_PRODUCTION) {
        setTimeout(() => {
            process.exit(1);
        }, 1000);
    }
});

/**
 * Graceful shutdown on SIGTERM
 */
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, starting graceful shutdown');
    setTimeout(() => {
        process.exit(0);
    }, 1000);
});

/**
 * Graceful shutdown on SIGINT
 */
process.on('SIGINT', () => {
    logger.info('SIGINT received, starting graceful shutdown');
    setTimeout(() => {
        process.exit(0);
    }, 1000);
});

// ============================================================
// SERVER STARTUP
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
║ 🔗 API URL: http://localhost:${PORT}                            ║
║ 🌐 Frontend: ${process.env.FRONTEND_URL || 'Not set'}           ║
║ 🔒 JWT: ${JWT_SECRET ? 'Set ✓' : 'Missing ✗'}                  ║
║ 👑 Admin: ${process.env.ADMIN_EMAIL || 'Not configured'}        ║
║ 📚 API Docs: http://localhost:${PORT}/api/docs                  ║
║ 🔐 Admin Panel: /admin/login                                     ║
║ 🎭 Dashboard: /admin/dashboard (after login)                     ║
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