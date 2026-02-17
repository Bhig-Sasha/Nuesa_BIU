require('dotenv').config();

// ==================== IMPORTS ====================
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

// ==================== ENVIRONMENT VALIDATION ====================
const requiredEnvVars = [
    'JWT_SECRET',
    'SUPABASE_URL',
    'SUPABASE_SERVICE_ROLE_KEY'
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
    console.error('❌ ERROR: Missing required environment variables:', missingEnvVars.join(', '));
    process.exit(1);
}

// ==================== CONFIGURATION ====================
const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const isProduction = NODE_ENV === 'production';

// Security Configuration
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';

// ==================== REDIS SETUP (Optional) ====================
let redis = null;
if (process.env.REDIS_URL) {
    try {
        redis = new Redis(process.env.REDIS_URL, {
            maxRetriesPerRequest: 3,
            retryStrategy: (times) => Math.min(times * 50, 2000)
        });
        console.log('✅ Redis connected successfully');
    } catch (error) {
        console.warn('⚠️ Redis connection failed, using in-memory cache:', error.message);
    }
}

// ==================== SUPABASE SETUP ====================
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

// ==================== CUSTOM ERROR CLASSES ====================
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

// ==================== ENHANCED QUERY HELPER ====================
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

// ==================== ENHANCED LOGGING SETUP ====================
const logDir = 'logs';
if (!fsSync.existsSync(logDir)) {
    fsSync.mkdirSync(logDir, { recursive: true });
}

const logger = winston.createLogger({
    level: isProduction ? 'info' : 'debug',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'nuesa-biu-api', environment: NODE_ENV },
    transports: [
        new winston.transports.File({
            filename: `${logDir}/error.log`,
            level: 'error',
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 10,
            tailable: true
        }),
        new winston.transports.File({
            filename: `${logDir}/combined.log`,
            maxsize: 20 * 1024 * 1024, // 20MB
            maxFiles: 10,
            tailable: true
        }),
        new winston.transports.File({
            filename: `${logDir}/audit.log`,
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
if (!isProduction) {
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

// ==================== ENHANCED CACHE SYSTEM WITH REDIS ====================
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

    async get(key, options = {}) {
        if (this.redis) {
            const value = await this.redis.get(key);
            if (value) {
                return JSON.parse(value);
            }
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
        if (this.redis) {
            stats.redis = { connected: true };
        }
        return stats;
    }
}

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

const cacheManager = new CacheManager();
const userCache = cacheManager.getCache('users', { maxSize: 200, ttl: 300000 });
const dataCache = cacheManager.getCache('data', { maxSize: 100, ttl: 60000 });

// ==================== REQUEST ID MIDDLEWARE ====================
app.use((req, res, next) => {
    req.id = uuid.v4();
    res.setHeader('X-Request-ID', req.id);
    next();
});

// ==================== SECURITY HEADERS MIDDLEWARE ====================
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});

// ==================== ENHANCED MIDDLEWARE ====================
app.set('trust proxy', 1);

// Compression
app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

// Security headers with enhanced CSP
    const cspDirectives = {
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
        cspDirectives.connectSrc.push(supabaseUrl);
    }

    if (process.env.FRONTEND_URL) {
        cspDirectives.connectSrc.push(process.env.FRONTEND_URL);
    }

    // Add Supabase wildcard
    cspDirectives.connectSrc.push("https://*.supabase.co");

    // Handle upgrade insecure requests properly
    if (isProduction) {
        cspDirectives.upgradeInsecureRequests = [];
    }

    app.use(helmet({
        contentSecurityPolicy: {
            directives: cspDirectives,
            reportOnly: false
        },
        crossOriginEmbedderPolicy: false,
        crossOriginResourcePolicy: { policy: "cross-origin" }
    }));

// CSRF Protection (except for API routes)
const csrfProtection = csrf({ cookie: true });
app.use('/portal', csrfProtection);

// XSS protection
app.use(xss());

// Parameter pollution protection
app.use(hpp({
    whitelist: ['page', 'limit', 'sort', 'fields']
}));

// Enhanced CORS configuration
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(origin => origin.trim())
    .filter(origin => origin.length > 0);

if (process.env.FRONTEND_URL && !allowedOrigins.includes(process.env.FRONTEND_URL)) {
    allowedOrigins.push(process.env.FRONTEND_URL);
}

allowedOrigins.push('https://nuesa-biu.vercel.app');
allowedOrigins.push('https://www.nuesa-biu.vercel.app');
allowedOrigins.push('https://adminbiunuesa.vercel.app');

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) {
            return callback(null, true);
        }

        if (!isProduction) {
            return callback(null, true);
        }

        if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            logger.warn(`Blocked by CORS: ${origin}`, { allowedOrigins });
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

// Cookie parser middleware
app.use(cookieParser());

// Enhanced request parsing
app.use(express.json({
    limit: process.env.MAX_REQUEST_SIZE || '10mb',
    verify: (req, res, buf, encoding) => {
        req.rawBody = buf;
    }
}));

app.use(express.urlencoded({
    extended: true,
    limit: process.env.MAX_REQUEST_SIZE || '10mb',
    parameterLimit: 100
}));

// Enhanced request logging
const morganFormat = isProduction ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
    stream: {
        write: (message) => logger.http(message.trim())
    },
    skip: (req, res) => req.path === '/api/health' && req.method === 'GET'
}));

// Request timeout
app.use(timeout('30s'));
app.use(haltOnTimedout);

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

// Enhanced rate limiting with configurable limits
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

// Apply rate limiting
app.use('/api/auth/login', createRateLimiter(10, 15 * 60 * 1000, 'Too many login attempts'));
app.use('/api/admin/login', createRateLimiter(5, 15 * 60 * 1000, 'Too many admin login attempts'));
app.use('/api/contact/submit', createRateLimiter(10, 15 * 60 * 1000, 'Too many contact form submissions'));
app.use('/api/', createRateLimiter(200, 15 * 60 * 1000));

// Cache middleware with Redis support
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

// Response time middleware
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

// ==================== ACCOUNT LOCKOUT SYSTEM ====================
const loginAttempts = new Map();

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

async function resetLoginAttempts(identifier) {
    loginAttempts.delete(identifier);
}

// ==================== ENHANCED FILE UPLOAD ====================
const uploadDirs = {
    images: './uploads/images',
    resources: './uploads/resources',
    profiles: './uploads/profiles',
    temp: './uploads/temp'
};

// Create upload directories
Object.values(uploadDirs).forEach(dir => {
    if (!fsSync.existsSync(dir)) {
        fsSync.mkdirSync(dir, { recursive: true });
        logger.info(`Created upload directory: ${dir}`);
    }
});

// Enhanced storage configuration
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

            const destDir = path.join(uploadDirs[subDir], new Date().toISOString().split('T')[0]);
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

// File filter with enhanced validation
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
    limits: {
        fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB
        files: 5
    },
    fileFilter: fileFilter
});

// ==================== VALIDATION SCHEMAS ====================
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
    })
};

// Validation middleware
const validate = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            throw new ValidationError('Validation failed', error.details);
        }
        next();
    };
};

// ==================== ENHANCED AUTHENTICATION ====================
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
                issuer: 'nuesa-biu-api',
                audience: 'nuesa-biu-client'
            });
        } catch (error) {
            throw new AuthError('Invalid token', error.name);
        }
    }

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

// ==================== ENHANCED ADMIN AUTH MIDDLEWARE ====================
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
                    secure: isProduction,  // Must be true in production
                    sameSite: 'none',      // ✅ Critical change for cross-domain
                    maxAge: 8 * 60 * 60 * 1000,
                    path: '/'
                };
                
                if (isProduction && process.env.FRONTEND_URL) {
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

// Middleware for regular authentication
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

// ==================== DATABASE INITIALIZATION ====================
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
    // Note: Tables should be created via Supabase migrations
    // This is just for logging
    logger.info('Checking database tables...');
}

// ==================== ENHANCED AUTH ROUTES ====================
const authRouter = express.Router();

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
            secure: isProduction,
            sameSite: 'strict',
            maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
            path: '/',
            domain: isProduction ? new URL(process.env.FRONTEND_URL || '').hostname : undefined
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

authRouter.get('/verify', verifyToken, async (req, res) => {
    res.json({
        status: 'success',
        data: req.user,
        message: 'Token is valid'
    });
});

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

// ==================== ADMIN AUTH ROUTES ====================
async function adminLoginHandler(req, res) {
    const requestId = req.id;
    console.log(`[${requestId}] Admin login attempt started`);
    
    try {
        const { email, password, rememberMe } = req.body;
        console.log(`[${requestId}] Login attempt for email:`, email);

        // Validate input
        const { error } = schemas.login.validate({ email, password });
        if (error) {
            throw new ValidationError('Validation failed', error.details);
        }

        // Check login attempts
        await checkLoginAttempts(email.toLowerCase());

        // Get user from database
        console.log(`[${requestId}] Querying database for user...`);
        const result = await db.query('select', 'users', {
            where: { email: email.toLowerCase().trim() },
            select: 'id, email, full_name, role, department, is_active, password_hash, created_at, last_login'
        });

        if (result.data.length === 0) {
            await recordFailedAttempt(email.toLowerCase());
            throw new AuthError('Invalid credentials');
        }

        const user = result.data[0];

        // Check if account is active
        if (!user.is_active) {
            throw new AuthError('Account is deactivated', 'ACCOUNT_DEACTIVATED');
        }

        // Check if user has admin role
        if (user.role !== 'admin') {
            await recordFailedAttempt(email.toLowerCase());
            throw new AuthError('Invalid credentials');
        }

        // Verify password
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

        // Create token payload
        const tokenPayload = {
            userId: user.id,
            email: user.email,
            role: user.role,
            fullName: user.full_name,
            sessionType: 'admin_panel',
            loginTime: Date.now(),
            jti: uuid.v4()
        };

        // Generate admin session token
        const token = jwt.sign(tokenPayload, JWT_SECRET, {
            expiresIn: '8h',
            issuer: 'nuesa-biu-system',
            audience: 'nuesa-biu-admin'
        });

        // Set cookie
        let cookieDomain;
        if (isProduction && process.env.FRONTEND_URL) {
            try {
                const frontendUrl = new URL(process.env.FRONTEND_URL);
                cookieDomain = frontendUrl.hostname;
            } catch (error) {
                logger.error('Invalid FRONTEND_URL:', error);
            }
        }

        const cookieOptions = {
            httpOnly: true,
            secure: isProduction,  // Must be true in production
            sameSite: 'none',      // ✅ CRITICAL: Allows cross-domain cookies
            maxAge: 8 * 60 * 60 * 1000,
            path: '/'
        };

        if (cookieDomain) {
            cookieOptions.domain = cookieDomain;
        }

        res.cookie('admin_session', token, cookieOptions);

        // Return success
        const userResponse = {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            department: user.department,
            lastLogin: user.last_login
        };

        logger.info('Admin login successful', { userId: user.id, requestId });
        res.json({
            status: 'success',
            data: {
                user: userResponse,
                token: token,
                expiresIn: '8h'
            },
            message: 'Login successful'
        });

    } catch (error) {
        console.error(`[${requestId}] Admin login error:`, error.message);
        
        // Log the error
        logger.error('Admin login error', {
            requestId,
            error: error.message,
            code: error.code,
            name: error.name
        });
        
        // Send appropriate error response
        const statusCode = error.statusCode || 500;
        const errorResponse = {
            status: 'error',
            code: error.code || 'INTERNAL_ERROR',
            message: error.message || 'Authentication failed'
        };
        
        if (!isProduction && error.stack) {
            errorResponse.stack = error.stack;
        }
        
        res.status(statusCode).json(errorResponse);
    }
}

// Register admin routes
app.post('/api/admin/login', createRateLimiter(5), adminLoginHandler);
app.post('/admin/login', createRateLimiter(5), adminLoginHandler);

// Admin logout endpoint
app.post('/api/admin/logout', async (req, res) => {
    try {
        const cookieOptions = {
            path: '/'
        };
        
        if (isProduction && process.env.FRONTEND_URL) {
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

// Admin session verification
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

// ==================== REGULAR CONTACT FORM ENDPOINT ====================
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

// ==================== ENHANCED USER MANAGEMENT ====================
const userRouter = express.Router();

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

// ==================== PROFILE ROUTES ====================
app.get('/api/profile', verifyToken, async (req, res) => {
    res.json({
        status: 'success',
        data: req.user
    });
});

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

// ==================== ENHANCED MEMBERS ROUTES ====================
const memberRouter = express.Router();

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

// ==================== EVENTS ROUTES (UPDATED TO USE biu_events TABLE) ====================
console.log('🔧 [1] Starting to define eventRouter...');
const eventRouter = express.Router();
console.log('✅ [2] eventRouter created successfully');

// Test route to verify router is working
eventRouter.get('/test', (req, res) => {
    console.log('📡 [TEST] Test route hit at:', new Date().toISOString());
    res.json({ 
        message: 'Event router test route works',
        timestamp: new Date().toISOString(),
        requestId: req.id 
    });
});

// GET all events (public) - FIXED: changed from 'events' to 'biu_events'
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

        const result = await db.query('select', 'biu_events', {  // ← FIXED: 'biu_events' instead of 'events'
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

// GET single event by ID - FIXED: changed from 'events' to 'biu_events'
eventRouter.get('/:id', cacheMiddleware(300, ['biu_events']), async (req, res) => {
    console.log(`📡 GET /api/events/${req.params.id} called`);
    
    try {
        const result = await db.query('select', 'biu_events', {  // ← FIXED: 'biu_events' instead of 'events'
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

// Get upcoming events (status = 'upcoming') - FIXED: changed from 'events' to 'biu_events'
eventRouter.get('/status/upcoming', cacheMiddleware(60, ['biu_events']), async (req, res) => {
    console.log('📡 GET /api/events/status/upcoming called');
    
    try {
        const result = await db.query('select', 'biu_events', {  // ← FIXED: 'biu_events' instead of 'events'
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

// Get past events (status = 'past') - FIXED: changed from 'events' to 'biu_events'
eventRouter.get('/status/past', cacheMiddleware(300, ['biu_events']), async (req, res) => {
    console.log('📡 GET /api/events/status/past called');
    
    try {
        const result = await db.query('select', 'biu_events', {  // ← FIXED: 'biu_events' instead of 'events'
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

// Get events by category - FIXED: changed from 'events' to 'biu_events'
eventRouter.get('/category/:category', cacheMiddleware(120, ['biu_events']), async (req, res) => {
    console.log(`📡 GET /api/events/category/${req.params.category} called`);
    
    try {
        const result = await db.query('select', 'biu_events', {  // ← FIXED: 'biu_events' instead of 'events'
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

// CREATE event (admin/editor only) - FIXED: changed from 'events' to 'biu_events'
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

        const result = await db.query('insert', 'biu_events', { data: eventData });  // ← FIXED: 'biu_events' instead of 'events'

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

// UPDATE event - FIXED: changed from 'events' to 'biu_events'
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

        const result = await db.query('update', 'biu_events', {  // ← FIXED: 'biu_events' instead of 'events'
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

// DELETE event - FIXED: changed from 'events' to 'biu_events'
eventRouter.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    console.log(`📡 DELETE /api/events/${req.params.id} called`);
    
    try {
        const result = await db.query('delete', 'biu_events', {  // ← FIXED: 'biu_events' instead of 'events'
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

// ==================== REGISTER THE ROUTER ====================
console.log('🔧 [11] Attempting to register /api/events router...');
console.log('🔧 [11a] Current time:', new Date().toISOString());
console.log('🔧 [11b] Is eventRouter defined?', eventRouter ? 'Yes' : 'No');
console.log('🔧 [11c] eventRouter type:', typeof eventRouter);

// Register the events router
try {
    app.use('/api/events', eventRouter);
    console.log('✅ [12] SUCCESS! /api/events router registered');
    
    // Verify the router was registered
    const registeredRoutes = app._router?.stack
        .filter(layer => layer.route || layer.name === 'router')
        .map(layer => {
            if (layer.route) {
                return `${Object.keys(layer.route.methods).join(',')} ${layer.route.path}`;
            }
            if (layer.name === 'router' && layer.regexp) {
                return `Router: ${layer.regexp}`;
            }
            return null;
        })
        .filter(Boolean);
    
    console.log('🔧 [13] Currently registered routes:', registeredRoutes);
    
} catch (error) {
    console.error('❌ [ERROR] Failed to register /api/events router:', error.message);
}

// Improved health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        // Try to query the database
        const dbStatus = await db.query('select', 'biu_events', { limit: 1 })
            .then(() => ({ status: 'healthy' }))
            .catch(err => ({ status: 'unhealthy', error: err.message }));

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

// ==================== RESOURCES ROUTES ====================
console.log('🔧 [R1] Starting to define resourceRouter...');
const resourceRouter = express.Router();
console.log('✅ [R2] resourceRouter created successfully');

// Test route to verify router is working
resourceRouter.get('/test', (req, res) => {
    console.log('📡 [TEST] Resources test route hit at:', new Date().toISOString());
    res.json({ 
        message: 'Resources router test route works',
        timestamp: new Date().toISOString(),
        requestId: req.id 
    });
});

// GET all resources (public)
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
        
        console.log('📡 [R9] Response structure:', {
            status: 'success',
            dataCount: result.data.length,
            hasData: result.data.length > 0
        });

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

// GET resources by category (for backward compatibility with your frontend)
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

// GET single resource by ID
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

// CREATE resource (admin/editor only)
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

// UPDATE resource
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

// DELETE resource
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

// Increment download count
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

// Get unique categories for filtering
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

// Get unique departments for filtering
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

// Get unique course codes for filtering
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

// ==================== REGISTER THE ROUTER ====================
console.log('🔧 [R51] Attempting to register /api/resources router...');
console.log('🔧 [R51a] Current time:', new Date().toISOString());
console.log('🔧 [R51b] Is resourceRouter defined?', resourceRouter ? 'Yes' : 'No');
console.log('🔧 [R51c] resourceRouter type:', typeof resourceRouter);

// Register the resources router
try {
    app.use('/api/resources', resourceRouter);
    console.log('✅ [R52] SUCCESS! /api/resources router registered');
    
    // Log all registered routes for verification
    const registeredRoutes = app._router?.stack
        .filter(layer => layer.route || layer.name === 'router')
        .map(layer => {
            if (layer.route) {
                return `${Object.keys(layer.route.methods).join(',')} ${layer.route.path}`;
            }
            if (layer.name === 'router' && layer.regexp) {
                return `Router: ${layer.regexp}`;
            }
            return null;
        })
        .filter(Boolean);
    
    console.log('🔧 [R53] Currently registered routes:', registeredRoutes);
    
} catch (error) {
    console.error('❌ [R-ERROR] Failed to register /api/resources router:', error.message);
}

console.log('🔧 [R54] Resources router setup complete');

// ==================== ARTICLES/NEWS ROUTES ====================
console.log('🔧 [A1] Setting up articles/news routes...');
const articleRouter = express.Router();

// Validation schema for articles
const articleSchema = Joi.object({
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
});

// GET all published articles (public)
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

// GET single article by slug or id (public)
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

// GET articles by category (public)
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

// CREATE article (admin/editor only)
articleRouter.post('/', verifyToken, requireRole('admin', 'editor'), validate(articleSchema), async (req, res) => {
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

// UPDATE article
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

// DELETE article
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

// GET meta data for filtering
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

// Register the articles router
try {
    app.use('/api/articles', articleRouter);
    app.use('/api/news', articleRouter); // Also support /api/news endpoint
    console.log('✅ Articles/News router registered at /api/articles and /api/news');
} catch (error) {
    console.error('❌ Failed to register articles router:', error.message);
}

// ==================== FILE MANAGEMENT ROUTES ====================
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

// ==================== PUBLIC PAGES ROUTING ====================
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

// ==================== HIDDEN ADMIN ROUTING ====================
if (adminExists) {
    console.log('✅ Admin folder found. Setting up hidden admin routes...');
    
    // CSRF token endpoint for admin forms
    app.get('/api/csrf-token', csrfProtection, (req, res) => {
        res.json({
            status: 'success',
            csrfToken: req.csrfToken()
        });
    });
    
    // 1. DISGUISED ADMIN PORTAL
    app.get('/portal/system', csrfProtection, async (req, res) => {
        try {
            if (!req.isAdmin) {
                return res.status(404).send('Not found');
            }
            
            // Serve dashboard HTML file
            const dashPath = path.join(adminDir, 'dash.html');
            if (fsSync.existsSync(dashPath)) {
                // Read and inject user data
                let dashHtml = await fs.readFile(dashPath, 'utf8');
                
                const userData = {
                    id: req.admin?.id,
                    email: req.admin?.email,
                    fullName: req.admin?.full_name || req.admin?.email?.split('@')[0] || 'Admin',
                    role: req.admin?.role || 'admin'
                };
                
                dashHtml = dashHtml.replace(
                    '</head>',
                    `<script>
                        window.ADMIN_USER = ${JSON.stringify(userData)};
                        window.API_BASE_URL = '${req.protocol}://${req.get('host')}';
                        window.CSRF_TOKEN = '${req.csrfToken()}';
                    </script>
                    </head>`
                );
                
                res.send(dashHtml);
            } else {
                res.status(404).send('Dashboard not found');
            }
        } catch (error) {
            res.status(500).send('Server error');
        }
    });
    
    // 2. HIDDEN ADMIN LOGIN PAGE - NO FALLBACK
    app.get('/portal/login', csrfProtection, async (req, res) => {
        try {
            if (req.isAdmin) {
                return res.redirect('/portal/system');
            }
            
            // Serve login HTML file
            const loginPath = path.join(adminDir, 'adlog.html');
            if (fsSync.existsSync(loginPath)) {
                let loginHtml = await fs.readFile(loginPath, 'utf8');
                
                loginHtml = loginHtml.replace(
                    '</head>',
                    `<script>
                        window.CSRF_TOKEN = '${req.csrfToken()}';
                    </script>
                    </head>`
                );
                
                res.send(loginHtml);
            } else {
                res.status(404).send('Login page not found');
            }
        } catch (error) {
            res.status(500).send('Server error');
        }
    });
    
    // 3. ADMIN LOGOUT
    app.get('/portal/logout', (req, res) => {
        // Clear admin cookies
        const cookieOptions = {
            path: '/'
        };
        
        if (isProduction && process.env.FRONTEND_URL) {
            try {
                const frontendUrl = new URL(process.env.FRONTEND_URL);
                cookieOptions.domain = frontendUrl.hostname;
            } catch (error) {
                console.warn('Invalid FRONTEND_URL for cookie clearing:', error);
            }
        }
        
        res.clearCookie('admin_session', cookieOptions);
        res.clearCookie('admin_token', cookieOptions);
        res.clearCookie('auth_token', cookieOptions);
        
        // Redirect to home page
        res.redirect('/');
    });
    
    // 4. SERVE ADMIN ASSETS
    app.get('/assets/:folder/:file', (req, res) => {
        try {
            const { folder, file } = req.params;
            
            // Only serve if admin
            if (!req.isAdmin) {
                return res.status(404).send('Not found');
            }
            
            // Sanitize and validate path
            const filePath = path.join(adminDir, folder, file);
            const resolvedPath = path.resolve(filePath);
            const resolvedAdminDir = path.resolve(adminDir);
            
            // Ensure resolved path is within admin directory
            if (!resolvedPath.startsWith(resolvedAdminDir + path.sep)) {
                return res.status(403).send('Access denied');
            }
            
            if (fsSync.existsSync(resolvedPath)) {
                res.sendFile(resolvedPath);
            } else {
                res.status(404).send('File not found');
            }
        } catch (error) {
            res.status(500).send('Server error');
        }
    });
    
    // 5. BLOCK DIRECT ACCESS TO ADMIN FOLDER
    app.all('/admin/*', (req, res) => {
        res.status(404).send('Not found');
    });
    
    console.log('✅ Hidden admin system activated:');
    console.log('   • Admin login: /portal/login');
    console.log('   • Admin dashboard: /portal/system');
    console.log('   • Admin logout: /portal/logout');
    console.log('   • Admin assets: /assets/*');
    console.log('   • Direct /admin/* routes are blocked');
    
} else {
    console.log('⚠️ Admin folder not found at:', adminDir);
    console.log('⚠️ Please ensure admin folder contains: adlog.html and dash.html');
}

// ==================== SWAGGER API DOCUMENTATION ====================
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
                url: isProduction ? 'https://nuesa-biu-pjp0.onrender.com' : `http://localhost:${PORT}`,
                description: isProduction ? 'Production server' : 'Development server'
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

// ==================== SYSTEM ENDPOINTS ====================
// Enhanced health check
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

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

app.get('/api/ping', (req, res) => {
    res.json({
        status: 'success',
        message: 'pong',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        requestId: req.id
    });
});

// Metrics endpoint
app.get('/api/metrics', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        // Get request stats from logs (simplified)
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

// Helper functions for metrics 
async function getRequestCount() {
    // In production, you'd query this from your logs or a database
    return 0;
}

async function getEndpointStats() {
    return {};
}

async function getStatusStats() {
    return {};
}

async function getAvgResponseTime() {
    return '0ms';
}

async function getP95ResponseTime() {
    return '0ms';
}

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

// Debug endpoints (only in development)
if (!isProduction) {
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
}

// ==================== STATIC FILES ====================
app.use('/uploads', compression(), express.static(path.join(__dirname, 'uploads'), {
    maxAge: isProduction ? '30d' : '0',
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

// ==================== ROOT ENDPOINTS ====================
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

// ==================== 404 HANDLER ====================
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

// ==================== ERROR HANDLER ====================
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
                message: `File size too large. Maximum size is ${process.env.MAX_FILE_SIZE || '10MB'}.`,
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
    const message = isProduction ? 'Internal server error' : err.message;
    const statusCode = err.statusCode || 500;

    res.status(statusCode).json({
        status: 'error',
        code: 'INTERNAL_ERROR',
        message: message,
        ...(!isProduction && { stack: err.stack, details: err.message }),
        requestId: req.id
    });
});

// ==================== PROCESS EVENT HANDLERS ====================
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', {
        reason: reason.message || reason,
        stack: reason.stack,
        promise: promise
    });

    if (isProduction) {
        logger.error('Unhandled rejection in production, continuing...');
    }
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', {
        error: error.message,
        stack: error.stack
    });

    if (isProduction) {
        setTimeout(() => {
            process.exit(1);
        }, 1000);
    }
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, starting graceful shutdown');
    
    // Close database connections
    // Close server
    setTimeout(() => {
        process.exit(0);
    }, 1000);
});

process.on('SIGINT', () => {
    logger.info('SIGINT received, starting graceful shutdown');
    
    // Close database connections
    // Close server
    setTimeout(() => {
        process.exit(0);
    }, 1000);
});

// ==================== SERVER STARTUP ====================
async function startServer() {
    try {
        await initializeDatabase();

        app.listen(PORT, '0.0.0.0', () => {
            console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║     🚀 NUESA BIU API Server Started Successfully!               ║
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
║ 🔐 Admin Panel: /portal/login                                   ║
║ 🎭 Dashboard: /portal/system (after login)                      ║
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