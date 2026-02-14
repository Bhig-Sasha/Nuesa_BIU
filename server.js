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
const crypto = require('crypto'); // Added for obfuscation

// ==================== CONFIGURATION ====================
const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const isProduction = NODE_ENV === 'production';

// Security Configuration
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';

if (!JWT_SECRET) {
    console.error('❌ ERROR: JWT_SECRET is required in environment variables');
    process.exit(1);
}

// ==================== SUPABASE SETUP ====================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ ERROR: SUPABASE_URL and SUPABASE_KEY are required');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false
    },
    db: {
        schema: 'public'
    },
    global: {
        headers: {
            'x-application-name': 'nuesa-biu-api',
            'x-version': '1.0.0'
        }
    }
});

// ==================== ENHANCED QUERY HELPER ====================
class DatabaseService {
    constructor(supabase) {
        this.supabase = supabase;
    }

    async query(operation, table, options = {}) {
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

            // Apply filters
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

            if (result.error) {
                throw new DatabaseError(result.error.message, result.error.code, table, operation);
            }

            return {
                data: result.data || [],
                count: result.count,
                status: 'success'
            };
        } catch (error) {
            console.error(`Database ${operation} error on table ${table}:`, error);
            throw error;
        }
    }
}

class DatabaseError extends Error {
    constructor(message, code, table, operation) {
        super(message);
        this.name = 'DatabaseError';
        this.code = code;
        this.table = table;
        this.operation = operation;
        this.timestamp = new Date();
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

// ==================== ENHANCED CACHE SYSTEM ====================
class CacheManager {
    constructor() {
        this.caches = new Map();
    }

    getCache(name, options = {}) {
        if (!this.caches.has(name)) {
            this.caches.set(name, new LRUCache(options.maxSize || 100, options.ttl || 300000));
        }
        return this.caches.get(name);
    }

    clearAll() {
        this.caches.forEach(cache => cache.clear());
    }

    invalidate(pattern) {
        this.caches.forEach((cache, cacheName) => {
            if (cacheName.match(pattern)) {
                cache.clear();
            }
        });
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
        // Check size and remove oldest if needed
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

        // Update access time
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
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: ["'self'", supabaseUrl, process.env.FRONTEND_URL || '', "https://*.supabase.co"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            upgradeInsecureRequests: isProduction ? [] : null
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

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

// Add your Vercel frontend URL
if (process.env.FRONTEND_URL && !allowedOrigins.includes(process.env.FRONTEND_URL)) {
    allowedOrigins.push(process.env.FRONTEND_URL);
}

// ALSO add the specific Vercel URL directly:
allowedOrigins.push('https://nuesa-biu.vercel.app');
allowedOrigins.push('https://www.nuesa-biu.vercel.app');

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, postman)
        if (!origin) {
            return callback(null, true);
        }

        // In development, allow all origins
        if (!isProduction) {
            return callback(null, true);
        }

        // In production, check against allowed origins
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
        'X-Page-Count'
    ],
    exposedHeaders: [
        'X-Total-Count',
        'X-Page-Count',
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset'
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

// Enhanced rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: (req) => {
        // Allow more requests for authenticated users
        return req.headers.authorization ? 200 : 100;
    },
    message: {
        status: 'error',
        code: 'TOO_MANY_REQUESTS',
        message: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        return req.headers['x-forwarded-for'] || req.ip;
    },
    handler: (req, res) => {
        logger.warn('Rate limit exceeded', {
            ip: req.ip,
            url: req.url,
            method: req.method
        });
        res.status(429).json({
            status: 'error',
            code: 'TOO_MANY_REQUESTS',
            message: 'Too many requests from this IP, please try again later.'
        });
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    skipSuccessfulRequests: false,
    message: {
        status: 'error',
        code: 'TOO_MANY_LOGIN_ATTEMPTS',
        message: 'Too many login attempts, please try again later.'
    }
});

// Rate limiter for contact form submissions to prevent abuse
const contactFormLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    skipSuccessfulRequests: false,
    message: {
        status: 'error',
        code: 'TOO_MANY_CONTACT_REQUESTS',
        message: 'Too many contact form submissions, please try again later.'
    }
});

// Apply rate limiting
app.use('/api/auth/login', authLimiter);
app.use('/api/admin/login', authLimiter);
app.use('/api/', apiLimiter);

// Cache middleware
const cacheMiddleware = (duration = 60) => {
    return (req, res, next) => {
        if (req.method !== 'GET' || req.headers.authorization) {
            return next();
        }

        const key = req.originalUrl || req.url;
        const cachedResponse = dataCache.get(key);

        if (cachedResponse) {
            return res.json(cachedResponse);
        }

        const originalSend = res.json;
        res.json = function (body) {
            if (res.statusCode >= 200 && res.statusCode < 300) {
                dataCache.set(key, body, duration * 1000);
            }
            originalSend.call(this, body);
        };

        next();
    };
};

// Response time middleware
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info('Request completed', {
            method: req.method,
            url: req.url,
            status: res.statusCode,
            duration: `${duration}ms`,
            userId: req.user?.id
        });
    });
    next();
});

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
            audience: 'nuesa-biu-client'
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
            const result = await db.query('select', 'users', {
                where: { email: email.toLowerCase().trim() },
                select: 'id, email, password_hash, full_name, role, department, is_active, created_at, last_login'
            });

            if (result.data.length === 0) {
                throw new AuthError('Invalid credentials');
            }

            const user = result.data[0];

            if (!user.is_active) {
                throw new AuthError('Account is deactivated');
            }

            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                throw new AuthError('Invalid credentials');
            }

            // Update last login
            await db.query('update', 'users', {
                data: { last_login: new Date() },
                where: { id: user.id }
            });

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

class AuthError extends Error {
    constructor(message, code = 'AUTH_ERROR') {
        super(message);
        this.name = 'AuthError';
        this.code = code;
        this.statusCode = 401;
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
        const cachedUser = userCache.get(cacheKey);

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

        userCache.set(cacheKey, user, 300000);
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

        logger.error('Authentication error:', error);
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
            return res.status(401).json({
                status: 'error',
                message: 'Authentication required'
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                status: 'error',
                code: 'INSUFFICIENT_PERMISSIONS',
                message: `Required roles: ${roles.join(', ')}`
            });
        }

        next();
    };
};

const requirePermission = (permission) => {
    const permissions = {
        admin: ['manage_users', 'manage_content', 'manage_settings'],
        editor: ['manage_content'],
        member: ['view_content']
    };

    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                status: 'error',
                message: 'Authentication required'
            });
        }

        const userPermissions = permissions[req.user.role] || [];
        if (!userPermissions.includes(permission)) {
            return res.status(403).json({
                status: 'error',
                code: 'INSUFFICIENT_PERMISSIONS',
                message: `Required permission: ${permission}`
            });
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
    const tables = [
        {
            name: 'users',
            columns: [
                'id UUID PRIMARY KEY DEFAULT gen_random_uuid()',
                'email VARCHAR(255) UNIQUE NOT NULL',
                'password_hash VARCHAR(255) NOT NULL',
                'full_name VARCHAR(255) NOT NULL',
                'username VARCHAR(100) UNIQUE',
                'role VARCHAR(50) DEFAULT \'member\'',
                'department VARCHAR(100)',
                'is_active BOOLEAN DEFAULT true',
                'profile_picture VARCHAR(500)',
                'last_login TIMESTAMPTZ',
                'created_at TIMESTAMPTZ DEFAULT NOW()',
                'updated_at TIMESTAMPTZ DEFAULT NOW()'
            ]
        },
        {
            name: 'executive_members',
            columns: [
                'id UUID PRIMARY KEY DEFAULT gen_random_uuid()',
                'full_name VARCHAR(255) NOT NULL',
                'position VARCHAR(100) NOT NULL',
                'department VARCHAR(100)',
                'level VARCHAR(50)',
                'email VARCHAR(255)',
                'phone VARCHAR(50)',
                'bio TEXT',
                'committee VARCHAR(100)',
                'display_order INTEGER DEFAULT 0',
                'status VARCHAR(50) DEFAULT \'active\'',
                'social_links JSONB DEFAULT \'{}\'',
                'profile_image VARCHAR(500)',
                'created_at TIMESTAMPTZ DEFAULT NOW()',
                'updated_at TIMESTAMPTZ DEFAULT NOW()'
            ]
        }
    ];

    for (const table of tables) {
        try {
            // Note: In Supabase, tables are created via SQL or Dashboard
            // This is just a placeholder for schema validation
            logger.info(`Checking table: ${table.name}`);
        } catch (error) {
            logger.warn(`Table ${table.name} may not exist: ${error.message}`);
        }
    }
}

// ==================== ENHANCED AUTH ROUTES ====================
const authRouter = express.Router();

authRouter.post('/login', async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                status: 'error',
                code: 'VALIDATION_ERROR',
                message: 'Email and password are required'
            });
        }

        const user = await authService.authenticateUser(email, password);
        const tokenPayload = authService.createTokenPayload(user);
        const token = authService.generateToken(tokenPayload);

        userCache.set(`user:${user.id}`, user, rememberMe ? 604800000 : 300000); // 7 days or 5 minutes

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
        userCache.delete(`user:${req.user.id}`);
        dataCache.clear();

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

// Password reset endpoints
authRouter.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                status: 'error',
                message: 'Email is required'
            });
        }

        // In production, send reset email
        // For now, just return success
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

// Mount auth router
app.use('/api/auth', authRouter);

// ==================== ADMIN AUTH ROUTES ====================
// ==================== ADMIN AUTH ROUTES ====================
// Reusable admin login handler
async function adminLoginHandler(req, res) {
    const requestId = Date.now() + '-' + Math.random().toString(36).substring(7);
    console.log(`[${requestId}] Admin login attempt started`);
    
    try {
        const { email, password, rememberMe } = req.body;
        console.log(`[${requestId}] Login attempt for email:`, email);

        if (!email || !password) {
            console.log(`[${requestId}] Missing email or password`);
            return res.status(400).json({
                status: 'error',
                code: 'VALIDATION_ERROR',
                message: 'Email and password are required'
            });
        }

        // Get user from database
        console.log(`[${requestId}] Querying database for user...`);
        const result = await db.query('select', 'users', {
            where: { email: email.toLowerCase().trim() },
            select: 'id, email, full_name, role, department, is_active, password_hash, created_at, last_login'
        });
        console.log(`[${requestId}] Database query complete. Found:`, result.data.length > 0 ? 'Yes' : 'No');

        if (result.data.length === 0) {
            console.log(`[${requestId}] User not found`);
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_FAILED',
                message: 'Invalid credentials'
            });
        }

        const user = result.data[0];
        console.log(`[${requestId}] User found:`, { 
            id: user.id, 
            email: user.email, 
            role: user.role,
            is_active: user.is_active 
        });

        // Check if account is active
        if (!user.is_active) {
            console.log(`[${requestId}] Account is deactivated`);
            return res.status(401).json({
                status: 'error',
                code: 'ACCOUNT_DEACTIVATED',
                message: 'Account is deactivated'
            });
        }

        // Check if user has admin role
        if (user.role !== 'admin') {
            console.log(`[${requestId}] User is not admin. Role:`, user.role);
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_FAILED',
                message: 'Invalid credentials'
            });
        }

        // Verify password
        console.log(`[${requestId}] Verifying password...`);
        console.log(`[${requestId}] Stored hash:`, user.password_hash.substring(0, 20) + '...');
        
        let validPassword = false;
        try {
            validPassword = await bcrypt.compare(password, user.password_hash);
            console.log(`[${requestId}] Password verification result:`, validPassword);
        } catch (bcryptError) {
            console.error(`[${requestId}] Bcrypt error:`, bcryptError);
            throw bcryptError;
        }
        
        if (!validPassword) {
            console.log(`[${requestId}] Invalid password`);
            return res.status(401).json({
                status: 'error',
                code: 'AUTH_FAILED',
                message: 'Invalid credentials'
            });
        }

        // Update last login
        console.log(`[${requestId}] Updating last login...`);
        await db.query('update', 'users', {
            data: { last_login: new Date() },
            where: { id: user.id }
        });
        console.log(`[${requestId}] Last login updated`);

        // Create token payload
        const tokenPayload = {
            userId: user.id,
            email: user.email,
            role: user.role,
            fullName: user.full_name,
            sessionType: 'admin_panel',
            loginTime: Date.now()
        };
        console.log(`[${requestId}] Token payload created`);

        // Generate admin session token
        console.log(`[${requestId}] Generating JWT...`);
        let token;
        try {
            token = jwt.sign(tokenPayload, JWT_SECRET, {
                expiresIn: '8h',
                issuer: 'nuesa-biu-system',
                audience: 'nuesa-biu-admin'
            });
            console.log(`[${requestId}] JWT generated successfully`);
        } catch (jwtError) {
            console.error(`[${requestId}] JWT generation error:`, jwtError);
            throw jwtError;
        }

        // Set cookie
        console.log(`[${requestId}] Setting cookie...`);
        try {
            let cookieDomain;
            if (isProduction && process.env.FRONTEND_URL) {
                try {
                    const frontendUrl = new URL(process.env.FRONTEND_URL);
                    cookieDomain = frontendUrl.hostname;
                    console.log(`[${requestId}] Cookie domain:`, cookieDomain);
                } catch (error) {
                    console.error(`[${requestId}] Invalid FRONTEND_URL:`, error);
                    cookieDomain = undefined;
                }
            }

            const cookieOptions = {
                httpOnly: true,
                secure: isProduction,
                sameSite: 'strict',
                maxAge: 8 * 60 * 60 * 1000,
                path: '/'
            };

            if (cookieDomain) {
                cookieOptions.domain = cookieDomain;
            }

            res.cookie('admin_session', token, cookieOptions);
            console.log(`[${requestId}] Cookie set successfully`);
        } catch (cookieError) {
            console.error(`[${requestId}] Cookie error:`, cookieError);
            throw cookieError;
        }

        // Return success
        const userResponse = {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            department: user.department,
            lastLogin: user.last_login
        };

        console.log(`[${requestId}] Login successful for user:`, user.id);
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
        console.error(`[${requestId}] Admin login error:`, {
            message: error.message,
            stack: error.stack,
            name: error.name,
            code: error.code
        });
        
        // Send more detailed error in development, generic in production
        const errorResponse = {
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Authentication failed'
        };
        
        // Add details only in development
        if (!isProduction) {
            errorResponse.details = error.message;
            errorResponse.stack = error.stack;
        }
        
        res.status(500).json(errorResponse);
    }
}

// Register routes using the reusable handler so cookies and headers are handled in-process
app.post('/api/admin/login', authLimiter, adminLoginHandler);
app.post('/admin/login', authLimiter, adminLoginHandler);

// Admin logout endpoint
app.post('/api/admin/logout', async (req, res) => {
    try {
        // Safely clear admin cookie
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
// Regular contact form submission (kept separate from admin auth)
app.post('/api/contact/submit', contactFormLimiter, async (req, res) => {
    try {
        const { name, email, message, subject } = req.body;

        if (!name || !email || !message) {
            return res.status(400).json({
                status: 'error',
                message: 'Name, email, and message are required'
            });
        }

        // Validate email format
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid email format'
            });
        }

        // Here you would typically:
        // 1. Save to database
        // 2. Send email notification
        // 3. Trigger any workflow

        logger.info('Contact form submitted', { name, email, subject: subject || 'No subject' });

        res.json({
            status: 'success',
            message: 'Thank you for your message! We will get back to you soon.'
        });

    } catch (error) {
        logger.error('Contact form error:', error);
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
        logger.error('Error fetching users:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch users'
        });
    }
});

userRouter.post('/', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const {
            email,
            password,
            full_name,
            department,
            role = 'member',
            is_active = true
        } = req.body;

        // Validation
        if (!email || !password || !full_name) {
            return res.status(400).json({
                status: 'error',
                code: 'VALIDATION_ERROR',
                message: 'Email, password, and full name are required'
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid email format'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                status: 'error',
                message: 'Password must be at least 8 characters long'
            });
        }

        // Check existing user
        const existing = await db.query('select', 'users', {
            where: { email: email.toLowerCase() },
            select: 'id'
        });

        if (existing.data.length > 0) {
            return res.status(400).json({
                status: 'error',
                message: 'User with this email already exists'
            });
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

        res.status(201).json({
            status: 'success',
            data: user,
            message: 'User created successfully'
        });
    } catch (error) {
        logger.error('Error creating user:', error);
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
            return res.status(403).json({
                status: 'error',
                message: 'Access denied'
            });
        }

        const result = await db.query('select', 'users', {
            where: { id: req.params.id },
            select: 'id, email, full_name, role, department, is_active, created_at, updated_at, last_login, profile_picture'
        });

        if (result.data.length === 0) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        res.json({
            status: 'success',
            data: authService.createUserResponse(result.data[0])
        });
    } catch (error) {
        logger.error('Error fetching user:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch user'
        });
    }
});

userRouter.put('/:id', verifyToken, async (req, res) => {
    try {
        // Check permissions
        if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
            return res.status(403).json({
                status: 'error',
                message: 'Access denied'
            });
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
            if (password.length < 8) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Password must be at least 8 characters long'
                });
            }
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
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        // Clear caches
        userCache.delete(`user:${req.params.id}`);
        if (req.user.id === req.params.id) {
            req.user = authService.createUserResponse(result.data[0]);
        }

        res.json({
            status: 'success',
            data: authService.createUserResponse(result.data[0]),
            message: 'User updated successfully'
        });
    } catch (error) {
        logger.error('Error updating user:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to update user'
        });
    }
});

userRouter.delete('/:id', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        if (req.params.id === req.user.id) {
            return res.status(400).json({
                status: 'error',
                message: 'Cannot delete your own account'
            });
        }

        const result = await db.query('delete', 'users', {
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }

        userCache.delete(`user:${req.params.id}`);

        res.json({
            status: 'success',
            message: 'User deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting user:', error);
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

app.put('/api/profile', verifyToken, async (req, res) => {
    try {
        const { full_name, department } = req.body;

        if (!full_name) {
            return res.status(400).json({
                status: 'error',
                message: 'Full name is required'
            });
        }

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
        userCache.set(`user:${req.user.id}`, updatedUser, 300000);
        req.user = updatedUser;

        res.json({
            status: 'success',
            data: updatedUser,
            message: 'Profile updated successfully'
        });
    } catch (error) {
        logger.error('Error updating profile:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to update profile'
        });
    }
});

app.put('/api/profile/password', verifyToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                status: 'error',
                message: 'Current password and new password are required'
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                status: 'error',
                message: 'New password must be at least 8 characters long'
            });
        }

        // Verify current password
        const result = await db.query('select', 'users', {
            where: { id: req.user.id },
            select: 'password_hash'
        });

        const validPassword = await bcrypt.compare(currentPassword, result.data[0].password_hash);
        if (!validPassword) {
            return res.status(401).json({
                status: 'error',
                message: 'Current password is incorrect'
            });
        }

        // Update password
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        await db.query('update', 'users', {
            data: { password_hash: hashedPassword, updated_at: new Date() },
            where: { id: req.user.id }
        });

        res.json({
            status: 'success',
            message: 'Password updated successfully'
        });
    } catch (error) {
        logger.error('Error updating password:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to update password'
        });
    }
});

// ==================== ENHANCED MEMBERS ROUTES ====================
const memberRouter = express.Router();

memberRouter.get('/', cacheMiddleware(120), async (req, res) => {
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
        logger.error('Error fetching members:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch members'
        });
    }
});

memberRouter.get('/:id', cacheMiddleware(300), async (req, res) => {
    try {
        const result = await db.query('select', 'executive_members', {
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            return res.status(404).json({
                status: 'error',
                message: 'Member not found'
            });
        }

        res.json({
            status: 'success',
            data: result.data[0]
        });
    } catch (error) {
        logger.error('Error fetching member:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch member'
        });
    }
});

memberRouter.post('/', verifyToken, requireRole('admin', 'editor'), upload.single('profile_image'), async (req, res) => {
    try {
        const {
            full_name, position, department, level, email, phone,
            bio, committee, display_order, status, social_links
        } = req.body;

        if (!full_name || !position) {
            return res.status(400).json({
                status: 'error',
                message: 'Full name and position are required'
            });
        }

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
            social_links: social_links ? JSON.parse(social_links) : {},
            created_at: new Date(),
            updated_at: new Date()
        };

        if (req.file) {
            memberData.profile_image = `/uploads/${req.file.filename}`;
        }

        const result = await db.query('insert', 'executive_members', { data: memberData });

        cacheManager.invalidate(/members/);

        res.status(201).json({
            status: 'success',
            data: result.data[0],
            message: 'Member created successfully'
        });
    } catch (error) {
        logger.error('Error creating member:', error);
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
            memberData.social_links = JSON.parse(req.body.social_links);
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
            return res.status(404).json({
                status: 'error',
                message: 'Member not found'
            });
        }

        cacheManager.invalidate(/members/);

        res.json({
            status: 'success',
            data: result.data[0],
            message: 'Member updated successfully'
        });
    } catch (error) {
        logger.error('Error updating member:', error);
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
            return res.status(404).json({
                status: 'error',
                message: 'Member not found'
            });
        }

        cacheManager.invalidate(/members/);

        res.json({
            status: 'success',
            message: 'Member deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting member:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to delete member'
        });
    }
});

app.use('/api/members', memberRouter);

// ==================== FILE MANAGEMENT ROUTES ====================
app.post('/api/upload', verifyToken, requireRole('admin', 'editor'), upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                status: 'error',
                message: 'No file uploaded'
            });
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

        res.json({
            status: 'success',
            data: fileInfo,
            message: 'File uploaded successfully'
        });
    } catch (error) {
        logger.error('Error uploading file:', error);
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

        res.json({
            status: 'success',
            message: 'File deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting file:', error);
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
        // Do not reveal the existence of admin resources to unauthenticated users
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
    
    // 1. DISGUISED ADMIN PORTAL (looks like a system portal)
    app.get('/portal/system', async (req, res) => {
        try {
            if (!req.isAdmin) {
                // Show access denied page that looks like regular 404
                return res.status(404).send(`
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Page Not Found - NUESA BIU</title>
                        <style>
                            body { font-family: Arial, sans-serif; padding: 40px; text-align: center; }
                            .error-box { max-width: 600px; margin: 50px auto; padding: 30px; border: 1px solid #ddd; }
                        </style>
                    </head>
                    <body>
                        <div class="error-box">
                            <h1>404 - Page Not Found</h1>
                            <p>The page you are looking for does not exist.</p>
                            <a href="/">Return to Home</a>
                        </div>
                    </body>
                    </html>
                `);
            }
            
            // Admin is logged in, serve dashboard
            res.sendFile(path.join(adminDir, 'dash.html'));
        } catch (error) {
            res.status(404).send('Page not found');
        }
    });
    
    // 2. HIDDEN ADMIN LOGIN PAGE (disguised as internal portal)
    app.get('/portal/login', async (req, res) => {
        // Check if user is already admin
        if (req.isAdmin) {
            // Redirect to admin dashboard
            return res.redirect('/portal/system');
        }
        
        // Show disguised login page without hardcoded secret
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Internal Portal - NUESA BIU</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        max-width: 500px;
                        margin: 50px auto;
                        padding: 20px;
                        background: #f5f5f5;
                    }
                    .login-box {
                        background: white;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        text-align: center;
                    }
                    .logo {
                        font-size: 24px;
                        font-weight: bold;
                        color: #0066cc;
                        margin-bottom: 20px;
                    }
                    input {
                        width: 100%;
                        padding: 12px;
                        margin: 10px 0;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                        box-sizing: border-box;
                    }
                    button {
                        background: #0066cc;
                        color: white;
                        padding: 12px 30px;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 16px;
                        width: 100%;
                        margin-top: 10px;
                    }
                    .message {
                        margin-top: 15px;
                        padding: 10px;
                        border-radius: 4px;
                    }
                    .error { background: #ffe6e6; color: #cc0000; }
                    .success { background: #e6ffe6; color: #006600; }
                </style>
            </head>
            <body>
                <div class="login-box">
                    <div class="logo">NUESA BIU</div>
                    <h2>Internal Portal</h2>
                    <p>Authorized access only</p>
                    
                    <form id="portalLogin">
                        <input type="email" name="admin_email" placeholder="Email Address" required>
                        <input type="password" name="admin_password" placeholder="Password" required>
                        <button type="submit">Access Portal</button>
                    </form>
                    
                    <div id="message" class="message"></div>
                    
                    <p style="margin-top: 30px; font-size: 0.9em; color: #666;">
                        Forgot your credentials? Contact system administrator.
                    </p>
                </div>
                
                <script>
                    document.getElementById('portalLogin').addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const formData = new FormData(e.target);
                        const data = Object.fromEntries(formData);
                        
                        const messageDiv = document.getElementById('message');
                        messageDiv.textContent = 'Authenticating...';
                        messageDiv.className = 'message';
                        
                        try {
                            // Use proper admin login endpoint
                            const response = await fetch('/api/admin/login', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    email: data.admin_email,
                                    password: data.admin_password,
                                    rememberMe: false
                                })
                            });
                            
                            const result = await response.json();
                            
                            if (result.status === 'success') {
                                messageDiv.textContent = 'Login successful! Redirecting...';
                                messageDiv.className = 'message success';
                                setTimeout(() => {
                                    window.location.href = '/portal/system';
                                }, 1000);
                            } else {
                                messageDiv.textContent = result.message || 'Authentication failed';
                                messageDiv.className = 'message error';
                            }
                        } catch (error) {
                            messageDiv.textContent = 'Connection error. Please try again.';
                            messageDiv.className = 'message error';
                        }
                    });
                </script>
            </body>
            </html>
        `);
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
        
        // Redirect to home page
        res.redirect('/');
    });
    
    // 4. SERVE ADMIN ASSETS
    app.get('/assets/:folder/:file', (req, res) => {
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
    });
    
    // 5. BLOCK DIRECT ACCESS TO ADMIN FOLDER
    app.all('/admin/*', (req, res) => {
        // Always redirect to home page
        res.redirect('/');
    });
    
    console.log('✅ Hidden admin system activated:');
    console.log('   • Admin login: /portal/login');
    console.log('   • Admin dashboard: /portal/system');
    console.log('   • Admin logout: /portal/logout');
    console.log('   • Direct /admin/* routes are blocked');
    
} else {
    console.log('⚠️ Admin folder not found.');
}

// ==================== SYSTEM ENDPOINTS ====================
// TEMPORARY DEBUG ENDPOINT - REMOVE AFTER FIXING
app.get('/api/debug/env', (req, res) => {
    res.json({
        admin_email: process.env.ADMIN_EMAIL ? '✓ Set' : '✗ Missing',
        admin_password: process.env.ADMIN_PASSWORD ? '✓ Set' : '✗ Missing',
        jwt_secret: process.env.JWT_SECRET ? '✓ Set' : '✗ Missing',
        supabase_url: process.env.SUPABASE_URL ? '✓ Set' : '✗ Missing',
        supabase_key: process.env.SUPABASE_SERVICE_ROLE_KEY ? '✓ Set' : '✗ Missing',
        node_env: process.env.NODE_ENV
    });
});

app.get('/api/debug/db', async (req, res) => {
    try {
        // Test database connection
        const result = await db.query('select', 'users', { limit: 1 });
        res.json({
            status: 'connected',
            message: 'Database connection successful',
            data: result.data
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: error.message,
            code: error.code
        });
    }
});

app.get('/api/health', async (req, res) => {
    try {
        const health = {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            database: 'unknown',
            cache: {
                users: userCache.getStats(),
                data: dataCache.getStats()
            }
        };

        try {
            await db.query('select', 'users', { limit: 1 });
            health.database = 'connected';
        } catch (error) {
            health.database = 'disconnected';
            health.databaseError = error.message;
        }

        const status = health.database === 'connected' ? 200 : 503;

        res.status(status).json({
            status: health.status,
            ...health
        });
    } catch (error) {
        res.status(503).json({
            status: 'unhealthy',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

app.get('/api/ping', (req, res) => {
    res.json({
        status: 'success',
        message: 'pong',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

app.get('/api/stats', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const [users, members, cacheStats] = await Promise.all([
            db.query('select', 'users', { count: true }),
            db.query('select', 'executive_members', { count: true }),
            Promise.resolve({
                users: userCache.getStats(),
                data: dataCache.getStats()
            })
        ]);

        res.json({
            status: 'success',
            data: {
                users: users.count || 0,
                members: members.count || 0,
                cache: cacheStats,
                uptime: process.uptime(),
                environment: NODE_ENV
            }
        });
    } catch (error) {
        logger.error('Error fetching stats:', error);
        res.status(500).json({
            status: 'error',
            message: 'Failed to fetch statistics'
        });
    }
});

// ==================== STATIC FILES ====================
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
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
            profile: '/api/profile',
            health: '/api/health',
            stats: '/api/stats',
            contact: '/api/contact/submit'
        }
    });
});

app.get('/api/docs', (req, res) => {
    res.json({
        title: 'API Documentation',
        description: 'NUESA BIU API Server Documentation',
        version: '1.0.0',
        endpoints: [
            {
                path: '/api/auth/login',
                method: 'POST',
                description: 'User authentication',
                body: 'email, password'
            },
            {
                path: '/api/admin/login',
                method: 'POST',
                description: 'Admin authentication',
                body: 'email, password'
            },
            {
                path: '/api/members',
                method: 'GET',
                description: 'Get all executive members',
                query: '?committee=tech&status=active'
            },
            {
                path: '/api/users',
                method: 'GET',
                description: 'Get users (admin only)',
                auth: 'Bearer token required'
            }
        ]
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
            timestamp: new Date().toISOString()
        });
    }
    
    // For HTML routes, serve 404 page if exists, otherwise return JSON
    const notFoundPage = path.join(publicDir, '404.html');
    if (publicExists && fsSync.existsSync(notFoundPage)) {
        res.status(404).sendFile(notFoundPage);
    } else {
        res.status(404).json({
            status: 'error',
            message: 'Page not found'
        });
    }
});

// ==================== ERROR HANDLER ====================
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', {
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
                message: `File size too large. Maximum size is ${process.env.MAX_FILE_SIZE || '10MB'}.`
            });
        }
        return res.status(400).json({
            status: 'error',
            code: 'UPLOAD_ERROR',
            message: `File upload error: ${err.message}`
        });
    }

    // Database errors
    if (err instanceof DatabaseError) {
        return res.status(400).json({
            status: 'error',
            code: 'DATABASE_ERROR',
            message: `Database error: ${err.message}`
        });
    }

    // Authentication errors
    if (err instanceof AuthError) {
        return res.status(err.statusCode || 401).json({
            status: 'error',
            code: err.code,
            message: err.message
        });
    }

    // Validation errors
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            status: 'error',
            code: 'VALIDATION_ERROR',
            message: err.message,
            errors: err.errors
        });
    }

    // Default error response
    const message = isProduction ? 'Internal server error' : err.message;
    const statusCode = err.statusCode || 500;

    res.status(statusCode).json({
        status: 'error',
        code: 'INTERNAL_ERROR',
        message: message,
        ...(!isProduction && { stack: err.stack, details: err.message })
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
    process.exit(0);
});

process.on('SIGINT', () => {
    logger.info('SIGINT received, starting graceful shutdown');
    process.exit(0);
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
║ 🔗 API URL: http://localhost:${PORT}                            ║
║ 🌐 Frontend: ${process.env.FRONTEND_URL || 'Not set'}           ║
║ 🔒 JWT: ${JWT_SECRET ? 'Set ✓' : 'Missing ✗'}                  ║
║ 👑 Admin: ${process.env.ADMIN_EMAIL || 'Not configured'}        ║
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