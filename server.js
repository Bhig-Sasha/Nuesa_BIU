/**
 * ============================================================
 * NUESA BIU API SERVER - ORGANIZED VERSION
 * ============================================================
 * @author Sasha Troger
 * @version 1.2.0  (added Media Library)
 * @license MIT
 * @DevSignature ST-BIU-2026
 */

// ============================================================
// ================ SECTION 1: CORE INFRASTRUCTURE ===========
// ============================================================

// -------------------- 1.1 ENVIRONMENT ----------------------
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

// -------------------- 1.2 CONFIGURATION --------------------
const REQUIRED_ENV_VARS = ['JWT_SECRET', 'SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY'];

const missingEnvVars = REQUIRED_ENV_VARS.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
    console.error('❌ ERROR: Missing required environment variables:', missingEnvVars.join(', '));
    process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const IS_PRODUCTION = NODE_ENV === 'production';
const BASE_URL = process.env.API_URL || (IS_PRODUCTION
  ? 'https://nuesa-biu-pjp0.onrender.com'
  : `http://localhost:${PORT}`);
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024;
const MAX_MEDIA_FILE_SIZE = parseInt(process.env.MAX_MEDIA_FILE_SIZE) || 50 * 1024 * 1024; // 50 MB for media
const MAX_REQUEST_SIZE = process.env.MAX_REQUEST_SIZE || '10mb';

// -------------------- 1.3 DATABASE SETUP -------------------
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

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    db: { schema: 'public', pool: { max: 20, idleTimeoutMillis: 30000 } },
    global: { headers: { 'x-application-name': 'nuesa-biu-api', 'x-version': '1.2.0' } }
});

const STORAGE_BUCKET = 'nuesa-media';

// -------------------- 1.4 CUSTOM ERROR CLASSES -------------
class DatabaseError extends Error {
    constructor(message, code, table, operation) {
        super(message); this.name = 'DatabaseError';
        this.code = code; this.table = table; this.operation = operation;
        this.timestamp = new Date(); this.statusCode = 400;
    }
}
class ValidationError extends Error {
    constructor(message, errors = []) {
        super(message); this.name = 'ValidationError'; this.errors = errors; this.statusCode = 400;
    }
}
class NotFoundError extends Error {
    constructor(resource) {
        super(`${resource} not found`); this.name = 'NotFoundError'; this.statusCode = 404;
    }
}
class AuthError extends Error {
    constructor(message, code = 'AUTH_ERROR') {
        super(message); this.name = 'AuthError'; this.code = code; this.statusCode = 401;
    }
}
class ForbiddenError extends Error {
    constructor(message = 'Access denied') {
        super(message); this.name = 'ForbiddenError'; this.statusCode = 403;
    }
}

// -------------------- 1.5 DATABASE SERVICE -----------------
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
            const { data = null, select = '*', where = {}, order = {}, limit = null, offset = 0, count = false } = options;
            let query;

            switch (operation) {
                case 'select': query = this.supabase.from(table).select(select, count ? { count: 'exact' } : {}); break;
                case 'insert': query = this.supabase.from(table).insert(data).select(select); break;
                case 'update': query = this.supabase.from(table).update(data).select(select); break;
                case 'upsert': query = this.supabase.from(table).upsert(data).select(select); break;
                case 'delete': query = this.supabase.from(table).delete().select(select); break;
                default: throw new Error(`Unknown operation: ${operation}`);
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
                query = query.order(order.column, { ascending: order.ascending !== false, nullsFirst: order.nullsFirst || false });
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

            return { data: result.data || [], count: result.count, status: 'success', queryTime };
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

// -------------------- 1.6 LOGGING SYSTEM -------------------
const LOG_DIR = 'logs';
if (!fsSync.existsSync(LOG_DIR)) fsSync.mkdirSync(LOG_DIR, { recursive: true });

const logger = winston.createLogger({
    level: IS_PRODUCTION ? 'info' : 'debug',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'nuesa-biu-api', environment: NODE_ENV },
    transports: [
        new winston.transports.File({ filename: `${LOG_DIR}/error.log`, level: 'error', maxsize: 10 * 1024 * 1024, maxFiles: 10, tailable: true }),
        new winston.transports.File({ filename: `${LOG_DIR}/combined.log`, maxsize: 20 * 1024 * 1024, maxFiles: 10, tailable: true }),
        new winston.transports.File({
            filename: `${LOG_DIR}/audit.log`, level: 'info', maxsize: 10 * 1024 * 1024, maxFiles: 5,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.printf(({ timestamp, level, message, ...meta }) => JSON.stringify({ timestamp, level, message, ...meta }))
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

// -------------------- 1.7 CACHE MANAGEMENT -----------------
class LRUCache {
    constructor(maxSize = 100, ttl = 300000) {
        this.cache = new Map(); this.maxSize = maxSize; this.ttl = ttl;
        this.hits = 0; this.misses = 0;
    }
    set(key, value, customTTL = null) {
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        this.cache.set(key, { value, expiry: Date.now() + (customTTL || this.ttl), accessed: Date.now() });
    }
    get(key) {
        const item = this.cache.get(key);
        if (!item) { this.misses++; return null; }
        if (Date.now() > item.expiry) { this.cache.delete(key); this.misses++; return null; }
        item.accessed = Date.now(); this.hits++;
        return item.value;
    }
    delete(key) { return this.cache.delete(key); }
    clear() { this.cache.clear(); this.hits = 0; this.misses = 0; }
    getStats() {
        const hitRate = this.hits + this.misses > 0 ? this.hits / (this.hits + this.misses) : 0;
        return {
            size: this.cache.size, maxSize: this.maxSize,
            hits: this.hits, misses: this.misses,
            hitRate: Math.round(hitRate * 100) + '%', ttl: this.ttl
        };
    }
}

class CacheManager {
    constructor() { this.caches = new Map(); this.redis = redis; }
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
        if (this.redis) await this.redis.del(key);
        else this.caches.forEach(cache => cache.delete(key));
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
        for (const tag of tags) await this.invalidate(`tag:${tag}:*`);
    }
    clearAll() {
        if (this.redis) this.redis.flushdb();
        else this.caches.forEach(cache => cache.clear());
    }
    getStats() {
        const stats = {};
        this.caches.forEach((cache, name) => { stats[name] = cache.getStats(); });
        if (this.redis) stats.redis = { connected: true };
        return stats;
    }
}

const cacheManager = new CacheManager();
const userCache = cacheManager.getCache('users', { maxSize: 200, ttl: 300000 });
const dataCache = cacheManager.getCache('data', { maxSize: 100, ttl: 60000 });

// -------------------- 1.8 FILE UPLOAD CONFIG ---------------
const UPLOAD_DIRS = {
    images: './uploads/images',
    resources: './uploads/resources',
    profiles: './uploads/profiles',
    mediaImages: './uploads/media/images',
    mediaVideos: './uploads/media/videos',
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
            if (type.includes('profile') || type.includes('avatar')) subDir = 'profiles';
            else if (type.includes('image') || /\.(jpg|jpeg|png|gif|webp)$/i.test(file.originalname)) subDir = 'images';
            else subDir = 'resources';

            const destDir = path.join(UPLOAD_DIRS[subDir], new Date().toISOString().split('T')[0]);
            await fs.mkdir(destDir, { recursive: true });
            cb(null, destDir);
        } catch (error) { cb(error); }
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
        const ext = path.extname(file.originalname).toLowerCase();
        const safeName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 50);
        cb(null, `${safeName}-${uniqueSuffix}${ext}`);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedMimeTypes = {
        'image/jpeg': ['.jpg', '.jpeg'], 'image/png': ['.png'], 'image/gif': ['.gif'], 'image/webp': ['.webp'],
        'application/pdf': ['.pdf'], 'application/msword': ['.doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
        'text/plain': ['.txt'], 'application/zip': ['.zip'], 'application/x-rar-compressed': ['.rar']
    };

    const allowedExts = Object.values(allowedMimeTypes).flat();
    const ext = path.extname(file.originalname).toLowerCase();

    if (!allowedMimeTypes[file.mimetype] || !allowedExts.includes(ext)) {
        return cb(new Error(`File type ${file.mimetype} with extension ${ext} is not allowed`), false);
    }
    cb(null, true);
};

const upload = multer({ storage, limits: { fileSize: MAX_FILE_SIZE, files: 5 }, fileFilter });

// ---------- 1.8b MEDIA-ONLY UPLOAD (pictures + videos) ----------
const MEDIA_PICTURE_MIMES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
const MEDIA_PICTURE_EXTS  = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
const MEDIA_VIDEO_MIMES   = ['video/mp4', 'video/webm', 'video/quicktime'];
const MEDIA_VIDEO_EXTS    = ['.mp4', '.webm', '.mov'];

const mediaFileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const isPicture = MEDIA_PICTURE_MIMES.includes(file.mimetype) && MEDIA_PICTURE_EXTS.includes(ext);
    const isVideo   = MEDIA_VIDEO_MIMES.includes(file.mimetype)   && MEDIA_VIDEO_EXTS.includes(ext);

    if (!isPicture && !isVideo) {
        return cb(new Error(`Media file type ${file.mimetype} (${ext}) is not allowed. Only pictures (JPG/PNG/WEBP/GIF) and videos (MP4/WEBM/MOV).`), false);
    }
    cb(null, true);
};

const mediaStorage = multer.diskStorage({
    destination: async (req, file, cb) => {
        try {
            const isVideo = file.mimetype.startsWith('video/');
            const baseDir = isVideo ? UPLOAD_DIRS.mediaVideos : UPLOAD_DIRS.mediaImages;
            const destDir = path.join(baseDir, new Date().toISOString().split('T')[0]);
            await fs.mkdir(destDir, { recursive: true });
            cb(null, destDir);
        } catch (err) { cb(err); }
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = `${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
        const ext = path.extname(file.originalname).toLowerCase();
        const safe = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 50);
        cb(null, `${safe}-${uniqueSuffix}${ext}`);
    }
});

const mediaUpload = multer({
    storage: mediaStorage,
    limits: { fileSize: MAX_MEDIA_FILE_SIZE, files: 1 },
    fileFilter: mediaFileFilter
});

// -------------------- 1.9 VALIDATION SCHEMAS ---------------
const schemas = {
    login: Joi.object({ email: Joi.string().email().required(), password: Joi.string().min(8).required(), rememberMe: Joi.boolean() }),
    register: Joi.object({ email: Joi.string().email().required(), password: Joi.string().min(8).required(), full_name: Joi.string().min(2).max(100).required(), department: Joi.string().optional(), role: Joi.string().valid('member', 'editor', 'admin').default('member') }),
    createUser: Joi.object({ email: Joi.string().email().required(), password: Joi.string().min(8).required(), full_name: Joi.string().min(2).max(100).required(), department: Joi.string().optional(), role: Joi.string().valid('member', 'editor', 'admin').default('member'), is_active: Joi.boolean().default(true) }),
    updateUser: Joi.object({ full_name: Joi.string().min(2).max(100).optional(), department: Joi.string().optional(), role: Joi.string().valid('member', 'editor', 'admin').optional(), is_active: Joi.boolean().optional(), password: Joi.string().min(8).optional() }),
    changePassword: Joi.object({ currentPassword: Joi.string().required(), newPassword: Joi.string().min(8).required() }),
    createMember: Joi.object({ full_name: Joi.string().required(), position: Joi.string().required(), department: Joi.string().optional(), level: Joi.string().optional(), email: Joi.string().email().optional(), phone: Joi.string().optional(), bio: Joi.string().optional(), committee: Joi.string().optional(), display_order: Joi.number().integer().default(0), status: Joi.string().valid('active', 'inactive', 'alumni').default('active'), social_links: Joi.object().default({}) }),
    contactForm: Joi.object({ name: Joi.string().min(2).max(100).required(), email: Joi.string().email().required(), message: Joi.string().min(10).max(1000).required(), subject: Joi.string().max(200).optional() }),
    article: Joi.object({ title: Joi.string().required(), slug: Joi.string().optional(), content: Joi.string().required(), excerpt: Joi.string().optional(), author: Joi.string().optional(), category: Joi.string().optional(), tags: Joi.array().items(Joi.string()).default([]), status: Joi.string().valid('draft', 'published').default('draft'), is_published: Joi.boolean().default(false), published_at: Joi.date().optional() }),
    updateMedia: Joi.object({
        title: Joi.string().max(200).optional(),
        description: Joi.string().allow('', null).optional(),
        alt_text: Joi.string().allow('', null).optional(),
        tags: Joi.array().items(Joi.string()).optional()
    })
};

const validate = (schema) => (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) throw new ValidationError('Validation failed', error.details);
    next();
};

// -------------------- 1.10 AUTHENTICATION SERVICE ----------
class AuthService {
    constructor() { this.secret = JWT_SECRET; this.expire = JWT_EXPIRE; }

    generateToken(payload) {
        return jwt.sign(payload, this.secret, {
            expiresIn: this.expire, issuer: 'nuesa-biu-api',
            audience: 'nuesa-biu-client', jwtid: uuid.v4()
        });
    }

    verifyToken(token) {
        try {
            return jwt.verify(token, this.secret, {
                issuer: ['nuesa-biu-api'], audience: ['nuesa-biu-client']
            });
        } catch (error) {
            throw new AuthError('Invalid token', error.name);
        }
    }

    async authenticateUser(email, password) {
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
        await db.query('update', 'users', { data: { last_login: new Date() }, where: { id: user.id } });

        logger.info('User logged in successfully', { userId: user.id, email: user.email });
        return this.createUserResponse(user);
    }

    createUserResponse(user) {
        return {
            id: user.id, email: user.email, fullName: user.full_name, role: user.role,
            department: user.department, isActive: user.is_active,
            createdAt: user.created_at, lastLogin: user.last_login
        };
    }

    createTokenPayload(user) {
        return { userId: user.id, email: user.email, role: user.role, fullName: user.full_name };
    }
}

const authService = new AuthService();

// -------------------- 1.11 ACCOUNT LOCKOUT -----------------
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

async function resetLoginAttempts(identifier) { loginAttempts.delete(identifier); }

// -------------------- 1.12 DATABASE INIT -------------------
async function initializeDatabase() {
    const { error } = await supabase.from('users').select('count').limit(1);
    if (error) {
        logger.error(`Database check failed: ${error.message}`);
        throw new Error(`Database connection failed: ${error.message}`);
    }
    logger.info('Database connected successfully');
    await createDefaultAdmin();
    await createDefaultTables();
    logger.info('Database initialization complete');
}

async function createDefaultAdmin() {
    try {
        const adminEmail = process.env.ADMIN_EMAIL;
        if (!adminEmail) { logger.warn('ADMIN_EMAIL not set, skipping admin creation'); return; }

        const result = await db.query('select', 'users', { where: { email: adminEmail }, select: 'id' });

        if (result.data.length === 0) {
            const adminPassword = process.env.ADMIN_PASSWORD;
            if (!adminPassword) { logger.warn('ADMIN_PASSWORD not set, skipping admin creation'); return; }

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
    } catch (error) { logger.error('Could not create admin user:', error); }
}

async function createDefaultTables() { logger.info('Checking database tables...'); }

// ============================================================
// ================ SECTION 2: SHARED MIDDLEWARE =============
// ============================================================

app.set('trust proxy', 1);

app.use((req, res, next) => {
    req.id = uuid.v4();
    res.setHeader('X-Request-ID', req.id);
    next();
});

app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});

app.use(compression({
    level: 6, threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

const csrfProtection = csrf({ cookie: true });
app.use('/portal', (req, res, next) => {
    if (req.path === '/login') return next();
    csrfProtection(req, res, next);
});

app.use(xss());
app.use(hpp({ whitelist: ['page', 'limit', 'sort', 'fields'] }));

// -------------------- 2.2 CORS CONFIG -----------------------
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
    .split(',').map(o => o.trim()).filter(o => o.length > 0);

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500';
if (!ALLOWED_ORIGINS.includes(FRONTEND_URL)) ALLOWED_ORIGINS.push(FRONTEND_URL);

// Render
ALLOWED_ORIGINS.push('https://nuesa-biu-pjp0.onrender.com');
ALLOWED_ORIGINS.push('https://www.nuesa-biu-pjp0.onrender.com');

// Vercel frontend
ALLOWED_ORIGINS.push('https://nuesa-biu.vercel.app');
ALLOWED_ORIGINS.push('https://www.nuesa-biu.vercel.app');

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
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With', 'X-API-Key', 'X-Total-Count', 'X-Page-Count', 'X-CSRF-Token'],
    exposedHeaders: ['X-Total-Count', 'X-Page-Count', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'X-Request-ID'],
    maxAge: 86400,
    preflightContinue: false,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.use(cookieParser());

// -------------------- 2.3 BODY PARSING ----------------------
app.use(express.json({
    limit: MAX_REQUEST_SIZE,
    verify: (req, res, buf) => { req.rawBody = buf; }
}));

app.use(express.urlencoded({ extended: true, limit: MAX_REQUEST_SIZE, parameterLimit: 100 }));

// -------------------- 2.4 LOGGING & TIMEOUT -----------------
const morganFormat = IS_PRODUCTION ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
    stream: { write: (message) => logger.http(message.trim()) },
    skip: (req, res) => req.path === '/api/health' && req.method === 'GET'
}));

app.use(timeout('30s'));
app.use((req, res, next) => {
    if (req.timedout) {
        logger.error('Request timeout', { requestId: req.id, url: req.url, method: req.method, ip: req.ip, userId: req.user?.id });
        return res.status(503).json({ status: 'error', code: 'TIMEOUT', message: 'Request timeout. Please try again.' });
    }
    next();
});

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

// -------------------- 2.5 RATE LIMITING ---------------------
const createRateLimiter = (max, windowMs = 15 * 60 * 1000, message = 'Too many requests') => {
    return rateLimit({
        windowMs, max,
        message: { status: 'error', code: 'TOO_MANY_REQUESTS', message },
        standardHeaders: true, legacyHeaders: false, skipSuccessfulRequests: false,
        keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip,
        handler: (req, res) => {
            logger.warn('Rate limit exceeded', { requestId: req.id, ip: req.ip, url: req.url, method: req.method });
            res.status(429).json({ status: 'error', code: 'TOO_MANY_REQUESTS', message });
        }
    });
};

app.use('/api/', createRateLimiter(200, 15 * 60 * 1000));
app.use('/api/auth/login', createRateLimiter(10, 15 * 60 * 1000, 'Too many login attempts'));
app.use('/api/admin/login', createRateLimiter(10, 15 * 60 * 1000, 'Too many login attempts'));
app.use('/api/contact/submit', createRateLimiter(10, 15 * 60 * 1000, 'Too many contact form submissions'));

// -------------------- 2.6 CACHE MIDDLEWARE ------------------
const cacheMiddleware = (duration = 60, tags = []) => {
    return async (req, res, next) => {
        if (req.method !== 'GET' || req.headers.authorization) return next();

        const key = `cache:${req.originalUrl || req.url}`;

        try {
            const cachedResponse = await cacheManager.get(key);
            if (cachedResponse) return res.json(cachedResponse);

            const originalJson = res.json.bind(res);
            res.json = function (body) {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    cacheManager.set(key, body, duration * 1000).catch(() => {});
                    for (const tag of tags) {
                        cacheManager.set(`tag:${tag}:${key}`, true, duration * 1000).catch(() => {});
                    }
                }
                return originalJson(body);
            };
            next();
        } catch (error) {
            logger.error('Cache middleware error:', { requestId: req.id, error: error.message });
            next();
        }
    };
};

// -------------------- 2.7 AUTH MIDDLEWARE -------------------
const verifyToken = async (req, res, next) => {
    try {
        let token = null;
        const authHeader = req.headers.authorization;

        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.split(' ')[1];
        } else if (req.cookies && req.cookies.auth_token) {
            token = req.cookies.auth_token;
        }

        if (!token) throw new AuthError('Access token required', 'TOKEN_REQUIRED');

        const decoded = authService.verifyToken(token);
        const cacheKey = `user:${decoded.userId}`;
        const cachedUser = await cacheManager.get(cacheKey);

        if (cachedUser) {
            req.user = cachedUser; req.token = token;
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
        req.user = user; req.token = token;
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
            status: 'error', code: error.code || 'AUTH_FAILED', message: error.message || 'Authentication failed'
        });
    }
};

const requireRole = (...roles) => (req, res, next) => {
    if (!req.user) return next(new AuthError('Authentication required', 'AUTH_REQUIRED'));
    if (!roles.includes(req.user.role)) return next(new ForbiddenError(`Required roles: ${roles.join(', ')}`));
    next();
};

const requirePermission = (permission) => {
    const permissions = {
        admin: ['manage_users', 'manage_content', 'manage_settings', 'view_all'],
        editor: ['manage_content', 'view_all'],
        member: ['view_content']
    };
    return (req, res, next) => {
        if (!req.user) return next(new AuthError('Authentication required', 'AUTH_REQUIRED'));
        const userPermissions = permissions[req.user.role] || [];
        if (!userPermissions.includes(permission)) return next(new ForbiddenError(`Required permission: ${permission}`));
        next();
    };
};

// -------------------- 2.8 COOKIE HELPER ---------------------
function buildCookieOptions(rememberMe) {
    return {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: IS_PRODUCTION ? 'none' : 'lax',
        maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
        path: '/'
    };
}

// ============================================================
// ================== SECTION 3: PUBLIC ROUTES ===============
// ============================================================

// -------------------- 3.1 HEALTH & SYSTEM -------------------
app.get('/api/health', async (req, res) => {
    try {
        const dbStatus = await checkDatabase();
        res.status(200).json({
            status: 'healthy', database: dbStatus,
            uptime: process.uptime(), timestamp: new Date().toISOString(), version: '1.2.0'
        });
    } catch (error) {
        res.status(200).json({ status: 'degraded', message: 'Partial service disruption', timestamp: new Date().toISOString() });
    }
});

app.get('/api/ping', (req, res) => {
    res.json({ status: 'success', message: 'pong', timestamp: new Date().toISOString(), version: '1.2.0', requestId: req.id });
});

app.get('/api', (req, res) => {
    res.json({
        message: 'NUESA BIU API Server', version: '1.2.0', environment: NODE_ENV, status: 'operational',
        timestamp: new Date().toISOString(),
        documentation: `${req.protocol}://${req.get('host')}/api/docs`,
        endpoints: {
            auth: '/api/auth', users: '/api/users', members: '/api/members', events: '/api/events',
            resources: '/api/resources', articles: '/api/articles', profile: '/api/profile',
            health: '/api/health', 'stats-public': '/api/stats/public',
            contact: '/api/contact/submit', docs: '/api/docs', 'course-reps': '/api/course-reps',
            media: '/api/admin/media'
        },
        requestId: req.id
    });
});

// -------------------- 3.1b PUBLIC STATS ---------------------
app.get('/api/stats/public', cacheMiddleware(300, ['stats']), async (req, res) => {
    try {
        const [membersRes, eventsRes, resourcesRes, articlesRes] = await Promise.allSettled([
            db.query('select', 'executive_members', { count: true, where: { status: 'active' } }),
            db.query('select', 'biu_events', { count: true }),
            db.query('select', 'resources', { count: true }),
            db.query('select', 'articles', { count: true, where: { status: 'published', is_published: true } })
        ]);
        const safeCount = (r) => (r.status === 'fulfilled' ? (r.value.count || 0) : 0);

        res.json({
            status: 'success',
            data: {
                members: safeCount(membersRes),
                departments: 3,
                events: safeCount(eventsRes),
                resources: safeCount(resourcesRes),
                articles: safeCount(articlesRes)
            }
        });
    } catch (error) {
        logger.error('Public stats error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch stats' });
    }
});

// -------------------- 3.2 DOCUMENTATION ---------------------
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: { title: 'NUESA BIU API', version: '1.2.0', description: 'API documentation for NUESA BIU application', contact: { name: 'NUESA BIU', email: process.env.ADMIN_EMAIL } },
        servers: [{ url: IS_PRODUCTION ? 'https://nuesa-biu-pjp0.onrender.com' : `http://localhost:${PORT}`, description: IS_PRODUCTION ? 'Production server' : 'Development server' }],
        components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } } }
    },
    apis: ['./server.js']
};
const swaggerSpecs = swaggerJsdoc(swaggerOptions);
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs));

// -------------------- 3.3 PUBLIC AUTH ROUTES ----------------
const authRouter = express.Router();

authRouter.post('/login', validate(schemas.login), async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;
        const user = await authService.authenticateUser(email, password);
        const tokenPayload = authService.createTokenPayload(user);
        const token = authService.generateToken(tokenPayload);

        await cacheManager.set(`user:${user.id}`, user, rememberMe ? 604800000 : 300000);
        res.cookie('auth_token', token, buildCookieOptions(rememberMe));

        res.json({ status: 'success', data: { user, token, expiresIn: JWT_EXPIRE }, message: 'Login successful' });
    } catch (error) {
        logger.error('Login failed:', { email: req.body.email, error: error.message });
        res.status(error.statusCode || 500).json({ status: 'error', code: error.code || 'LOGIN_FAILED', message: error.message || 'Login failed' });
    }
});

authRouter.post('/logout', verifyToken, async (req, res) => {
    try {
        await cacheManager.delete(`user:${req.user.id}`);
        await cacheManager.invalidate('data:*');
        res.clearCookie('auth_token', { path: '/' });
        res.json({ status: 'success', message: 'Logged out successfully' });
    } catch (error) {
        logger.error('Logout error:', error);
        res.status(500).json({ status: 'error', message: 'Logout failed' });
    }
});

authRouter.get('/verify', verifyToken, async (req, res) => {
    res.json({ status: 'success', data: req.user, message: 'Token is valid' });
});

authRouter.post('/refresh', verifyToken, async (req, res) => {
    try {
        const newToken = authService.generateToken(authService.createTokenPayload(req.user));
        res.json({ status: 'success', data: { token: newToken, expiresIn: JWT_EXPIRE }, message: 'Token refreshed successfully' });
    } catch (error) {
        logger.error('Token refresh error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to refresh token' });
    }
});

authRouter.post('/forgot-password', validate(Joi.object({ email: Joi.string().email().required() })), async (req, res) => {
    try {
        logger.info('Password reset requested', { email: req.body.email });
        res.json({ status: 'success', message: 'If an account exists with this email, you will receive a reset link' });
    } catch (error) {
        logger.error('Forgot password error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to process request' });
    }
});

app.use('/api/auth', authRouter);

// -------------------- 3.4 ACTIVE ACADEMIC SESSION (PUBLIC) -------------
app.get('/api/sessions/active', cacheMiddleware(60, ['sessions']), async (req, res) => {
    try {
        const result = await db.query('select', 'academic_sessions', {
            where: { is_active: true }, select: '*'
        });
        const active = result.data[0] || null;
        res.json({
            status: 'success',
            data: active,
            count: active ? 1 : 0
        });
    } catch (error) {
        logger.error('Active session fetch error:', { requestId: req.id, error: error.message });
        // If table doesn't exist yet, return null gracefully rather than 500
        if (error.message && error.message.includes('relation') && error.message.includes('does not exist')) {
            return res.json({ status: 'success', data: null, count: 0 });
        }
        res.status(500).json({ status: 'error', message: 'Failed to fetch active session' });
    }
});

// -------------------- 3.4b PUBLIC MEMBERS ROUTES -------------
const memberRouter = express.Router();

memberRouter.get('/', cacheMiddleware(120, ['members']), async (req, res) => {
    try {
        const {
            committee,
            status = 'active',
            session,
            sort = 'display_order',
            order = 'asc',
            limit = 100
        } = req.query;

        let where = { status };
        if (committee && committee !== 'all') where.committee = committee;

        // Session filtering
        if (session === 'all') {
            // No session filter — return everything
        } else if (session) {
            // Explicit session name provided (e.g. ?session=2025/2026)
            where.session = session;
        } else {
            // Default: filter by currently active session
            try {
                const activeSessionRes = await db.query('select', 'academic_sessions', {
                    where: { is_active: true },
                    select: 'id, name'
                });
                const activeSession = activeSessionRes.data[0];
                if (activeSession) {
                    // Try session_id first (new schema), fall back to session name (legacy)
                    where.session = activeSession.name;
                }
                // If no active session exists, don't filter — show all members
            } catch (sessionErr) {
                // If academic_sessions table doesn't exist, skip session filtering entirely
                logger.warn('Could not resolve active session for member filter:', {
                    requestId: req.id,
                    error: sessionErr.message
                });
            }
        }

        const result = await db.query('select', 'executive_members', {
            where,
            order: { column: sort, ascending: order === 'asc' },
            limit: parseInt(limit) || 100
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
 * GET /api/members/:id
 * Returns a single member by ID
 */
memberRouter.get('/:id', cacheMiddleware(300, ['members']), async (req, res) => {
    try {
        const result = await db.query('select', 'executive_members', {
            where: { id: req.params.id }
        });
        if (result.data.length === 0) throw new NotFoundError('Member');
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Error fetching member:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) {
            return res.status(404).json({ status: 'error', message: error.message });
        }
        res.status(500).json({ status: 'error', message: 'Failed to fetch member' });
    }
});

app.use('/api/members', memberRouter);

// -------------------- 3.5 PUBLIC EVENTS ROUTES --------------
const eventRouter = express.Router();

// GET /api/events — list all events
eventRouter.get('/', cacheMiddleware(120, ['biu_events']), async (req, res) => {
    try {
        const { status = 'all', category, limit = 100 } = req.query;

        let where = {};
        if (status && status !== 'all') where.status = status;
        if (category && category !== 'all') where.category = category;

        const result = await db.query('select', 'biu_events', {
            where,
            order: {
                column: 'date',
                ascending: status === 'past' ? false : true
            },
            limit: parseInt(limit)
        });

        res.json({
            status: 'success',
            data: result.data,
            count: result.data.length
        });
    } catch (error) {
        logger.error('Events API error:', {
            message: error.message,
            code: error.code,
            requestId: req.id
        });
        res.status(500).json({ status: 'error', message: 'Failed to fetch events' });
    }
});

// GET /api/events/status/upcoming — explicit upcoming filter
eventRouter.get('/status/upcoming', cacheMiddleware(60, ['biu_events']), async (req, res) => {
    try {
        const result = await db.query('select', 'biu_events', {
            where: { status: 'upcoming' },
            order: { column: 'date', ascending: true }
        });
        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        logger.error('Error fetching upcoming events:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch upcoming events' });
    }
});

// GET /api/events/status/past — explicit past filter
eventRouter.get('/status/past', cacheMiddleware(300, ['biu_events']), async (req, res) => {
    try {
        const result = await db.query('select', 'biu_events', {
            where: { status: 'past' },
            order: { column: 'date', ascending: false }
        });
        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        logger.error('Error fetching past events:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch past events' });
    }
});

// GET /api/events/category/:category
eventRouter.get('/category/:category', cacheMiddleware(120, ['biu_events']), async (req, res) => {
    try {
        const result = await db.query('select', 'biu_events', {
            where: { category: req.params.category },
            order: { column: 'date', ascending: true }
        });
        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        logger.error('Error fetching events by category:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch events' });
    }
});

// GET /api/events/:id — single event (must stay LAST, since :id matches anything)
eventRouter.get('/:id', cacheMiddleware(300, ['biu_events']), async (req, res) => {
    try {
        const result = await db.query('select', 'biu_events', { where: { id: req.params.id } });
        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Event not found' });
        }
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Error fetching event:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch event' });
    }
});

app.use('/api/events', eventRouter);
console.log('✅ [12] /api/events router registered');

// -------------------- 3.6 PUBLIC RESOURCES ROUTES -----------
const resourceRouter = express.Router();

// GET /api/resources — list all resources with optional filters
resourceRouter.get('/', cacheMiddleware(120, ['resources']), async (req, res) => {
    try {
        const { category, department, level, course_code, year, semester, limit = 100 } = req.query;

        let where = {};
        if (category && category !== 'all') where.category = category;
        if (department && department !== 'all') where.department = department;
        if (level && level !== 'all') {
            // Accept "100" or "100L" — normalize to integer
            const levelNum = parseInt(String(level).replace(/[^\d]/g, ''), 10);
            if (!isNaN(levelNum)) where.level = levelNum;
        }
        if (course_code && course_code !== 'all') where.course_code = course_code;
        if (year && year !== 'all') where.year = year;
        if (semester && semester !== 'all') where.semester = semester;

        const result = await db.query('select', 'resources', {
            where,
            order: { column: 'created_at', ascending: false },
            limit: parseInt(limit)
        });

        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        logger.error('Resources API error:', {
            message: error.message, code: error.code, requestId: req.id
        });
        if (error.message && error.message.includes('relation') && error.message.includes('does not exist')) {
            return res.status(500).json({ status: 'error', message: 'Resources table not found in database' });
        }
        res.status(500).json({ status: 'error', message: 'Failed to fetch resources' });
    }
});

// GET /api/resources/past-questions — filter category flexibly (singular OR plural)
resourceRouter.get('/past-questions', cacheMiddleware(120, ['resources']), async (req, res) => {
    try {
        const { department, level, course_code, year, semester, limit = 100 } = req.query;

        // Accept any of these common spellings so old data still works
        // Supabase `.in()` needs an array — use the operator form
        let where = {
            category: { operator: 'in', value: ['past-question', 'past-questions', 'past_question', 'Past Question', 'Past Questions'] }
        };

        if (department && department !== 'all') where.department = department;
        if (level && level !== 'all') {
            const levelNum = parseInt(String(level).replace(/[^\d]/g, ''), 10);
            if (!isNaN(levelNum)) where.level = levelNum;
        }
        if (course_code && course_code !== 'all') where.course_code = course_code;
        if (year && year !== 'all') where.year = year;
        if (semester && semester !== 'all') where.semester = semester;

        const result = await db.query('select', 'resources', {
            where,
            order: { column: 'year', ascending: false },
            limit: parseInt(limit)
        });

        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        logger.error('Past questions API error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch past questions' });
    }
});

// GET /api/resources/meta/categories — return distinct categories
// Supabase JS client does NOT support SQL DISTINCT in .select(),
// so we fetch the column and dedupe in JS.
resourceRouter.get('/meta/categories', async (req, res) => {
    try {
        const result = await db.query('select', 'resources', {
            select: 'category',
            where: { category: { operator: 'isNull', value: false } }
        });
        const categories = [...new Set(result.data.map(i => i.category).filter(Boolean))].sort();
        res.json({ status: 'success', data: categories });
    } catch (error) {
        logger.error('Error fetching categories:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch categories' });
    }
});

// GET /api/resources/meta/departments — return distinct departments
resourceRouter.get('/meta/departments', async (req, res) => {
    try {
        const result = await db.query('select', 'resources', {
            select: 'department',
            where: { department: { operator: 'isNull', value: false } }
        });
        const departments = [...new Set(result.data.map(i => i.department).filter(Boolean))].sort();
        res.json({ status: 'success', data: departments });
    } catch (error) {
        logger.error('Error fetching departments:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch departments' });
    }
});

// GET /api/resources/meta/courses — return distinct course codes/titles
resourceRouter.get('/meta/courses', async (req, res) => {
    try {
        const { department } = req.query;

        let where = { course_code: { operator: 'isNull', value: false } };
        if (department && department !== 'all') where.department = department;

        const result = await db.query('select', 'resources', {
            select: 'course_code, course_title',
            where
        });

        // Dedupe by course_code in JS (Supabase has no DISTINCT)
        const seen = new Set();
        const courses = [];
        for (const row of result.data) {
            if (!row.course_code) continue;
            const key = row.course_code.toLowerCase();
            if (seen.has(key)) continue;
            seen.add(key);
            courses.push({ course_code: row.course_code, course_title: row.course_title || '' });
        }
        courses.sort((a, b) => a.course_code.localeCompare(b.course_code));

        res.json({ status: 'success', data: courses });
    } catch (error) {
        logger.error('Error fetching courses:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch courses' });
    }
});

// POST /api/resources/:id/download — increment download count
resourceRouter.post('/:id/download', async (req, res) => {
    try {
        const getResult = await db.query('select', 'resources', {
            where: { id: req.params.id },
            select: 'download_count'
        });
        if (getResult.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Resource not found' });
        }

        const newCount = (getResult.data[0].download_count || 0) + 1;
        await db.query('update', 'resources', {
            data: { download_count: newCount, updated_at: new Date() },
            where: { id: req.params.id }
        });

        res.json({ status: 'success', data: { download_count: newCount }, message: 'Download count updated' });
    } catch (error) {
        logger.error('Error updating download count:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update download count' });
    }
});

// GET /api/resources/:id — single resource (must stay LAST — matches any single segment)
resourceRouter.get('/:id', cacheMiddleware(300, ['resources']), async (req, res) => {
    try {
        const result = await db.query('select', 'resources', { where: { id: req.params.id } });
        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Resource not found' });
        }
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Error fetching resource:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch resource' });
    }
});

app.use('/api/resources', resourceRouter);
console.log('✅ [R52] /api/resources router registered');

// -------------------- 3.7 PUBLIC ARTICLES ROUTES ------------
const articleRouter = express.Router();

articleRouter.get('/', cacheMiddleware(120, ['articles']), async (req, res) => {
    try {
        const { category, tag, limit = 50, page = 1, sort = 'published_at', order = 'desc' } = req.query;
        const offset = (page - 1) * limit;

        let where = { status: 'published', is_published: true };
        if (category && category !== 'all') where.category = category;
        if (tag) where.tags = { operator: 'contains', value: [tag] };

        const [articles, totalCount] = await Promise.all([
            db.query('select', 'articles', {
                where, order: { column: sort, ascending: order === 'asc' },
                limit: parseInt(limit), offset: parseInt(offset)
            }),
            db.query('select', 'articles', { where, count: true })
        ]);

        res.setHeader('X-Total-Count', totalCount.count || 0);
        res.setHeader('X-Page-Count', Math.ceil((totalCount.count || 0) / limit));

        res.json({
            status: 'success', data: articles.data,
            pagination: {
                page: parseInt(page), limit: parseInt(limit),
                total: totalCount.count || 0,
                pages: Math.ceil((totalCount.count || 0) / limit)
            }
        });
    } catch (error) {
        logger.error('Error fetching articles:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch articles' });
    }
});

articleRouter.get('/meta/categories', async (req, res) => {
    try {
        const result = await db.query('select', 'articles', {
            select: 'category',
            where: { category: { operator: 'isNull', value: false }, status: 'published', is_published: true }
        });
        const categories = [...new Set(result.data.map(i => i.category).filter(Boolean))].sort();
        res.json({ status: 'success', data: categories });
    } catch (error) {
        logger.error('Error fetching categories:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch categories' });
    }
});

articleRouter.get('/meta/tags', async (req, res) => {
    try {
        const result = await db.query('select', 'articles', {
            select: 'tags',
            where: { tags: { operator: 'isNull', value: false }, status: 'published', is_published: true }
        });
        const allTags = result.data.flatMap(i => i.tags || []).filter(Boolean);
        res.json({ status: 'success', data: [...new Set(allTags)] });
    } catch (error) {
        logger.error('Error fetching tags:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch tags' });
    }
});

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

app.use('/api/articles', articleRouter);
app.use('/api/news', articleRouter);
console.log('✅ Articles/News router registered at /api/articles and /api/news');

// -------------------- 3.8 PUBLIC COURSE REPS ROUTES ---------
app.get('/api/course-reps/sessions', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('course_representatives').select('session').order('session', { ascending: false });
        if (error) throw error;
        res.json({ status: 'success', data: [...new Set(data.map(i => i.session))] });
    } catch (error) {
        logger.error('Error fetching sessions:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: error.message });
    }
});

app.get('/api/course-reps/detailed', cacheMiddleware(300, ['course-reps']), async (req, res) => {
    try {
        const { session = '2025/2026', level } = req.query;

        let courseRepsQuery = supabase.from('course_representatives').select('*').eq('session', session);
        if (level && level !== 'all') courseRepsQuery = courseRepsQuery.eq('level', level);

        const { data: courseReps, error: courseRepsError } = await courseRepsQuery.order('level');
        if (courseRepsError) throw courseRepsError;
        if (!courseReps || courseReps.length === 0) return res.json({ status: 'success', data: [], count: 0 });

        const courseRepIds = courseReps.map(rep => rep.id);
        const { data: deptReps, error: deptRepsError } = await supabase
            .from('department_reps').select('*')
            .in('course_rep_id', courseRepIds).eq('session', session).eq('status', 'active');
        if (deptRepsError) throw deptRepsError;

        const deptRepsByCourseRepId = {};
        deptReps.forEach(dept => {
            if (!deptRepsByCourseRepId[dept.course_rep_id]) deptRepsByCourseRepId[dept.course_rep_id] = [];
            deptRepsByCourseRepId[dept.course_rep_id].push(dept);
        });

        const transformedData = courseReps.map(courseRep => {
            const filteredDeptReps = deptRepsByCourseRepId[courseRep.id] || [];
            return {
                level: courseRep.level,
                genRep: courseRep.gen_rep || 'Not Assigned',
                asstGenRep: courseRep.asst_gen_rep || 'Not Assigned',
                deptCount: filteredDeptReps.length,
                departments: filteredDeptReps.map(dept => ({
                    name: dept.department_name, rep: dept.representative_name || 'Pending'
                }))
            };
        });

        res.json({ status: 'success', data: transformedData, count: transformedData.length });
    } catch (error) {
        logger.error('Error fetching public course reps:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch course representatives' });
    }
});

app.get('/api/course-reps/levels', cacheMiddleware(300, ['course-reps']), async (req, res) => {
    try {
        const { session } = req.query;
        if (!session) return res.status(400).json({ status: 'error', message: 'Session parameter is required' });

        const { data, error } = await supabase
            .from('course_representatives').select('level').eq('session', session).order('level');
        if (error) throw error;

        const levels = [...new Set(data.map(i => i.level))].sort((a, b) => parseInt(a) - parseInt(b));
        res.json({ status: 'success', data: levels });
    } catch (error) {
        logger.error('Error fetching levels:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch levels' });
    }
});

app.get('/api/course-reps', async (req, res) => {
    try {
        const { session = '2025/2026', level } = req.query;
        let query = supabase.from('course_representatives').select('*').eq('session', session);
        if (level && level !== 'all') query = query.eq('level', level);

        const { data, error } = await query.order('level');
        if (error) throw error;
        res.json({ status: 'success', data, count: data.length });
    } catch (error) {
        logger.error('Error fetching course reps:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: error.message });
    }
});

// -------------------- 3.9 PUBLIC CONTACT FORM -----------------
app.post('/api/contact/submit', createRateLimiter(10), validate(schemas.contactForm), async (req, res) => {
    try {
        const { name, email, message, subject } = req.body;

        const contactData = {
            name: name.trim(), email: email.toLowerCase().trim(),
            subject: subject || 'No Subject', message: message.trim(),
            is_read: false, created_at: new Date()
        };

        try {
            await db.query('insert', 'contact_messages', { data: contactData });
        } catch (dbError) {
            if (dbError.message && dbError.message.includes('relation') && dbError.message.includes('does not exist')) {
                logger.warn('contact_messages table does not exist, skipping database save');
            } else throw dbError;
        }

        logger.info('Contact form submitted', { requestId: req.id, name, email, subject: subject || 'No subject' });
        res.json({ status: 'success', message: 'Thank you for your message! We will get back to you soon.' });
    } catch (error) {
        logger.error('Contact form error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to submit form. Please try again later.' });
    }
});

// -------------------- 3.10 PUBLIC PROFILE ROUTES -------------
app.get('/api/profile', verifyToken, async (req, res) => {
    res.json({ status: 'success', data: req.user });
});

app.put('/api/profile', verifyToken, validate(Joi.object({
    full_name: Joi.string().min(2).max(100).required(),
    department: Joi.string().optional()
})), async (req, res) => {
    try {
        const { full_name, department } = req.body;
        const result = await db.query('update', 'users', {
            data: { full_name: full_name.trim(), department: department || null, updated_at: new Date() },
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

app.put('/api/profile/password', verifyToken, validate(schemas.changePassword), async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const result = await db.query('select', 'users', { where: { id: req.user.id }, select: 'password_hash' });

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

// ============================================================
// ================== SECTION 4: ADMIN ROUTES =================
// ============================================================

// -------------------- 4.1 ADMIN AUTH ROUTES -----------------
app.post('/api/admin/login', createRateLimiter(10, 15 * 60 * 1000), validate(schemas.login), async (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;
        await checkLoginAttempts(email.toLowerCase());

        const result = await db.query('select', 'users', {
            where: { email: email.toLowerCase().trim() },
            select: 'id, email, password_hash, full_name, role, department, is_active, created_at, last_login'
        });

        if (result.data.length === 0) {
            await recordFailedAttempt(email.toLowerCase());
            logger.warn('Admin login failed - user not found', { email });
            return res.status(401).json({ status: 'error', code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });
        }

        const user = result.data[0];

        if (user.role !== 'admin') {
            logger.warn('Admin login failed - not admin', { email, role: user.role });
            return res.status(403).json({ status: 'error', code: 'FORBIDDEN', message: 'Access denied. Admin privileges required.' });
        }

        if (!user.is_active) {
            logger.warn('Admin login failed - account deactivated', { email });
            return res.status(401).json({ status: 'error', code: 'ACCOUNT_DEACTIVATED', message: 'Your account has been deactivated' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            await recordFailedAttempt(email.toLowerCase());
            logger.warn('Admin login failed - invalid password', { email });
            return res.status(401).json({ status: 'error', code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });
        }

        await resetLoginAttempts(email.toLowerCase());
        await db.query('update', 'users', { data: { last_login: new Date() }, where: { id: user.id } });

        const userResponse = authService.createUserResponse(user);
        const tokenPayload = authService.createTokenPayload(user);
        const token = authService.generateToken(tokenPayload);

        res.cookie('auth_token', token, buildCookieOptions(rememberMe));
        await cacheManager.set(`user:${user.id}`, userResponse, rememberMe ? 604800000 : 300000);

        logger.info('Admin logged in successfully', { requestId: req.id, userId: user.id, email: user.email });

        res.json({
            status: 'success',
            data: { user: userResponse, token, expiresIn: JWT_EXPIRE },
            message: 'Admin login successful'
        });
    } catch (error) {
        logger.error('Admin login error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', code: 'SERVER_ERROR', message: 'Login failed. Please try again.' });
    }
});

app.post('/api/admin/logout', verifyToken, async (req, res) => {
    try {
        await cacheManager.delete(`user:${req.user.id}`);
        res.clearCookie('auth_token', { path: '/' });
        logger.info('Admin logged out', { requestId: req.id, userId: req.user.id });
        res.json({ status: 'success', message: 'Logged out successfully' });
    } catch (error) {
        logger.error('Admin logout error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Logout failed' });
    }
});

app.get('/api/admin/session', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ status: 'error', code: 'FORBIDDEN', message: 'Not authorized' });
        }
        res.json({ status: 'success', data: req.user, message: 'Session valid' });
    } catch (error) {
        logger.error('Session check error:', { requestId: req.id, error: error.message });
        res.status(401).json({ status: 'error', code: 'INVALID_SESSION', message: 'No valid session' });
    }
});

// -------------------- 4.2 ADMIN MAIN ROUTER ------------------
const adminRouter = express.Router();
adminRouter.use(verifyToken);
adminRouter.use(requireRole('admin'));

// ==================== DASHBOARD STATS ====================
adminRouter.get('/stats', async (req, res) => {
    try {
        const [users, members, events, resources, articles, media] = await Promise.allSettled([
            db.query('select', 'users', { count: true }),
            db.query('select', 'executive_members', { count: true }),
            db.query('select', 'biu_events', { count: true }),
            db.query('select', 'resources', { count: true }),
            db.query('select', 'articles', { count: true }),
            db.query('select', 'media', { count: true })
        ]);

        res.json({
            status: 'success',
            data: {
                users: users.status === 'fulfilled' ? users.value.count || 0 : 0,
                members: members.status === 'fulfilled' ? members.value.count || 0 : 0,
                events: events.status === 'fulfilled' ? events.value.count || 0 : 0,
                resources: resources.status === 'fulfilled' ? resources.value.count || 0 : 0,
                articles: articles.status === 'fulfilled' ? articles.value.count || 0 : 0,
                media: media.status === 'fulfilled' ? media.value.count || 0 : 0,
                uptime: process.uptime(), environment: NODE_ENV
            }
        });
    } catch (error) {
        logger.error('Admin stats error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch statistics' });
    }
});

// ==================== MEMBERS MANAGEMENT ====================
adminRouter.get('/members', async (req, res) => {
    try {
        const { status, committee, search, page = 1, limit = 50 } = req.query;
        let where = {};
        if (status && status !== 'all') where.status = status;
        if (committee && committee !== 'all') where.committee = committee;
        if (search) where.full_name = { operator: 'ilike', value: `%${search}%` };

        const offset = (parseInt(page) - 1) * parseInt(limit);
        const result = await db.query('select', 'executive_members', {
            where, order: { column: 'display_order', ascending: true },
            limit: parseInt(limit), offset: parseInt(offset)
        });
        const countResult = await db.query('select', 'executive_members', { where, count: true });

        res.json({
            status: 'success', data: result.data,
            pagination: {
                page: parseInt(page), limit: parseInt(limit),
                total: countResult.count || 0,
                pages: Math.ceil((countResult.count || 0) / parseInt(limit))
            }
        });
    } catch (error) {
        logger.error('Admin members error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch members' });
    }
});

adminRouter.get('/members/:id', async (req, res) => {
    try {
        const result = await db.query('select', 'executive_members', { where: { id: req.params.id } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Member not found' });
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Admin member fetch error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch member' });
    }
});

adminRouter.post('/members', upload.single('profile_image'), async (req, res) => {
    try {
        let memberData = req.body.data ? JSON.parse(req.body.data) : req.body;
        const { full_name, position, department, level, email, phone, bio, committee, display_order, status, social_links } = memberData;

        if (!full_name || !position) {
            return res.status(400).json({ status: 'error', message: 'Full name and position are required' });
        }

        let parsedSocialLinks = {};
        if (social_links) {
            try { parsedSocialLinks = typeof social_links === 'string' ? JSON.parse(social_links) : social_links; }
            catch { parsedSocialLinks = {}; }
        }

        const newMember = {
            full_name: full_name?.trim(), position: position?.trim(),
            department: department?.trim() || null, level: level?.trim() || null,
            email: email?.toLowerCase().trim() || null, phone: phone?.trim() || null,
            bio: bio?.trim() || null, committee: committee?.trim() || null,
            display_order: display_order ? parseInt(display_order) : 0,
            status: status || 'active', social_links: parsedSocialLinks,
            created_at: new Date().toISOString(), updated_at: new Date().toISOString()
        };

        if (req.file) newMember.profile_image = `/uploads/${req.file.filename}`;

        const result = await db.query('insert', 'executive_members', { data: newMember });
        await cacheManager.invalidateByTags(['members']);

        logger.info('Admin created member', { requestId: req.id, memberId: result.data[0].id, hasPhoto: !!req.file });
        res.status(201).json({ status: 'success', data: result.data[0], message: 'Member created successfully' });
    } catch (error) {
        logger.error('Admin create member error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to create member' });
    }
});

adminRouter.put('/members/:id', upload.single('profile_image'), async (req, res) => {
    try {
        let memberData = req.body.data ? JSON.parse(req.body.data) : req.body;
        const updateData = {};
        const fields = ['full_name', 'position', 'department', 'level', 'email', 'phone', 'bio', 'committee', 'display_order', 'status', 'social_links'];

        fields.forEach(field => {
            if (memberData[field] !== undefined && memberData[field] !== null) {
                if (field === 'email') updateData[field] = memberData[field]?.toLowerCase().trim();
                else if (field === 'display_order') updateData[field] = parseInt(memberData[field]);
                else if (field === 'social_links') {
                    try { updateData[field] = typeof memberData[field] === 'string' ? JSON.parse(memberData[field]) : memberData[field]; }
                    catch { updateData[field] = {}; }
                } else if (typeof memberData[field] === 'string') updateData[field] = memberData[field].trim();
                else updateData[field] = memberData[field];
            }
        });

        if (req.file) updateData.profile_image = `/uploads/${req.file.filename}`;
        updateData.updated_at = new Date().toISOString();

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ status: 'error', message: 'No fields to update' });
        }

        const result = await db.query('update', 'executive_members', { data: updateData, where: { id: req.params.id } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Member not found' });

        await cacheManager.invalidateByTags(['members']);
        logger.info('Member updated', { requestId: req.id, memberId: req.params.id, photoUpdated: !!req.file });
        res.json({ status: 'success', data: result.data[0], message: 'Member updated successfully' });
    } catch (error) {
        logger.error('Admin update member error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update member' });
    }
});

adminRouter.delete('/members/:id', async (req, res) => {
    try {
        const checkResult = await db.query('select', 'executive_members', {
            where: { id: req.params.id }, select: 'id, profile_image'
        });
        if (checkResult.data.length === 0) return res.status(404).json({ status: 'error', message: 'Member not found' });

        await db.query('delete', 'executive_members', { where: { id: req.params.id } });

        const profileImage = checkResult.data[0].profile_image;
        if (profileImage) {
            const filename = profileImage.split('/').pop();
            const filePath = path.join(__dirname, 'uploads', filename);
            try { await fs.unlink(filePath); }
            catch (fileError) { logger.warn('Could not delete profile image file', { error: fileError.message }); }
        }

        await cacheManager.invalidateByTags(['members']);
        logger.info('Member deleted', { requestId: req.id, memberId: req.params.id, deletedBy: req.user.id });
        res.json({ status: 'success', message: 'Member deleted successfully' });
    } catch (error) {
        logger.error('Admin delete member error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete member' });
    }
});

adminRouter.post('/members/:id/photo', upload.single('photo'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ status: 'error', message: 'No photo file uploaded' });

        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (!allowedTypes.includes(req.file.mimetype)) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ status: 'error', message: 'Invalid file type. Only JPEG, PNG, GIF, and WEBP are allowed.' });
        }

        if (req.file.size > 5 * 1024 * 1024) {
            await fs.unlink(req.file.path);
            return res.status(400).json({ status: 'error', message: 'File too large. Maximum size is 5MB.' });
        }

        const checkResult = await db.query('select', 'executive_members', {
            where: { id: req.params.id }, select: 'id, profile_image'
        });
        if (checkResult.data.length === 0) {
            await fs.unlink(req.file.path);
            return res.status(404).json({ status: 'error', message: 'Member not found' });
        }

        const oldProfileImage = checkResult.data[0].profile_image;
        if (oldProfileImage) {
            const oldFilename = oldProfileImage.split('/').pop();
            const oldFilePath = path.join(__dirname, 'uploads', oldFilename);
            try { await fs.unlink(oldFilePath); }
            catch (fileError) { logger.warn('Could not delete old profile image', { error: fileError.message }); }
        }

        const photoUrl = `/uploads/${req.file.filename}`;
        const result = await db.query('update', 'executive_members', {
            data: { profile_image: photoUrl, updated_at: new Date().toISOString() },
            where: { id: req.params.id }
        });

        await cacheManager.invalidateByTags(['members']);
        logger.info('Member photo uploaded', { requestId: req.id, memberId: req.params.id, filename: req.file.filename });
        res.json({ status: 'success', data: { photo_url: photoUrl, member: result.data[0] }, message: 'Photo uploaded successfully' });
    } catch (error) {
        if (req.file && req.file.path) {
            try { await fs.unlink(req.file.path); }
            catch (unlinkError) { logger.error('Failed to clean up file', { error: unlinkError.message }); }
        }
        logger.error('Member photo upload error:', { requestId: req.id, error: error.message, memberId: req.params.id });
        res.status(500).json({ status: 'error', message: 'Failed to upload photo' });
    }
});

adminRouter.patch('/members/:id/session', async (req, res) => {
    try {
        const { session } = req.body;
        if (!session) return res.status(400).json({ status: 'error', message: 'Session is required' });

        const result = await db.query('update', 'executive_members', {
            data: { session, updated_at: new Date().toISOString() }, where: { id: req.params.id }
        });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Member not found' });

        await cacheManager.invalidateByTags(['members']);
        logger.info('Member session updated', { requestId: req.id, memberId: req.params.id, session });
        res.json({ status: 'success', data: result.data[0], message: 'Member session updated successfully' });
    } catch (error) {
        logger.error('Error updating member session:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update session' });
    }
});

adminRouter.patch('/members/bulk/status', async (req, res) => {
    try {
        const { memberIds, status } = req.body;
        if (!memberIds || !Array.isArray(memberIds) || memberIds.length === 0) {
            return res.status(400).json({ status: 'error', message: 'Member IDs array is required' });
        }
        if (!status || !['active', 'inactive', 'alumni'].includes(status)) {
            return res.status(400).json({ status: 'error', message: 'Valid status is required' });
        }

        const result = await db.query('update', 'executive_members', {
            data: { status, updated_at: new Date().toISOString() },
            where: { id: { operator: 'in', value: memberIds } }
        });

        await cacheManager.invalidateByTags(['members']);
        res.json({ status: 'success', message: `Updated ${result.data.length} members successfully`, data: result.data });
    } catch (error) {
        logger.error('Bulk status update error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update members' });
    }
});

adminRouter.delete('/members/bulk/delete', async (req, res) => {
    try {
        const { memberIds } = req.body;
        if (!memberIds || !Array.isArray(memberIds) || memberIds.length === 0) {
            return res.status(400).json({ status: 'error', message: 'Member IDs array is required' });
        }

        const imagesResult = await db.query('select', 'executive_members', {
            where: { id: { operator: 'in', value: memberIds } }, select: 'profile_image'
        });
        const result = await db.query('delete', 'executive_members', { where: { id: { operator: 'in', value: memberIds } } });

        for (const member of imagesResult.data) {
            if (member.profile_image) {
                const filename = member.profile_image.split('/').pop();
                const filePath = path.join(__dirname, 'uploads', filename);
                try { await fs.unlink(filePath); }
                catch (fileError) { logger.warn('Could not delete image', { error: fileError.message }); }
            }
        }

        await cacheManager.invalidateByTags(['members']);
        res.json({ status: 'success', message: `Deleted ${result.data.length} members successfully` });
    } catch (error) {
        logger.error('Bulk delete error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete members' });
    }
});

// ==================== EVENTS MANAGEMENT ====================
adminRouter.get('/events', async (req, res) => {
    try {
        const { status, category } = req.query;
        let where = {};
        if (status && status !== 'all') where.status = status;
        if (category && category !== 'all') where.category = category;

        const result = await db.query('select', 'biu_events', { where, order: { column: 'date', ascending: true } });
        res.json({ status: 'success', data: result.data });
    } catch (error) {
        logger.error('Admin events error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch events' });
    }
});

adminRouter.get('/events/:id', async (req, res) => {
    try {
        const result = await db.query('select', 'biu_events', { where: { id: req.params.id } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Event not found' });
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Admin event fetch error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch event' });
    }
});

adminRouter.post('/events', async (req, res) => {
    try {
        const { title, description, date, start_time, end_time, location, category, organizer, max_participants, status } = req.body;
        const eventData = {
            title: title?.trim(), description: description?.trim(), date, start_time, end_time,
            location: location?.trim(), category: category?.trim(), organizer: organizer?.trim(),
            max_participants: max_participants ? parseInt(max_participants) : null,
            status: status || 'upcoming', created_at: new Date(), updated_at: new Date()
        };

        const result = await db.query('insert', 'biu_events', { data: eventData });
        await cacheManager.invalidateByTags(['biu_events']);
        res.status(201).json({ status: 'success', data: result.data[0], message: 'Event created successfully' });
    } catch (error) {
        logger.error('Admin create event error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to create event' });
    }
});

adminRouter.put('/events/:id', async (req, res) => {
    try {
        const { title, description, date, start_time, end_time, location, category, organizer, max_participants, status } = req.body;
        const updateData = {
            title: title?.trim(), description: description?.trim(), date, start_time, end_time,
            location: location?.trim(), category: category?.trim(), organizer: organizer?.trim(),
            max_participants: max_participants ? parseInt(max_participants) : null,
            status, updated_at: new Date()
        };

        Object.keys(updateData).forEach(key => updateData[key] === undefined && delete updateData[key]);

        const result = await db.query('update', 'biu_events', { data: updateData, where: { id: req.params.id } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Event not found' });

        await cacheManager.invalidateByTags(['biu_events']);
        res.json({ status: 'success', data: result.data[0], message: 'Event updated successfully' });
    } catch (error) {
        logger.error('Admin update event error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update event' });
    }
});

adminRouter.delete('/events/:id', async (req, res) => {
    try {
        const result = await db.query('delete', 'biu_events', { where: { id: req.params.id } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Event not found' });
        await cacheManager.invalidateByTags(['biu_events']);
        res.json({ status: 'success', message: 'Event deleted successfully' });
    } catch (error) {
        logger.error('Admin delete event error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete event' });
    }
});

// ==================== RESOURCES MANAGEMENT ====================
adminRouter.get('/resources', async (req, res) => {
    try {
        const { category, department } = req.query;
        let where = {};
        if (category && category !== 'all') where.category = category;
        if (department && department !== 'all') where.department = department;

        const result = await db.query('select', 'resources', { where, order: { column: 'created_at', ascending: false } });
        res.json({ status: 'success', data: result.data });
    } catch (error) {
        logger.error('Admin resources error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch resources' });
    }
});

adminRouter.get('/resources/:id', async (req, res) => {
    try {
        const result = await db.query('select', 'resources', { where: { id: req.params.id } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Resource not found' });
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Admin resource fetch error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch resource' });
    }
});

adminRouter.post('/resources', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ status: 'error', message: 'No file uploaded' });

        const resourceData = JSON.parse(req.body.data || '{}');
        const newResource = {
            uuid: uuid.v4(),
            title: resourceData.title?.trim(), category: resourceData.category?.trim(),
            description: resourceData.description?.trim(), department: resourceData.department?.trim(),
            course_code: resourceData.course_code?.trim(), course_title: resourceData.course_title?.trim(),
            year: resourceData.year, semester: resourceData.semester,
            level: resourceData.level ? parseInt(resourceData.level) : null,
            file_url: `/uploads/${req.file.filename}`,
            file_size: req.file.size, file_type: req.file.mimetype,
            download_count: 0, uploaded_by: req.user.id, created_at: new Date()
        };

        const result = await db.query('insert', 'resources', { data: newResource });
        await cacheManager.invalidateByTags(['resources']);
        res.status(201).json({ status: 'success', data: result.data[0], message: 'Resource uploaded successfully' });
    } catch (error) {
        logger.error('Admin upload resource error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to upload resource' });
    }
});

adminRouter.delete('/resources/:id', async (req, res) => {
    try {
        const result = await db.query('delete', 'resources', { where: { id: req.params.id } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Resource not found' });
        await cacheManager.invalidateByTags(['resources']);
        res.json({ status: 'success', message: 'Resource deleted successfully' });
    } catch (error) {
        logger.error('Admin delete resource error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete resource' });
    }
});

// ==================== MEDIA LIBRARY ====================
function inferMediaType(mime) {
    return mime && mime.startsWith('video/') ? 'video' : 'picture';
}

function buildMediaPublicUrl(absPath) {
    const rel = path.relative(path.join(__dirname, 'uploads'), absPath).split(path.sep).join('/');
    return `/uploads/${rel}`;
}

function shapeMediaRow(m) {
    return {
        id: m.id,
        title: m.title,
        filename: m.filename,
        url: m.file_url,
        thumbnail_url: m.thumbnail_url,
        file_type: m.file_type,
        type: m.media_type,                  // 'picture' | 'video'
        size_bytes: m.size_bytes,
        dimensions: (m.width && m.height) ? `${m.width} × ${m.height}` : null,
        width: m.width,
        height: m.height,
        duration: m.duration,
        alt_text: m.alt_text,
        description: m.description,
        tags: m.tags || [],
        usage: m.usage || [],
        uploader_name: m.uploader_name,
        created_at: m.created_at,
        updated_at: m.updated_at
    };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function requireUuidParam(res, id) {
    if (!UUID_RE.test(id)) {
        res.status(400).json({ status: 'error', message: 'Invalid media ID format' });
        return false;
    }
    return true;
}

// GET /api/admin/media — list all pictures + videos
adminRouter.get('/media', async (req, res) => {
    try {
        const { type, search, sort = 'newest' } = req.query;
        let where = {};
        if (type && type !== 'all') where.media_type = type;
        if (search) where.title = { operator: 'ilike', value: `%${search}%` };

        let orderCol = 'created_at';
        let ascending = false;
        if (sort === 'oldest')        { ascending = true; }
        else if (sort === 'size_desc') { orderCol = 'size_bytes'; ascending = false; }
        else if (sort === 'size_asc')  { orderCol = 'size_bytes'; ascending = true; }

        const result = await db.query('select', 'media', {
            where,
            order: { column: orderCol, ascending }
        });

        const mapped = result.data.map(shapeMediaRow);

        res.json({
            status: 'success',
            data: mapped,
            count: mapped.length,
            counts: {
                all: mapped.length,
                pictures: mapped.filter(m => m.type === 'picture').length,
                videos: mapped.filter(m => m.type === 'video').length,
                total_bytes: mapped.reduce((sum, m) => sum + (m.size_bytes || 0), 0)
            }
        });
    } catch (error) {
        logger.error('Admin media list error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch media' });
    }
});

// POST /api/admin/media — multipart upload (single file per request)
adminRouter.post('/media', mediaUpload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ status: 'error', message: 'No file uploaded' });
        }

        const isVideo = (req.file.mimetype || '').startsWith('video/');
        const mediaType = isVideo ? 'video' : 'picture';

        // Build a unique path inside the bucket, e.g.
        //   images/2026-11-14/biu-poster-1731600000000.jpg
        const ext = path.extname(req.file.originalname).toLowerCase();
        const safeName = path.basename(req.file.originalname, ext)
            .replace(/[^a-zA-Z0-9_-]/g, '_')
            .substring(0, 50) || 'file';
        const datePart = new Date().toISOString().split('T')[0];
        const storageKey = `${isVideo ? 'videos' : 'images'}/${datePart}/${safeName}-${Date.now()}${ext}`;

        // Read the temp file multer just saved to disk
        const fileBuffer = await fs.readFile(req.file.path);

        // Upload to Supabase Storage
        const { error: uploadErr } = await supabase.storage
            .from(STORAGE_BUCKET)
            .upload(storageKey, fileBuffer, {
                contentType: req.file.mimetype,
                upsert: false,
                cacheControl: '31536000'   // 1 year — files never change
            });

        if (uploadErr) throw uploadErr;

        // Get the permanent public URL
        const { data: urlData } = supabase.storage
            .from(STORAGE_BUCKET)
            .getPublicUrl(storageKey);
        const publicUrl = urlData.publicUrl;

        // Clean up the temp file that multer left on Render's disk
        try { await fs.unlink(req.file.path); } catch {}

        // Parse tags — same as before
        let tags = [];
        if (req.body.tags) {
            try {
                const parsed = JSON.parse(req.body.tags);
                tags = Array.isArray(parsed) ? parsed : [parsed];
            } catch {
                tags = String(req.body.tags).split(',').map(t => t.trim()).filter(Boolean);
            }
        }
        tags = tags.map(String).map(t => t.trim()).filter(Boolean);

        const title = (req.body.title || req.file.originalname.replace(/\.[^.]+$/, '')).toString().trim();

        const newMedia = {
            title,
            filename: req.file.originalname,
            file_url: publicUrl,               // ← permanent https://xyz.supabase.co/storage/...
            file_type: req.file.mimetype,
            media_type: mediaType,
            size_bytes: req.file.size,
            width: req.body.width ? parseInt(req.body.width) : null,
            height: req.body.height ? parseInt(req.body.height) : null,
            duration: req.body.duration ? parseFloat(req.body.duration) : null,
            thumbnail_url: req.body.thumbnail_url || null,
            description: req.body.description ? String(req.body.description).trim() : null,
            alt_text: req.body.alt_text ? String(req.body.alt_text).trim() : null,
            tags,
            usage: [],
            uploader_id: req.user.id,
            uploader_name: req.user.fullName || req.user.email || 'Admin'
        };

        const result = await db.query('insert', 'media', { data: newMedia });
        const saved = result.data[0];

        logger.info('Media uploaded to Supabase Storage', {
            requestId: req.id, mediaId: saved.id, storageKey, type: mediaType
        });

        res.status(201).json({
            status: 'success',
            data: shapeMediaRow(saved),
            message: 'Media uploaded successfully'
        });
    } catch (error) {
        if (req.file && req.file.path) {
            try { await fs.unlink(req.file.path); } catch {}
        }

        logger.error('Admin media upload error:', {
            requestId: req.id, error: error.message, code: error.code
        });

        if (error instanceof multer.MulterError) {
            if (error.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({
                    status: 'error',
                    message: `File too large. Maximum size is ${Math.round(MAX_MEDIA_FILE_SIZE / 1024 / 1024)}MB.`
                });
            }
            return res.status(400).json({ status: 'error', message: error.message });
        }

        res.status(500).json({ status: 'error', message: error.message || 'Failed to upload media' });
    }
});

// ==================== ADMIN: GALLERY MANAGEMENT ====================
// GET /api/admin/media/gallery — list all gallery items
adminRouter.get('/media/gallery', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('media_gallery')
            .select(`
                id, media_id, title, description, category, status, display_order,
                created_at, updated_at,
                media:media!media_gallery_media_id_fkey(
                    id, title, file_url, thumbnail_url, file_type, media_type, size_bytes
                )
            `)
            .order('display_order', { ascending: true })
            .order('created_at', { ascending: false });

        if (error) throw error;

        const mapped = (data || []).map(g => ({
            id: g.id,
            media_id: g.media_id,
            title: g.title,
            description: g.description,
            category: g.category,
            status: g.status,
            published: g.status === 'published',
            order: g.display_order,
            created_at: g.created_at,
            updated_at: g.updated_at,
            media: g.media ? {
                id: g.media.id,
                url: g.media.file_url,
                thumbnail_url: g.media.thumbnail_url || g.media.file_url,
                mime_type: g.media.file_type,
                type: g.media.media_type,
                size_bytes: g.media.size_bytes
            } : null
        }));

        res.json({ status: 'success', data: mapped, count: mapped.length });
    } catch (error) {
        logger.error('Admin gallery list error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch gallery' });
    }
});

// POST /api/admin/media/gallery — send a media item to the gallery
adminRouter.post('/media/gallery', async (req, res) => {
    try {
        const { media_id, title, description, category, status, display_order } = req.body;

        if (!media_id) {
            return res.status(400).json({ status: 'error', message: 'media_id is required' });
        }
        if (!title || !String(title).trim()) {
            return res.status(400).json({ status: 'error', message: 'title is required' });
        }

        const { data: media, error: mediaErr } = await supabase
            .from('media')
            .select('id, title')
            .eq('id', media_id)
            .maybeSingle();

        if (mediaErr) throw mediaErr;
        if (!media) {
            return res.status(404).json({ status: 'error', message: 'Media not found' });
        }

        const { data: existing } = await supabase
            .from('media_gallery')
            .select('id')
            .eq('media_id', media_id)
            .maybeSingle();

        if (existing) {
            return res.status(409).json({
                status: 'error',
                message: 'This media is already in the gallery. Edit the existing entry instead.'
            });
        }

        const finalStatus = (status === 'published') ? 'published' : 'draft';

        const { data, error } = await supabase
            .from('media_gallery')
            .insert([{
                media_id,
                title: String(title).trim(),
                description: description ? String(description).trim() : null,
                category: (category || 'events').toLowerCase(),
                status: finalStatus,
                display_order: Number.isFinite(parseInt(display_order)) ? parseInt(display_order) : 0,
                created_by: req.user.id
            }])
            .select()
            .single();

        if (error) throw error;

        logger.info('Gallery item created', {
            requestId: req.id, galleryId: data.id, mediaId: media_id, status: finalStatus
        });

        res.status(201).json({ status: 'success', data, message: 'Sent to gallery' });
    } catch (error) {
        logger.error('Admin gallery create error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: error.message || 'Failed to send to gallery' });
    }
});

// PUT /api/admin/media/gallery/:id — edit a gallery item
adminRouter.put('/media/gallery/:id', async (req, res) => {
    try {
        const { title, description, category, status, display_order } = req.body;
        const updateData = { updated_at: new Date().toISOString() };

        if (title !== undefined) updateData.title = String(title).trim();
        if (description !== undefined) updateData.description = description ? String(description).trim() : null;
        if (category !== undefined) updateData.category = String(category).toLowerCase();
        if (status !== undefined) updateData.status = status === 'published' ? 'published' : 'draft';
        if (display_order !== undefined) updateData.display_order = parseInt(display_order) || 0;

        const { data, error } = await supabase
            .from('media_gallery')
            .update(updateData)
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Gallery item not found' });

        logger.info('Gallery item updated', { requestId: req.id, galleryId: req.params.id });
        res.json({ status: 'success', data, message: 'Gallery item updated' });
    } catch (error) {
        logger.error('Admin gallery update error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update gallery item' });
    }
});

// PATCH /api/admin/media/gallery/:id — quick status toggle
adminRouter.patch('/media/gallery/:id', async (req, res) => {
    try {
        const { status } = req.body;
        if (!['draft', 'published'].includes(status)) {
            return res.status(400).json({ status: 'error', message: 'status must be draft or published' });
        }

        const { data, error } = await supabase
            .from('media_gallery')
            .update({ status, updated_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Gallery item not found' });

        res.json({ status: 'success', data, message: `Gallery item ${status}` });
    } catch (error) {
        logger.error('Admin gallery toggle error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update gallery status' });
    }
});

// DELETE /api/admin/media/gallery/:id — remove from gallery (keeps media file)
adminRouter.delete('/media/gallery/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('media_gallery')
            .delete()
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Gallery item not found' });

        logger.info('Gallery item removed', { requestId: req.id, galleryId: req.params.id });
        res.json({ status: 'success', message: 'Removed from gallery (file kept in Media Library)' });
    } catch (error) {
        logger.error('Admin gallery delete error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to remove from gallery' });
    }
});

// ==================== ADMIN: HOMEPAGE PLACEMENT ====================
// GET /api/admin/media/placements/homepage-hero
adminRouter.get('/media/placements/homepage-hero', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('media_placements')
            .select(`
                id, slot, media_id, updated_at,
                media:media!media_placements_media_id_fkey(
                    id, title, file_url, thumbnail_url, media_type)
            `)
            .eq('slot', 'homepage-hero')
            .maybeSingle();

        if (error && error.code !== 'PGRST116') throw error;

        if (!data) {
            return res.json({ status: 'success', data: null });
        }

        res.json({
            status: 'success',
            data: {
                media_id: data.media_id,
                url: data.media?.file_url || null,
                thumbnail_url: data.media?.thumbnail_url || null,
                title: data.media?.title || null,
                updated_at: data.updated_at
            }
        });
    } catch (error) {
        logger.error('Admin placement get error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch placement' });
    }
});

// PUT /api/admin/media/placements/homepage-hero
adminRouter.put('/media/placements/homepage-hero', async (req, res) => {
    try {
        const { media_id } = req.body;
        if (!media_id) {
            return res.status(400).json({ status: 'error', message: 'media_id is required' });
        }

        const { data: media, error: mediaErr } = await supabase
            .from('media')
            .select('id, media_type, file_url, thumbnail_url, title')
            .eq('id', media_id)
            .maybeSingle();

        if (mediaErr) throw mediaErr;
        if (!media) return res.status(404).json({ status: 'error', message: 'Media not found' });
        if (media.media_type !== 'picture') {
            return res.status(400).json({ status: 'error', message: 'Only pictures can be used for the homepage hero' });
        }

        const { data, error } = await supabase
            .from('media_placements')
            .upsert({
                slot: 'homepage-hero',
                media_id,
                updated_by: req.user.id,
                updated_at: new Date().toISOString()
            }, { onConflict: 'slot' })
            .select()
            .single();

        if (error) throw error;

        logger.info('Homepage hero placement set', {
            requestId: req.id, mediaId: media_id, by: req.user.id
        });

        res.json({
            status: 'success',
            data: {
                media_id: data.media_id,
                url: media.file_url,
                thumbnail_url: media.thumbnail_url || media.file_url,
                title: media.title,
                updated_at: data.updated_at
            },
            message: 'Homepage hero image updated'
        });
    } catch (error) {
        logger.error('Admin placement set error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update placement' });
    }
});

// DELETE /api/admin/media/placements/homepage-hero
adminRouter.delete('/media/placements/homepage-hero', async (req, res) => {
    try {
        await supabase.from('media_placements').delete().eq('slot', 'homepage-hero');
        logger.info('Homepage hero placement cleared', { requestId: req.id, by: req.user.id });
        res.json({ status: 'success', message: 'Homepage hero image cleared' });
    } catch (error) {
        logger.error('Admin placement delete error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to clear placement' });
    }
});

// GET /api/admin/media/:id — single item
adminRouter.get('/media/:id', async (req, res) => {
    if (!requireUuidParam(res, req.params.id)) return;
    try {
        const result = await db.query('select', 'media', { where: { id: req.params.id } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Media not found' });
        res.json({ status: 'success', data: shapeMediaRow(result.data[0]) });
    } catch (error) {
        logger.error('Admin media fetch error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch media' });
    }
});

// PUT /api/admin/media/:id — edit metadata only
adminRouter.put('/media/:id', validate(schemas.updateMedia), async (req, res) => {
    if (!requireUuidParam(res, req.params.id)) return;
    try {
        const { title, description, alt_text, tags } = req.body;
        const updateData = { updated_at: new Date().toISOString() };

        if (title !== undefined)       updateData.title = String(title).trim();
        if (description !== undefined) updateData.description = description ? String(description).trim() : null;
        if (alt_text !== undefined)    updateData.alt_text = alt_text ? String(alt_text).trim() : null;
        if (tags !== undefined) {
            if (Array.isArray(tags)) updateData.tags = tags.map(String).map(t => t.trim()).filter(Boolean);
            else if (typeof tags === 'string') updateData.tags = tags.split(',').map(t => t.trim()).filter(Boolean);
            else updateData.tags = [];
        }

        const result = await db.query('update', 'media', {
            data: updateData,
            where: { id: req.params.id }
        });

        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Media not found' });
        }

        logger.info('Media updated', { requestId: req.id, mediaId: req.params.id, updatedBy: req.user.id });
        res.json({ status: 'success', data: shapeMediaRow(result.data[0]), message: 'Media updated successfully' });
    } catch (error) {
        logger.error('Admin media update error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update media' });
    }
});

// DELETE /api/admin/media/:id — remove DB row + file on disk
adminRouter.delete('/media/:id', async (req, res) => {
    if (!requireUuidParam(res, req.params.id)) return;
    try {
        const checkResult = await db.query('select', 'media', {
            where: { id: req.params.id },
            select: 'id, file_url, title'
        });

        if (checkResult.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Media not found' });
        }

        const { file_url, title } = checkResult.data[0];

        // Delete from Supabase Storage if the URL is a storage URL
        if (file_url && file_url.includes(`/storage/v1/object/public/${STORAGE_BUCKET}/`)) {
            const storageKey = decodeURIComponent(
                file_url.split(`/storage/v1/object/public/${STORAGE_BUCKET}/`)[1] || ''
            );
            if (storageKey) {
                try {
                    const { error: storageErr } = await supabase.storage
                        .from(STORAGE_BUCKET)
                        .remove([storageKey]);
                    if (storageErr) throw storageErr;
                } catch (storageErr) {
                    logger.warn('Could not delete storage object', {
                        requestId: req.id, storageKey, error: storageErr.message
                    });
                }
            }
        }

        await db.query('delete', 'media', { where: { id: req.params.id } });

        logger.info('Media deleted', {
            requestId: req.id, mediaId: req.params.id, title, deletedBy: req.user.id
        });

        res.json({ status: 'success', message: 'Media deleted successfully' });
    } catch (error) {
        logger.error('Admin media delete error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete media' });
    }
});

// ==================== ADMIN: GALLERY MANAGEMENT ====================
// GET /api/admin/media/gallery — list all gallery items
adminRouter.get('/media/gallery', async (req, res) => {
    try {

        const { data, error } = await supabase
            .from('media_gallery')
            .select(`
                id, media_id, title, description, category, status, display_order,
                created_at, updated_at,
                media:media!media_gallery_media_id_fkey(
                    id, title, file_url, thumbnail_url, file_type, media_type, size_bytes
                )
            `)
            .order('display_order', { ascending: true })
            .order('created_at', { ascending: false });

        if (error) throw error;

        const mapped = (data || []).map(g => ({
            id: g.id,
            media_id: g.media_id,
            title: g.title,
            description: g.description,
            category: g.category,
            status: g.status,
            published: g.status === 'published',
            order: g.display_order,
            created_at: g.created_at,
            updated_at: g.updated_at,
            media: g.media ? {
                id: g.media.id,
                url: g.media.file_url,
                thumbnail_url: g.media.thumbnail_url || g.media.file_url,
                mime_type: g.media.file_type,
                type: g.media.media_type,
                size_bytes: g.media.size_bytes
            } : null
        }));

        res.json({ status: 'success', data: mapped, count: mapped.length });
    } catch (error) {
        logger.error('Admin gallery list error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch gallery' });
    }
});

// POST /api/admin/media/gallery — send a media item to the gallery
adminRouter.post('/media/gallery', async (req, res) => {
    try {
        const { media_id, title, description, category, status, display_order } = req.body;

        if (!media_id) {
            return res.status(400).json({ status: 'error', message: 'media_id is required' });
        }
        if (!title || !String(title).trim()) {
            return res.status(400).json({ status: 'error', message: 'title is required' });
        }

        // Verify media exists
        const { data: media, error: mediaErr } = await supabase
            .from('media')
            .select('id, title')
            .eq('id', media_id)
            .maybeSingle();

        if (mediaErr) throw mediaErr;
        if (!media) {
            return res.status(404).json({ status: 'error', message: 'Media not found' });
        }

        // Reject duplicates (one gallery entry per media)
        const { data: existing } = await supabase
            .from('media_gallery')
            .select('id')
            .eq('media_id', media_id)
            .maybeSingle();

        if (existing) {
            return res.status(409).json({
                status: 'error',
                message: 'This media is already in the gallery. Edit the existing entry instead.'
            });
        }

        const finalStatus = (status === 'published') ? 'published' : 'draft';

        const { data, error } = await supabase
            .from('media_gallery')
            .insert([{
                media_id,
                title: String(title).trim(),
                description: description ? String(description).trim() : null,
                category: (category || 'events').toLowerCase(),
                status: finalStatus,
                display_order: Number.isFinite(parseInt(display_order)) ? parseInt(display_order) : 0,
                created_by: req.user.id
            }])
            .select()
            .single();

        if (error) throw error;

        logger.info('Gallery item created', {
            requestId: req.id, galleryId: data.id, mediaId: media_id, status: finalStatus
        });

        res.status(201).json({ status: 'success', data, message: 'Sent to gallery' });
    } catch (error) {
        logger.error('Admin gallery create error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: error.message || 'Failed to send to gallery' });
    }
});

// PUT /api/admin/media/gallery/:id — edit a gallery item
adminRouter.put('/media/gallery/:id', async (req, res) => {
    try {
        const { title, description, category, status, display_order } = req.body;
        const updateData = { updated_at: new Date().toISOString() };

        if (title !== undefined) updateData.title = String(title).trim();
        if (description !== undefined) updateData.description = description ? String(description).trim() : null;
        if (category !== undefined) updateData.category = String(category).toLowerCase();
        if (status !== undefined) updateData.status = status === 'published' ? 'published' : 'draft';
        if (display_order !== undefined) updateData.display_order = parseInt(display_order) || 0;

        const { data, error } = await supabase
            .from('media_gallery')
            .update(updateData)
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Gallery item not found' });

        logger.info('Gallery item updated', { requestId: req.id, galleryId: req.params.id });
        res.json({ status: 'success', data, message: 'Gallery item updated' });
    } catch (error) {
        logger.error('Admin gallery update error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update gallery item' });
    }
});

// PATCH /api/admin/media/gallery/:id — quick status toggle
adminRouter.patch('/media/gallery/:id', async (req, res) => {
    try {
        const { status } = req.body;
        if (!['draft', 'published'].includes(status)) {
            return res.status(400).json({ status: 'error', message: 'status must be draft or published' });
        }

        const { data, error } = await supabase
            .from('media_gallery')
            .update({ status, updated_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Gallery item not found' });

        res.json({ status: 'success', data, message: `Gallery item ${status}` });
    } catch (error) {
        logger.error('Admin gallery toggle error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update gallery status' });
    }
});

// DELETE /api/admin/media/gallery/:id — remove from gallery (keeps media file)
adminRouter.delete('/media/gallery/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('media_gallery')
            .delete()
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Gallery item not found' });

        logger.info('Gallery item removed', { requestId: req.id, galleryId: req.params.id });
        res.json({ status: 'success', message: 'Removed from gallery (file kept in Media Library)' });
    } catch (error) {
        logger.error('Admin gallery delete error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to remove from gallery' });
    }
});

// ==================== ADMIN: HOMEPAGE PLACEMENT ====================

// GET /api/admin/media/placements/homepage-hero
adminRouter.get('/media/placements/homepage-hero', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('media_placements')
            .select(`
                id, slot, media_id, updated_at,
                media:media!media_placements_media_id_fkey(
                    id, title, file_url, thumbnail_url, media_type)
            `)
            .eq('slot', 'homepage-hero')
            .maybeSingle();

        if (error && error.code !== 'PGRST116') throw error;

        if (!data) {
            return res.json({ status: 'success', data: null });
        }

        res.json({
            status: 'success',
            data: {
                media_id: data.media_id,
                url: data.media?.file_url || null,
                thumbnail_url: data.media?.thumbnail_url || null,
                title: data.media?.title || null,
                updated_at: data.updated_at
            }
        });
    } catch (error) {
        logger.error('Admin placement get error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch placement' });
    }
});

// PUT /api/admin/media/placements/homepage-hero
adminRouter.put('/media/placements/homepage-hero', async (req, res) => {
    try {
        const { media_id } = req.body;
        if (!media_id) {
            return res.status(400).json({ status: 'error', message: 'media_id is required' });
        }

        // Verify media exists and is a picture
        const { data: media, error: mediaErr } = await supabase
            .from('media')
            .select('id, media_type, file_url, thumbnail_url, title')
            .eq('id', media_id)
            .maybeSingle();

        if (mediaErr) throw mediaErr;
        if (!media) return res.status(404).json({ status: 'error', message: 'Media not found' });
        if (media.media_type !== 'picture') {
            return res.status(400).json({ status: 'error', message: 'Only pictures can be used for the homepage hero' });
        }

        // Upsert (one row per slot)
        const { data, error } = await supabase
            .from('media_placements')
            .upsert({
                slot: 'homepage-hero',
                media_id,
                updated_by: req.user.id,
                updated_at: new Date().toISOString()
            }, { onConflict: 'slot' })
            .select()
            .single();

        if (error) throw error;

        logger.info('Homepage hero placement set', {
            requestId: req.id, mediaId: media_id, by: req.user.id
        });

        res.json({
            status: 'success',
            data: {
                media_id: data.media_id,
                url: media.file_url,
                thumbnail_url: media.thumbnail_url || media.file_url,
                title: media.title,
                updated_at: data.updated_at
            },
            message: 'Homepage hero image updated'
        });
    } catch (error) {
        logger.error('Admin placement set error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update placement' });
    }
});

// DELETE /api/admin/media/placements/homepage-hero
adminRouter.delete('/media/placements/homepage-hero', async (req, res) => {
    try {
        await supabase.from('media_placements').delete().eq('slot', 'homepage-hero');
        logger.info('Homepage hero placement cleared', { requestId: req.id, by: req.user.id });
        res.json({ status: 'success', message: 'Homepage hero image cleared' });
    } catch (error) {
        logger.error('Admin placement delete error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to clear placement' });
    }
});

// ==================== ACADEMIC SESSIONS MANAGEMENT ====================

// GET /api/admin/sessions — list all sessions
adminRouter.get('/sessions', async (req, res) => {
    try {
        const result = await db.query('select', 'academic_sessions', {
            order: { column: 'name', ascending: false }
        });
        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        logger.error('Sessions list error:', { requestId: req.id, error: error.message });
        if (error.message && error.message.includes('relation') && error.message.includes('does not exist')) {
            return res.json({ status: 'success', data: [], count: 0 });
        }
        res.status(500).json({ status: 'error', message: 'Failed to fetch sessions' });
    }
});

// POST /api/admin/sessions — create (inactive by default)
adminRouter.post('/sessions', async (req, res) => {
    try {
        const { name, session_name, start_date, end_date, description } = req.body;
        const finalName = (name || session_name || '').trim();

        if (!finalName) {
            return res.status(400).json({ status: 'error', message: 'Session name is required' });
        }
        if (!/^\d{4}\/\d{4}$/.test(finalName)) {
            return res.status(400).json({ status: 'error', message: 'Session name must be in the format YYYY/YYYY' });
        }

        // Duplicate check
        const existing = await db.query('select', 'academic_sessions', { where: { name: finalName }, select: 'id' });
        if (existing.data.length > 0) {
            return res.status(409).json({ status: 'error', message: 'A session with this name already exists' });
        }

        const newSession = {
            name: finalName,
            start_date: start_date || null,
            end_date: end_date || null,
            description: description || null,
            is_active: false,  // NEVER auto-activate
            created_by: req.user.id
        };

        const result = await db.query('insert', 'academic_sessions', { data: newSession });
        logger.info('Academic session created', { requestId: req.id, sessionId: result.data[0].id, name: finalName });
        res.status(201).json({ status: 'success', data: result.data[0], message: 'Session created successfully' });
    } catch (error) {
        logger.error('Session create error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to create session' });
    }
});

// PUT /api/admin/sessions/:id — edit
adminRouter.put('/sessions/:id', async (req, res) => {
    try {
        const { name, session_name, start_date, end_date, description } = req.body;
        const finalName = (name || session_name || '').trim();
        const updateData = { updated_at: new Date().toISOString() };

        if (finalName) {
            if (!/^\d{4}\/\d{4}$/.test(finalName)) {
                return res.status(400).json({ status: 'error', message: 'Session name must be in the format YYYY/YYYY' });
            }
            const existing = await db.query('select', 'academic_sessions', {
                where: { name: finalName, id: { operator: 'neq', value: req.params.id } },
                select: 'id'
            });
            if (existing.data.length > 0) {
                return res.status(409).json({ status: 'error', message: 'Another session with this name already exists' });
            }
            updateData.name = finalName;
        }
        if (start_date !== undefined) updateData.start_date = start_date || null;
        if (end_date !== undefined) updateData.end_date = end_date || null;
        if (description !== undefined) updateData.description = description || null;

        const result = await db.query('update', 'academic_sessions', {
            data: updateData, where: { id: req.params.id }
        });
        if (result.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Session not found' });
        }

        logger.info('Academic session updated', { requestId: req.id, sessionId: req.params.id });
        res.json({ status: 'success', data: result.data[0], message: 'Session updated successfully' });
    } catch (error) {
        logger.error('Session update error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update session' });
    }
});

// PATCH /api/admin/sessions/:id/activate — atomically activate one, deactivate all others
adminRouter.patch('/sessions/:id/activate', async (req, res) => {
    try {
        const sessionId = req.params.id;

        // Check target exists
        const target = await db.query('select', 'academic_sessions', { where: { id: sessionId } });
        if (target.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Session not found' });
        }

        // Deactivate all others first
        await db.query('update', 'academic_sessions', {
            data: { is_active: false, updated_at: new Date().toISOString() },
            where: { is_active: true }
        });

        // Activate target
        const result = await db.query('update', 'academic_sessions', {
            data: { is_active: true, updated_at: new Date().toISOString() },
            where: { id: sessionId }
        });

        logger.info('Academic session activated', {
            requestId: req.id, sessionId, sessionName: target.data[0].name,
            activatedBy: req.user.id
        });

        res.json({ status: 'success', data: result.data[0], message: 'Session activated successfully' });
    } catch (error) {
        logger.error('Session activate error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to activate session' });
    }
});

// DELETE /api/admin/sessions/:id — delete (reject if active)
adminRouter.delete('/sessions/:id', async (req, res) => {
    try {
        const check = await db.query('select', 'academic_sessions', {
            where: { id: req.params.id }, select: 'id, name, is_active'
        });
        if (check.data.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Session not found' });
        }

        if (check.data[0].is_active) {
            return res.status(400).json({
                status: 'error',
                message: 'Cannot delete the active session. Activate a different session first.'
            });
        }

        await db.query('delete', 'academic_sessions', { where: { id: req.params.id } });
        logger.info('Academic session deleted', { requestId: req.id, sessionId: req.params.id, deletedBy: req.user.id });
        res.json({ status: 'success', message: 'Session deleted successfully' });
    } catch (error) {
        logger.error('Session delete error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete session' });
    }
});

// ==================== SETTINGS MANAGEMENT ====================

// GET /api/admin/settings — fetch all settings as a single object
adminRouter.get('/settings', async (req, res) => {
    try {
        const result = await db.query('select', 'settings', {});
        const settings = {};
        for (const row of result.data) {
            settings[row.key] = row.value;
        }
        res.json({ status: 'success', data: settings });
    } catch (error) {
        // If table doesn't exist, return empty settings so frontend still works
        if (error.message && error.message.includes('relation') && error.message.includes('does not exist')) {
            return res.json({ status: 'success', data: {}, note: 'settings table not created yet' });
        }
        logger.error('Settings fetch error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch settings' });
    }
});

// PUT /api/admin/settings — upsert settings (accepts { settings: { key: value, ... } })
adminRouter.put('/settings', async (req, res) => {
    try {
        const { settings } = req.body;
        if (!settings || typeof settings !== 'object') {
            return res.status(400).json({ status: 'error', message: 'settings object is required' });
        }

        const rows = Object.entries(settings).map(([key, value]) => ({
            key,
            value: typeof value === 'object' ? value : String(value ?? ''),
            updated_at: new Date().toISOString()
        }));

        if (rows.length > 0) {
            await db.query('upsert', 'settings', { data: rows });
        }

        logger.info('Settings saved', { requestId: req.id, keys: Object.keys(settings), updatedBy: req.user.id });
        res.json({ status: 'success', message: 'Settings saved successfully' });
    } catch (error) {
        logger.error('Settings save error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to save settings' });
    }
});

// ==================== MESSAGES MANAGEMENT ====================
adminRouter.get('/messages', async (req, res) => {
    try {
        const result = await db.query('select', 'contact_messages', { order: { column: 'created_at', ascending: false } });
        res.json({ status: 'success', data: result.data });
    } catch (error) {
        logger.error('Admin messages error:', error);
        if (error.message && error.message.includes('relation') && error.message.includes('does not exist')) {
            return res.json({ status: 'success', data: [] });
        }
        res.status(500).json({ status: 'error', message: 'Failed to fetch messages' });
    }
});

adminRouter.get('/messages/:id', async (req, res) => {
    try {
        const result = await db.query('select', 'contact_messages', { where: { id: req.params.id } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Message not found' });
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Admin message fetch error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch message' });
    }
});

adminRouter.put('/messages/:id/read', async (req, res) => {
    try {
        await db.query('update', 'contact_messages', {
            data: { is_read: true, read_at: new Date() }, where: { id: req.params.id }
        });
        res.json({ status: 'success', message: 'Message marked as read' });
    } catch (error) {
        logger.error('Admin mark message read error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to update message' });
    }
});

adminRouter.delete('/messages/:id', async (req, res) => {
    try {
        await db.query('delete', 'contact_messages', { where: { id: req.params.id } });
        res.json({ status: 'success', message: 'Message deleted successfully' });
    } catch (error) {
        logger.error('Admin delete message error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to delete message' });
    }
});

adminRouter.post('/messages/mark-all-read', async (req, res) => {
    try {
        await db.query('update', 'contact_messages', {
            data: { is_read: true, read_at: new Date() }, where: { is_read: false }
        });
        res.json({ status: 'success', message: 'All messages marked as read' });
    } catch (error) {
        logger.error('Admin mark all read error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to mark messages as read' });
    }
});

// ==================== ARTICLES MANAGEMENT ====================
adminRouter.get('/articles/stats', async (req, res) => {
    try {
        const [total, published, drafts, archived] = await Promise.all([
            db.query('select', 'articles', { count: true }),
            db.query('select', 'articles', { where: { status: 'published' }, count: true }),
            db.query('select', 'articles', { where: { status: 'draft' }, count: true }),
            db.query('select', 'articles', { where: { status: 'archived' }, count: true })
        ]);

        const recentActivity = await db.query('select', 'articles', {
            select: 'uuid, title, status, updated_at, updated_by',
            order: { column: 'updated_at', ascending: false }, limit: 10
        });

        res.json({
            status: 'success',
            data: {
                counts: {
                    total: total.count || 0, published: published.count || 0,
                    drafts: drafts.count || 0, archived: archived.count || 0
                },
                recentActivity: recentActivity.data || []
            }
        });
    } catch (error) {
        logger.error('Admin articles stats error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch article statistics' });
    }
});

adminRouter.get('/articles', async (req, res) => {
    try {
        const { status, category, search } = req.query;
        let where = {};
        if (status && status !== 'all') where.status = status;
        if (category && category !== 'all') where.category = category;
        if (search) where.title = { operator: 'ilike', value: `%${search}%` };

        const result = await db.query('select', 'articles', {
            where, order: { column: 'created_at', ascending: false }
        });
        res.json({ status: 'success', data: result.data, count: result.data.length });
    } catch (error) {
        logger.error('Admin articles list error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch articles' });
    }
});

adminRouter.get('/articles/categories', async (req, res) => {
    try {
        const result = await db.query('select', 'articles', {
            select: 'category', where: { category: { operator: 'isNull', value: false } }
        });
        const categories = [...new Set(result.data.map(i => i.category).filter(Boolean))];
        res.json({ status: 'success', data: categories });
    } catch (error) {
        logger.error('Admin article categories error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch categories' });
    }
});

adminRouter.get('/articles/:uuid', async (req, res) => {
    try {
        const result = await db.query('select', 'articles', { where: { uuid: req.params.uuid } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Article not found' });
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        logger.error('Admin article fetch error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch article' });
    }
});

adminRouter.post('/articles', upload.single('featured_image'), async (req, res) => {
    try {
        const articleData = req.body.data ? JSON.parse(req.body.data) : req.body;
        const { title, content, excerpt, author, category, tags, status, is_published, published_at, meta_title, meta_description, meta_keywords } = articleData;

        if (!title || !content) {
            return res.status(400).json({ status: 'error', message: 'Title and content are required' });
        }

        let articleSlug = title.toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-').replace(/--+/g, '-').trim();
        const existing = await db.query('select', 'articles', { where: { slug: articleSlug } });
        if (existing.data.length > 0) articleSlug = `${articleSlug}-${Date.now()}`;

        let featuredImage = null;
        if (req.file) featuredImage = `/uploads/${req.file.filename}`;
        else if (articleData.featured_image) featuredImage = articleData.featured_image;

        const newArticle = {
            uuid: uuid.v4(), title: title.trim(), slug: articleSlug, content,
            excerpt: excerpt || null, author: author || req.user.fullName || 'NUESA BIU',
            category: category || null, tags: tags || [],
            status: status || 'draft', is_published: is_published || false,
            published_at: published_at || (is_published ? new Date().toISOString() : null),
            featured_image: featuredImage, meta_title: meta_title || null,
            meta_description: meta_description || null, meta_keywords: meta_keywords || null,
            view_count: 0, created_by: req.user.id, updated_by: req.user.id,
            created_at: new Date().toISOString(), updated_at: new Date().toISOString()
        };

        const result = await db.query('insert', 'articles', { data: newArticle });
        await cacheManager.invalidateByTags(['articles']);

        logger.info('Admin created article', { requestId: req.id, articleId: result.data[0].uuid, createdBy: req.user.id });
        res.status(201).json({ status: 'success', data: result.data[0], message: 'Article created successfully' });
    } catch (error) {
        logger.error('Admin create article error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to create article' });
    }
});

adminRouter.put('/articles/:uuid', upload.single('featured_image'), async (req, res) => {
    try {
        const articleData = req.body.data ? JSON.parse(req.body.data) : req.body;
        const allowedFields = ['title', 'content', 'excerpt', 'author', 'category', 'tags', 'status', 'is_published', 'published_at', 'meta_title', 'meta_description', 'meta_keywords'];
        const updateData = {};

        allowedFields.forEach(field => {
            if (articleData[field] !== undefined && articleData[field] !== null) {
                if (field === 'tags') {
                    updateData[field] = Array.isArray(articleData[field]) ? articleData[field]
                        : typeof articleData[field] === 'string' ? articleData[field].split(',').map(t => t.trim()) : [];
                } else if (field === 'is_published') {
                    updateData[field] = Boolean(articleData[field]);
                    if (updateData[field] && !articleData.published_at) updateData.published_at = new Date().toISOString();
                } else if (typeof articleData[field] === 'string') updateData[field] = articleData[field].trim();
                else updateData[field] = articleData[field];
            }
        });

        if (articleData.title) {
            let newSlug = articleData.title.toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-').replace(/--+/g, '-').trim();
            const existing = await db.query('select', 'articles', { where: { slug: newSlug, uuid: { operator: 'neq', value: req.params.uuid } } });
            if (existing.data.length > 0) newSlug = `${newSlug}-${Date.now()}`;
            updateData.slug = newSlug;
        }

        if (req.file) updateData.featured_image = `/uploads/${req.file.filename}`;
        updateData.updated_at = new Date().toISOString();
        updateData.updated_by = req.user.id;

        if (Object.keys(updateData).length <= 2) return res.status(400).json({ status: 'error', message: 'No fields to update' });

        const result = await db.query('update', 'articles', { data: updateData, where: { uuid: req.params.uuid } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Article not found' });

        await cacheManager.invalidateByTags(['articles']);
        res.json({ status: 'success', data: result.data[0], message: 'Article updated successfully' });
    } catch (error) {
        logger.error('Admin update article error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update article' });
    }
});

adminRouter.delete('/articles/:uuid', async (req, res) => {
    try {
        const checkResult = await db.query('select', 'articles', {
            where: { uuid: req.params.uuid }, select: 'uuid, title, featured_image'
        });
        if (checkResult.data.length === 0) return res.status(404).json({ status: 'error', message: 'Article not found' });

        await db.query('delete', 'articles', { where: { uuid: req.params.uuid } });

        const featuredImage = checkResult.data[0].featured_image;
        if (featuredImage && featuredImage.startsWith('/uploads/')) {
            const filename = featuredImage.split('/').pop();
            const filePath = path.join(__dirname, 'uploads', filename);
            try { await fs.unlink(filePath); }
            catch (fileError) { logger.warn('Could not delete image', { error: fileError.message }); }
        }

        await cacheManager.invalidateByTags(['articles']);
        res.json({ status: 'success', message: 'Article deleted successfully', data: { uuid: req.params.uuid } });
    } catch (error) {
        logger.error('Admin delete article error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete article' });
    }
});

adminRouter.patch('/articles/:uuid/publish', async (req, res) => {
    try {
        const { publish } = req.body;
        if (publish === undefined) return res.status(400).json({ status: 'error', message: 'publish field is required (true/false)' });

        const updateData = {
            is_published: Boolean(publish),
            status: Boolean(publish) ? 'published' : 'draft',
            updated_at: new Date().toISOString(),
            updated_by: req.user.id
        };

        if (publish) {
            const article = await db.query('select', 'articles', { where: { uuid: req.params.uuid }, select: 'published_at' });
            if (article.data.length > 0 && !article.data[0].published_at) updateData.published_at = new Date().toISOString();
        }

        const result = await db.query('update', 'articles', { data: updateData, where: { uuid: req.params.uuid } });
        if (result.data.length === 0) return res.status(404).json({ status: 'error', message: 'Article not found' });

        await cacheManager.invalidateByTags(['articles']);
        res.json({ status: 'success', data: result.data[0], message: `Article ${publish ? 'published' : 'unpublished'} successfully` });
    } catch (error) {
        logger.error('Admin article publish error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update article status' });
    }
});

adminRouter.post('/articles/:uuid/photo', upload.single('photo'), async (req, res) => {
    try {
        if (!req.file) throw new Error('No file uploaded');
        const result = await db.query('update', 'articles', {
            data: { featured_image: `/uploads/${req.file.filename}`, updated_at: new Date() },
            where: { uuid: req.params.uuid }
        });
        res.json({ status: 'success', data: result.data[0] });
    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
});

adminRouter.delete('/articles/bulk/delete', async (req, res) => {
    try {
        const { articleUuids } = req.body;
        if (!articleUuids || !Array.isArray(articleUuids) || articleUuids.length === 0) {
            return res.status(400).json({ status: 'error', message: 'Article UUIDs array is required' });
        }

        const imagesResult = await db.query('select', 'articles', {
            where: { uuid: { operator: 'in', value: articleUuids } }, select: 'featured_image'
        });
        const result = await db.query('delete', 'articles', { where: { uuid: { operator: 'in', value: articleUuids } } });

        for (const article of imagesResult.data) {
            if (article.featured_image && article.featured_image.startsWith('/uploads/')) {
                const filename = article.featured_image.split('/').pop();
                const filePath = path.join(__dirname, 'uploads', filename);
                try { await fs.unlink(filePath); }
                catch (fileError) { logger.warn('Could not delete image', { error: fileError.message }); }
            }
        }

        await cacheManager.invalidateByTags(['articles']);
        res.json({ status: 'success', message: `Deleted ${result.data.length} articles successfully`, data: { deleted: result.data.length } });
    } catch (error) {
        logger.error('Bulk delete articles error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete articles' });
    }
});

adminRouter.patch('/articles/bulk/status', async (req, res) => {
    try {
        const { articleUuids, status } = req.body;
        if (!articleUuids || !Array.isArray(articleUuids) || articleUuids.length === 0) {
            return res.status(400).json({ status: 'error', message: 'Article UUIDs array is required' });
        }
        if (!status || !['draft', 'published', 'archived'].includes(status)) {
            return res.status(400).json({ status: 'error', message: 'Valid status is required (draft, published, or archived)' });
        }

        const updateData = {
            status, is_published: status === 'published',
            updated_at: new Date().toISOString(), updated_by: req.user.id
        };
        if (status === 'published') updateData.published_at = new Date().toISOString();

        const result = await db.query('update', 'articles', { data: updateData, where: { uuid: { operator: 'in', value: articleUuids } } });
        await cacheManager.invalidateByTags(['articles']);
        res.json({ status: 'success', message: `Updated ${result.data.length} articles successfully`, data: result.data });
    } catch (error) {
        logger.error('Bulk status update articles error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update articles' });
    }
});

// ==================== USER MANAGEMENT ====================
const userRouter = express.Router();
userRouter.use(verifyToken);
userRouter.use(requireRole('admin'));

userRouter.get('/', async (req, res) => {
    try {
        const { page = 1, limit = 20, role, department, search, sort = 'created_at', order = 'desc' } = req.query;
        const offset = (page - 1) * limit;
        let where = {};
        if (role && role !== 'all') where.role = role;
        if (department && department !== 'all') where.department = department;
        if (search) where.full_name = { operator: 'ilike', value: `%${search}%` };

        const [usersResult, totalResult] = await Promise.all([
            db.query('select', 'users', {
                where, select: 'id, email, full_name, role, department, is_active, created_at, updated_at, last_login',
                order: { column: sort, ascending: order === 'asc' }, limit: parseInt(limit), offset: parseInt(offset)
            }),
            db.query('select', 'users', { where, count: true })
        ]);

        res.setHeader('X-Total-Count', totalResult.count || 0);
        res.setHeader('X-Page-Count', Math.ceil((totalResult.count || 0) / limit));

        res.json({
            status: 'success', data: usersResult.data,
            pagination: {
                page: parseInt(page), limit: parseInt(limit),
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

userRouter.post('/', validate(schemas.createUser), async (req, res) => {
    try {
        const { email, password, full_name, department, role = 'member', is_active = true } = req.body;
        const existing = await db.query('select', 'users', { where: { email: email.toLowerCase() }, select: 'id' });
        if (existing.data.length > 0) throw new ValidationError('User with this email already exists');

        const hashedPassword = await bcrypt.hash(password, 12);
        const username = email.split('@')[0].toLowerCase();
        const userData = {
            email: email.toLowerCase(), password_hash: hashedPassword,
            full_name: full_name.trim(), username,
            department: department || null, role, is_active,
            created_at: new Date(), updated_at: new Date()
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

userRouter.get('/:id', async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.id !== req.params.id) throw new ForbiddenError('Access denied');
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

userRouter.put('/:id', validate(schemas.updateUser), async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.id !== req.params.id) throw new ForbiddenError('Access denied');

        const { full_name, department, role, is_active, password } = req.body;
        const updateData = { updated_at: new Date() };
        if (full_name) updateData.full_name = full_name.trim();
        if (department !== undefined) updateData.department = department;

        if (req.user.role === 'admin') {
            if (role !== undefined) updateData.role = role;
            if (is_active !== undefined) updateData.is_active = is_active;
        }
        if (password) updateData.password_hash = await bcrypt.hash(password, 12);

        const cleanUpdateData = Object.fromEntries(Object.entries(updateData).filter(([_, v]) => v !== undefined));
        const result = await db.query('update', 'users', { data: cleanUpdateData, where: { id: req.params.id } });
        if (result.data.length === 0) throw new NotFoundError('User');

        await cacheManager.delete(`user:${req.params.id}`);
        await cacheManager.invalidate('data:*');
        if (req.user.id === req.params.id) req.user = authService.createUserResponse(result.data[0]);

        logger.info('User updated', { requestId: req.id, userId: req.params.id, updatedBy: req.user.id });
        res.json({ status: 'success', data: authService.createUserResponse(result.data[0]), message: 'User updated successfully' });
    } catch (error) {
        logger.error('Error updating user:', { requestId: req.id, error: error.message });
        if (error instanceof NotFoundError) return res.status(404).json({ status: 'error', message: error.message });
        if (error instanceof ForbiddenError) return res.status(403).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update user' });
    }
});

userRouter.delete('/:id', async (req, res) => {
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

// ==================== COURSE REPS MANAGEMENT ====================

// GET /api/admin/course-reps — list all representatives
adminRouter.get('/course-reps', async (req, res) => {
    try {
        const { session, level, rep_type, status, department } = req.query;
        let query = supabase.from('course_representatives').select('*');

        if (session)    query = query.eq('session', session);
        if (level && level !== 'all') query = query.eq('level', level);
        if (rep_type && rep_type !== 'all') query = query.eq('rep_type', rep_type);
        if (status && status !== 'all') query = query.eq('status', status);
        if (department && department !== 'all') query = query.eq('department_name', department);

        const { data, error } = await query.order('level');
        if (error) throw error;

        const enrichedData = await Promise.all(data.map(async (rep) => {
            const { data: deptReps, error: deptError } = await supabase
                .from('department_reps').select('*').eq('course_rep_id', rep.id).eq('session', rep.session);

            if (deptError) return { ...rep, departments: [] };
            const departments = deptReps.map(dept => ({
                name: dept.department_name, rep: dept.representative_name || 'Pending'
            }));
            return { ...rep, departments };
        }));

        res.json({
            status: 'success',
            data: enrichedData,
            pagination: { total: enrichedData.length, filtered: enrichedData.length }
        });
    } catch (error) {
        logger.error('Error fetching course reps:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch course representatives' });
    }
});

// POST /api/admin/course-reps — create a representative
adminRouter.post('/course-reps', async (req, res) => {
    try {
        const {
            full_name, matric_no, email, phone, department, level,
            session, rep_type, representative_type, status,
            appointment_date, notes, profile_picture,
            gen_rep, asst_gen_rep, departments
        } = req.body;

        if (!session || !level) {
            return res.status(400).json({ status: 'error', message: 'Session and level are required' });
        }

        const finalType = (rep_type || representative_type || 'general').toLowerCase();
        if (!['general', 'assistant', 'departmental'].includes(finalType)) {
            return res.status(400).json({ status: 'error', message: 'Invalid rep_type. Use: general, assistant, or departmental' });
        }

        const finalName = (full_name || gen_rep || '').trim();
        if (!finalName) {
            return res.status(400).json({ status: 'error', message: 'Full name is required' });
        }

        if (finalType === 'departmental' && !department) {
            return res.status(400).json({ status: 'error', message: 'Department is required for departmental reps' });
        }

        const finalStatus = (status || 'active').toLowerCase();
        if (!['active', 'inactive', 'graduated', 'resigned'].includes(finalStatus)) {
            return res.status(400).json({ status: 'error', message: 'Invalid status' });
        }

        // Duplicate matric check — scoped per (session, rep_type) so the same
        // student can hold both a general and a departmental role.
        if (matric_no) {
            const { data: dupMatric, error: dupErr } = await supabase
                .from('course_representatives')
                .select('id, full_name, rep_type')
                .eq('session', session)
                .eq('rep_type', finalType)
                .ilike('matric_no', matric_no.trim())
                .maybeSingle();

            if (dupErr && dupErr.code !== 'PGRST116') throw dupErr;
            if (dupMatric) {
                return res.status(409).json({
                    status: 'error',
                    message: `${dupMatric.full_name} is already registered as a ${finalType} rep for ${session}`
                });
            }
        }

        // Duplicate active position check
        if (finalStatus === 'active') {
            let dupQuery = supabase
                .from('course_representatives')
                .select('id, full_name')
                .eq('status', 'active')
                .eq('session', session)
                .eq('level', level)
                .eq('rep_type', finalType);

            if (finalType === 'departmental') {
                dupQuery = dupQuery.eq('department_name', department);
            }

            const { data: dupPosition, error: dupPosErr } = await dupQuery.maybeSingle();
            if (dupPosErr && dupPosErr.code !== 'PGRST116') throw dupPosErr;

            if (dupPosition) {
                const scope = finalType === 'departmental'
                    ? `${department} ${level} departmental rep`
                    : `${level} ${finalType} rep`;
                return res.status(409).json({
                    status: 'error',
                    message: `An active ${scope} already exists for ${session} (${dupPosition.full_name}). Deactivate them first.`
                });
            }
        }

        const insertData = {
            full_name: finalName,
            matric_no: matric_no ? String(matric_no).trim().toUpperCase() : null,
            email: email ? String(email).trim().toLowerCase() : null,
            phone: phone ? String(phone).trim() : null,
            department_name: department || null,
            level,
            session,
            rep_type: finalType,
            status: finalStatus,
            appointment_date: appointment_date || null,
            notes: notes ? String(notes).trim() : null,
            profile_picture: profile_picture || null,
            gen_rep: finalType === 'general' ? finalName : (gen_rep || 'Not Assigned'),
            asst_gen_rep: asst_gen_rep || 'Not Assigned',
            created_by: req.user.id,
            updated_by: req.user.id,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };

        const { data: courseRep, error: insertError } = await supabase
            .from('course_representatives')
            .insert([insertData])
            .select()
            .single();

        if (insertError) throw insertError;

        if (departments && Array.isArray(departments) && departments.length > 0) {
            const deptRepsData = departments
                .filter(d => d && d.name)
                .map(dept => ({
                    course_rep_id: courseRep.id,
                    department_name: dept.name,
                    session,
                    level,
                    representative_name: dept.rep || 'Pending',
                    status: 'active',
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }));
            if (deptRepsData.length > 0) {
                const { error: deptError } = await supabase.from('department_reps').insert(deptRepsData);
                if (deptError) logger.warn('Failed to insert legacy department reps', { requestId: req.id, error: deptError.message });
            }
        }

        await cacheManager.invalidateByTags(['course-reps']);

        logger.info('Course rep created', {
            requestId: req.id, repId: courseRep.id, type: finalType, createdBy: req.user.id
        });

        res.status(201).json({
            status: 'success',
            data: courseRep,
            message: 'Representative created successfully'
        });
    } catch (error) {
        logger.error('Error creating course reps:', {
            requestId: req.id, error: error.message, code: error.code
        });
        res.status(500).json({
            status: 'error',
            message: error.message || 'Failed to create course representative'
        });
    }
});

// PUT /api/admin/course-reps/:id — update a representative
adminRouter.put('/course-reps/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const {
            full_name, matric_no, email, phone, department, level,
            session, rep_type, representative_type, status,
            appointment_date, notes, profile_picture
        } = req.body;

        const { data: existing, error: existErr } = await supabase
            .from('course_representatives')
            .select('*')
            .eq('id', id)
            .maybeSingle();

        if (existErr) throw existErr;
        if (!existing) return res.status(404).json({ status: 'error', message: 'Representative not found' });

        const updateData = { updated_at: new Date().toISOString(), updated_by: req.user.id };

        if (full_name !== undefined) {
            const trimmed = String(full_name).trim();
            if (!trimmed) return res.status(400).json({ status: 'error', message: 'Full name cannot be empty' });
            updateData.full_name = trimmed;
            if (existing.rep_type === 'general') updateData.gen_rep = trimmed;
        }
        if (matric_no !== undefined)       updateData.matric_no = matric_no ? String(matric_no).trim().toUpperCase() : null;
        if (email !== undefined)           updateData.email = email ? String(email).trim().toLowerCase() : null;
        if (phone !== undefined)           updateData.phone = phone ? String(phone).trim() : null;
        if (department !== undefined)      updateData.department_name = department || null;
        if (level !== undefined)           updateData.level = level || null;
        if (session !== undefined)         updateData.session = session || null;
        if (rep_type !== undefined || representative_type !== undefined) {
            const newType = (rep_type || representative_type || 'general').toLowerCase();
            if (!['general', 'assistant', 'departmental'].includes(newType)) {
                return res.status(400).json({ status: 'error', message: 'Invalid rep_type' });
            }
            updateData.rep_type = newType;
        }
        if (status !== undefined) {
            const newStatus = String(status).toLowerCase();
            if (!['active', 'inactive', 'graduated', 'resigned'].includes(newStatus)) {
                return res.status(400).json({ status: 'error', message: 'Invalid status' });
            }
            updateData.status = newStatus;
        }
        if (appointment_date !== undefined) updateData.appointment_date = appointment_date || null;
        if (notes !== undefined)            updateData.notes = notes ? String(notes).trim() : null;
        if (profile_picture !== undefined)  updateData.profile_picture = profile_picture || null;

        const finalState = {
            rep_type: updateData.rep_type ?? existing.rep_type,
            session:  updateData.session  ?? existing.session,
            level:    updateData.level    ?? existing.level,
            department_name: updateData.department_name !== undefined
                ? updateData.department_name
                : existing.department_name,
            status:   updateData.status ?? existing.status,
            matric_no: updateData.matric_no !== undefined ? updateData.matric_no : existing.matric_no
        };

        if (finalState.rep_type === 'departmental' && !finalState.department_name) {
            return res.status(400).json({ status: 'error', message: 'Department is required for departmental reps' });
        }

        if (finalState.status === 'active') {
            let dupQuery = supabase
                .from('course_representatives')
                .select('id, full_name')
                .neq('id', id)
                .eq('status', 'active')
                .eq('session', finalState.session)
                .eq('level', finalState.level)
                .eq('rep_type', finalState.rep_type);

            if (finalState.rep_type === 'departmental') {
                dupQuery = dupQuery.eq('department_name', finalState.department_name);
            }

            const { data: dup, error: dupErr } = await dupQuery.maybeSingle();
            if (dupErr && dupErr.code !== 'PGRST116') throw dupErr;

            if (dup) {
                const scope = finalState.rep_type === 'departmental'
                    ? `${finalState.department_name} ${finalState.level} departmental rep`
                    : `${finalState.level} ${finalState.rep_type} rep`;
                return res.status(409).json({
                    status: 'error',
                    message: `An active ${scope} already exists for ${finalState.session} (${dup.full_name}). Deactivate them first.`
                });
            }
        }

        if (updateData.matric_no && updateData.matric_no !== existing.matric_no) {
            const { data: dupMatric, error: dupMatErr } = await supabase
                .from('course_representatives')
                .select('id, full_name')
                .neq('id', id)
                .eq('session', finalState.session)
                .eq('rep_type', finalState.rep_type)
                .ilike('matric_no', updateData.matric_no)
                .maybeSingle();

            if (dupMatErr && dupMatErr.code !== 'PGRST116') throw dupMatErr;
            if (dupMatric) {
                return res.status(409).json({
                    status: 'error',
                    message: `Another ${finalState.rep_type} rep (${dupMatric.full_name}) already uses this matric number in the same session`
                });
            }
        }

        const { data: updated, error: updateErr } = await supabase
            .from('course_representatives')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();

        if (updateErr) throw updateErr;

        await cacheManager.invalidateByTags(['course-reps']);

        logger.info('Course rep updated', {
            requestId: req.id, repId: id, updatedBy: req.user.id, fields: Object.keys(updateData)
        });

        res.json({ status: 'success', data: updated, message: 'Representative updated successfully' });
    } catch (error) {
        logger.error('Error updating course rep:', {
            requestId: req.id, repId: req.params.id, error: error.message, code: error.code
        });
        res.status(500).json({
            status: 'error',
            message: error.message || 'Failed to update representative'
        });
    }
});

// PATCH /api/admin/course-reps/:id/status — quick status toggle
adminRouter.patch('/course-reps/:id/status', async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!status || !['active', 'inactive', 'graduated', 'resigned'].includes(status)) {
            return res.status(400).json({
                status: 'error',
                message: 'Valid status required: active, inactive, graduated, resigned'
            });
        }

        const { data: existing, error: existErr } = await supabase
            .from('course_representatives').select('*').eq('id', id).maybeSingle();

        if (existErr) throw existErr;
        if (!existing) return res.status(404).json({ status: 'error', message: 'Representative not found' });

        if (status === 'active' && existing.status !== 'active') {
            let dupQuery = supabase
                .from('course_representatives')
                .select('id, full_name')
                .neq('id', id)
                .eq('status', 'active')
                .eq('session', existing.session)
                .eq('level', existing.level)
                .eq('rep_type', existing.rep_type);

            if (existing.rep_type === 'departmental') {
                dupQuery = dupQuery.eq('department_name', existing.department_name);
            }

            const { data: dup } = await dupQuery.maybeSingle();
            if (dup) {
                return res.status(409).json({
                    status: 'error',
                    message: `Cannot activate: an active rep already exists in this position (${dup.full_name})`
                });
            }
        }

        const { data: updated, error: updateErr } = await supabase
            .from('course_representatives')
            .update({ status, updated_at: new Date().toISOString(), updated_by: req.user.id })
            .eq('id', id)
            .select()
            .single();

        if (updateErr) throw updateErr;

        await cacheManager.invalidateByTags(['course-reps']);

        logger.info('Course rep status changed', {
            requestId: req.id, repId: id, newStatus: status, by: req.user.id
        });

        res.json({ status: 'success', data: updated, message: `Status updated to ${status}` });
    } catch (error) {
        logger.error('Course rep status update error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to update status' });
    }
});

// DELETE /api/admin/course-reps/:id
adminRouter.delete('/course-reps/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const { data: existing, error: existErr } = await supabase
            .from('course_representatives').select('id, full_name').eq('id', id).maybeSingle();

        if (existErr) throw existErr;
        if (!existing) return res.status(404).json({ status: 'error', message: 'Representative not found' });

        await supabase.from('department_reps').delete().eq('course_rep_id', id);
        const { error } = await supabase.from('course_representatives').delete().eq('id', id);
        if (error) throw error;

        await cacheManager.invalidateByTags(['course-reps']);

        logger.info('Course rep deleted', { requestId: req.id, repId: id, deletedBy: req.user.id });
        res.json({ status: 'success', message: 'Representative deleted successfully' });
    } catch (error) {
        logger.error('Error deleting course reps:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete representative' });
    }
});

// GET /api/admin/course-reps/:id — single rep (admin view, with nested dept reps)
adminRouter.get('/course-reps/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('course_representatives').select('*').eq('id', req.params.id).maybeSingle();

        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Representative not found' });

        const { data: deptReps } = await supabase
            .from('department_reps').select('*').eq('course_rep_id', req.params.id);

        res.json({ status: 'success', data: { ...data, department_reps: deptReps || [] } });
    } catch (error) {
        logger.error('Course rep fetch error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch representative' });
    }
});

// GET /api/admin/course-reps/stats — dashboard counts
adminRouter.get('/course-reps/stats', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('course_representatives')
            .select('rep_type, status, session, level');

        if (error) throw error;

        const stats = {
            total: data.length,
            byType: { general: 0, assistant: 0, departmental: 0 },
            byStatus: { active: 0, inactive: 0, graduated: 0, resigned: 0 },
            bySession: {},
            activeSession: null
        };

        data.forEach(rep => {
            if (stats.byType[rep.rep_type] !== undefined) stats.byType[rep.rep_type]++;
            if (stats.byStatus[rep.status] !== undefined) stats.byStatus[rep.status]++;
            if (rep.session) stats.bySession[rep.session] = (stats.bySession[rep.session] || 0) + 1;
        });

        const sessionCounts = Object.entries(stats.bySession);
        if (sessionCounts.length > 0) {
            sessionCounts.sort((a, b) => b[1] - a[1]);
            stats.activeSession = sessionCounts[0][0];
        }

        res.json({ status: 'success', data: stats });
    } catch (error) {
        logger.error('Course rep stats error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to load stats' });
    }
});

// Meta endpoints
adminRouter.get('/course-reps/meta/sessions', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('course_representatives').select('session').order('session', { ascending: false });
        if (error) throw error;
        res.json({ status: 'success', data: [...new Set(data.map(i => i.session).filter(Boolean))] });
    } catch (error) {
        logger.error('Error fetching sessions:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch sessions' });
    }
});

adminRouter.get('/course-reps/meta/levels', async (req, res) => {
    try {
        const { data, error } = await supabase.from('course_representatives').select('level').order('level');
        if (error) throw error;
        res.json({
            status: 'success',
            data: [...new Set(data.map(i => i.level).filter(Boolean))].sort((a, b) => parseInt(a) - parseInt(b))
        });
    } catch (error) {
        logger.error('Error fetching levels:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch levels' });
    }
});

// ==================== FILE UPLOAD (GENERIC) ====================
adminRouter.post('/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ status: 'error', message: 'No file uploaded' });
        const fileInfo = {
            filename: req.file.filename, originalname: req.file.originalname,
            mimetype: req.file.mimetype, size: req.file.size,
            url: `/uploads/${req.file.filename}`, uploaded_at: new Date()
        };
        res.json({ status: 'success', data: fileInfo, message: 'File uploaded successfully' });
    } catch (error) {
        logger.error('Admin upload error:', error);
        res.status(500).json({ status: 'error', message: 'Failed to upload file' });
    }
});

// ==================== MOUNT ADMIN ROUTERS ====================
app.use('/api/admin', adminRouter);
app.use('/api/users', userRouter);

console.log('✅ Admin routes registered at /api/admin/*');
console.log('✅ Media Library routes registered at /api/admin/media');
console.log('✅ User management routes registered at /api/users/*');


// ============================================================
// ================ SECTION 4.3: ELECTION SYSTEM =============
// ============================================================

const electionRouter = express.Router();

// ---------- Helper: get the current election with time-derived phase ----------
async function getActiveElection() {
    const { data, error } = await supabase
        .from('elections')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();

    if (error && error.code !== 'PGRST116') throw error;
    if (!data) return null;

    const now        = Date.now();
    const nomStart   = new Date(data.nomination_start).getTime();
    const nomEnd     = new Date(data.nomination_end).getTime();
    const voteStart  = new Date(data.voting_start).getTime();
    const voteEnd    = new Date(data.voting_end).getTime();

    let phase = 'closed';
    if (now < nomStart)                        phase = 'pending';
    else if (now >= nomStart && now < nomEnd)  phase = 'nomination';
    else if (now >= voteStart && now < voteEnd) phase = 'voting';
    else                                       phase = 'closed';

    return { ...data, phase };
}

// ---------- Helper: require a valid voter in the body/params/query ----------
async function requireVoter(req, res, next) {
    try {
        const voterId = (req.body && req.body.voterId)
                     || (req.params && req.params.voterId)
                     || (req.query && req.query.voterId);

        if (!voterId) {
            return res.status(401).json({ status: 'error', message: 'Voter ID required' });
        }

        const { data, error } = await supabase
            .from('voters')
            .select('*')
            .eq('voter_id', voterId)
            .maybeSingle();

        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Voter not found. Please register.' });

        req.voter = data;
        next();
    } catch (err) {
        logger.error('requireVoter error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Voter verification failed' });
    }
}

// =============== PUBLIC: GET ACTIVE ELECTION ===============
electionRouter.get('/active', async (req, res) => {
    try {
        const election = await getActiveElection();
        if (!election) {
            return res.json({ status: 'success', data: null, message: 'No active election' });
        }

        const { data: positions, error: posErr } = await supabase
            .from('positions').select('*')
            .eq('election_id', election.id)
            .order('display_order', { ascending: true });

        if (posErr) throw posErr;

        const { data: nominations, error: nomErr } = await supabase
            .from('nominations')
            .select(`
                id, position_id, nominee_id, manifesto, status,
                nominee:voters!nominations_nominee_id_fkey (
                    id, full_name, matric_no, department, level, voter_id
                )
            `)
            .eq('election_id', election.id)
            .eq('status', 'approved');

        if (nomErr) throw nomErr;

        const candidatesByPosition = {};
        nominations.forEach(n => {
            if (!candidatesByPosition[n.position_id]) candidatesByPosition[n.position_id] = [];
            candidatesByPosition[n.position_id].push({
                id: n.id,
                name: n.nominee?.full_name || 'Unknown',
                matric: n.nominee?.matric_no || '',
                department: n.nominee?.department || '',
                level: n.nominee?.level || '',
                manifesto: n.manifesto || ''
            });
        });

        res.json({
            status: 'success',
            data: {
                id: election.id,
                title: election.title,
                phase: election.phase,
                status: election.status,
                nomination_start: election.nomination_start,
                nomination_end: election.nomination_end,
                voting_start: election.voting_start,
                voting_end: election.voting_end,
                results_published: election.results_published,
                positions: (positions || []).map(p => ({
                    id: p.id,
                    title: p.title,
                    description: p.description,
                    candidates: candidatesByPosition[p.id] || []
                })),
                departments: [
                    'Electrical/Electronics Engineering',
                    'Civil Engineering',
                    'Mechanical Engineering'
                ],
                levels: ['100L', '200L', '300L', '400L', '500L']
            }
        });
    } catch (err) {
        logger.error('Election active error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to load election' });
    }
});

// =============== VOTER REGISTRATION ===============
electionRouter.post('/register', async (req, res) => {
    try {
        const { fullName, matricNumber, phone, receiptNumber, department, level } = req.body;

        if (!fullName || !matricNumber || !phone || !receiptNumber || !department || !level) {
            return res.status(400).json({ status: 'error', message: 'All fields are required' });
        }

        const election = await getActiveElection();
        if (!election) {
            return res.status(400).json({ status: 'error', message: 'No active election' });
        }

        const { data: existing } = await supabase
            .from('voters')
            .select('voter_id')
            .eq('session_id', election.session_id)
            .ilike('matric_no', matricNumber.trim())
            .maybeSingle();

        if (existing) {
            return res.status(409).json({
                status: 'error',
                message: `You are already registered. Your Voter ID is ${existing.voter_id}`
            });
        }

        const voterId = `VOTER-${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
        const insertData = {
            session_id: election.session_id,
            full_name: fullName.trim(),
            matric_no: matricNumber.trim().toUpperCase(),
            phone: phone.trim(),
            receipt_number: receiptNumber.trim().toUpperCase(),
            department,
            level,
            voter_id: voterId
        };

        const { data, error } = await supabase
            .from('voters').insert([insertData]).select().single();

        if (error) throw error;

        logger.info('Voter registered', {
            requestId: req.id, voterId: data.voter_id, level: data.level, eligible: data.eligible_to_vote
        });

        res.status(201).json({
            status: 'success',
            data: {
                voterId: data.voter_id,
                fullName: data.full_name,
                matricNumber: data.matric_no,
                level: data.level,
                eligibleToVote: data.eligible_to_vote
            },
            message: data.eligible_to_vote
                ? 'Registration successful. You can now vote.'
                : 'Registration successful. Note: 100L students cannot vote in this election.'
        });
    } catch (err) {
        logger.error('Voter registration error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Registration failed' });
    }
});

// =============== VERIFY VOTER ===============
electionRouter.get('/voter/:voterId', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('voters')
            .select('voter_id, full_name, matric_no, department, level, eligible_to_vote, has_voted')
            .eq('voter_id', req.params.voterId)
            .maybeSingle();

        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Voter not found' });

        res.json({ status: 'success', data });
    } catch (err) {
        logger.error('Voter verify error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Verification failed' });
    }
});

// =============== NOMINATIONS ===============
electionRouter.post('/nominate', requireVoter, async (req, res) => {
    try {
        const { positionId, nomineeVoterId, manifesto } = req.body;

        if (!positionId || !nomineeVoterId) {
            return res.status(400).json({ status: 'error', message: 'Position and nominee required' });
        }

        const election = await getActiveElection();
        if (!election) return res.status(400).json({ status: 'error', message: 'No active election' });

        if (election.phase !== 'nomination') {
            return res.status(403).json({
                status: 'error',
                message: `Nominations are ${election.phase === 'voting' ? 'closed (voting in progress)' : 'closed'}. Current phase: ${election.phase}`
            });
        }

        const { data: position } = await supabase
            .from('positions').select('id')
            .eq('id', positionId).eq('election_id', election.id).maybeSingle();

        if (!position) return res.status(404).json({ status: 'error', message: 'Position not found' });

        const { data: nominee } = await supabase
            .from('voters').select('id, full_name')
            .eq('voter_id', nomineeVoterId).eq('session_id', election.session_id).maybeSingle();

        if (!nominee) return res.status(404).json({ status: 'error', message: 'Nominee not found in this session' });

        const { data: existing } = await supabase
            .from('nominations').select('id')
            .eq('election_id', election.id)
            .eq('position_id', positionId)
            .eq('nominee_id', nominee.id)
            .maybeSingle();

        if (existing) {
            return res.status(409).json({ status: 'error', message: 'This person is already nominated for this position' });
        }

        const { data, error } = await supabase
            .from('nominations')
            .insert([{
                election_id: election.id,
                position_id: positionId,
                nominee_id: nominee.id,
                nominated_by: req.voter.id,
                manifesto: manifesto || null,
                status: 'pending'
            }])
            .select()
            .single();

        if (error) throw error;

        logger.info('Nomination submitted', {
            requestId: req.id, nominationId: data.id, nominee: nominee.full_name, nominatedBy: req.voter.voter_id
        });

        res.status(201).json({
            status: 'success',
            data,
            message: `Nomination submitted for ${nominee.full_name}. Awaiting admin approval.`
        });
    } catch (err) {
        logger.error('Nomination error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Nomination failed' });
    }
});

electionRouter.get('/nominations', async (req, res) => {
    try {
        const election = await getActiveElection();
        if (!election) return res.json({ status: 'success', data: [] });

        const { data, error } = await supabase
            .from('nominations')
            .select(`
                id, position_id, manifesto, status, created_at,
                nominee:voters!nominations_nominee_id_fkey (id, full_name, matric_no, department, level),
                position:positions (id, title)
            `)
            .eq('election_id', election.id)
            .eq('status', 'approved');

        if (error) throw error;
        res.json({ status: 'success', data });
    } catch (err) {
        logger.error('Nominations list error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to load nominations' });
    }
});

// =============== VOTING ===============
electionRouter.post('/vote', requireVoter, async (req, res) => {
    try {
        const { votes } = req.body;

        if (!votes || typeof votes !== 'object' || Object.keys(votes).length === 0) {
            return res.status(400).json({ status: 'error', message: 'No votes submitted' });
        }

        const election = await getActiveElection();
        if (!election) return res.status(400).json({ status: 'error', message: 'No active election' });

        if (election.phase !== 'voting') {
            return res.status(403).json({
                status: 'error',
                message: `Voting is not open. Current phase: ${election.phase}`
            });
        }

        // ⚠️ CRITICAL: 100L restriction enforced on the server
        if (req.voter.level === '100L' || req.voter.eligible_to_vote === false) {
            return res.status(403).json({
                status: 'error',
                message: '100 Level students are not eligible to vote in this election'
            });
        }

        if (req.voter.has_voted) {
            return res.status(409).json({ status: 'error', message: 'You have already voted' });
        }

        const voteRows = [];
        for (const [positionId, candidateId] of Object.entries(votes)) {
            const { data: nomination } = await supabase
                .from('nominations')
                .select('id, position_id')
                .eq('id', candidateId)
                .eq('position_id', positionId)
                .eq('election_id', election.id)
                .eq('status', 'approved')
                .maybeSingle();

            if (!nomination) {
                return res.status(400).json({
                    status: 'error',
                    message: `Invalid candidate for position ${positionId}`
                });
            }

            voteRows.push({
                election_id: election.id,
                position_id: positionId,
                voter_id: req.voter.id,
                candidate_id: candidateId
            });
        }

        const { error: voteErr } = await supabase.from('votes').insert(voteRows);
        if (voteErr) {
            if (voteErr.code === '23505') {
                return res.status(409).json({ status: 'error', message: 'You have already voted for one or more positions' });
            }
            throw voteErr;
        }

        await supabase
            .from('voters')
            .update({ has_voted: true, voted_at: new Date().toISOString() })
            .eq('id', req.voter.id);

        logger.info('Vote submitted', {
            requestId: req.id, voterId: req.voter.voter_id, positionsVoted: Object.keys(votes).length
        });

        res.json({ status: 'success', message: 'Your vote has been recorded. Thank you!' });
    } catch (err) {
        logger.error('Vote error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Voting failed' });
    }
});

// =============== RESULTS / TALLIES ===============
electionRouter.get('/tallies', async (req, res) => {
    try {
        const election = await getActiveElection();
        if (!election) return res.json({ status: 'success', data: {} });

        const now = Date.now();
        const voteEnd = new Date(election.voting_end).getTime();
        if (now < voteEnd) {
            return res.status(403).json({
                status: 'error',
                message: 'Results are not yet available. Voting is still in progress.'
            });
        }

        const { data: positions, error: posErr } = await supabase
            .from('positions').select('id, title')
            .eq('election_id', election.id)
            .order('display_order');

        if (posErr) throw posErr;

        const { data: votes, error: voteErr } = await supabase
            .from('votes').select('position_id, candidate_id')
            .eq('election_id', election.id);

        if (voteErr) throw voteErr;

        const tallies = {};
        votes.forEach(v => { tallies[v.candidate_id] = (tallies[v.candidate_id] || 0) + 1; });

        const { data: nominations } = await supabase
            .from('nominations')
            .select(`
                id, position_id,
                nominee:voters!nominations_nominee_id_fkey (full_name, department, level)
            `)
            .eq('election_id', election.id)
            .eq('status', 'approved');

        const detailed = {};
        nominations?.forEach(n => {
            detailed[n.id] = {
                votes: tallies[n.id] || 0,
                name: n.nominee?.full_name,
                department: n.nominee?.department,
                level: n.nominee?.level,
                position_id: n.position_id
            };
        });

        res.json({
            status: 'success',
            data: {
                election_id: election.id,
                results_published: election.results_published,
                positions,
                candidates: detailed
            }
        });
    } catch (err) {
        logger.error('Tallies error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to load tallies' });
    }
});

// ---------- Mount public election routes ----------
app.use('/api/elections', electionRouter);
console.log('✅ [ELEC] /api/elections router registered (nomination → voting → closed)');


// =============== ADMIN: ELECTION MANAGEMENT ===============

// Create a new election
adminRouter.post('/elections', async (req, res) => {
    try {
        const {
            title, session_id,
            nomination_start, nomination_end,
            voting_start, voting_end,
            positions   // [{ title, description }]
        } = req.body;

        if (!title || !session_id || !nomination_start || !nomination_end || !voting_start || !voting_end) {
            return res.status(400).json({ status: 'error', message: 'All date fields are required' });
        }

        if (new Date(nomination_end) <= new Date(nomination_start)) {
            return res.status(400).json({ status: 'error', message: 'Nomination end must be after start' });
        }
        if (new Date(voting_start) < new Date(nomination_end)) {
            return res.status(400).json({ status: 'error', message: 'Voting cannot start before nominations end' });
        }
        if (new Date(voting_end) <= new Date(voting_start)) {
            return res.status(400).json({ status: 'error', message: 'Voting end must be after start' });
        }

        const active = await getActiveElection();
        if (active && active.phase !== 'closed') {
            return res.status(409).json({ status: 'error', message: 'An election is already in progress. Close it first.' });
        }

        const { data: election, error } = await supabase
            .from('elections')
            .insert([{
                session_id, title, status: 'nomination',
                nomination_start, nomination_end, voting_start, voting_end,
                created_by: req.user.id
            }])
            .select().single();

        if (error) throw error;

        if (Array.isArray(positions) && positions.length > 0) {
            const posRows = positions.map((p, i) => ({
                election_id: election.id,
                title: p.title,
                description: p.description || null,
                display_order: i
            }));
            await supabase.from('positions').insert(posRows);
        }

        logger.info('Election created', { requestId: req.id, electionId: election.id });
        res.status(201).json({ status: 'success', data: election, message: 'Election created successfully' });
    } catch (err) {
        logger.error('Create election error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to create election' });
    }
});

// List nominations (admin — all statuses)
adminRouter.get('/elections/nominations', async (req, res) => {
    try {
        const election = await getActiveElection();
        if (!election) return res.json({ status: 'success', data: [] });

        const { data, error } = await supabase
            .from('nominations')
            .select(`
                id, status, manifesto, created_at,
                nominee:voters!nominations_nominee_id_fkey (full_name, matric_no, department, level),
                position:positions (id, title)
            `)
            .eq('election_id', election.id)
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json({ status: 'success', data });
    } catch (err) {
        logger.error('Admin nominations list error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to load nominations' });
    }
});

// Approve / reject a nomination
adminRouter.patch('/elections/nominations/:id', async (req, res) => {
    try {
        const { status } = req.body;
        if (!['approved', 'rejected', 'pending'].includes(status)) {
            return res.status(400).json({ status: 'error', message: 'Invalid status' });
        }

        const { data, error } = await supabase
            .from('nominations')
            .update({ status, reviewed_by: req.user.id, reviewed_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .select().single();

        if (error) throw error;
        res.json({ status: 'success', data, message: `Nomination ${status}` });
    } catch (err) {
        logger.error('Nomination update error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to update nomination' });
    }
});

// Manually advance phase (overrides time windows by rewriting them)
adminRouter.patch('/elections/phase', async (req, res) => {
    try {
        const { status } = req.body;
        if (!['nomination', 'voting', 'closed'].includes(status)) {
            return res.status(400).json({ status: 'error', message: 'Invalid phase' });
        }

        const election = await getActiveElection();
        if (!election) return res.status(404).json({ status: 'error', message: 'No active election' });

        const now = new Date().toISOString();
        const update = { status, updated_at: now };

        if (status === 'nomination') {
            update.nomination_start = now;
            update.nomination_end   = new Date(Date.now() + 7 * 864e5).toISOString();
            update.voting_start     = new Date(Date.now() + 8 * 864e5).toISOString();
            update.voting_end       = new Date(Date.now() + 15 * 864e5).toISOString();
        } else if (status === 'voting') {
            update.nomination_end = now;
            update.voting_start   = now;
            update.voting_end     = new Date(Date.now() + 7 * 864e5).toISOString();
        } else {
            update.voting_end = now;
        }

        const { data, error } = await supabase
            .from('elections').update(update).eq('id', election.id).select().single();

        if (error) throw error;
        logger.info('Election phase changed', { requestId: req.id, electionId: election.id, status });
        res.json({ status: 'success', data, message: `Election phase → ${status}` });
    } catch (err) {
        logger.error('Phase change error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to change phase' });
    }
});

// ⚡ PUBLISH RESULTS — auto-promotes winners into executive_members
adminRouter.post('/elections/publish-results', async (req, res) => {
    try {
        const election = await getActiveElection();
        if (!election) return res.status(404).json({ status: 'error', message: 'No active election' });

        if (Date.now() < new Date(election.voting_end).getTime()) {
            return res.status(400).json({ status: 'error', message: 'Cannot publish results before voting ends' });
        }
        if (election.results_published) {
            return res.status(409).json({ status: 'error', message: 'Results have already been published' });
        }

        const { data: nominations, error: nomErr } = await supabase
            .from('nominations')
            .select(`
                id, position_id,
                nominee:voters!nominations_nominee_id_fkey (full_name, department, level, email, phone, matric_no)
            `)
            .eq('election_id', election.id)
            .eq('status', 'approved');

        if (nomErr) throw nomErr;

        const { data: votes, error: voteErr } = await supabase
            .from('votes').select('candidate_id').eq('election_id', election.id);

        if (voteErr) throw voteErr;

        const tallies = {};
        votes.forEach(v => { tallies[v.candidate_id] = (tallies[v.candidate_id] || 0) + 1; });

        const { data: positions } = await supabase
            .from('positions').select('id, title').eq('election_id', election.id);

        const winners = [];
        for (const pos of positions || []) {
            const posCandidates = nominations.filter(n => n.position_id === pos.id);
            if (posCandidates.length === 0) continue;

            posCandidates.sort((a, b) => (tallies[b.id] || 0) - (tallies[a.id] || 0));
            const top = posCandidates[0];

            if (posCandidates.length > 1 && (tallies[posCandidates[0].id] || 0) === (tallies[posCandidates[1].id] || 0)) {
                logger.warn('Tie in position — skipping', { position: pos.title });
                continue;
            }

            winners.push({ position_title: pos.title, votes: tallies[top.id] || 0, nominee: top.nominee });
        }

        const { data: session } = await supabase
            .from('academic_sessions').select('name').eq('id', election.session_id).single();

        const sessionName = session?.name || 'Unknown';

        const memberRows = winners.map(w => ({
            full_name: w.nominee.full_name,
            position: w.position_title,
            department: w.nominee.department,
            level: w.nominee.level,
            email: w.nominee.email || null,
            phone: w.nominee.phone || null,
            session: sessionName,
            status: 'active',
            committee: 'Executive',
            display_order: 0,
            bio: null,
            social_links: {},
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        }));

        if (memberRows.length > 0) {
            const { error: insertErr } = await supabase.from('executive_members').insert(memberRows);
            if (insertErr) throw insertErr;
        }

        await supabase
            .from('elections')
            .update({ results_published: true, status: 'closed', updated_at: new Date().toISOString() })
            .eq('id', election.id);

        await cacheManager.invalidateByTags(['members']);

        logger.info('Election results published', {
            requestId: req.id, electionId: election.id, winnersPromoted: memberRows.length
        });

        res.json({
            status: 'success',
            data: {
                winners: winners.map(w => ({
                    position: w.position_title,
                    name: w.nominee.full_name,
                    votes: w.votes
                }))
            },
            message: `${memberRows.length} winner(s) promoted to executive members`
        });
    } catch (err) {
        logger.error('Publish results error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to publish results' });
    }
});

// List registered voters (admin)
adminRouter.get('/elections/voters', async (req, res) => {
    try {
        const election = await getActiveElection();
        if (!election) return res.json({ status: 'success', data: [] });

        const { data, error } = await supabase
            .from('voters').select('*')
            .eq('session_id', election.session_id)
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json({ status: 'success', data, count: data.length });
    } catch (err) {
        logger.error('Voters list error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to load voters' });
    }
});

// ============================================================
// ================ SECTION 4.4: AWARDS SYSTEM ================
// ============================================================

// ---------- Helper: get the active award edition ----------
async function getActiveAwardEdition() {
    const { data, error } = await supabase
        .from('award_editions')
        .select('*')
        .in('status', ['draft', 'preparation', 'active'])
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();

    if (error && error.code !== 'PGRST116') throw error;
    if (!data) return null;

    // Attach session name
    let sessionName = null;
    if (data.session_id) {
        const { data: session } = await supabase
            .from('academic_sessions').select('name').eq('id', data.session_id).maybeSingle();
        sessionName = session?.name || null;
    }

    // Attach categories count
    const { count: categoriesCount } = await supabase
        .from('award_categories')
        .select('id', { count: 'exact', head: true })
        .eq('edition_id', data.id);

    // Derive phase from time — FIXED: voting/closed work without nomination dates
    const now = Date.now();
    const nomStart  = data.nomination_start ? new Date(data.nomination_start).getTime() : null;
    const nomEnd    = data.nomination_end   ? new Date(data.nomination_end).getTime()   : null;
    const voteStart = data.voting_start     ? new Date(data.voting_start).getTime()     : null;
    const voteEnd   = data.voting_end       ? new Date(data.voting_end).getTime()       : null;

    let phase = 'preparation';
    if (voteEnd && now >= voteEnd) {
        phase = 'closed';
    } else if (voteStart && now >= voteStart && voteEnd && now < voteEnd) {
        phase = 'voting';
    } else if (nomStart && nomEnd && now >= nomStart && now < nomEnd) {
        phase = 'nomination';
    } else if (nomStart && now < nomStart) {
        phase = 'preparation';
    }
    // else: no dates configured → stays 'preparation'

    return {
        ...data,
        phase,
        session_name: sessionName,
        categories_count: categoriesCount || 0
    };
}

// ---------- Helper: require registered voter ----------
async function requireAwardVoter(req, res, next) {
    try {
        const voterId = (req.body && req.body.voterId)
                     || (req.params && req.params.voterId)
                     || (req.query && req.query.voterId);

        if (!voterId) return res.status(401).json({ status: 'error', message: 'Voter ID required' });

        const { data, error } = await supabase
            .from('voters').select('*').eq('voter_id', voterId).maybeSingle();
        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Voter not found' });

        req.voter = data;
        next();
    } catch (err) {
        logger.error('requireAwardVoter error:', { error: err.message });
        res.status(500).json({ status: 'error', message: 'Voter verification failed' });
    }
}

// ============================================================
// PUBLIC AWARD ENDPOINTS
// ============================================================
const awardRouter = express.Router();

// GET /api/awards/active — current award edition + categories + approved nominees
awardRouter.get('/active', async (req, res) => {
    try {
        const edition = await getActiveAwardEdition();
        if (!edition) {
            return res.json({ status: 'success', data: null, message: 'No active award edition' });
        }

        const { data: categories, error: catErr } = await supabase
            .from('award_categories')
            .select('*')
            .eq('edition_id', edition.id)
            .order('display_order', { ascending: true });
        if (catErr) throw catErr;

        const { data: nominees, error: nomErr } = await supabase
            .from('award_nominations')
            .select('*')
            .eq('edition_id', edition.id)
            .eq('status', 'approved');
        if (nomErr) throw nomErr;

        const nomineesByCategory = {};
        (nominees || []).forEach(n => {
            if (!nomineesByCategory[n.category_id]) nomineesByCategory[n.category_id] = [];
            nomineesByCategory[n.category_id].push({
                id: n.id,
                name: n.nominee_name,
                type: n.nominee_type,
                department: n.nominee_department,
                level: n.nominee_level,
                matric: n.nominee_matric,
                group_name: n.nominee_group_name,
                group_photo: n.nominee_group_photo,
                group_description: n.nominee_group_description,
                reason: n.reason,
                evidence_url: n.evidence_url
            });
        });

        res.json({
            status: 'success',
            data: {
                ...edition,
                categories: (categories || []).map(c => ({
                    ...c,
                    nominees: nomineesByCategory[c.id] || []
                }))
            }
        });
    } catch (err) {
        logger.error('Awards active error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to load award edition' });
    }
});

// GET /api/awards/archive — public list of archived editions (NEW)
awardRouter.get('/archive', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('award_editions')
            .select('id, name, session_id, winner_announcement, results_published, status, created_at')
            .eq('status', 'archived')
            .eq('results_published', true)
            .order('winner_announcement', { ascending: false, nullsFirst: false });
        if (error) throw error;

        const enriched = await Promise.all((data || []).map(async (ed) => {
            const [catCount, winCount] = await Promise.all([
                supabase.from('award_categories')
                    .select('id', { count: 'exact', head: true })
                    .eq('edition_id', ed.id),
                supabase.from('award_winners')
                    .select('id', { count: 'exact', head: true })
                    .eq('edition_id', ed.id)
            ]);

            let sessionName = null;
            if (ed.session_id) {
                const { data: s } = await supabase
                    .from('academic_sessions').select('name').eq('id', ed.session_id).maybeSingle();
                sessionName = s?.name || null;
            }

            return {
                id: ed.id,
                name: ed.name,
                session_name: sessionName,
                winner_announcement: ed.winner_announcement,
                categories_count: catCount.count || 0,
                winners_count: winCount.count || 0
            };
        }));

        res.json({ status: 'success', data: enriched, count: enriched.length });
    } catch (err) {
        logger.error('Public award archive error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to load archive' });
    }
});

// GET /api/awards/results — public results (only after published)
awardRouter.get('/results', async (req, res) => {
    try {
        const edition = await getActiveAwardEdition();
        if (!edition) return res.json({ status: 'success', data: null });

        if (!edition.results_published) {
            return res.status(403).json({
                status: 'error',
                message: 'Results have not been published yet'
            });
        }

        const { data: winners, error: winErr } = await supabase
            .from('award_winners')
            .select(`
                id, winner_name, final_score,
                category:award_categories (id, name, type),
                nomination:award_nominations (nominee_name, nominee_department, nominee_level)
            `)
            .eq('edition_id', edition.id)
            .eq('is_published', true);

        if (winErr) throw winErr;

        res.json({
            status: 'success',
            data: {
                edition_id: edition.id,
                edition_name: edition.name,
                winners: (winners || []).map(w => ({
                    award_name: w.category?.name,
                    award_id: w.category?.id,
                    winner_name: w.winner_name,
                    department: w.nomination?.nominee_department || null,
                    level: w.nomination?.nominee_level || null,
                    score: w.final_score,
                    published: true
                }))
            }
        });
    } catch (err) {
        logger.error('Awards results error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to load results' });
    }
});

// POST /api/awards/vote — cast a vote for a nominee
awardRouter.post('/vote', requireAwardVoter, async (req, res) => {
    try {
        const { categoryId, nominationId } = req.body;

        if (!categoryId || !nominationId) {
            return res.status(400).json({ status: 'error', message: 'categoryId and nominationId required' });
        }

        const edition = await getActiveAwardEdition();
        if (!edition) return res.status(400).json({ status: 'error', message: 'No active award edition' });
        if (edition.phase !== 'voting') {
            return res.status(403).json({
                status: 'error',
                message: `Voting is not open. Current phase: ${edition.phase}`
            });
        }

        const { data: category } = await supabase
            .from('award_categories').select('*')
            .eq('id', categoryId).eq('edition_id', edition.id).maybeSingle();
        if (!category) return res.status(404).json({ status: 'error', message: 'Category not found' });

        if (!['public', 'registered', 'combined'].includes(category.selection_method)) {
            return res.status(403).json({
                status: 'error',
                message: 'This category does not use public voting'
            });
        }

        const { data: nomination } = await supabase
            .from('award_nominations').select('id, status')
            .eq('id', nominationId).eq('category_id', categoryId).maybeSingle();
        if (!nomination || nomination.status !== 'approved') {
            return res.status(400).json({ status: 'error', message: 'Invalid nominee' });
        }

        const { error: voteErr } = await supabase.from('award_votes').insert([{
            edition_id: edition.id,
            category_id: categoryId,
            nomination_id: nominationId,
            voter_id: req.voter.id
        }]);

        if (voteErr) {
            if (voteErr.code === '23505') {
                return res.status(409).json({
                    status: 'error',
                    message: 'You have already voted in this category'
                });
            }
            throw voteErr;
        }

        logger.info('Award vote submitted', {
            requestId: req.id, voterId: req.voter.voter_id,
            categoryId, nominationId
        });

        res.json({ status: 'success', message: 'Your vote has been recorded. Thank you!' });
    } catch (err) {
        logger.error('Award vote error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Voting failed' });
    }
});

// ---------- Mount public award router ----------
app.use('/api/awards', awardRouter);
console.log('✅ [AWARD] /api/awards router registered (public)');


// ============================================================
// ADMIN AWARD ENDPOINTS
// ============================================================

// ---------- ADMIN: AWARD EDITIONS ----------

// GET /api/admin/awards/editions — list all editions
adminRouter.get('/awards/editions', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('award_editions')
            .select(`
                *,
                session:academic_sessions (id, name)
            `)
            .order('created_at', { ascending: false });
        if (error) throw error;

        const enriched = await Promise.all((data || []).map(async (ed) => {
            const [catCount, nomCount, winCount] = await Promise.all([
                supabase.from('award_categories').select('id', { count: 'exact', head: true }).eq('edition_id', ed.id),
                supabase.from('award_nominations').select('id', { count: 'exact', head: true }).eq('edition_id', ed.id),
                supabase.from('award_winners').select('id', { count: 'exact', head: true }).eq('edition_id', ed.id)
            ]);
            return {
                ...ed,
                session_name: ed.session?.name || null,
                categories_count: catCount.count || 0,
                nominations_count: nomCount.count || 0,
                winners_count: winCount.count || 0
            };
        }));

        res.json({ status: 'success', data: enriched, count: enriched.length });
    } catch (err) {
        logger.error('Award editions list error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch award editions' });
    }
});

// POST /api/admin/awards/editions — create edition
adminRouter.post('/awards/editions', async (req, res) => {
    try {
        const { name, session_id, status, description, categories } = req.body;

        if (!name || !session_id) {
            return res.status(400).json({ status: 'error', message: 'Name and session_id are required' });
        }

        // Archive any existing active/preparation editions (preserve history)
        await supabase
            .from('award_editions')
            .update({ status: 'archived', updated_at: new Date().toISOString() })
            .in('status', ['draft', 'preparation', 'active']);

        const { data: edition, error } = await supabase
            .from('award_editions')
            .insert([{
                name: name.trim(),
                session_id,
                status: status || 'draft',
                description: description || null,
                created_by: req.user.id
            }])
            .select().single();
        if (error) throw error;

        // Create categories if provided
        if (Array.isArray(categories) && categories.length > 0) {
            const rows = categories.map((c, i) => ({
                edition_id: edition.id,
                name: c.name,
                type: c.type || 'individual',
                selection_method: c.selection_method || 'public',
                description: c.description || null,
                eligibility: c.eligibility || null,
                status: c.status || 'draft',
                display_order: i
            }));
            const { error: catErr } = await supabase.from('award_categories').insert(rows);
            if (catErr) logger.warn('Some categories failed:', { error: catErr.message });
        }

        logger.info('Award edition created', { requestId: req.id, editionId: edition.id });
        res.status(201).json({ status: 'success', data: edition, message: 'Award edition created' });
    } catch (err) {
        logger.error('Create award edition error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to create award edition' });
    }
});

// PUT /api/admin/awards/editions/:id — update edition
adminRouter.put('/awards/editions/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const {
            name, session_id, status, description, poster_url,
            announcement_date, nomination_start, nomination_end,
            review_deadline, voting_start, voting_end,
            verification_deadline, winner_announcement
        } = req.body;

        // Validate date order if both provided
        if (nomination_start && nomination_end &&
            new Date(nomination_end) <= new Date(nomination_start)) {
            return res.status(400).json({ status: 'error', message: 'Nomination end must be after start' });
        }
        if (voting_start && voting_end &&
            new Date(voting_end) <= new Date(voting_start)) {
            return res.status(400).json({ status: 'error', message: 'Voting end must be after start' });
        }

        const updateData = { updated_at: new Date().toISOString() };
        if (name !== undefined) updateData.name = String(name).trim();
        if (session_id !== undefined) updateData.session_id = session_id;
        if (status !== undefined) updateData.status = status;
        if (description !== undefined) updateData.description = description;
        if (poster_url !== undefined) updateData.poster_url = poster_url;
        if (announcement_date !== undefined) updateData.announcement_date = announcement_date;
        if (nomination_start !== undefined) updateData.nomination_start = nomination_start;
        if (nomination_end !== undefined) updateData.nomination_end = nomination_end;
        if (review_deadline !== undefined) updateData.review_deadline = review_deadline;
        if (voting_start !== undefined) updateData.voting_start = voting_start;
        if (voting_end !== undefined) updateData.voting_end = voting_end;
        if (verification_deadline !== undefined) updateData.verification_deadline = verification_deadline;
        if (winner_announcement !== undefined) updateData.winner_announcement = winner_announcement;

        const { data, error } = await supabase
            .from('award_editions').update(updateData).eq('id', id).select().single();
        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Edition not found' });

        logger.info('Award edition updated', { requestId: req.id, editionId: id });
        res.json({ status: 'success', data, message: 'Edition updated' });
    } catch (err) {
        logger.error('Update award edition error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to update edition' });
    }
});

// DELETE /api/admin/awards/editions/:id — only draft editions (cascades children)
adminRouter.delete('/awards/editions/:id', async (req, res) => {
    try {
        const { data: existing } = await supabase
            .from('award_editions').select('status').eq('id', req.params.id).maybeSingle();
        if (!existing) return res.status(404).json({ status: 'error', message: 'Edition not found' });
        if (existing.status !== 'draft') {
            return res.status(400).json({
                status: 'error',
                message: 'Only draft editions can be deleted. Archive active editions instead.'
            });
        }

        // Cascade deletes (best-effort cleanup)
        try {
            const { data: cats } = await supabase.from('award_categories').select('id').eq('edition_id', req.params.id);
            const catIds = (cats || []).map(c => c.id);
            if (catIds.length) {
                await supabase.from('award_votes').delete().in('category_id', catIds);
                await supabase.from('award_judge_scores').delete().in('category_id', catIds);
            }
            await supabase.from('award_nominations').delete().eq('edition_id', req.params.id);
            await supabase.from('award_winners').delete().eq('edition_id', req.params.id);
            await supabase.from('award_judges').delete().eq('edition_id', req.params.id);
            await supabase.from('award_categories').delete().eq('edition_id', req.params.id);
        } catch (cascadeErr) {
            logger.warn('Cascade delete warning:', { error: cascadeErr.message });
        }

        await supabase.from('award_editions').delete().eq('id', req.params.id);
        logger.info('Award edition deleted', { requestId: req.id, editionId: req.params.id });
        res.json({ status: 'success', message: 'Edition deleted' });
    } catch (err) {
        logger.error('Delete award edition error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete edition' });
    }
});

// GET /api/admin/awards/archive — list archived editions
adminRouter.get('/awards/archive', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('award_editions')
            .select(`
                *,
                session:academic_sessions (id, name)
            `)
            .eq('status', 'archived')
            .order('created_at', { ascending: false });
        if (error) throw error;

        const enriched = await Promise.all((data || []).map(async (ed) => {
            const [catCount, winCount] = await Promise.all([
                supabase.from('award_categories').select('id', { count: 'exact', head: true }).eq('edition_id', ed.id),
                supabase.from('award_winners').select('id', { count: 'exact', head: true }).eq('edition_id', ed.id)
            ]);
            return {
                ...ed,
                session_name: ed.session?.name || null,
                categories_count: catCount.count || 0,
                winners_count: winCount.count || 0
            };
        }));

        res.json({ status: 'success', data: enriched, count: enriched.length });
    } catch (err) {
        logger.error('Award archive list error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch archive' });
    }
});


// ---------- ADMIN: AWARD CATEGORIES ----------

// GET /api/admin/awards/categories
adminRouter.get('/awards/categories', async (req, res) => {
    try {
        const edition = await getActiveAwardEdition();
        if (!edition) return res.json({ status: 'success', data: [] });

        const { data: categories, error } = await supabase
            .from('award_categories')
            .select('*')
            .eq('edition_id', edition.id)
            .order('display_order', { ascending: true });
        if (error) throw error;

        const enriched = await Promise.all((categories || []).map(async (c) => {
            const { count } = await supabase
                .from('award_nominations')
                .select('id', { count: 'exact', head: true })
                .eq('category_id', c.id);
            return { ...c, nominations_count: count || 0 };
        }));

        res.json({ status: 'success', data: enriched, count: enriched.length });
    } catch (err) {
        logger.error('Award categories list error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch categories' });
    }
});

// POST /api/admin/awards/categories
adminRouter.post('/awards/categories', async (req, res) => {
    try {
        const edition = await getActiveAwardEdition();
        if (!edition) return res.status(400).json({ status: 'error', message: 'No active edition' });

        const { name, type, selection_method, description, eligibility, status } = req.body;
        if (!name) return res.status(400).json({ status: 'error', message: 'Name is required' });

        const { data: last } = await supabase
            .from('award_categories')
            .select('display_order')
            .eq('edition_id', edition.id)
            .order('display_order', { ascending: false })
            .limit(1)
            .maybeSingle();
        const nextOrder = (last?.display_order || 0) + 1;

        const { data, error } = await supabase
            .from('award_categories')
            .insert([{
                edition_id: edition.id,
                name: name.trim(),
                type: type || 'individual',
                selection_method: selection_method || 'public',
                description: description || null,
                eligibility: eligibility || null,
                status: status || 'draft',
                display_order: nextOrder
            }])
            .select().single();
        if (error) throw error;

        logger.info('Award category created', { requestId: req.id, categoryId: data.id });
        res.status(201).json({ status: 'success', data, message: 'Category created' });
    } catch (err) {
        logger.error('Create award category error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to create category' });
    }
});

// PUT /api/admin/awards/categories/:id
adminRouter.put('/awards/categories/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, type, selection_method, description, eligibility, status, display_order } = req.body;

        const updateData = {};
        if (name !== undefined) updateData.name = String(name).trim();
        if (type !== undefined) updateData.type = type;
        if (selection_method !== undefined) updateData.selection_method = selection_method;
        if (description !== undefined) updateData.description = description;
        if (eligibility !== undefined) updateData.eligibility = eligibility;
        if (status !== undefined) updateData.status = status;
        if (display_order !== undefined) updateData.display_order = parseInt(display_order);

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ status: 'error', message: 'No fields to update' });
        }

        const { data, error } = await supabase
            .from('award_categories').update(updateData).eq('id', id).select().single();
        if (error) throw error;
        if (!data) return res.status(404).json({ status: 'error', message: 'Category not found' });

        res.json({ status: 'success', data, message: 'Category updated' });
    } catch (err) {
        logger.error('Update award category error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to update category' });
    }
});

// DELETE /api/admin/awards/categories/:id
adminRouter.delete('/awards/categories/:id', async (req, res) => {
    try {
        const { count } = await supabase
            .from('award_nominations')
            .select('id', { count: 'exact', head: true })
            .eq('category_id', req.params.id);

        if ((count || 0) > 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Cannot delete category with existing nominations. Deactivate instead.'
            });
        }

        await supabase.from('award_categories').delete().eq('id', req.params.id);
        res.json({ status: 'success', message: 'Category deleted' });
    } catch (err) {
        logger.error('Delete award category error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete category' });
    }
});


// ---------- ADMIN: AWARD NOMINATIONS ----------

// GET /api/admin/awards/nominations
adminRouter.get('/awards/nominations', async (req, res) => {
    try {
        const edition = await getActiveAwardEdition();
        if (!edition) return res.json({ status: 'success', data: [] });

        const { status } = req.query;
        let query = supabase
            .from('award_nominations')
            .select(`
                *,
                category:award_categories (id, name, type, selection_method)
            `)
            .eq('edition_id', edition.id)
            .order('created_at', { ascending: false });

        if (status && status !== 'all') query = query.eq('status', status);

        const { data, error } = await query;
        if (error) throw error;

        // Attach nominator name (from voters table) if available
        const enriched = await Promise.all((data || []).map(async (n) => {
            let nominatedByName = null;
            if (n.nominated_by) {
                const { data: voter } = await supabase
                    .from('voters').select('full_name').eq('id', n.nominated_by).maybeSingle();
                nominatedByName = voter?.full_name || null;
            }

            return {
                id: n.id,
                nominee_name: n.nominee_name,
                nominee_type: n.nominee_type,
                nominee_department: n.nominee_department,
                nominee_level: n.nominee_level,
                nominee_matric: n.nominee_matric,
                group_name: n.nominee_group_name,
                group_photo: n.nominee_group_photo,
                category_id: n.category_id,
                award_name: n.category?.name,
                award_type: n.category?.type,
                nominated_by_name: nominatedByName,
                reason: n.reason,
                evidence_url: n.evidence_url,
                status: n.status,
                created_at: n.created_at
            };
        }));

        res.json({ status: 'success', data: enriched, count: enriched.length });
    } catch (err) {
        logger.error('Admin award nominations list error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch nominations' });
    }
});

// PATCH /api/admin/awards/nominations/:id — approve/reject
adminRouter.patch('/awards/nominations/:id', async (req, res) => {
    try {
        const { status } = req.body;
        if (!['approved', 'rejected', 'pending'].includes(status)) {
            return res.status(400).json({ status: 'error', message: 'Invalid status' });
        }

        const { data, error } = await supabase
            .from('award_nominations')
            .update({ status, reviewed_by: req.user.id, reviewed_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .select().single();
        if (error) throw error;

        logger.info('Award nomination updated', {
            requestId: req.id, nominationId: req.params.id, status
        });
        res.json({ status: 'success', data, message: `Nomination ${status}` });
    } catch (err) {
        logger.error('Update award nomination error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to update nomination' });
    }
});

// DELETE /api/admin/awards/nominations/:id
adminRouter.delete('/awards/nominations/:id', async (req, res) => {
    try {
        await supabase.from('award_nominations').delete().eq('id', req.params.id);
        res.json({ status: 'success', message: 'Nomination deleted' });
    } catch (err) {
        logger.error('Delete award nomination error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to delete nomination' });
    }
});


// ---------- ADMIN: AWARD NOMINEES ----------

// GET /api/admin/awards/nominees
adminRouter.get('/awards/nominees', async (req, res) => {
    try {
        const edition = await getActiveAwardEdition();
        if (!edition) return res.json({ status: 'success', data: [] });

        const { data, error } = await supabase
            .from('award_nominations')
            .select(`
                *,
                category:award_categories (id, name, type, selection_method)
            `)
            .eq('edition_id', edition.id)
            .eq('status', 'approved')
            .order('created_at', { ascending: false });
        if (error) throw error;

        const enriched = (data || []).map(n => ({
            id: n.id,
            name: n.nominee_name,
            type: n.nominee_type,
            department: n.nominee_department,
            level: n.nominee_level,
            matric: n.nominee_matric,
            category_id: n.category_id,
            award_name: n.category?.name,
            award_type: n.category?.type,
            group_name: n.nominee_group_name,
            group_photo: n.nominee_group_photo,
            group_description: n.nominee_group_description,
            reason: n.reason,
            evidence_url: n.evidence_url,
            status: 'approved'
        }));

        res.json({ status: 'success', data: enriched, count: enriched.length });
    } catch (err) {
        logger.error('Admin award nominees list error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch nominees' });
    }
});


// ---------- ADMIN: PUBLISH WINNERS ----------

// POST /api/admin/awards/publish
adminRouter.post('/awards/publish', async (req, res) => {
    try {
        const edition = await getActiveAwardEdition();
        if (!edition) return res.status(404).json({ status: 'error', message: 'No active edition' });

        if (edition.results_published) {
            return res.status(409).json({ status: 'error', message: 'Results already published' });
        }

        const { data: categories } = await supabase
            .from('award_categories').select('*').eq('edition_id', edition.id);
        if (!categories?.length) {
            return res.status(400).json({ status: 'error', message: 'No categories configured' });
        }

        const winners = [];
        const skipped = [];
        const ties = [];

        for (const cat of categories) {
            const { data: nominees } = await supabase
                .from('award_nominations').select('*')
                .eq('category_id', cat.id)
                .eq('status', 'approved');
            if (!nominees?.length) { skipped.push(cat.name); continue; }

            let scores = {};

            if (cat.selection_method === 'public' || cat.selection_method === 'registered') {
                for (const n of nominees) {
                    const { count } = await supabase
                        .from('award_votes').select('id', { count: 'exact', head: true })
                        .eq('nomination_id', n.id);
                    scores[n.id] = count || 0;
                }
            } else if (cat.selection_method === 'judges') {
                for (const n of nominees) {
                    const { data: jScores } = await supabase
                        .from('award_judge_scores').select('score')
                        .eq('nomination_id', n.id);
                    scores[n.id] = (jScores || []).reduce((s, j) => s + (parseFloat(j.score) || 0), 0);
                }
            } else if (cat.selection_method === 'combined') {
                for (const n of nominees) {
                    const [voteRes, judgeRes] = await Promise.all([
                        supabase.from('award_votes').select('id', { count: 'exact', head: true }).eq('nomination_id', n.id),
                        supabase.from('award_judge_scores').select('score').eq('nomination_id', n.id)
                    ]);
                    const voteCount = voteRes.count || 0;
                    const judgeSum = (judgeRes.data || []).reduce((s, j) => s + (parseFloat(j.score) || 0), 0);
                    scores[n.id] = voteCount + judgeSum;
                }
            }

            const sorted = [...nominees].sort((a, b) => (scores[b.id] || 0) - (scores[a.id] || 0));
            const top = sorted[0];
            const second = sorted[1];

            // Skip ties — admin must resolve manually
            if (second && (scores[top.id] || 0) === (scores[second.id] || 0)) {
                logger.warn('Tie detected in category', { categoryId: cat.id, categoryName: cat.name });
                ties.push(cat.name);
                continue;
            }

            winners.push({
                edition_id: edition.id,
                category_id: cat.id,
                nomination_id: top.id,
                winner_name: top.nominee_name,
                final_score: scores[top.id] || 0,
                is_published: true,
                published_at: new Date().toISOString(),
                published_by: req.user.id
            });
        }

        if (winners.length === 0) {
            return res.status(400).json({
                status: 'error',
                message: 'No winners could be determined',
                details: { ties, skipped }
            });
        }

        const { error: winErr } = await supabase.from('award_winners').insert(winners);
        if (winErr) throw winErr;

        await supabase
            .from('award_editions')
            .update({ results_published: true, updated_at: new Date().toISOString() })
            .eq('id', edition.id);

        logger.info('Award winners published', {
            requestId: req.id, editionId: edition.id, winnersCount: winners.length
        });

        res.json({
            status: 'success',
            data: {
                winners_count: winners.length,
                winners,
                skipped_categories: skipped,
                tied_categories: ties
            },
            message: `${winners.length} winners published${ties.length ? ` (${ties.length} tie${ties.length !== 1 ? 's' : ''} skipped)` : ''}`
        });
    } catch (err) {
        logger.error('Publish award winners error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to publish winners' });
    }
});


// ---------- ADMIN: AWARD JUDGES ----------

// GET /api/admin/awards/judges
adminRouter.get('/awards/judges', async (req, res) => {
    try {
        const edition = await getActiveAwardEdition();
        if (!edition) return res.json({ status: 'success', data: [] });

        const { data, error } = await supabase
            .from('award_judges')
            .select(`
                *,
                user:users (id, full_name, email)
            `)
            .eq('edition_id', edition.id);
        if (error) throw error;

        const enriched = (data || []).map(j => ({
            id: j.id,
            user_id: j.user_id,
            user_name: j.user?.full_name,
            user_email: j.user?.email,
            assigned_at: j.created_at
        }));

        res.json({ status: 'success', data: enriched, count: enriched.length });
    } catch (err) {
        logger.error('Award judges list error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch judges' });
    }
});

// POST /api/admin/awards/judges
adminRouter.post('/awards/judges', async (req, res) => {
    try {
        const edition = await getActiveAwardEdition();
        if (!edition) return res.status(400).json({ status: 'error', message: 'No active edition' });

        const { user_id } = req.body;
        if (!user_id) return res.status(400).json({ status: 'error', message: 'user_id required' });

        const { data, error } = await supabase
            .from('award_judges')
            .insert([{
                edition_id: edition.id,
                user_id,
                assigned_by: req.user.id
            }])
            .select().single();

        if (error) {
            if (error.code === '23505') {
                return res.status(409).json({ status: 'error', message: 'User is already a judge' });
            }
            throw error;
        }

        res.status(201).json({ status: 'success', data, message: 'Judge assigned' });
    } catch (err) {
        logger.error('Assign award judge error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to assign judge' });
    }
});

// DELETE /api/admin/awards/judges/:id
adminRouter.delete('/awards/judges/:id', async (req, res) => {
    try {
        await supabase.from('award_judges').delete().eq('id', req.params.id);
        res.json({ status: 'success', message: 'Judge removed' });
    } catch (err) {
        logger.error('Remove award judge error:', { requestId: req.id, error: err.message });
        res.status(500).json({ status: 'error', message: 'Failed to remove judge' });
    }
});

console.log('✅ [AWARD-ADMIN] /api/admin/awards/* routes registered');

// ============================================================
// ================ SECTION 4.5: PUBLIC GALLERY + PLACEMENT ===
// ============================================================

const publicMediaRouter = express.Router();

// GET /api/gallery — PUBLIC. Only published items, no auth required.
publicMediaRouter.get('/gallery', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('media_gallery')
            .select(`
                id, title, description, category, status, display_order, created_at,
                media:media!media_gallery_media_id_fkey(
                    id, file_url, thumbnail_url, file_type, media_type, size_bytes)
            `)
            .eq('status', 'published')
            .order('display_order', { ascending: true })
            .order('created_at', { ascending: false });

        if (error) throw error;

        const mapped = (data || []).map(g => ({
            id: g.id,
            title: g.title,
            description: g.description,
            category: g.category,
            status: g.status,
            display_order: g.display_order,
            created_at: g.created_at,
            media: g.media ? {
                id: g.media.id,
                url: g.media.file_url,
                thumbnail_url: g.media.thumbnail_url || g.media.file_url,
                mime_type: g.media.file_type,
                media_type: g.media.media_type,
                size_bytes: g.media.size_bytes
            } : null
        }));

        // Cache for 60s — public pages hit this a lot
        res.setHeader('Cache-Control', 'public, max-age=60');
        res.json({ status: 'success', data: mapped, count: mapped.length });
    } catch (error) {
        logger.error('Public gallery error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to load gallery' });
    }
});

// GET /api/media/placements/homepage-hero — PUBLIC. Returns the current hero image.
publicMediaRouter.get('/media/placements/homepage-hero', async (req, res) => {
    try {
        const { data, error } = await supabase
                        .from('media_placements')
            .select(`
                media_id, updated_at,
                media:media!media_placements_media_id_fkey(
                    id, file_url, thumbnail_url, title, media_type)
            `)
            .eq('slot', 'homepage-hero')
            .maybeSingle();

        if (error && error.code !== 'PGRST116') throw error;

        if (!data || !data.media) {
            return res.json({ status: 'success', data: null });
        }

        res.setHeader('Cache-Control', 'public, max-age=120');
        res.json({
            status: 'success',
            data: {
                media_id: data.media_id,
                url: data.media.file_url,
                thumbnail_url: data.media.thumbnail_url || data.media.file_url,
                title: data.media.title,
                updated_at: data.updated_at
            }
        });
    } catch (error) {
        logger.error('Public placement error:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch placement' });
    }
});

app.use('/api', publicMediaRouter);
console.log('✅ [PUBLIC-MEDIA] /api/gallery and /api/media/placements/* registered');

// ============================================================
// ================== SECTION 5: FILE MANAGEMENT ==============
// ============================================================
app.post('/api/upload', verifyToken, requireRole('admin', 'editor'), upload.single('file'), async (req, res) => {
    try {
        if (!req.file) throw new ValidationError('No file uploaded');
        const fileInfo = {
            filename: req.file.filename, originalname: req.file.originalname,
            mimetype: req.file.mimetype, size: req.file.size,
            path: `/uploads/${req.file.filename}`,
            url: `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`,
            uploadedBy: req.user.id, uploadedAt: new Date()
        };
        logger.info('File uploaded', { requestId: req.id, filename: req.file.filename, uploadedBy: req.user.id });
        res.json({ status: 'success', data: fileInfo, message: 'File uploaded successfully' });
    } catch (error) {
        logger.error('Error uploading file:', { requestId: req.id, error: error.message });
        if (error instanceof ValidationError) return res.status(400).json({ status: 'error', message: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to upload file' });
    }
});

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
// ================== SECTION 6: STATIC FILES =================
// ============================================================
app.use('/uploads', compression(), express.static(path.join(__dirname, 'uploads'), {
    maxAge: IS_PRODUCTION ? '30d' : '0',
    setHeaders: (res, filePath) => {
        const ext = path.extname(filePath).toLowerCase();
        const mimeType = mime.lookup(ext) || 'application/octet-stream';
        if (ext.match(/\.(jpg|jpeg|png|gif|webp|svg|mp4|webm|mov)$/)) {
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
        '/': 'index.html', '/index.html': 'index.html',
        '/about': 'about.html', '/about.html': 'about.html',
        '/events': 'event.html', '/event.html': 'event.html',
        '/members': 'member.html', '/member.html': 'member.html',
        '/resources': 'resources.html', '/resources.html': 'resources.html',
        '/news': 'news.html', '/news.html': 'news.html',
        '/contact': 'contacts.html', '/contacts.html': 'contacts.html'
    };

    Object.entries(publicRoutes).forEach(([route, file]) => {
        app.get(route, (req, res) => res.sendFile(path.join(publicDir, file)));
    });

    console.log('✅ Public pages served from /public folder');
} else {
    console.log('⚠️ Public folder not found at:', publicDir);
}

// ============================================================
// ================== SECTION 7: SYSTEM ENDPOINTS ============
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

app.get('/api/metrics', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const metrics = {
            database: db.getStats(),
            cache: cacheManager.getStats(),
            system: { uptime: process.uptime(), memory: process.memoryUsage(), cpu: process.cpuUsage() }
        };
        res.json({ status: 'success', data: metrics, timestamp: new Date().toISOString(), requestId: req.id });
    } catch (error) {
        logger.error('Error fetching metrics:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch metrics' });
    }
});

app.get('/api/stats', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const [users, members, media] = await Promise.all([
            db.query('select', 'users', { count: true }),
            db.query('select', 'executive_members', { count: true }),
            db.query('select', 'media', { count: true })
        ]);
        res.json({
            status: 'success',
            data: {
                users: users.count || 0, members: members.count || 0, media: media.count || 0,
                cache: cacheManager.getStats(), uptime: process.uptime(), environment: NODE_ENV
            },
            requestId: req.id
        });
    } catch (error) {
        logger.error('Error fetching stats:', { requestId: req.id, error: error.message });
        res.status(500).json({ status: 'error', message: 'Failed to fetch statistics' });
    }
});

// ============================================================
// ================== SECTION 8: DEBUG ENDPOINTS =============
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
            res.json({ status: 'connected', message: 'Database connection successful', data: result.data, stats: db.getStats(), requestId: req.id });
        } catch (error) {
            res.status(500).json({ status: 'error', message: error.message, code: error.code, requestId: req.id });
        }
    });

    app.get('/api/debug/test', (req, res) => {
        res.json({ message: 'Debug endpoint working', timestamp: new Date().toISOString(), requestId: req.id });
    });
}

// ============================================================
// ================== SECTION 9: ERROR HANDLING ==============
// ============================================================
app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({
            status: 'error', code: 'ROUTE_NOT_FOUND',
            message: `Route ${req.method} ${req.url} not found`,
            timestamp: new Date().toISOString(), requestId: req.id
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
        requestId: req.id, error: err.message, stack: err.stack,
        url: req.url, method: req.method, ip: req.ip, userId: req.user?.id
    });

    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                status: 'error', code: 'FILE_TOO_LARGE',
                message: `File size too large. Maximum size is ${formatBytes(MAX_FILE_SIZE)}.`,
                requestId: req.id
            });
        }
        return res.status(400).json({ status: 'error', code: 'UPLOAD_ERROR', message: `File upload error: ${err.message}`, requestId: req.id });
    }

    if (err instanceof DatabaseError) {
        return res.status(400).json({ status: 'error', code: 'DATABASE_ERROR', message: `Database error: ${err.message}`, requestId: req.id });
    }
    if (err instanceof AuthError) {
        return res.status(err.statusCode || 401).json({ status: 'error', code: err.code, message: err.message, requestId: req.id });
    }
    if (err instanceof ValidationError) {
        return res.status(400).json({ status: 'error', code: 'VALIDATION_ERROR', message: err.message, errors: err.errors, requestId: req.id });
    }
    if (err instanceof NotFoundError) {
        return res.status(404).json({ status: 'error', code: 'NOT_FOUND', message: err.message, requestId: req.id });
    }
    if (err instanceof ForbiddenError) {
        return res.status(403).json({ status: 'error', code: 'FORBIDDEN', message: err.message, requestId: req.id });
    }

    const message = IS_PRODUCTION ? 'Internal server error' : err.message;
    res.status(err.statusCode || 500).json({
        status: 'error', code: 'INTERNAL_ERROR', message,
        ...(!IS_PRODUCTION && { stack: err.stack, details: err.message }),
        requestId: req.id
    });
});

// ============================================================
// ================== SECTION 10: PROCESS HANDLERS ===========
// ============================================================
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', { reason: reason.message || reason, stack: reason.stack, promise });
    if (IS_PRODUCTION) logger.error('Unhandled rejection in production, continuing...');
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', { error: error.message, stack: error.stack });
    if (IS_PRODUCTION) setTimeout(() => process.exit(1), 1000);
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
// ================== SECTION 11: SERVER STARTUP =============
// ============================================================
async function startServer() {
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log(`✅ [1/2] Server LISTENING on 0.0.0.0:${PORT} (${NODE_ENV})`);
    });

    server.on('error', (err) => {
        console.error('❌ [1/2] Server listen error:', err);
        process.exit(1);
    });

    console.log(`⏳ [2/2] Initializing database...`);
    initializeDatabase()
        .then(() => console.log(`✅ [2/2] Database initialized`))
        .catch((err) => {
            console.error(`⚠️ [2/2] Database init failed (server still running):`, err.message);
        });
}

startServer();