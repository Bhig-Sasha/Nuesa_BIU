require('dotenv').config();

// ==================== IMPORTS ====================
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const winston = require('winston');
const xss = require('xss-clean');
const hpp = require('hpp');
const morgan = require('morgan');
const timeout = require('express-timeout-handler');

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
            'x-application-name': 'nuesa-biu-api'
        }
    }
});

console.log('✅ Supabase connected successfully');

// ==================== SUPABASE QUERY HELPER ====================
const executeQuery = async (operation, table, data = null, filters = {}) => {
    try {
        let query = supabase.from(table);
        
        // Apply filters
        if (filters.where) {
            Object.entries(filters.where).forEach(([key, value]) => {
                if (value !== undefined && value !== null) {
                    query = query.eq(key, value);
                }
            });
        }
        
        if (filters.order) {
            query = query.order(filters.order.column, { 
                ascending: filters.order.ascending !== false,
                nullsFirst: filters.order.nullsFirst || false
            });
        }
        
        if (filters.limit) {
            query = query.limit(filters.limit);
        }
        
        if (filters.offset) {
            query = query.range(filters.offset, filters.offset + (filters.limit || 1) - 1);
        }
        
        if (filters.select) {
            query = query.select(filters.select);
        }
        
        let result;
        switch(operation) {
            case 'select':
                result = await query;
                break;
            case 'insert':
                result = await query.insert(data).select();
                break;
            case 'update':
                if (filters.where) {
                    result = await query.update(data).match(filters.where).select();
                } else {
                    throw new Error('WHERE clause required for update');
                }
                break;
            case 'delete':
                if (filters.where) {
                    result = await query.delete().match(filters.where).select();
                } else {
                    throw new Error('WHERE clause required for delete');
                }
                break;
            case 'count':
                result = await query.select('*', { count: 'exact', head: true });
                break;
            case 'increment':
                if (!filters.where || !filters.column) {
                    throw new Error('WHERE clause and column required for increment');
                }
                const currentResult = await query.select(filters.column).single();
                if (currentResult.error) throw currentResult.error;
                const currentValue = currentResult.data[filters.column] || 0;
                const newValue = currentValue + (filters.incrementBy || 1);
                result = await query.update({ [filters.column]: newValue }).match(filters.where).select();
                break;
            default:
                throw new Error(`Unknown operation: ${operation}`);
        }
        
        if (result.error) {
            console.error('Supabase error:', result.error);
            throw result.error;
        }
        
        return {
            rows: result.data || [],
            rowCount: result.data?.length || 0,
            count: result.count
        };
    } catch (error) {
        console.error(`Database ${operation} error on table ${table}:`, error.message);
        throw error;
    }
};

// ==================== LOGGING SETUP ====================
const logger = winston.createLogger({
    level: isProduction ? 'info' : 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'nuesa-biu-api' },
    transports: [
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error',
            maxsize: 5242880,
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log',
            maxsize: 5242880,
            maxFiles: 5
        })
    ]
});

if (!isProduction) {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

// ==================== CACHE SETUP ====================
class LRUCache {
    constructor(maxSize = 100, ttl = 300000) {
        this.cache = new Map();
        this.maxSize = maxSize;
        this.ttl = ttl;
    }

    set(key, value, customTTL = null) {
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        this.cache.set(key, {
            value,
            expiry: Date.now() + (customTTL || this.ttl)
        });
    }

    get(key) {
        const item = this.cache.get(key);
        if (!item) return null;
        if (Date.now() > item.expiry) {
            this.cache.delete(key);
            return null;
        }
        return item.value;
    }

    delete(key) {
        return this.cache.delete(key);
    }

    clear() {
        this.cache.clear();
    }
}

const userCache = new LRUCache(200, 300000);
const dataCache = new LRUCache(100, 60000);

// ==================== MIDDLEWARE SETUP ====================
// Compression
app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: ["'self'", supabaseUrl, process.env.FRONTEND_URL],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            workerSrc: ["'self'", "blob:"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// XSS protection
app.use(xss());

// Parameter pollution protection
app.use(hpp());

// CORS configuration
const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5173',
    process.env.FRONTEND_URL,
    'https://nuesabiu.netlify.app'
].filter(Boolean);

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1 || origin.endsWith('.netlify.app')) {
            callback(null, true);
        } else {
            logger.warn('Blocked by CORS:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With', 'X-Refresh-Token'],
    exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
    maxAge: 86400
};

app.use(cors(corsOptions));

// Request parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
const morganFormat = isProduction ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

// Request timeout
app.use(timeout.handler({
    timeout: 30000,
    onTimeout: function(req, res) {
        logger.error('Request timeout for:', req.url);
        res.status(503).json({
            status: 'error',
            message: 'Request timeout'
        });
    }
}));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        status: 'error',
        message: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        status: 'error',
        message: 'Too many login attempts, please try again later.'
    }
});

app.use('/api/auth/login', authLimiter);
app.use('/api/', apiLimiter);

// Cache headers middleware
const setCacheHeaders = (req, res, next) => {
    if (req.headers.authorization) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
    } else if (req.method === 'GET') {
        res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=30');
    }
    next();
};
app.use(setCacheHeaders);

// ==================== FILE UPLOAD ====================
const uploadDirs = {
    images: './uploads/images',
    resources: './uploads/resources',
    profiles: './uploads/profiles'
};

// Create upload directories
Object.values(uploadDirs).forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        logger.info(`Created upload directory: ${dir}`);
    }
});

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (file.fieldname === 'file' || file.fieldname === 'resourceFile') {
            cb(null, uploadDirs.resources);
        } else if (file.fieldname.match(/(profilePicture|memberPhoto|eventImage|articleImage)/)) {
            cb(null, uploadDirs.images);
        } else {
            cb(null, uploadDirs.resources);
        }
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        const ext = path.extname(file.originalname).toLowerCase();
        const safeName = path.basename(file.originalname, ext)
            .replace(/[^a-zA-Z0-9_-]/g, '_')
            .substring(0, 50);
        cb(null, `${safeName}-${uniqueSuffix}${ext}`);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024,
        files: 1
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = [
            'image/jpeg',
            'image/jpg',
            'image/png',
            'image/gif',
            'image/webp',
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'text/plain',
            'application/zip',
            'application/x-rar-compressed',
            'application/x-zip-compressed'
        ];
        
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error(`File type ${file.mimetype} is not allowed`), false);
        }
        
        const ext = path.extname(file.originalname).toLowerCase();
        const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.doc', '.docx', '.xlsx', '.pptx', '.txt', '.zip', '.rar'];
        
        if (!allowedExts.includes(ext)) {
            return cb(new Error(`File extension ${ext} is not allowed`), false);
        }
        
        cb(null, true);
    }
});

// ==================== AUTHENTICATION MIDDLEWARE ====================
const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Access token required'
            });
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const cacheKey = `user:${decoded.userId}`;
        const cachedUser = userCache.get(cacheKey);
        
        if (cachedUser) {
            req.user = cachedUser;
            return next();
        }
        
        const userResult = await executeQuery('select', 'users', null, {
            where: { id: decoded.userId },
            select: 'id, email, full_name, role, department, is_active, created_at'
        });
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ status: 'error', message: 'User not found' });
        }
        
        if (!userResult.rows[0].is_active) {
            return res.status(403).json({ status: 'error', message: 'Account deactivated' });
        }
        
        const userData = {
            id: userResult.rows[0].id,
            email: userResult.rows[0].email,
            fullName: userResult.rows[0].full_name,
            role: userResult.rows[0].role,
            department: userResult.rows[0].department,
            createdAt: userResult.rows[0].created_at
        };
        
        userCache.set(cacheKey, userData, 300000);
        req.user = userData;
        
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ status: 'error', message: 'Token expired' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ status: 'error', message: 'Invalid token' });
        }
        logger.error('Token verification error:', error);
        res.status(500).json({ status: 'error', message: 'Authentication failed' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ 
            status: 'error', 
            message: 'Admin access required' 
        });
    }
    next();
};

const isAdminOrEditor = (req, res, next) => {
    const allowedRoles = ['admin', 'editor'];
    if (!allowedRoles.includes(req.user.role)) {
        return res.status(403).json({ 
            status: 'error', 
            message: 'Insufficient permissions' 
        });
    }
    next();
};

// ==================== DATABASE INITIALIZATION ====================
async function initializeDatabase() {
    try {
        const { data, error } = await supabase.from('users').select('count', { 
            count: 'exact', 
            head: true 
        });
        
        if (error) {
            logger.error('Supabase connection error:', error);
            throw error;
        }
        
        logger.info('✅ Database connected successfully');
        
        await createDefaultAdmin();
        
        logger.info('✅ Database initialization complete');
    } catch (error) {
        logger.error('❌ Database initialization failed:', error);
        process.exit(1);
    }
}

async function createDefaultAdmin() {
    try {
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@nuesabiu.org';
        
        const adminCheck = await executeQuery('select', 'users', null, {
            where: { email: adminEmail }
        });
        
        if (adminCheck.rows.length === 0) {
            const adminPassword = process.env.ADMIN_PASSWORD || 'Saint@2468..';
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
            
            await executeQuery('insert', 'users', adminData);
            logger.info(`👑 Admin user created: ${adminEmail}`);
            logger.info(`🔑 Admin password: ${adminPassword}`);
        } else {
            logger.info('✅ Admin user already exists');
        }
    } catch (error) {
        logger.error('⚠️ Could not create admin user:', error);
    }
}

// ==================== AUTH ROUTES ====================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Email and password are required' 
            });
        }
        
        if (!email.includes('@')) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Invalid email format' 
            });
        }
        
        const result = await executeQuery('select', 'users', null, {
            where: { email: email.toLowerCase().trim() },
            select: 'id, email, password_hash, full_name, role, department, is_active, created_at'
        });
        
        if (result.rows.length === 0) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Invalid credentials' 
            });
        }
        
        const user = result.rows[0];
        
        if (!user.is_active) {
            return res.status(403).json({ 
                status: 'error', 
                message: 'Account is deactivated. Please contact administrator.' 
            });
        }
        
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Invalid credentials' 
            });
        }
        
        const tokenPayload = {
            userId: user.id,
            email: user.email,
            role: user.role,
            fullName: user.full_name
        };
        
        const token = jwt.sign(tokenPayload, JWT_SECRET, { 
            expiresIn: JWT_EXPIRE 
        });
        
        const userResponse = {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            department: user.department,
            createdAt: user.created_at
        };
        
        userCache.set(`user:${user.id}`, userResponse, 300000);
        
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: isProduction,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        
        res.json({
            status: 'success',
            data: {
                user: userResponse,
                token,
                expiresIn: JWT_EXPIRE
            },
            message: 'Login successful'
        });
        
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Login failed. Please try again.' 
        });
    }
});

app.post('/api/auth/logout', verifyToken, async (req, res) => {
    try {
        userCache.delete(`user:${req.user.id}`);
        
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

app.get('/api/auth/verify', verifyToken, async (req, res) => {
    try {
        res.json({
            status: 'success',
            data: req.user,
            message: 'Token is valid'
        });
    } catch (error) {
        res.status(401).json({
            status: 'error',
            message: 'Token verification failed'
        });
    }
});

app.post('/api/auth/refresh', verifyToken, async (req, res) => {
    try {
        const newToken = jwt.sign(
            {
                userId: req.user.id,
                email: req.user.email,
                role: req.user.role,
                fullName: req.user.fullName
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRE }
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

// ==================== USER MANAGEMENT (ADMIN ONLY) ====================
app.get('/api/users', verifyToken, isAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, role, department } = req.query;
        const offset = (page - 1) * limit;
        
        let filters = {
            order: { column: 'created_at', ascending: false },
            limit: parseInt(limit),
            offset: parseInt(offset),
            select: 'id, email, full_name, role, department, is_active, created_at, updated_at'
        };
        
        if (role && role !== 'all') {
            filters.where = { ...filters.where, role };
        }
        
        if (department && department !== 'all') {
            filters.where = { ...filters.where, department };
        }
        
        const [usersResult, totalResult] = await Promise.all([
            executeQuery('select', 'users', null, filters),
            executeQuery('count', 'users', null, filters.where ? { where: filters.where } : {})
        ]);
        
        res.setHeader('X-Total-Count', totalResult.count || 0);
        res.setHeader('X-Page-Count', Math.ceil((totalResult.count || 0) / limit));
        
        res.json({
            status: 'success',
            data: usersResult.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: totalResult.count || 0,
                pages: Math.ceil((totalResult.count || 0) / limit)
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

app.post('/api/users', verifyToken, isAdmin, async (req, res) => {
    try {
        const { 
            email, 
            password, 
            full_name, 
            department, 
            role, 
            is_active = true 
        } = req.body;
        
        if (!email || !password || !full_name || !role) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Email, password, full name, and role are required' 
            });
        }
        
        if (!email.includes('@')) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Invalid email format' 
            });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Password must be at least 6 characters long' 
            });
        }
        
        const existingUser = await executeQuery('select', 'users', null, {
            where: { email: email.toLowerCase().trim() }
        });
        
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'User with this email already exists' 
            });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        
        const userData = {
            email: email.toLowerCase().trim(),
            password_hash: hashedPassword,
            full_name: full_name.trim(),
            department: department || null,
            username: email.split('@')[0].toLowerCase(),
            role: role,
            is_active: is_active,
            created_at: new Date(),
            updated_at: new Date()
        };
        
        const result = await executeQuery('insert', 'users', userData);
        
        const user = result.rows[0];
        const userResponse = {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            department: user.department,
            isActive: user.is_active,
            createdAt: user.created_at
        };
        
        res.status(201).json({
            status: 'success',
            data: userResponse,
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

app.put('/api/users/:id', verifyToken, isAdmin, async (req, res) => {
    try {
        const { 
            full_name, 
            department, 
            role, 
            is_active,
            password 
        } = req.body;
        
        const updateData = {
            full_name: full_name ? full_name.trim() : undefined,
            department: department || undefined,
            role: role || undefined,
            is_active: is_active !== undefined ? is_active : undefined,
            updated_at: new Date()
        };
        
        if (password && password.length >= 6) {
            updateData.password_hash = await bcrypt.hash(password, 12);
        }
        
        const cleanUpdateData = Object.fromEntries(
            Object.entries(updateData).filter(([_, v]) => v !== undefined)
        );
        
        if (Object.keys(cleanUpdateData).length === 0) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'No valid fields to update' 
            });
        }
        
        const result = await executeQuery('update', 'users', cleanUpdateData, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'User not found' 
            });
        }
        
        userCache.delete(`user:${req.params.id}`);
        
        const user = result.rows[0];
        const userResponse = {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            department: user.department,
            isActive: user.is_active,
            createdAt: user.created_at
        };
        
        res.json({
            status: 'success',
            data: userResponse,
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

app.delete('/api/users/:id', verifyToken, isAdmin, async (req, res) => {
    try {
        if (req.params.id === req.user.id) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Cannot delete your own account' 
            });
        }
        
        const result = await executeQuery('delete', 'users', null, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
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

// ==================== PROFILE ROUTES ====================
app.get('/api/profile', verifyToken, async (req, res) => {
    try {
        res.json({
            status: 'success',
            data: req.user
        });
    } catch (error) {
        logger.error('Error fetching profile:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch profile' 
        });
    }
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
            department: department || undefined,
            updated_at: new Date()
        };
        
        const result = await executeQuery('update', 'users', updateData, {
            where: { id: req.user.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'User not found' 
            });
        }
        
        userCache.delete(`user:${req.user.id}`);
        
        const updatedUser = {
            ...req.user,
            fullName: full_name.trim(),
            department: department
        };
        
        userCache.set(`user:${req.user.id}`, updatedUser, 300000);
        
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
        
        if (newPassword.length < 6) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'New password must be at least 6 characters long' 
            });
        }
        
        const userResult = await executeQuery('select', 'users', null, {
            where: { id: req.user.id },
            select: 'password_hash'
        });
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'User not found' 
            });
        }
        
        const validPassword = await bcrypt.compare(currentPassword, userResult.rows[0].password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Current password is incorrect' 
            });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        
        await executeQuery('update', 'users', {
            password_hash: hashedPassword,
            updated_at: new Date()
        }, {
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

// ==================== MEMBERS ROUTES ====================
app.get('/api/members', async (req, res) => {
    try {
        const cacheKey = 'members:all';
        const cachedData = dataCache.get(cacheKey);
        
        if (cachedData) {
            return res.json({
                status: 'success',
                data: cachedData,
                cached: true
            });
        }
        
        const result = await executeQuery('select', 'executive_members', null, {
            where: { status: 'active' },
            order: { column: 'display_order', ascending: true }
        });
        
        dataCache.set(cacheKey, result.rows, 120000);
        
        res.json({
            status: 'success',
            data: result.rows,
            count: result.rowCount
        });
    } catch (error) {
        logger.error('Error fetching members:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch members' 
        });
    }
});

app.get('/api/members/:id', async (req, res) => {
    try {
        const cacheKey = `member:${req.params.id}`;
        const cachedData = dataCache.get(cacheKey);
        
        if (cachedData) {
            return res.json({
                status: 'success',
                data: cachedData,
                cached: true
            });
        }
        
        const result = await executeQuery('select', 'executive_members', null, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Member not found' 
            });
        }
        
        dataCache.set(cacheKey, result.rows[0], 300000);
        
        res.json({
            status: 'success',
            data: result.rows[0]
        });
    } catch (error) {
        logger.error('Error fetching member:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch member' 
        });
    }
});

app.post('/api/members', verifyToken, isAdminOrEditor, async (req, res) => {
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
            social_links: social_links || {},
            created_at: new Date(),
            updated_at: new Date()
        };
        
        const result = await executeQuery('insert', 'executive_members', memberData);
        
        dataCache.clear();
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
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

app.put('/api/members/:id', verifyToken, isAdminOrEditor, async (req, res) => {
    try {
        const {
            full_name, position, department, level, email, phone,
            bio, committee, display_order, status, social_links
        } = req.body;
        
        const memberData = {
            full_name: full_name ? full_name.trim() : undefined,
            position: position ? position.trim() : undefined,
            department: department !== undefined ? (department ? department.trim() : null) : undefined,
            level: level !== undefined ? (level ? level.trim() : null) : undefined,
            email: email !== undefined ? (email ? email.toLowerCase().trim() : null) : undefined,
            phone: phone !== undefined ? (phone ? phone.trim() : null) : undefined,
            bio: bio !== undefined ? (bio ? bio.trim() : null) : undefined,
            committee: committee !== undefined ? (committee ? committee.trim() : null) : undefined,
            display_order: display_order !== undefined ? display_order : undefined,
            status: status !== undefined ? status : undefined,
            social_links: social_links !== undefined ? social_links : undefined,
            updated_at: new Date()
        };
        
        const cleanMemberData = Object.fromEntries(
            Object.entries(memberData).filter(([_, v]) => v !== undefined)
        );
        
        if (Object.keys(cleanMemberData).length === 0) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'No valid fields to update' 
            });
        }
        
        const result = await executeQuery('update', 'executive_members', cleanMemberData, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Member not found' 
            });
        }
        
        dataCache.delete(`member:${req.params.id}`);
        dataCache.delete('members:all');
        
        res.json({
            status: 'success',
            data: result.rows[0],
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

app.delete('/api/members/:id', verifyToken, isAdminOrEditor, async (req, res) => {
    try {
        const result = await executeQuery('delete', 'executive_members', null, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Member not found' 
            });
        }
        
        dataCache.delete(`member:${req.params.id}`);
        dataCache.delete('members:all');
        
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

// ==================== EVENTS ROUTES ====================
app.get('/api/events', async (req, res) => {
    try {
        const { category, status, upcoming, limit = 50 } = req.query;
        
        const cacheKey = `events:${category || 'all'}:${status || 'all'}:${upcoming || 'all'}:${limit}`;
        const cachedData = dataCache.get(cacheKey);
        
        if (cachedData) {
            return res.json({
                status: 'success',
                data: cachedData,
                cached: true
            });
        }
        
        let filters = {
            order: { column: 'date', ascending: true },
            limit: parseInt(limit)
        };
        
        if (category && category !== 'all') {
            filters.where = { ...filters.where, category };
        }
        
        if (status && status !== 'all') {
            filters.where = { ...filters.where, status };
        }
        
        const result = await executeQuery('select', 'events', null, filters);
        
        let events = result.rows;
        
        if (upcoming === 'true') {
            const now = new Date();
            events = events.filter(event => new Date(event.date) >= now);
        }
        
        dataCache.set(cacheKey, events, 60000);
        
        res.json({
            status: 'success',
            data: events,
            count: events.length
        });
    } catch (error) {
        logger.error('Error fetching events:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch events' 
        });
    }
});

app.get('/api/events/upcoming', async (req, res) => {
    try {
        const cacheKey = 'events:upcoming';
        const cachedData = dataCache.get(cacheKey);
        
        if (cachedData) {
            return res.json({
                status: 'success',
                data: cachedData,
                cached: true
            });
        }
        
        const result = await executeQuery('select', 'events', null, {
            order: { column: 'date', ascending: true },
            limit: 10
        });
        
        const now = new Date();
        const upcomingEvents = result.rows
            .filter(event => new Date(event.date) >= now && event.status === 'upcoming')
            .slice(0, 5);
        
        dataCache.set(cacheKey, upcomingEvents, 60000);
        
        res.json({
            status: 'success',
            data: upcomingEvents,
            count: upcomingEvents.length
        });
    } catch (error) {
        logger.error('Error fetching upcoming events:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch upcoming events' 
        });
    }
});

app.get('/api/events/:id', async (req, res) => {
    try {
        const cacheKey = `event:${req.params.id}`;
        const cachedData = dataCache.get(cacheKey);
        
        if (cachedData) {
            return res.json({
                status: 'success',
                data: cachedData,
                cached: true
            });
        }
        
        const result = await executeQuery('select', 'events', null, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Event not found' 
            });
        }
        
        dataCache.set(cacheKey, result.rows[0], 300000);
        
        res.json({
            status: 'success',
            data: result.rows[0]
        });
    } catch (error) {
        logger.error('Error fetching event:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch event' 
        });
    }
});

app.post('/api/events', verifyToken, isAdminOrEditor, async (req, res) => {
    try {
        const {
            title, description, category, date, start_time, end_time,
            location, organizer, max_participants, status
        } = req.body;
        
        if (!title || !category || !date) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Title, category, and date are required' 
            });
        }
        
        const eventData = {
            title: title.trim(),
            description: description ? description.trim() : null,
            category: category.trim(),
            date: new Date(date),
            start_time: start_time || null,
            end_time: end_time || null,
            location: location ? location.trim() : null,
            organizer: organizer ? organizer.trim() : null,
            max_participants: max_participants ? parseInt(max_participants) : null,
            status: status || 'upcoming',
            created_at: new Date(),
            updated_at: new Date()
        };
        
        const result = await executeQuery('insert', 'events', eventData);
        
        dataCache.clear();
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Event created successfully'
        });
    } catch (error) {
        logger.error('Error creating event:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to create event' 
        });
    }
});

app.put('/api/events/:id', verifyToken, isAdminOrEditor, async (req, res) => {
    try {
        const {
            title, description, category, date, start_time, end_time,
            location, organizer, max_participants, status
        } = req.body;
        
        const eventData = {
            title: title ? title.trim() : undefined,
            description: description !== undefined ? (description ? description.trim() : null) : undefined,
            category: category ? category.trim() : undefined,
            date: date ? new Date(date) : undefined,
            start_time: start_time !== undefined ? start_time : undefined,
            end_time: end_time !== undefined ? end_time : undefined,
            location: location !== undefined ? (location ? location.trim() : null) : undefined,
            organizer: organizer !== undefined ? (organizer ? organizer.trim() : null) : undefined,
            max_participants: max_participants !== undefined ? (max_participants ? parseInt(max_participants) : null) : undefined,
            status: status !== undefined ? status : undefined,
            updated_at: new Date()
        };
        
        const cleanEventData = Object.fromEntries(
            Object.entries(eventData).filter(([_, v]) => v !== undefined)
        );
        
        if (Object.keys(cleanEventData).length === 0) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'No valid fields to update' 
            });
        }
        
        const result = await executeQuery('update', 'events', cleanEventData, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Event not found' 
            });
        }
        
        dataCache.delete(`event:${req.params.id}`);
        dataCache.delete('events:upcoming');
        
        res.json({
            status: 'success',
            data: result.rows[0],
            message: 'Event updated successfully'
        });
    } catch (error) {
        logger.error('Error updating event:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to update event' 
        });
    }
});

app.delete('/api/events/:id', verifyToken, isAdminOrEditor, async (req, res) => {
    try {
        const result = await executeQuery('delete', 'events', null, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Event not found' 
            });
        }
        
        dataCache.delete(`event:${req.params.id}`);
        dataCache.delete('events:upcoming');
        
        res.json({
            status: 'success',
            message: 'Event deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting event:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to delete event' 
        });
    }
});

// ==================== ARTICLES ROUTES ====================
app.get('/api/articles', async (req, res) => {
    try {
        const { category, status, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        
        const cacheKey = `articles:${category || 'all'}:${status || 'all'}:${page}:${limit}`;
        const cachedData = dataCache.get(cacheKey);
        
        if (cachedData) {
            return res.json({
                status: 'success',
                data: cachedData.data,
                pagination: cachedData.pagination,
                cached: true
            });
        }
        
        let filters = {
            order: { column: 'created_at', ascending: false },
            limit: parseInt(limit),
            offset: parseInt(offset)
        };
        
        if (category && category !== 'all') {
            filters.where = { ...filters.where, category };
        }
        
        if (status === 'published') {
            filters.where = { ...filters.where, is_published: true };
        } else if (status === 'draft') {
            filters.where = { ...filters.where, is_published: false };
        } else if (status && status !== 'all') {
            filters.where = { ...filters.where, status };
        }
        
        const [articlesResult, totalResult] = await Promise.all([
            executeQuery('select', 'articles', null, filters),
            executeQuery('count', 'articles', null, filters.where ? { where: filters.where } : {})
        ]);
        
        const responseData = {
            data: articlesResult.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: totalResult.count || 0,
                pages: Math.ceil((totalResult.count || 0) / limit)
            }
        };
        
        dataCache.set(cacheKey, responseData, 60000);
        
        res.setHeader('X-Total-Count', totalResult.count || 0);
        res.setHeader('X-Page-Count', Math.ceil((totalResult.count || 0) / limit));
        
        res.json({
            status: 'success',
            ...responseData
        });
    } catch (error) {
        logger.error('Error fetching articles:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch articles' 
        });
    }
});

app.get('/api/articles/:id', async (req, res) => {
    try {
        const cacheKey = `article:${req.params.id}`;
        const cachedData = dataCache.get(cacheKey);
        
        if (cachedData) {
            return res.json({
                status: 'success',
                data: cachedData,
                cached: true
            });
        }
        
        const result = await executeQuery('select', 'articles', null, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Article not found' 
            });
        }
        
        dataCache.set(cacheKey, result.rows[0], 300000);
        
        res.json({
            status: 'success',
            data: result.rows[0]
        });
    } catch (error) {
        logger.error('Error fetching article:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch article' 
        });
    }
});

app.post('/api/articles', verifyToken, isAdminOrEditor, async (req, res) => {
    try {
        const {
            title, excerpt, content, author, category,
            tags, status
        } = req.body;
        
        if (!title || !content) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Title and content are required' 
            });
        }
        
        const slug = title.toLowerCase()
            .replace(/[^a-zA-Z0-9\s]/g, '')
            .replace(/\s+/g, '-')
            .substring(0, 200);
        
        const isPublished = status === 'published';
        
        const articleData = {
            title: title.trim(),
            slug,
            excerpt: excerpt ? excerpt.trim() : null,
            content: content.trim(),
            author: author ? author.trim() : null,
            category: category ? category.trim() : null,
            tags: tags || [],
            status: status || 'draft',
            published_at: isPublished ? new Date() : null,
            is_published: isPublished,
            created_at: new Date(),
            updated_at: new Date()
        };
        
        const result = await executeQuery('insert', 'articles', articleData);
        
        dataCache.clear();
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Article created successfully'
        });
    } catch (error) {
        logger.error('Error creating article:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to create article' 
        });
    }
});

app.put('/api/articles/:id', verifyToken, isAdminOrEditor, async (req, res) => {
    try {
        const {
            title, excerpt, content, author, category,
            tags, status
        } = req.body;
        
        const isPublished = status === 'published';
        
        const articleData = {
            title: title ? title.trim() : undefined,
            excerpt: excerpt !== undefined ? (excerpt ? excerpt.trim() : null) : undefined,
            content: content ? content.trim() : undefined,
            author: author !== undefined ? (author ? author.trim() : null) : undefined,
            category: category !== undefined ? (category ? category.trim() : null) : undefined,
            tags: tags !== undefined ? tags : undefined,
            status: status !== undefined ? status : undefined,
            published_at: isPublished ? new Date() : undefined,
            is_published: isPublished !== undefined ? isPublished : undefined,
            updated_at: new Date()
        };
        
        const cleanArticleData = Object.fromEntries(
            Object.entries(articleData).filter(([_, v]) => v !== undefined)
        );
        
        if (Object.keys(cleanArticleData).length === 0) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'No valid fields to update' 
            });
        }
        
        const result = await executeQuery('update', 'articles', cleanArticleData, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Article not found' 
            });
        }
        
        dataCache.delete(`article:${req.params.id}`);
        
        res.json({
            status: 'success',
            data: result.rows[0],
            message: 'Article updated successfully'
        });
    } catch (error) {
        logger.error('Error updating article:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to update article' 
        });
    }
});

app.delete('/api/articles/:id', verifyToken, isAdminOrEditor, async (req, res) => {
    try {
        const result = await executeQuery('delete', 'articles', null, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Article not found' 
            });
        }
        
        dataCache.delete(`article:${req.params.id}`);
        
        res.json({
            status: 'success',
            message: 'Article deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting article:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to delete article' 
        });
    }
});

// ==================== RESOURCES ROUTES ====================
app.get('/api/resources', async (req, res) => {
    try {
        const { category, department, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        
        const cacheKey = `resources:${category || 'all'}:${department || 'all'}:${page}:${limit}`;
        const cachedData = dataCache.get(cacheKey);
        
        if (cachedData) {
            return res.json({
                status: 'success',
                data: cachedData.data,
                pagination: cachedData.pagination,
                cached: true
            });
        }
        
        let filters = {
            order: { column: 'created_at', ascending: false },
            limit: parseInt(limit),
            offset: parseInt(offset)
        };
        
        if (category && category !== 'all') {
            filters.where = { ...filters.where, category };
        }
        
        if (department && department !== 'all') {
            filters.where = { ...filters.where, department };
        }
        
        const [resourcesResult, totalResult] = await Promise.all([
            executeQuery('select', 'resources', null, filters),
            executeQuery('count', 'resources', null, filters.where ? { where: filters.where } : {})
        ]);
        
        const responseData = {
            data: resourcesResult.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: totalResult.count || 0,
                pages: Math.ceil((totalResult.count || 0) / limit)
            }
        };
        
        dataCache.set(cacheKey, responseData, 120000);
        
        res.setHeader('X-Total-Count', totalResult.count || 0);
        res.setHeader('X-Page-Count', Math.ceil((totalResult.count || 0) / limit));
        
        res.json({
            status: 'success',
            ...responseData
        });
    } catch (error) {
        logger.error('Error fetching resources:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch resources' 
        });
    }
});

app.post('/api/resources/upload', verifyToken, isAdminOrEditor, upload.single('file'), async (req, res) => {
    try {
        const {
            title, description, category, department,
            level, course_code, course_title, year, semester
        } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'No file uploaded' 
            });
        }
        
        if (!title || !category) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Title and category are required' 
            });
        }
        
        const fileUrl = `/uploads/resources/${req.file.filename}`;
        
        let fileType = req.file.mimetype.split('/')[1];
        if (fileType === 'vnd.openxmlformats-officedocument.wordprocessingml.document') {
            fileType = 'docx';
        } else if (fileType === 'vnd.openxmlformats-officedocument.presentationml.presentation') {
            fileType = 'pptx';
        } else if (fileType === 'vnd.openxmlformats-officedocument.spreadsheetml.sheet') {
            fileType = 'xlsx';
        }
        
        let processedYear = year;
        if (year && year.includes('/')) {
            processedYear = year.split('/')[0];
        }
        
        const resourceData = {
            title: title.trim(),
            description: description ? description.trim() : null,
            category: category.trim(),
            department: department ? department.trim() : null,
            level: level ? parseInt(level) : null,
            course_code: course_code ? course_code.trim() : null,
            course_title: course_title ? course_title.trim() : null,
            year: processedYear || null,
            semester: semester || '1',
            file_url: fileUrl,
            file_type: fileType,
            file_size: req.file.size,
            uploaded_by: req.user.id,
            download_count: 0,
            created_at: new Date()
        };
        
        const result = await executeQuery('insert', 'resources', resourceData);
        
        dataCache.clear();
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Resource uploaded successfully'
        });
    } catch (error) {
        logger.error('Error uploading resource:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to upload resource' 
        });
    }
});

app.get('/api/resources/:id/download', async (req, res) => {
    try {
        const result = await executeQuery('select', 'resources', null, {
            where: { id: req.params.id },
            select: 'file_url, title, download_count'
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Resource not found' 
            });
        }
        
        const resource = result.rows[0];
        
        await executeQuery('increment', 'resources', null, {
            where: { id: req.params.id },
            column: 'download_count'
        });
        
        const filePath = path.join(__dirname, resource.file_url);
        
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'File not found' 
            });
        }
        
        const safeFilename = resource.title.replace(/[^a-z0-9]/gi, '_').toLowerCase();
        const ext = path.extname(resource.file_url);
        
        res.download(filePath, `${safeFilename}${ext}`);
    } catch (error) {
        logger.error('Error downloading resource:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to download resource' 
        });
    }
});

app.delete('/api/resources/:id', verifyToken, isAdminOrEditor, async (req, res) => {
    try {
        const resourceResult = await executeQuery('select', 'resources', null, {
            where: { id: req.params.id },
            select: 'file_url'
        });
        
        if (resourceResult.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Resource not found' 
            });
        }
        
        const result = await executeQuery('delete', 'resources', null, {
            where: { id: req.params.id }
        });
        
        const filePath = path.join(__dirname, resourceResult.rows[0].file_url);
        try {
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        } catch (fsError) {
            logger.warn('Could not delete file:', fsError.message);
        }
        
        dataCache.clear();
        
        res.json({
            status: 'success',
            message: 'Resource deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting resource:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to delete resource' 
        });
    }
});

// ==================== CONTACT/MESSAGES ROUTES ====================
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, subject, message, department } = req.body;
        
        if (!name || !email || !subject || !message) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'All fields are required' 
            });
        }
        
        if (!email.includes('@')) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Invalid email format' 
            });
        }
        
        const messageData = {
            name: name.trim(),
            email: email.toLowerCase().trim(),
            subject: subject.trim(),
            message: message.trim(),
            department: department ? department.trim() : null,
            status: 'new',
            created_at: new Date()
        };
        
        const result = await executeQuery('insert', 'messages', messageData);
        
        res.status(201).json({
            status: 'success',
            data: result.rows[0],
            message: 'Message sent successfully'
        });
    } catch (error) {
        logger.error('Error sending message:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to send message' 
        });
    }
});

app.get('/api/messages', verifyToken, isAdmin, async (req, res) => {
    try {
        const { status, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        
        let filters = {
            order: { column: 'created_at', ascending: false },
            limit: parseInt(limit),
            offset: parseInt(offset)
        };
        
        if (status && status !== 'all') {
            filters.where = { ...filters.where, status };
        }
        
        const [messagesResult, totalResult] = await Promise.all([
            executeQuery('select', 'messages', null, filters),
            executeQuery('count', 'messages', null, filters.where ? { where: filters.where } : {})
        ]);
        
        res.setHeader('X-Total-Count', totalResult.count || 0);
        res.setHeader('X-Page-Count', Math.ceil((totalResult.count || 0) / limit));
        
        res.json({
            status: 'success',
            data: messagesResult.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: totalResult.count || 0,
                pages: Math.ceil((totalResult.count || 0) / limit)
            }
        });
    } catch (error) {
        logger.error('Error fetching messages:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch messages' 
        });
    }
});

app.get('/api/messages/:id', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await executeQuery('select', 'messages', null, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Message not found' 
            });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0]
        });
    } catch (error) {
        logger.error('Error fetching message:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch message' 
        });
    }
});

app.put('/api/messages/:id/read', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await executeQuery('update', 'messages', {
            status: 'read'
        }, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Message not found' 
            });
        }
        
        res.json({
            status: 'success',
            data: result.rows[0],
            message: 'Message marked as read'
        });
    } catch (error) {
        logger.error('Error marking message as read:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to update message' 
        });
    }
});

app.delete('/api/messages/:id', verifyToken, isAdmin, async (req, res) => {
    try {
        const result = await executeQuery('delete', 'messages', null, {
            where: { id: req.params.id }
        });
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Message not found' 
            });
        }
        
        res.json({
            status: 'success',
            message: 'Message deleted successfully'
        });
    } catch (error) {
        logger.error('Error deleting message:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to delete message' 
        });
    }
});

// ==================== ANALYTICS ROUTES ====================
app.get('/api/analytics', verifyToken, isAdmin, async (req, res) => {
    try {
        const [
            usersResult,
            membersResult,
            eventsResult,
            articlesResult,
            resourcesResult,
            messagesResult
        ] = await Promise.all([
            executeQuery('count', 'users'),
            executeQuery('count', 'executive_members', null, { where: { status: 'active' } }),
            executeQuery('count', 'events', null, { where: { status: 'upcoming' } }),
            executeQuery('count', 'articles', null, { where: { is_published: true } }),
            executeQuery('count', 'resources'),
            executeQuery('count', 'messages', null, { where: { status: 'new' } })
        ]);
        
        const totalDownloads = await supabase
            .from('resources')
            .select('download_count')
            .then(({ data, error }) => {
                if (error) throw error;
                return data.reduce((sum, item) => sum + (item.download_count || 0), 0);
            });
        
        res.json({
            status: 'success',
            data: {
                total_users: usersResult.count || 0,
                active_members: membersResult.count || 0,
                upcoming_events: eventsResult.count || 0,
                published_articles: articlesResult.count || 0,
                total_resources: resourcesResult.count || 0,
                unread_messages: messagesResult.count || 0,
                total_downloads: totalDownloads,
                storage_used: 0 // You can implement this if storing file sizes
            }
        });
    } catch (error) {
        logger.error('Error fetching analytics:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch analytics' 
        });
    }
});

// ==================== SETTINGS ROUTES ====================
app.get('/api/settings', async (req, res) => {
    try {
        const cacheKey = 'site_settings';
        const cachedData = dataCache.get(cacheKey);
        
        if (cachedData) {
            return res.json({
                status: 'success',
                data: cachedData,
                cached: true
            });
        }
        
        const result = await executeQuery('select', 'site_settings');
        
        const settings = {};
        result.rows.forEach(setting => {
            settings[setting.setting_key] = setting.setting_value;
        });
        
        dataCache.set(cacheKey, settings, 300000);
        
        res.json({
            status: 'success',
            data: settings
        });
    } catch (error) {
        logger.error('Error fetching settings:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch settings' 
        });
    }
});

app.put('/api/settings', verifyToken, isAdmin, async (req, res) => {
    try {
        const settings = req.body;
        
        for (const [key, value] of Object.entries(settings)) {
            const existing = await executeQuery('select', 'site_settings', null, {
                where: { setting_key: key }
            });
            
            if (existing.rows.length > 0) {
                await executeQuery('update', 'site_settings', {
                    setting_value: value,
                    updated_at: new Date()
                }, {
                    where: { setting_key: key }
                });
            } else {
                await executeQuery('insert', 'site_settings', {
                    setting_key: key,
                    setting_value: value,
                    updated_at: new Date()
                });
            }
        }
        
        dataCache.delete('site_settings');
        
        res.json({
            status: 'success',
            message: 'Settings updated successfully'
        });
    } catch (error) {
        logger.error('Error updating settings:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to update settings' 
        });
    }
});

// ==================== HEALTH ENDPOINTS ====================
app.get('/api/health', async (req, res) => {
    try {
        await executeQuery('select', 'users', null, { limit: 1 });
        res.json({
            status: 'success',
            message: 'API is running',
            timestamp: new Date().toISOString(),
            database: 'connected',
            environment: NODE_ENV,
            uptime: process.uptime()
        });
    } catch (error) {
        res.status(503).json({
            status: 'error',
            message: 'Database disconnected',
            error: error.message
        });
    }
});

app.get('/api/ping', (req, res) => {
    res.json({ 
        status: 'success', 
        message: 'pong', 
        timestamp: new Date().toISOString() 
    });
});

// ==================== STATIC FILES ====================
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
    maxAge: isProduction ? '30d' : '0',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.pdf') || filePath.endsWith('.docx') || filePath.endsWith('.xlsx') || filePath.endsWith('.pptx')) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        } else if (filePath.match(/\.(jpg|jpeg|png|gif|webp)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=86400');
        }
    }
}));

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
    res.json({
        message: 'NUESA BIU API Server',
        version: '1.0.0',
        environment: NODE_ENV,
        database: 'Supabase',
        status: 'operational',
        timestamp: new Date().toISOString(),
        documentation: 'Contact administrator for API documentation'
    });
});

// ==================== ERROR HANDLERS ====================
app.use((req, res) => {
    res.status(404).json({ 
        status: 'error', 
        message: 'Route not found',
        path: req.url 
    });
});

app.use((err, req, res, next) => {
    logger.error({
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        user: req.user?.id
    });
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                status: 'error',
                message: 'File size too large. Maximum size is 10MB.'
            });
        }
        return res.status(400).json({
            status: 'error',
            message: 'File upload error: ' + err.message
        });
    }
    
    const message = isProduction ? 'Internal server error' : err.message;
    const statusCode = err.statusCode || 500;
    
    res.status(statusCode).json({
        status: 'error',
        message: message,
        ...(!isProduction && { stack: err.stack })
    });
});

// ==================== UNHANDLED ERROR HANDLERS ====================
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    if (isProduction) {
        process.exit(1);
    }
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    if (isProduction) {
        process.exit(1);
    }
});

// ==================== SERVER STARTUP ====================
async function startServer() {
    try {
        await initializeDatabase();
        
        app.listen(PORT, () => {
            console.log(`
╔═══════════════════════════════════════════════════════════╗
║     🚀 NUESA BIU API Server Started Successfully!       ║
╠═══════════════════════════════════════════════════════════╣
║ 📡 Port: ${PORT}                                         ║
║ 🌍 Environment: ${NODE_ENV}                              ║
║ 🗄️  Database: Supabase                                   ║
║ 🔗 API URL: http://localhost:${PORT}/api                  ║
║ 🌐 Frontend: ${process.env.FRONTEND_URL || 'Not set'}     ║
║ 👑 Admin: ${process.env.ADMIN_EMAIL || 'admin@nuesabiu.org'} ║
╚═══════════════════════════════════════════════════════════╝
            `);
            
            console.log('\n📋 Available Endpoints:');
            console.log('├── /api/auth/login');
            console.log('├── /api/auth/logout');
            console.log('├── /api/auth/verify');
            console.log('├── /api/members');
            console.log('├── /api/events');
            console.log('├── /api/articles');
            console.log('├── /api/resources');
            console.log('├── /api/analytics');
            console.log('├── /api/settings');
            console.log('├── /api/health');
            console.log('└── /api/contact');
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();