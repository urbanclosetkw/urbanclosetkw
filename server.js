const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const jwt    = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');

// Only allow actual image files, capped at 5MB, so a leaked/compromised
// admin token (or a bug) can't be used to push arbitrary or huge files
// into the storage bucket.
const ALLOWED_IMAGE_MIMETYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 20 * 1024 * 1024, // 20MB — real product photos run large; this still blocks anything absurd
  },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_IMAGE_MIMETYPES.includes(file.mimetype)) {
      return cb(new Error('Only JPEG, PNG, WEBP, or GIF images are allowed.'));
    }
    cb(null, true);
  },
});
const PaymentService = require('./paymentService');
const { ok, fail } = require('./utils/response');const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();

// Security headers
app.use(helmet());

// CORS from environment variable
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3000', 'http://localhost:5500'];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

app.use(express.json());

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { error: 'Too many attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter limiter for admin login — 3 attempts per 15 minutes.
// Admin credentials are higher-value than customer accounts, so we apply
// a tighter cap to slow down brute-force attempts on the admin panel.
const adminAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { error: 'Too many admin login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Verification codes are high-value targets for brute-forcing — cap attempts
// per IP separately from the general auth limiter.
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: { error: 'Too many verification attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

/* ── INVENTORY HELPERS ── */
// Validates every item before an order is created:
//  - product exists
//  - product is active (not soft-deleted)
//  - qty is a valid positive integer
//  - enough stock is available
async function validateOrderItems(items) {
  if (!Array.isArray(items) || !items.length) {
    return { ok: false, error: 'No items in order.' };
  }

  for (const item of items) {
    if (item.id === undefined || item.id === null) {
      return { ok: false, error: 'Order item is missing a product id.' };
    }
    const qty = item.qty;
    if (!Number.isInteger(qty) || qty < 1) {
      return { ok: false, error: `Invalid quantity for ${item.name || 'an item'}.` };
    }
  }

  const ids = items.map(i => i.id);
  const { data: products, error } = await supabase
    .from('products')
    .select('id, name, stock, is_deleted')
    .in('id', ids);
  if (error) return { ok: false, error: 'Could not verify products.' };

  for (const item of items) {
    const product = (products || []).find(p => String(p.id) === String(item.id));

    if (!product) {
      return { ok: false, error: `Product "${item.name || item.id}" no longer exists.` };
    }
    if (product.is_deleted) {
      return { ok: false, error: `${product.name} is no longer available.` };
    }
    if ((product.stock || 0) < item.qty) {
      return { ok: false, error: `${product.name} only has ${product.stock || 0} left in stock.` };
    }
  }

  return { ok: true };
}

async function decrementStock(items) {
  const ids = items.map(i => i.id).filter(Boolean);
  if (!ids.length) return;

  try {
    const { data: products, error } = await supabase
      .from('products')
      .select('id, stock')
      .in('id', ids);
    if (error) throw error;

    for (const item of items) {
      const product = (products || []).find(p => String(p.id) === String(item.id));
      if (!product) continue;
      const requestedQty = parseInt(item.qty, 10) || 1;
      const newStock = Math.max(0, (product.stock || 0) - requestedQty);

      const { error: updateErr } = await supabase
        .from('products')
        .update({ stock: newStock })
        .eq('id', item.id);
      if (updateErr) console.error(`decrementStock: failed to update product ${item.id}:`, updateErr.message);
    }
  } catch (e) {
    console.error('decrementStock error:', e.message);
  }
}

/* ── IMAGE NORMALIZATION HELPER ── */
// Coerces the images field to a clean array regardless of what was stored.
// Supabase stores it as JSONB, so it could arrive as an array, a plain string,
// or null/undefined if nothing was uploaded yet.
function normalizeImages(images) {
  if (Array.isArray(images)) return images.filter(Boolean);
  if (typeof images === 'string' && images) return [images];
  return [];
}

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is not set.');
if (!process.env.ADMIN_USER) throw new Error('ADMIN_USER environment variable is not set.');
if (!process.env.ADMIN_PASS) throw new Error('ADMIN_PASS environment variable is not set.');
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;
const STORAGE_BUCKET = process.env.STORAGE_BUCKET || 'product-images';

/* ── ACCOUNT VERIFICATION (email OTP) ── */
const EMAIL_OTP_TTL_MS      = 10 * 60 * 1000; // 10 minutes
const EMAIL_OTP_RESEND_MS   = 60 * 1000;      // 60s cooldown between resends
const EMAIL_OTP_MAX_ATTEMPTS = 5;             // wrong-code guesses before a resend is required
const PENDING_TOKEN_TTL     = '30m';

// 6-digit numeric code, e.g. "042613"
function generateEmailOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}
// Codes are never stored in plaintext — only their hash, same principle as passwords.
function hashOtp(code) {
  return crypto.createHash('sha256').update(String(code)).digest('hex');
}

function issueSessionToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}
function issuePendingToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, purpose: 'verify' },
    JWT_SECRET,
    { expiresIn: PENDING_TOKEN_TTL }
  );
}

async function sendEmailOtp(user) {
  const code = generateEmailOtp();
  const { error } = await supabase
    .from('users')
    .update({
      email_otp_hash:        hashOtp(code),
      email_otp_expires:     new Date(Date.now() + EMAIL_OTP_TTL_MS).toISOString(),
      email_otp_attempts:    0,
      last_email_otp_sent_at: new Date().toISOString(),
    })
    .eq('id', user.id);
  if (error) throw error;

  await sendEmail({
    to: user.email,
    subject: `${code} is your UrbanCloset verification code`,
    html: `
      <div style="font-family:sans-serif;max-width:420px;margin:auto;">
        <h2 style="color:#241a0f;">Verify your email</h2>
        <p style="color:#4a3f33;">Use this code to verify your UrbanCloset account. It expires in 10 minutes.</p>
        <div style="font-size:32px;letter-spacing:8px;font-weight:700;color:#8B5E4A;background:#F0E8DE;padding:16px 20px;border-radius:6px;text-align:center;margin:20px 0;">${code}</div>
        <p style="color:#7a6a5a;font-size:12px;">If you didn't request this, you can safely ignore this email.</p>
      </div>
    `
  });
}

/* ── STARTUP: Seed default admin account if none exists ── */
async function seedDefaultAdmin() {
  try {
    const { data, error } = await supabase
      .from('admin_users')
      .select('*')
      .limit(1);

    if (error) {
      console.error('Admin seed check failed:', error.message);
      return;
    }

    if (data && data.length > 0) {
      // Admin already exists — do not recreate
      return;
    }

    const hashed = await bcrypt.hash(ADMIN_PASS, 10);

    const { error: insertError } = await supabase
      .from('admin_users')
      .insert([{ username: ADMIN_USER, password: hashed }]);

    if (insertError) {
      console.error('Failed to create default admin:', insertError.message);
      return;
    }

    console.log('Default admin account created successfully.');
    console.log('Username:', ADMIN_USER);
    if (!process.env.ADMIN_PASS) {
      console.log('Password: admin123 (WARNING: ADMIN_PASS env var not set — using insecure default. Set it in Render now.)');
    } else {
      console.log('Password: (set from ADMIN_PASS env var)');
    }
    console.log('Please change immediately.');
  } catch (e) {
    console.error('Admin seed error:', e.message);
  }
}

/* ── AUTH MIDDLEWARE ── */
function requireAuth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return fail(res, 'No token', 401);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role === 'admin') {
  return fail(res, 'Admin tokens cannot access customer endpoints.', 403);
}
    req.user = payload;
    next();
  } catch (e) {
    return fail(res, 'Invalid token', 401);
  }
}


function requireAdminAuth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return fail(res, 'No token', 401);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') {
      return fail(res, 'Access denied. Admin only.', 403);
    }
    req.user = payload;
    next();
  } catch (e) {
    return fail(res, 'Invalid token', 401);
  }
}

// Guards the /verify/* endpoints. These use a short-lived "pending" token
// (issued at register/login) instead of a full session token, so an
// unverified account can never touch authenticated customer endpoints.
function requirePendingAuth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return fail(res, 'No token', 401);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.purpose !== 'verify') return fail(res, 'Invalid token', 401);
    req.pending = payload;
    next();
  } catch (e) {
    return fail(res, 'Verification session expired. Please log in again to get a new code.', 401);
  }
}

/* ── PUBLIC: POST /register ── */

app.post('/register', authLimiter, async (req, res) => {
  const { name, email: rawEmail, password } = req.body || {};
  if (!name || !rawEmail || !password)
    return fail(res, 'All fields are required.', 400);

  // Normalize email casing so "Sara@Gmail.com" and "sara@gmail.com" are
  // treated as the same account for both the duplicate check and login.
  const email = rawEmail.trim().toLowerCase();

  // Validate name length (2-100 chars)
  const trimmedName = name.trim();
  if (trimmedName.length < 2 || trimmedName.length > 100)
    return fail(res, 'Name must be between 2 and 100 characters.', 400);

  // Validate email format
  const emailRx = /^\S+@\S+\.\S+$/;
  if (!emailRx.test(email))
    return fail(res, 'Please enter a valid email address.', 400);

  // Validate password strength: min 8 chars, 1 uppercase, 1 lowercase, 1 number
  const passwordRx = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
  if (!passwordRx.test(password))
    return fail(res, 'Password must be at least 8 characters and include an uppercase letter, a lowercase letter, and a number.', 400);

  try {
    // Check if email already exists
    const { data: existing } = await supabase
      .from('users').select('id').eq('email', email).single();
    if (existing)
      return fail(res, 'Email already exists.', 409);

    const hashed = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert([{
        name: trimmedName,
        email,
        password: hashed,
        role: 'customer',
        email_verified: false,
      }])
      .select()
      .single();
    if (error) throw error;

    // Resend failing shouldn't block account creation — the user can hit
    // "resend" from the verify screen — but we report back whether it went
    // out so the frontend can react.
    let emailSent = true;
    try { await sendEmailOtp(data); } catch (e) {
      console.error('register: sendEmailOtp failed:', e.message);
      emailSent = false;
    }

    const pendingToken = issuePendingToken(data);

    res.status(201).json({
      success: true,
      pending: true,
      token: pendingToken,
      user: { id: data.id, name: data.name, email: data.email },
      emailSent
    });
  } catch (e) {
    console.error('POST /register error:', e.message);
    fail(res, 'Registration failed. Please try again.', 500);
  }
});

/* ── PUBLIC: POST /verify/email ── */
app.post('/verify/email', otpLimiter, requirePendingAuth, async (req, res) => {
  const { code } = req.body || {};
  if (!code) return fail(res, 'Code is required.', 400);

  try {
    const { data: user, error } = await supabase
      .from('users').select('*').eq('id', req.pending.id).single();
    if (error || !user) return fail(res, 'Account not found.', 404);

    if (user.email_verified) {
      return res.json({
        success: true,
        verified: true,
        token: issueSessionToken(user),
        user: { id: user.id, name: user.name, email: user.email, role: user.role }
      });
    }

    if (!user.email_otp_hash || !user.email_otp_expires) {
      return fail(res, 'No code was requested. Please resend a code.', 400);
    }
    if (new Date(user.email_otp_expires) < new Date()) {
      return fail(res, 'Code expired. Please request a new one.', 400);
    }
    if ((user.email_otp_attempts || 0) >= EMAIL_OTP_MAX_ATTEMPTS) {
      return fail(res, 'Too many incorrect attempts. Please request a new code.', 429);
    }
    if (hashOtp(code) !== user.email_otp_hash) {
      await supabase.from('users').update({ email_otp_attempts: (user.email_otp_attempts || 0) + 1 }).eq('id', user.id);
      return fail(res, 'Incorrect code.', 400);
    }

    const { data: updated, error: updateErr } = await supabase
      .from('users')
      .update({ email_verified: true, email_otp_hash: null, email_otp_expires: null, email_otp_attempts: 0 })
      .eq('id', user.id)
      .select()
      .single();
    if (updateErr) throw updateErr;

    res.json({
      success: true,
      verified: true,
      token: issueSessionToken(updated),
      user: { id: updated.id, name: updated.name, email: updated.email, role: updated.role }
    });
  } catch (e) {
    console.error('POST /verify/email error:', e.message);
    fail(res, 'Verification failed. Please try again.', 500);
  }
});

/* ── PUBLIC: POST /verify/resend-email ── */
app.post('/verify/resend-email', otpLimiter, requirePendingAuth, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users').select('*').eq('id', req.pending.id).single();
    if (error || !user) return fail(res, 'Account not found.', 404);
    if (user.email_verified) return fail(res, 'Email is already verified.', 400);

    if (user.last_email_otp_sent_at) {
      const waitMs = EMAIL_OTP_RESEND_MS - (Date.now() - new Date(user.last_email_otp_sent_at).getTime());
      if (waitMs > 0) {
        return fail(res, `Please wait ${Math.ceil(waitMs / 1000)}s before requesting another code.`, 429);
      }
    }

    await sendEmailOtp(user);
    res.json({ success: true, message: 'Code resent.' });
  } catch (e) {
    console.error('POST /verify/resend-email error:', e.message);
    fail(res, 'Could not resend code. Please try again.', 500);
  }
});

/* ── PUBLIC: POST /login ── */
app.post('/login', authLimiter, async (req, res) => {
  const { email: rawEmail, password } = req.body || {};
  if (!rawEmail || !password)
    return fail(res, 'Email and password are required.', 400);

  const email = rawEmail.trim().toLowerCase();

  try {
    const { data: user, error } = await supabase
      .from('users').select('*').eq('email', email).single();
    if (error || !user)
      return fail(res, 'Invalid email or password.', 401);

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return fail(res, 'Invalid email or password.', 401);

    // Admins are seeded pre-verified — only gate customer accounts on email verification.
    if (user.role !== 'admin' && !user.email_verified) {
      return res.status(403).json({
        success: false,
        error: 'Please verify your email to continue.',
        pending: true,
        token: issuePendingToken(user)
      });
    }

    const token = issueSessionToken(user);

    // Return flat shape: success, token, user (top-level) — matches frontend's
    // expectation of data.token / data.user in login.html
    res.status(200).json({
      success: true,
      token: token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (e) {
    console.error('POST /login error:', e.message);
    fail(res, 'Login failed. Please try again.', 500);
  }
});

/* ── PUBLIC: GET /products ── */
app.get('/products', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('*')
      .eq('is_deleted', false)
      .order('display_order', { ascending: true });
    if (error) throw error;

    const normalized = (data || []).map(p => ({
      ...p,
      images: normalizeImages(p.images),
      image_url: normalizeImages(p.images)[0] || null
    }));
    ok(res, normalized, 'Products fetched');
  } catch (e) {
    console.error('GET /products error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── PUBLIC: GET /products/:id ── */
app.get('/products/:id', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('*')
      .eq('id', req.params.id)
      .eq('is_deleted', false)
      .single();
    if (error) throw error;
    const normalized = {
      ...data,
      images: normalizeImages(data.images),
      image_url: normalizeImages(data.images)[0] || null
    };
    ok(res, normalized, 'Products fetched');
  } catch (e) {
    fail(res, 'Product not found', 404);
  }
});

/* ── ADMIN: POST /admin/login ── */
app.post('/admin/login', adminAuthLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return fail(res, 'Username and password are required.', 400);

  const { data, error } = await supabase
    .from('admin_users')
    .select('*')
    .eq('username', username)
    .single();

  if (error || !data)
    return fail(res, 'Invalid credentials', 401);

  const match = await bcrypt.compare(password, data.password);
  if (!match)
    return fail(res, 'Invalid credentials', 401);

  const token = jwt.sign({ adminId: data.id, username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });

  // Return flat shape: success, token (top-level) — matches admin-login.html's
  // expectation of data.token
  return res.status(200).json({
    success: true,
    token: token
  });
});

/* ── ADMIN: POST /admin/upload ── */
app.post('/admin/upload', requireAdminAuth, (req, res, next) => {
  // multer errors (file too large, wrong mimetype) happen before our route
  // body runs, so they're handled separately here rather than falling
  // through to the generic 500 error handler.
  upload.single('image')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return fail(res, 'File too large. Maximum size is 20MB.', 400);
      }
      return fail(res, err.message || 'Upload rejected.', 400);
    }
    next();
  });
}, async (req, res) => {
  try {
    if (!req.file) return fail(res, 'No file uploaded', 400);
    const ext      = req.file.originalname.split('.').pop();
    const filename = 'products/' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.' + ext;

    const { error } = await supabase.storage
      .from(STORAGE_BUCKET)
      .upload(filename, req.file.buffer, { contentType: req.file.mimetype });
    if (error) throw error;
    const { data: urlData } = supabase.storage
      .from(STORAGE_BUCKET)
      .getPublicUrl(filename);
    ok(res, { url: urlData.publicUrl }, 'File uploaded');
  } catch (e) {
    console.error('Upload error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: GET /admin/products ── */
// Returns ALL products including soft-deleted ones, for admin management
app.get('/admin/products', requireAdminAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('*')
      .order('display_order', { ascending: true });
    if (error) throw error;
    const normalized = (data || []).map(p => ({
      ...p,
      images: normalizeImages(p.images),
      image_url: normalizeImages(p.images)[0] || null
    }));
    ok(res, normalized, 'Products fetched');
  } catch (e) {
    console.error('GET /admin/products error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: POST /admin/products ── */
app.post('/admin/products', requireAdminAuth, async (req, res) => {
  try {
    const { name, price, stock, category, brand, series, sku } = req.body || {};

    // Required field validation (sku acts as the unique reference number)
    if (!name || stock === undefined || !category || !brand || !series || !sku) {
      return fail(res, 'name, stock, category, brand, series, and sku are required.', 400);
    }

    // Price is optional; if provided must be a non-negative number
    let safePrice = 0;
    if (price !== undefined && price !== null && price !== '') {
      safePrice = Number(price);
      if (isNaN(safePrice) || safePrice < 0) {
        return fail(res, 'Price must be a number greater than or equal to 0.', 400);
      }
    }

    // Stock must be >= 0
    if (typeof stock !== 'number' || stock < 0) {
      return fail(res, 'Stock must be a number greater than or equal to 0.', 400);
    }

    // Check sku uniqueness
    const { data: existing } = await supabase
      .from('products')
      .select('id')
      .eq('sku', sku)
      .single();
    if (existing) {
      return fail(res, 'A product with this SKU already exists.', 409);
    }

   const { id, price: _ignoredPrice, images: rawImages, ...bodyWithoutId } = req.body;
    const insertData = {
      ...bodyWithoutId,
      price: safePrice,
      is_deleted: false,  // new products are never deleted
      // Always store images as a proper array, even if the admin panel sent a string
      images: normalizeImages(rawImages)
    };

    const { data, error } = await supabase
      .from('products')
      .insert([insertData])
      .select()
      .single();
    if (error) throw error;
    ok(res, data, 'Product created');
  } catch (e) {
    console.error('POST /admin/products error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: PUT /admin/products/:id ── */
app.put('/admin/products/:id', requireAdminAuth, async (req, res) => {
  try {
    const updates = { ...req.body };

    // Validate price if provided (allow null/empty to clear it)
    if (updates.price !== undefined && updates.price !== null && updates.price !== '' && updates.price !== 0) {
      if (typeof updates.price !== 'number' || updates.price <= 0) {
        return fail(res, 'Price must be a number greater than 0.', 400);
      }
    }

    // Validate stock if provided
    if (updates.stock !== undefined) {
      if (typeof updates.stock !== 'number' || updates.stock < 0) {
        return fail(res, 'Stock must be a number greater than or equal to 0.', 400);
      }
    }

    // If sku is being changed, check uniqueness against other products
    if (updates.sku !== undefined) {
      const { data: existing } = await supabase
        .from('products')
        .select('id')
        .eq('sku', updates.sku)
        .neq('id', req.params.id)
        .single();
      if (existing) {
        return fail(res, 'A product with this SKU already exists.', 409);
      }
    }

    // Preserve existing images if no new images were sent; always store as array
    if (updates.images === undefined || (Array.isArray(updates.images) && updates.images.length === 0)) {
      delete updates.images;
    } else {
      updates.images = normalizeImages(updates.images);
    }

    const { data, error } = await supabase
      .from('products')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    ok(res, data, 'Product updated');
  } catch (e) {
    console.error('PUT /admin/products error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: DELETE /admin/products/:id ── */
app.delete('/admin/products/:id', requireAdminAuth, async (req, res) => {
  try {
    // Soft delete: mark as deleted instead of removing the row
    const { error } = await supabase
      .from('products')
      .update({ is_deleted: true })
      .eq('id', req.params.id);
    if (error) throw error;
    ok(res, {}, 'Product deleted');
  } catch (e) {
    console.error('DELETE /admin/products error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: DELETE /admin/products/:id/images ── */
app.delete('/admin/products/:id/images', requireAdminAuth, async (req, res) => {
  try {
    const urls = (req.body && req.body.urls) || [];
    if (!urls.length) return res.json({ deleted: 0 });

    const filenames = urls.map(url => {
      try {
        // Extract path after the bucket name, preserving the products/ folder
        const pathname = new URL(url).pathname;
        const bucketIdx = pathname.indexOf('/' + STORAGE_BUCKET + '/');
        if (bucketIdx !== -1) {
          return pathname.slice(bucketIdx + STORAGE_BUCKET.length + 2);
        }
        // Fallback: reconstruct the storage path by keeping the last two
        // segments (folder + filename), e.g. "products/image.jpg".
        // Dropping to just the filename would silently miss the delete.
        const parts = pathname.split('/').filter(Boolean);
        return parts.length >= 2
          ? parts.slice(-2).join('/')
          : parts[parts.length - 1];
      } catch (e) {
        return null;
      }
    }).filter(Boolean);

    if (!filenames.length) return res.json({ deleted: 0 });

    const { data, error } = await supabase.storage
      .from(STORAGE_BUCKET)
      .remove(filenames);

    if (error) {
      console.warn('Storage image delete warning:', error.message);
      return res.json({ deleted: 0, warning: error.message });
    }

    res.json({ deleted: (data || []).length });
  } catch (e) {
    console.error('DELETE /admin/products/:id/images error:', e.message);
    res.status(200).json({ deleted: 0, warning: e.message });
  }
});
/* ── CUSTOMER: PUT /users/:id ── */
app.put('/users/:id', requireAuth, async (req, res) => {
  try {
    // Ownership check: users can only edit their own profile, unless they're an admin
    if (String(req.user.id) !== String(req.params.id) && req.user.role !== 'admin') {
      return fail(res, 'Forbidden: you can only modify your own profile.', 403);
    }

    const { name, email, password } = req.body || {};
    const updates = {};
    if (name)  updates.name  = name;
    if (email) {
      const normalizedEmail = email.trim().toLowerCase();
      const { data: existing } = await supabase
        .from('users').select('id').eq('email', normalizedEmail).neq('id', req.params.id).single();
      if (existing) return fail(res, 'Email already exists.', 409);
      updates.email = normalizedEmail;
    }
    if (password) updates.password = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;

   ok(res, { id: data.id, name: data.name, email: data.email, role: data.role }, 'Profile updated');
  } catch (e) {
    fail(res, e.message, 500);
  }
});

/* ── CUSTOMER: DELETE /users/:id ── */
app.delete('/users/:id', requireAuth, async (req, res) => {
  try {
    // Ownership check: users can only delete their own account, unless they're an admin
    if (String(req.user.id) !== String(req.params.id) && req.user.role !== 'admin') {
      return fail(res, 'Forbidden: you can only delete your own account.', 403);
    }

    const { error } = await supabase
      .from('users')
      .delete()
      .eq('id', req.params.id);
    if (error) throw error;

    ok(res, {}, 'Account deleted');
  } catch (e) {
    fail(res, e.message, 500);
  }
}); 

/* ── CART: GET /cart ── */
app.get('/cart', requireAuth, async (req, res) => {
  try {
     const userId = req.user.id;

    const { data, error } = await supabase
      .from('cart')
      .select('qty, product_id, products(*)')
      .eq('user_id', userId);
    if (error) throw error;
    const items = (data || []).map(row => ({
      ...row.products,
      qty: row.qty,
      images: normalizeImages(row.products.images),
      image_url: normalizeImages(row.products.images)[0] || null
    }));
    ok(res, items, 'Cart fetched');
  } catch (e) {
    fail(res, e.message, 500);
  }
});

/* ── CART: POST /cart ── */
app.post('/cart', requireAuth, async (req, res) => {
  try {
     const userId = req.user.id;

    const { product_id, qty = 1 } = req.body || {};
    if (!product_id) return fail(res, 'product_id required', 400);

    // 1. Validate product
    const { data: product, error: productErr } = await supabase
      .from('products').select('id, stock, is_deleted').eq('id', product_id).single();
    if (productErr || !product) return fail(res, 'Product not found.', 404);
    if (product.is_deleted)     return fail(res, 'Product not available.', 410);
    if (product.stock <= 0)     return fail(res, 'Product is out of stock.', 400);

    // 2. Check existing cart row
    const { data: existing, error: findError } = await supabase
      .from('cart').select('*').eq('user_id', userId).eq('product_id', product_id).maybeSingle();
    if (findError) throw findError;

    // 3. Enforce stock limit
    const newQty = existing ? existing.qty + qty : qty;
    if (newQty > product.stock)
      return fail(res, `Only ${product.stock} item${product.stock !== 1 ? 's' : ''} available.`, 400);

    let data, error;
    if (existing) {
      ({ data, error } = await supabase
        .from('cart').update({ qty: newQty })
        .eq('user_id', userId).eq('product_id', product_id).select().single());
    } else {
      ({ data, error } = await supabase
        .from('cart').insert([{ user_id: userId, product_id, qty, added_at: new Date().toISOString() }])
        .select().single());
    }
    if (error) throw error;
    ok(res, data, 'Product added to cart');
  } catch (e) {
    fail(res, e.message, 500);
  }
});

/* ── CART: PUT /cart/:product_id ── */
app.put('/cart/:product_id', requireAuth, async (req, res) => {
  try {
     const userId = req.user.id;

    const { qty } = req.body || {};
    if (!qty || qty < 1) return fail(res, 'qty must be >= 1', 400);

    // Validate against current stock before updating — POST /cart already
    // did this for the initial add, but the +/- buttons on cart.html go
    // through this route and previously had no stock ceiling at all.
    const { data: product, error: productErr } = await supabase
      .from('products').select('id, stock, is_deleted').eq('id', req.params.product_id).single();
    if (productErr || !product) return fail(res, 'Product not found.', 404);
    if (product.is_deleted)     return fail(res, 'Product not available.', 410);
    if (qty > product.stock)
      return fail(res, `Only ${product.stock} item${product.stock !== 1 ? 's' : ''} available.`, 400);

    const { data, error } = await supabase
      .from('cart')
      .update({ qty })
      .eq('user_id', userId)
      .eq('product_id', req.params.product_id)
      .select()
      .single();
    if (error) throw error;
    ok(res, data, 'Cart updated');
  } catch (e) {
    fail(res, e.message, 500);
  }
});

/* ── CART: DELETE /cart/:product_id ── */
app.delete('/cart/:product_id', requireAuth, async (req, res) => {
  try {
     const userId = req.user.id;

    const { error } = await supabase
      .from('cart')
      .delete()
      .eq('user_id', userId)
      .eq('product_id', req.params.product_id);
    if (error) throw error;
    ok(res, {}, 'Item removed from cart');
  } catch (e) {
    fail(res, e.message, 500);
  }
});

/* ── CART: DELETE /cart  (clear entire cart) ── */
app.delete('/cart', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    const { error } = await supabase
      .from('cart')
      .delete()
      .eq('user_id', userId);
    if (error) throw error;
    ok(res, {}, 'Cart cleared');
  } catch (e) {
    fail(res, e.message, 500);
  }
});

/* ── ORDERS: POST /orders ── */
app.post('/orders', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

   const { customer_info, items, total, payment_method } = req.body || {};

    if (!items || !items.length)
      return fail(res, 'Your cart is empty. Add items before checking out.', 400);
    if (!customer_info || !customer_info.name || !customer_info.name.trim())
      return fail(res, 'Full name is required.', 400);
    if (!customer_info.email || !customer_info.email.trim())
      return fail(res, 'Email address is required.', 400);
    const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRx.test(customer_info.email.trim()))
      return fail(res, 'Please enter a valid email address.', 400);
    if (!customer_info.phone || !customer_info.phone.trim())
      return fail(res, 'Phone number is required.', 400);
    const phoneRx = /^[+]?[\d\s-]{7,20}$/;
    if (!phoneRx.test(customer_info.phone.trim()))
      return fail(res, 'Please enter a valid phone number.', 400);
    if (!customer_info.address || !customer_info.address.trim())
      return fail(res, 'Delivery address is required.', 400);

   const itemsCheck = await validateOrderItems(items);
    if (!itemsCheck.ok) return fail(res, itemsCheck.error, 400);

    const paymentFields = PaymentService.initPayment(payment_method);

    const { data, error } = await supabase
      .from('orders')
      .insert([{
        user_id:          userId,
        customer_info:    customer_info,
        customer_name:    customer_info.name,
        customer_email:   customer_info.email   || null,
        customer_phone:   customer_info.phone,
        customer_address: customer_info.address,
        items:            items,
        total:            total,
        status:           'pending',
        notes:            customer_info.notes   || null,
        updated_at:       new Date().toISOString(),
        ...paymentFields
      }])
      .select()
      .single();

 if (error) throw error;

    // Clear the user's cart after successful order
    await supabase.from('cart').delete().eq('user_id', userId);
    
if (paymentFields.payment_method === PaymentService.PAYMENT_METHODS.CASH_ON_DELIVERY) {
  // Stock for COD is deducted only when admin confirms — not here
      // COD orders are confirmed immediately — no payment step to wait for.
      sendOrderConfirmationEmail(data).catch(e =>
        console.error('sendOrderConfirmationEmail (COD) failed:', e.message));
    }

   // WhatsApp confirmation — wa.me links only fire when clicked, so we
    // build them here and return the customer link to the frontend
    // (so checkout/confirm pages can show a "Confirm via WhatsApp" button),
    // while logging the admin link server-side for now.
    let whatsapp = null;
    if (paymentFields.payment_method === PaymentService.PAYMENT_METHODS.CASH_ON_DELIVERY) {
      try {
        whatsapp = buildWhatsappLinks(data);
        console.log('WhatsApp admin link:', whatsapp.adminLink);
      } catch (waErr) {
        console.warn('WhatsApp link build failed:', waErr.message);
      }
    }

    ok(res, { order: data, whatsapp }, 'Order placed');
  } catch (e) {
    console.error('POST /orders error:', e.message);
    fail(res, 'Failed to place order. Please try again.', 500);
  }
});

/* ── CUSTOMER: GET /orders ── */
app.get('/orders', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { data, error } = await supabase
      .from('orders')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    ok(res, data || [], 'Orders fetched');
  } catch (e) {
    console.error('GET /orders error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── CUSTOMER: GET /orders/:id ── */
app.get('/orders/:id', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { data, error } = await supabase
      .from('orders')
      .select('*')
      .eq('id', req.params.id)
      .single();
    if (error || !data) return fail(res, 'Order not found.', 404);
    if (data.user_id !== userId)
      return fail(res, 'Access denied.', 403);
    ok(res, data, 'Order fetched');
  } catch (e) {
    console.error('GET /orders/:id error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: GET /admin/orders ── */
app.get('/admin/orders', requireAdminAuth, async (req, res) => {
  try {
        const { data, error } = await supabase
      .from('orders')
      .select('*, users(name, email)')
      .order('created_at', { ascending: false });
    if (error) throw error;

    const orders = (data || []).map(o => ({
      ...o,
      customer_name:  o.customer_name  || o.users?.name  || o.customer_info?.name  || '—',
      customer_email: o.customer_email || o.users?.email || o.customer_info?.email || '',
      customer_phone: o.customer_phone || o.customer_info?.phone || '',
      address:        o.customer_address || o.customer_info?.address || '',
    }));

    ok(res, orders, 'Orders fetched');

  } catch (e) {
    console.error('GET /admin/orders error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: PUT /admin/orders/:id ── */
app.put('/admin/orders/:id', requireAdminAuth, async (req, res) => {
  const allowed = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'];
  const { status, payment_status, transaction_id } = req.body || {};

  if (!status || !allowed.includes(status))
    return fail(res, 'Invalid status. Allowed: ' + allowed.join(', '), 400);

const updates = { status, updated_at: new Date().toISOString() };

  // Optional payment update (e.g. admin manually marks COD as paid)
  if (payment_status) {
    const allowedPayment = Object.values(PaymentService.PAYMENT_STATUS);
    if (!allowedPayment.includes(payment_status))
      return fail(res, 'Invalid payment_status.', 400);
    Object.assign(updates, payment_status === PaymentService.PAYMENT_STATUS.PAID
      ? PaymentService.markPaid(transaction_id)
      : { payment_status, transaction_id: transaction_id || null });
  }

  // Optional tracking number
  if (req.body.tracking_number !== undefined)
    updates.tracking_number = req.body.tracking_number || null;

  // Optional notes
  if (req.body.notes !== undefined)
    updates.notes = req.body.notes || null;

  try {
    // Capture the order's status before this update, so we can tell whether
    // this request is an actual pending→confirmed transition, or just a
    // re-save (e.g. adding a tracking number) while already confirmed.
    const { data: existingOrder } = await supabase
      .from('orders').select('status').eq('id', req.params.id).single();
    const previousStatus = existingOrder ? existingOrder.status : null;

    const { data, error } = await supabase
      .from('orders')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;

    // Deduct stock only on the actual pending→confirmed transition for a COD order
    if (status === 'confirmed' && previousStatus !== 'confirmed' && data.payment_method === PaymentService.PAYMENT_METHODS.CASH_ON_DELIVERY) {
      await decrementStock(data.items || []);
    }

    ok(res, data, 'Order updated');
  } catch (e) {
    console.error('PUT /admin/orders error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── EMAIL: shared transporter + sendOrderConfirmationEmail() ── */
async function sendEmail({ to, subject, html }) {
  const maxAttempts = 3;
  let lastError;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let res;
    try {
      res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + process.env.RESEND_API_KEY,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from: 'UrbanCloset <onboarding@resend.dev>',
          to: to,
          subject: subject,
          html: html
        })
      });
    } catch (networkErr) {
      // Network-level failure (DNS, timeout, connection reset) — always worth retrying.
      lastError = networkErr;
      if (attempt === maxAttempts) throw lastError;
      await new Promise(resolve => setTimeout(resolve, 500 * attempt));
      continue;
    }

    if (res.ok) return;

    const bodyText = await res.text();
    lastError = new Error('Resend failed (' + res.status + '): ' + bodyText);

    // Only retry on rate-limiting or Resend-side errors — a 4xx like an
    // invalid recipient address will never succeed no matter how many
    // times we retry it.
    const retryable = res.status === 429 || res.status >= 500;
    if (!retryable || attempt === maxAttempts) throw lastError;

    await new Promise(resolve => setTimeout(resolve, 500 * attempt));
  }

  throw lastError;
}

function paymentMethodLabel(method) {
  return method === PaymentService.PAYMENT_METHODS.CASH_ON_DELIVERY
    ? 'Cash on Delivery'
    : 'Online Payment';
}

function paymentStatusLabel(status) {
  const labels = {
    pending:  'Pending',
    paid:     'Paid',
    failed:   'Failed',
    refunded: 'Refunded'
  };
  return labels[status] || status || 'Pending';
}

/**
 * Send the order confirmation email to the customer, and a separate
 * new-order alert to the admin. Call this once an order is actually
 * confirmed (COD at creation, online payments once verified as paid).
 * Failures are logged but never thrown — email is best-effort and must
 * not break the order/payment flow that calls it.
 */
async function sendOrderConfirmationEmail(order) {
  const orderNumber = String(order.id).padStart(4, '0');
  const items = (order.items || []).map(i =>
    `<tr><td style="padding:8px 0;border-bottom:1px solid #eee;">${i.brand || ''} ${i.name || ''}${i.qty ? ` × ${i.qty}` : ''}</td><td style="padding:8px 0;border-bottom:1px solid #eee;text-align:right;color:#A48374;">KD ${parseFloat(i.price || 0).toFixed(3)}</td></tr>`
  ).join('');

  // ── Customer email ──
  const customerEmail = order.customer_email || order.customer_info?.email;
  if (customerEmail) {
    try {
     await sendEmail({
  to: customerEmail,
  subject: `Urban Closet Order Confirmation #${orderNumber}`,
  html:`
          <div style="font-family:sans-serif;max-width:520px;margin:0 auto;color:#241a0f;">
            <div style="background:#241a0f;padding:24px;text-align:center;">
              <span style="font-family:Georgia,serif;font-size:22px;color:#CBAD8D;letter-spacing:3px;">UrbanCloset</span>
            </div>
            <div style="padding:28px;">
              <p style="font-size:15px;">Hi ${order.customer_name || 'there'},</p>
<p style="margin-top:8px;color:#7a6a5a;">${order.payment_method === 'cash_on_delivery' ? 'Your order has been received! We will contact you via WhatsApp within 24 hours to confirm payment.' : 'Your order has been confirmed and payment received. Here\'s a summary:'}</p>              <p style="margin-top:12px;font-size:13px;color:#7a6a5a;">Order Number: <strong>#${orderNumber}</strong></p>
              <table style="width:100%;margin-top:20px;border-collapse:collapse;font-size:13px;">${items}</table>
              <div style="margin-top:16px;padding-top:12px;border-top:2px solid #eee;display:flex;justify-content:space-between;font-size:14px;font-weight:600;">
                <span>Total</span><span style="color:#A48374;">KD ${parseFloat(order.total || 0).toFixed(3)}</span>
              </div>
              <p style="margin-top:24px;font-size:13px;color:#7a6a5a;">Payment Method: ${paymentMethodLabel(order.payment_method)}</p>
              <p style="margin-top:4px;font-size:13px;color:#7a6a5a;">Status: ${paymentStatusLabel(order.payment_status)}</p>
              <p style="margin-top:20px;font-size:13px;">Questions? WhatsApp us at <a href="https://wa.me/96590910123" style="color:#A48374;">+965 9091 0123</a></p>
              <p style="margin-top:24px;font-size:12px;color:#A48374;">Thank you for shopping with UrbanCloset 🤍</p>
            </div>
          </div>`
      });
    } catch (e) {
      console.error(`sendOrderConfirmationEmail: customer email failed for order ${order.id}:`, e.message);
    }
  } else {
    console.warn(`sendOrderConfirmationEmail: no customer email on order ${order.id}, skipped.`);
  }
// ── Admin alert ──
  const adminEmail = process.env.ADMIN_EMAIL;
  if (adminEmail) {
    try {
      await sendEmail({
        to: adminEmail,
        subject: `New Order Received #${orderNumber} — KD ${parseFloat(order.total || 0).toFixed(3)}`,
        html: `
          <div style="font-family:sans-serif;max-width:520px;margin:0 auto;color:#241a0f;">
            <div style="background:#241a0f;padding:24px;text-align:center;">
              <span style="font-family:Georgia,serif;font-size:20px;color:#CBAD8D;letter-spacing:3px;">New Order Alert</span>
            </div>
            <div style="padding:28px;">
              <p style="font-size:15px;">Order <strong>#${orderNumber}</strong> has been placed.</p>
              <p style="margin-top:12px;font-size:13px;color:#7a6a5a;">
                Customer: ${order.customer_name || '—'}<br>
                Email: ${customerEmail || '—'}<br>
                Phone: ${order.customer_phone || order.customer_info?.phone || '—'}<br>
                Address: ${order.customer_address || order.customer_info?.address || '—'}
              </p>
              <table style="width:100%;margin-top:16px;border-collapse:collapse;font-size:13px;">${items}</table>
              <div style="margin-top:16px;padding-top:12px;border-top:2px solid #eee;font-size:14px;font-weight:600;">
                <span>Total</span><span style="color:#A48374;">KD ${parseFloat(order.total || 0).toFixed(3)}</span>
              </div>
              <p style="margin-top:12px;font-size:13px;color:#7a6a5a;">Payment Method: ${paymentMethodLabel(order.payment_method)}</p>
            </div>
          </div>`
      });
    } catch (e) {
      console.error(`sendOrderConfirmationEmail: admin email failed for order ${order.id}:`, e.message);
    }
  } else {
    console.warn('sendOrderConfirmationEmail: ADMIN_EMAIL not set, skipped admin alert.');
  }
}
/**
 * Build wa.me click-to-send links for an order — one for the customer,
 * one for the admin. wa.me cannot send automatically; a human must click
 * the link and press send inside WhatsApp. Returned so routes/frontend
 * can surface "Send WhatsApp" buttons at the right moment.
 */
function buildWhatsappLinks(order) {
  const orderNumber = String(order.id).padStart(4, '0');
  const itemLines = (order.items || []).map(i =>
    `• ${i.brand || ''} ${i.name || ''}${i.qty ? ` x${i.qty}` : ''} — KD ${parseFloat(i.price || 0).toFixed(3)}`
  ).join('\n');

  const customerInfo = order.customer_info || {};
  const customerPhone = (order.customer_phone || customerInfo.phone || '').replace(/[^\d]/g, '');

  // Customer confirmation message
  const customerMsg =
    `🛍 *UrbanCloset Order #${orderNumber} Confirmed*\n\n` +
    `Hi ${order.customer_name || 'there'}, your order is confirmed!\n\n` +
    `*Items:*\n${itemLines}\n\n` +
    `💰 *Total: KD ${parseFloat(order.total || 0).toFixed(3)}*\n` +
    `💳 Payment: ${paymentMethodLabel(order.payment_method)}\n\n` +
    `Thank you for shopping with UrbanCloset 🤍`;

  // Admin new-order alert
const orderDate = new Date(order.created_at || Date.now())
    .toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });

  // Admin new-order alert
  const adminMsg =
    `🛍 *New Order #${orderNumber}*\n\n` +
    `👤 ${order.customer_name || customerInfo.name || ''}\n` +
    `📞 ${order.customer_phone || customerInfo.phone || ''}\n` +
    (order.customer_email ? `📧 ${order.customer_email}\n` : '') +
    `🏠 ${order.customer_address || customerInfo.address || ''}\n\n` +
    `*Items:*\n${itemLines}\n\n` +
    `💰 *Total: KD ${parseFloat(order.total || 0).toFixed(3)}*\n` +
    `💳 Payment: ${paymentMethodLabel(order.payment_method)}\n` +
    `📅 Date: ${orderDate}\n` +
    `\n_Reply to confirm this order._`;

  const ADMIN_WHATSAPP = process.env.ADMIN_WHATSAPP || '96590910123';

  return {
    customerLink: customerPhone
      ? `https://wa.me/${customerPhone}?text=${encodeURIComponent(customerMsg)}`
      : null,
    adminLink: `https://wa.me/${ADMIN_WHATSAPP}?text=${encodeURIComponent(adminMsg)}`
  };
}

/* ── ADMIN: POST /admin/orders/:id/send-email ── */
app.post('/admin/orders/:id/send-email', requireAdminAuth, async (req, res) => {
  try {
    const { data: o, error } = await supabase
      .from('orders').select('*').eq('id', req.params.id).single();
    if (error || !o) return fail(res, 'Order not found.', 404);

    const email = o.customer_email || o.customer_info?.email;
    if (!email) return fail(res, 'No email address on this order.', 400);

    await sendOrderConfirmationEmail(o);
    ok(res, {}, 'Email sent');
  } catch (e) {
    console.error('POST /admin/orders/:id/send-email error:', e.message);
    fail(res, 'Failed to send email.', 500);
  }
});

/* ── PAYMENT: GET /payment/verify ── */
// confirm.html calls this after Deema redirects with ?orderId=
app.get('/payment/verify', async (req, res) => {
  try {
    const { orderId } = req.query;
    if (!orderId) return fail(res, 'orderId required.', 400);

    const { data: order } = await supabase
      .from('orders').select('*').eq('id', orderId).single();
    if (!order) return fail(res, 'Order not found.', 404);

    // Re-verify with Deema if still pending
    if (order.payment_status === 'pending' && order.transaction_id) {
      const verification = await PaymentService.verifyDeemaPayment({
        order_reference: order.transaction_id
      });
      if (verification.success && verification.isPaid) {
        await supabase.from('orders').update({
          status: 'confirmed',
          ...PaymentService.markPaid(verification.transaction_id),
          updated_at: new Date().toISOString()
        }).eq('id', order.id);
        await decrementStock(order.items || []);
        sendOrderConfirmationEmail({ ...order, status: 'confirmed', payment_status: 'paid' })
          .catch(e => console.error('sendOrderConfirmationEmail (verify) failed:', e.message));
      }
    }

    ok(res, { orderId: order.id, isPaid: order.payment_status === 'paid' }, 'Payment verified');
  } catch (e) {
    console.error('GET /payment/verify error:', e.message);
    fail(res, 'Verification error.', 500);
  }
});

/* ── PAYMENT: POST /payment/initiate ── */
app.post('/payment/initiate', requireAuth, async (req, res) => {
  try {
    const { orderId, total } = req.body || {};
    if (!orderId || !total) return fail(res, 'orderId and total required.', 400);

    // Verify order belongs to this user
    const { data: order, error: orderErr } = await supabase
      .from('orders').select('*').eq('id', orderId).single();
    if (orderErr || !order) return fail(res, 'Order not found.', 404);
    if (order.user_id !== req.user.id) return fail(res, 'Access denied.', 403);

    const mfRes = await fetch(`${process.env.MYFATOORAH_BASE_URL}/v2/SendPayment`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.MYFATOORAH_API_KEY}`
      },
      body: JSON.stringify({
        NotificationOption: 'LNK',
        InvoiceValue: parseFloat(total),
        CallBackUrl: `${process.env.FRONTEND_URL}/pages/confirm.html`,
        ErrorUrl:    `${process.env.FRONTEND_URL}/pages/checkout.html`,
        CustomerName:  order.customer_name  || '',
        CustomerEmail: order.customer_email || '',
        CustomerMobile: order.customer_phone || '',
        Language: 'en',
        CustomerReference: String(orderId),
        DisplayCurrencyIso: 'KWD'
      })
    });

    const mfData = await mfRes.json();
    if (!mfData.IsSuccess) {
      console.error('MyFatoorah initiate error:', mfData);
      return fail(res, 'Payment gateway error.', 502);
    }

    // Store the MyFatoorah invoice ID on the order for callback matching
    await supabase.from('orders').update({
      transaction_id: String(mfData.Data.InvoiceId),
      payment_status: 'pending'
    }).eq('id', orderId);

    ok(res, { paymentUrl: mfData.Data.InvoiceURL }, 'Payment initiated');
  } catch (e) {
    console.error('POST /payment/initiate error:', e.message);
    fail(res, 'Failed to initiate payment.', 500);
  }
});

/* ── PAYMENT: POST /payment/deema/initiate ── */
app.post('/payment/deema/initiate', requireAuth, async (req, res) => {
  try {
    const { orderId, total } = req.body || {};
    if (!orderId || !total) return fail(res, 'orderId and total required.', 400);

    const { data: order, error: orderErr } = await supabase
      .from('orders').select('*').eq('id', orderId).single();
    if (orderErr || !order) return fail(res, 'Order not found.', 404);
    if (order.user_id !== req.user.id) return fail(res, 'Access denied.', 403);

    const result = await PaymentService.createDeemaSession({
      orderId,
      amount: total,
      customer_info: {
        name:  order.customer_name,
        email: order.customer_email,
        phone: order.customer_phone
      }
    });

    if (!result.success) return fail(res, result.error || 'Deema session failed.', 500);

    await supabase.from('orders').update({
      status: 'awaiting_payment',
      payment_status: 'pending',
      transaction_id: result.sessionId || null,
      updated_at: new Date().toISOString()
    }).eq('id', orderId);

    ok(res, { paymentUrl: result.sessionUrl }, 'Deema session created');
  } catch (e) {
    console.error('POST /payment/deema/initiate error:', e.message);
    fail(res, 'Failed to initiate Deema payment.', 500);
  }
});

/* ── PAYMENT: POST /payments/deema/webhook ── */
// deema calls this when an order's payment status changes (captured / expired / cancelled).
// Body shape isn't strictly documented, so we read whichever of these deema sends:
//   order_reference (deema's own purchase ID) and/or merchant_order_id (our order id).
// We then re-confirm the real status server-to-server via verifyDeemaPayment()
// rather than trusting the webhook body's claimed status outright.
app.post('/webhook/deema', async (req, res) => {
  try {
    if (!PaymentService.isValidWebhookRequest(req.headers)) {
      return res.status(401).json({ error: 'Invalid webhook credentials.' });
    }

    const body = req.body || {};
    const orderReference   = body.order_reference || body.data?.order_reference;
    const merchantOrderId  = body.merchant_order_id || body.data?.merchant_order_id;

    if (!orderReference && !merchantOrderId) {
      return res.status(400).json({ error: 'Missing order_reference / merchant_order_id.' });
    }

    // Find the order: prefer merchant_order_id (= our orders.id), fall back to
    // matching on the transaction_id we stored at session-creation time.
    let order = null;
    if (merchantOrderId) {
      const { data } = await supabase.from('orders').select('*').eq('id', merchantOrderId).single();
      order = data || null;
    }
    if (!order && orderReference) {
      const { data } = await supabase.from('orders').select('*').eq('transaction_id', orderReference).single();
      order = data || null;
    }
    if (!order) return res.status(404).json({ error: 'Order not found.' });

    // Re-confirm with deema directly instead of trusting the webhook payload alone.
    const verification = await PaymentService.verifyDeemaPayment({
      order_reference: orderReference || order.transaction_id
    });
    if (!verification.success) {
      console.error('Deema webhook verification failed:', verification.error);
      return res.status(502).json({ error: 'Could not verify payment status with deema.' });
    }

    if (verification.isPaid) {
      // Deema (like most payment providers) may redeliver the same webhook
      // event more than once. Only run the one-time side effects — stock
      // deduction and the confirmation email — the first time this order
      // actually transitions into 'paid'.
      const alreadyPaid = order.payment_status === PaymentService.PAYMENT_STATUS.PAID;

      await supabase.from('orders').update({
        status: 'confirmed',
        ...PaymentService.markPaid(verification.transaction_id),
        updated_at: new Date().toISOString()
      }).eq('id', order.id);

      if (!alreadyPaid) {
        await decrementStock(order.items || []);

        sendOrderConfirmationEmail({
          ...order,
          status: 'confirmed',
          payment_status: PaymentService.PAYMENT_STATUS.PAID
        }).catch(e => console.error('sendOrderConfirmationEmail (Deema) failed:', e.message));
      }
    } else if (verification.isFailed) {
      await supabase.from('orders').update({
        status: 'payment_failed',
        ...PaymentService.markFailed(verification.transaction_id),
        updated_at: new Date().toISOString()
      }).eq('id', order.id);
    }
    // status === 'pending' → no-op, wait for the next webhook call

    res.status(200).json({ received: true });
  } catch (e) {
    console.error('POST /payments/deema/webhook error:', e.message);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

/* ── PAYMENT: GET /payment/callback ── */
// MyFatoorah redirects here after payment — but we use frontend confirm.html
// as the CallBackUrl directly. This endpoint is for server-side webhook (optional).
// If you set CallBackUrl to confirm.html, the PaymentId arrives as a query param
// and confirm.html handles display. This route is for manual server verification.
app.get('/payment/callback', async (req, res) => {
  try {
    const { paymentId } = req.query;
    if (!paymentId) return res.redirect(`${process.env.FRONTEND_URL}/pages/checkout.html`);

    const mfRes = await fetch(`${process.env.MYFATOORAH_BASE_URL}/v2/GetPaymentStatus`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.MYFATOORAH_API_KEY}`
      },
      body: JSON.stringify({ Key: paymentId, KeyType: 'PaymentId' })
    });

    const mfData = await mfRes.json();
    if (!mfData.IsSuccess) return res.redirect(`${process.env.FRONTEND_URL}/pages/checkout.html`);

    const invoiceId = String(mfData.Data.InvoiceId);
    const isPaid    = mfData.Data.InvoiceStatus === 'Paid';

    // Find order by the invoice ID we stored at initiation
    const { data: order } = await supabase
      .from('orders').select('*').eq('transaction_id', invoiceId).single();

    if (order && isPaid) {
      const alreadyPaid = order.payment_status === PaymentService.PAYMENT_STATUS.PAID;

      await supabase.from('orders').update({
        status: 'confirmed',
        ...PaymentService.markPaid(invoiceId),
        updated_at: new Date().toISOString()
      }).eq('id', order.id);

      if (!alreadyPaid) {
        await decrementStock(order.items || []);
        sendOrderConfirmationEmail({
          ...order,
          status: 'confirmed',
          payment_status: PaymentService.PAYMENT_STATUS.PAID
        }).catch(e => console.error('sendOrderConfirmationEmail (MyFatoorah) failed:', e.message));
      }

      return res.redirect(`${process.env.FRONTEND_URL}/pages/confirm.html?orderId=${order.id}`);
    }

    res.redirect(`${process.env.FRONTEND_URL}/pages/checkout.html`);
  } catch (e) {
    console.error('GET /payment/callback error:', e.message);
    res.redirect(`${process.env.FRONTEND_URL}/pages/checkout.html`);
  }
});

/* ── PUBLIC: GET /series ── */
// Returns ALL series — all series are always visible to customers.
// The `status` field ('available' | 'coming_soon') controls the card label,
// not visibility.
app.get('/series', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('series')
      .select('*')
      .order('display_order', { ascending: true });
    if (error) throw error;
    ok(res, data || [], 'Series fetched');
  } catch (e) {
    console.error('GET /series error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: GET /admin/series ── */
// Returns ALL series including disabled ones
app.get('/admin/series', requireAdminAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('series')
      .select('*')
      .order('display_order', { ascending: true });
    if (error) throw error;
    ok(res, data || [], 'Series fetched');
  } catch (e) {
    console.error('GET /admin/series error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: POST /admin/series ── */
app.post('/admin/series', requireAdminAuth, async (req, res) => {
  try {
    const { name, status = 'available', display_order = 0 } = req.body || {};
    if (!name || !name.trim()) return fail(res, 'Series name is required.', 400);

    const allowedStatuses = ['available', 'coming_soon'];
    if (!allowedStatuses.includes(status)) {
      return fail(res, 'status must be "available" or "coming_soon".', 400);
    }

    // Check uniqueness
    const { data: existing } = await supabase
      .from('series')
      .select('id')
      .ilike('name', name.trim())
      .single();
    if (existing) return fail(res, 'A series with this name already exists.', 409);

    const { data, error } = await supabase
      .from('series')
      .insert([{
        name: name.trim(),
        enabled: true,          // always visible
        status: status,
        display_order: Number(display_order) || 0
      }])
      .select()
      .single();
    if (error) throw error;
    ok(res, data, 'Series created');
  } catch (e) {
    console.error('POST /admin/series error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: PUT /admin/series/:id ── */
app.put('/admin/series/:id', requireAdminAuth, async (req, res) => {
  try {
    const updates = {};
    if (req.body.name !== undefined) updates.name = req.body.name.trim();
    if (req.body.display_order !== undefined) updates.display_order = Number(req.body.display_order) || 0;

    // status: 'available' | 'coming_soon' — the only toggle allowed
    if (req.body.status !== undefined) {
      const allowedStatuses = ['available', 'coming_soon'];
      if (!allowedStatuses.includes(req.body.status)) {
        return fail(res, 'status must be "available" or "coming_soon".', 400);
      }
      updates.status = req.body.status;
    }

    // Always keep enabled = true — series are never hidden
    updates.enabled = true;

    const { data, error } = await supabase
      .from('series')
      .update(updates)
      .eq('id', req.params.id)
      .select();
    if (error) throw error;
    if (!data || data.length === 0) {
      return fail(res, 'Series not found — id ' + req.params.id + ' does not match any row.', 404);
    }
    ok(res, data[0], 'Series updated');
  } catch (e) {
    console.error('PUT /admin/series error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: DELETE /admin/series/:id ── */
app.delete('/admin/series/:id', requireAdminAuth, async (req, res) => {
  try {
    const { error } = await supabase
      .from('series')
      .delete()
      .eq('id', req.params.id);
    if (error) throw error;
    ok(res, {}, 'Series deleted');
  } catch (e) {
    console.error('DELETE /admin/series error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── ADMIN: POST /admin/series/:id/upload-image ── */
// Uploads an image for a series card. Reuses the same product-images bucket
// (under a 'series/' prefix to keep things organised) and stores the publicUrl
// directly on series.image_url — no separate images[] array needed.
app.post('/admin/series/:id/upload-image', requireAdminAuth, (req, res, next) => {
  upload.single('image')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return fail(res, 'File too large. Maximum size is 20MB.', 400);
      }
      return fail(res, err.message || 'Upload rejected.', 400);
    }
    next();
  });
}, async (req, res) => {
  try {
    if (!req.file) return fail(res, 'No file uploaded.', 400);

    const seriesId = parseInt(req.params.id, 10);
    if (!seriesId) return fail(res, 'Invalid series id.', 400);

    // Confirm the series row exists before uploading anything
    const { data: existing, error: lookupErr } = await supabase
      .from('series')
      .select('id')
      .eq('id', seriesId)
      .single();
    if (lookupErr || !existing) return fail(res, 'Series not found.', 404);

    // Upload to storage under series/ prefix
    const ext      = req.file.originalname.split('.').pop();
    const filename = 'series/' + seriesId + '-' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.' + ext;

    const { error: uploadErr } = await supabase.storage
      .from(STORAGE_BUCKET)
      .upload(filename, req.file.buffer, { contentType: req.file.mimetype, upsert: true });
    if (uploadErr) throw uploadErr;

    const { data: urlData } = supabase.storage
      .from(STORAGE_BUCKET)
      .getPublicUrl(filename);
    const publicUrl = urlData.publicUrl;

    // Persist the URL on the series row
    const { error: updateErr } = await supabase
      .from('series')
      .update({ image_url: publicUrl })
      .eq('id', seriesId);
    if (updateErr) throw updateErr;

    ok(res, { image_url: publicUrl }, 'Series image uploaded');
  } catch (e) {
    console.error('POST /admin/series/:id/upload-image error:', e.message);
    fail(res, e.message, 500);
  }
});

/* ── START ── */
const PORT = process.env.PORT || 3000;
// Add this before the app.listen line at the bottom of server.js
app.use((err, req, res, next) => {
  console.error(err);
  return res.status(500).json({
    success: false,
    message: 'Internal Server Error'
  });
});

// Run admin seed, then start server
seedDefaultAdmin().then(() => {
  app.listen(PORT, () => console.log('Urban Closet server running on port ' + PORT));
});