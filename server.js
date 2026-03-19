const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const log      = require('./logger');
const { sanitize, sanitizeQuery, validateBody } = require('./validate');

const app = express();
app.set('trust proxy', 1); // Trust ngrok/reverse proxy headers
const PORT = process.env.PORT || 5001;

// ============================================================
//  1. CREDENTIALS — all from .env, never hardcoded
// ============================================================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const JWT_SECRET  = process.env.JWT_SECRET;

if (!supabaseUrl || !supabaseKey || !JWT_SECRET) {
    log.error('❌  Missing required env vars. Check your .env file.');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// ============================================================
//  eTIMS — DigiTax Integration
// ============================================================
const DIGITAX_BASE_URL = process.env.DIGITAX_BASE_URL || 'https://api.digitax.tech/ke/v2';
const DIGITAX_API_KEY  = process.env.DIGITAX_API_KEY  || '';

async function submitSaleToEtims(saleData) {
    if (!DIGITAX_API_KEY) { log.warn('[eTIMS] DIGITAX_API_KEY not set — skipping'); return null; }
    try {
        const now  = new Date();
        const date = `${String(now.getDate()).padStart(2,'0')}/${String(now.getMonth()+1).padStart(2,'0')}/${now.getFullYear()}`;
        const time = now.toLocaleTimeString('en-US', { hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:true });
        const payMap = { 'Cash':'01', 'M-Pesa':'05', 'Credit':'01' };

        const unitPrice  = parseFloat(saleData.unitPrice) || 0;
        const quantity   = parseFloat(saleData.quantity)  || 1;
        const totalAmount = parseFloat((unitPrice * quantity).toFixed(2));

        const payload = {
            trader_invoice_number: saleData.invoiceNumber || saleData.receiptNumber,
            date, time,
            payment_type_code: payMap[saleData.paymentMethod] || '01',
            customer_pin:      saleData.customerPin  || null,
            customer_name:     saleData.customerName || null,
            sale_items: [{
                id:            saleData.digitaxItemId || null,
                item_name:     saleData.itemName,
                quantity:      quantity,
                unit_price:    unitPrice,
                total_amount:  totalAmount,
                tax_type_code: 'A',
                discount_rate: 0
            }]
        };

        log.info('[eTIMS] Submitting sale to DigiTax', {
            invoice:   payload.trader_invoice_number,
            item:      saleData.itemName,
            itemId:    saleData.digitaxItemId || 'not-registered',
            total:     totalAmount,
            sale_date: now.toISOString().split('T')[0]
        });

        const res  = await fetch(`${DIGITAX_BASE_URL}/sales`, { method:'POST', headers:{ 'x-api-key': DIGITAX_API_KEY, 'Content-Type':'application/json' }, body: JSON.stringify(payload), signal: AbortSignal.timeout(10000) });
        const data = await res.json();
        if (!res.ok) { log.warn('[eTIMS] DigiTax rejected sale', { status: res.status, body: data }); return null; }
        log.info('[eTIMS] ✅ Sale submitted to KRA', { invoice: saleData.invoiceNumber, kraReceiptNo: data?.data?.receipt_number });
        return { kraReceiptNo: data?.data?.receipt_number || null, kraQrUrl: data?.data?.etims_url || null };
    } catch (err) {
        log.warn('[eTIMS] DigiTax call failed (sale still saved):', err.message);
        return null;
    }
}

// ============================================================
//  2. EMAIL CONFIGURATION
// ============================================================
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// ============================================================
//  3. MIDDLEWARE
// ============================================================

// CORS — restrict to your frontend origins only
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:5001')
    .split(',').map(o => o.trim());

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, Postman, curl)
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        callback(new Error(`CORS blocked: ${origin} is not allowed.`));
    },
    credentials: true
}));

// Rate limiter — login endpoint: max 5 attempts per 15 minutes per IP
// FIX: Reduced from 10 to 5 — 4-digit PINs are brute-forceable with too many attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: { success: false, message: 'Too many login attempts. Please wait 15 minutes and try again.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// General API limiter — 300 requests per minute per IP (protects all endpoints)
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 300,
    message: { success: false, message: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/', apiLimiter);
app.use(log.middleware);          // structured JSON request logging
app.use(sanitizeQuery);           // strip PostgREST injection chars from all query params
app.use(express.json({ limit: '2mb' })); // Body size cap — prevents oversized bulk import abuse







// ── 3. Explicit "Shallow" Routes (The Fix) ──────────────────────────────────
// This allows you to navigate to 'http://localhost:5001/inventory.html' 
// even though the file is buried in /src/pages/
const HTML_PAGES = [
    'inventory', 'suppliers','purchase_orders', 'add_product', 'stock_audit', 'stock_movement',
    'stock_valuation', 'expenses', 'profit_loss', 'debt_status',
    'debtors_report', 'reports', 'debts_repayment', 'payments_report', 'returns_audit'
];
HTML_PAGES.forEach(page => {
    app.get(`/${page}.html`, (req, res) => {
        const file = path.join(pagesPath, `${page}.html`);
        if (require('fs').existsSync(file)) {
            res.sendFile(file);
        } else {
            res.status(404).send(`Page ${page} not found at ${file}`);
        }
    });
});

// ── 4. Root Routes ──────────────────────────────────────────────────────────

app.get('/', (req, res) => {
    res.status(200).json({ 
        message: "Elite Hardware POS API is running", 
        status: "Live" 
    });
});
// ============================================================
//  4. AUTH MIDDLEWARE
// ============================================================

/** Verifies JWT from Authorization header. Attaches decoded payload to req.user. */
function requireAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) {
        return res.status(401).json({ success: false, message: 'No token provided. Please log in.' });
    }
    try {
        req.user = jwt.verify(token, JWT_SECRET); // { empId, name, role, iat, exp }
        next();
    } catch {
        return res.status(401).json({ success: false, message: 'Invalid or expired session. Please log in again.' });
    }
}

/** Role-based access guard — must follow requireAuth. */
function requireRole(...roles) {
    return (req, res, next) => {
        if (!roles.map(r => r.toLowerCase()).includes(req.user?.role?.toLowerCase())) {
            return res.status(403).json({ success: false, message: `Access denied. Required: ${roles.join(' or ')}.` });
        }
        next();
    };
}

// ============================================================
//  5. LOGIN — issues JWT (public)
// ============================================================
app.post('/api/login', loginLimiter, async (req, res) => {
    const { employeeId, pin } = req.body;
    if (!employeeId || !pin) {
        return res.status(400).json({ success: false, message: 'Employee ID and PIN are required.' });
    }
    try {
        const { data: user, error } = await supabase
            .from('employees').select('*').eq('emp_id', employeeId.toUpperCase()).single();
        if (error || !user) return res.status(401).json({ success: false, message: 'Invalid ID or PIN.' });

        const isMatch = await bcrypt.compare(String(pin), user.pin);
        if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid ID or PIN.' });

        // Block deactivated accounts
        if (user.is_active === false) {
            return res.status(403).json({ success: false, message: 'Your account has been deactivated. Contact your administrator.' });
        }

        const token = jwt.sign(
            { empId: user.emp_id, name: user.name, role: user.role },
            JWT_SECRET,
            { expiresIn: '12h' }
        );
        res.json({ success: true, token, role: user.role, name: user.name });
    } catch (err) {
        log.error('Login error', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ============================================================
//  6. INVENTORY ROUTES
// ============================================================

app.get('/api/inventory', requireAuth, async (req, res) => {
    const { search, category, page } = req.query;
    const role = req.user.role;
    let columns = role?.toLowerCase() === 'admin'
        ? '*, stock_batches(*)'
        : 'id, item_name, category, price, stock_quantity, unit, stock_batches(*)';
    let query = supabase.from('Inventory').select(columns, { count: 'exact' });
    if (search) query = query.ilike('item_name', `%${sanitize(search)}%`);
    if (category && category !== 'All') query = query.eq('category', category);
    try {
        let items = [], totalCount = 0;
        const perPage = 15;
        if (page) {
            const start = (parseInt(page) - 1) * perPage;
            const { data, count, error } = await query.order('item_name', { ascending: true }).range(start, start + perPage - 1);
            if (error) throw error;
            items = data; totalCount = count;
        } else {
            const { data, error } = await query.order('item_name', { ascending: true });
            if (error) throw error;
            items = data;
        }
        const enriched = items.map(item => {
            const active = item.stock_batches ? item.stock_batches.filter(b => b.remaining_qty > 0) : [];
            return { ...item, active_batches: active.length, batch_details: active };
        });
        if (page) return res.json({ items: enriched, totalCount, totalPages: Math.ceil(totalCount / perPage) });
        res.json(enriched);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/inventory', requireAuth, requireRole('admin', 'manager'), validateBody({
    item_name:      { type: 'string', required: true, maxLen: 200 },
    price:          { type: 'number', required: true, min: 0 },
    cost_price:     { type: 'number', min: 0 },
    stock_quantity: { type: 'number', min: 0 },
    unit:           { type: 'string', maxLen: 50 },
    category:       { type: 'string', maxLen: 100 },
}), async (req, res) => {
    const { itemName, category, unit, costPrice, sellingPrice, stockQty, deliveryNote } = req.body;
    const userName = req.user.name;
    try {
        const { data: existing } = await supabase.from('stock_batches').select('delivery_number')
            .eq('delivery_number', deliveryNote?.trim().toUpperCase()).maybeSingle();
        if (existing) return res.status(400).json({ success: false, message: `DN ${deliveryNote} already used.` });

        const { data: newItem, error: invError } = await supabase.from('Inventory')
            .insert([{ item_name: itemName, category, unit, cost_price: parseFloat(costPrice), price: parseFloat(sellingPrice), stock_quantity: parseInt(stockQty) }])
            .select().single();
        if (invError) throw invError;

        const { data: newBatch, error: batchError } = await supabase.from('stock_batches').insert([{
            inventory_id: newItem.id, batch_qty: parseInt(stockQty), remaining_qty: parseInt(stockQty),
            unit_cost: parseFloat(costPrice), delivery_number: deliveryNote?.trim().toUpperCase() || 'INITIAL-STOCK',
            stock_at_entry: 0, performed_by: userName
        }]).select('id').single();
        if (batchError) { await supabase.from('Inventory').delete().eq('id', newItem.id); throw batchError; }

        const { error: auditErr1 } = await supabase.from('audit_logs').insert([{
            performed_by: userName,
            action: 'INITIAL_STOCK',
            dn_number: deliveryNote?.trim().toUpperCase() || 'N/A',
            item_name: itemName,
            old_stock: 0,
            added_qty: parseInt(stockQty),
            new_stock: parseInt(stockQty),
            batch_id: newBatch?.id || null,
            details: `NEW PRODUCT registered: ${itemName} | Category: ${category} | Unit: ${unit} | Qty: ${stockQty} | Cost: KES ${costPrice} | Selling: KES ${sellingPrice} | DN: ${deliveryNote || 'N/A'}`,
            timestamp: new Date().toISOString()
        }]);
        if (auditErr1) console.error('Audit log error (INITIAL_STOCK):', auditErr1.message);
        res.json({ success: true, message: 'Product registered successfully!' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/inventory/restock-fifo', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { inventory_id, batch_qty, unit_cost, new_selling_price, delivery_number } = req.body;
    const userName = req.user.name;
    try {
        const { data: existing, error: checkErr } = await supabase.from('stock_batches').select('id')
            .eq('delivery_number', String(delivery_number)).maybeSingle();
        if (checkErr) throw checkErr;
        if (existing) return res.status(400).json({ success: false, message: `DN "${delivery_number}" already exists.` });

        const { data: item, error: fetchErr } = await supabase.from('Inventory')
            .select('item_name, stock_quantity').eq('id', inventory_id).single();
        if (fetchErr) throw fetchErr;

        const oldStock = parseInt(item.stock_quantity) || 0;
        const added = parseInt(batch_qty);
        const newTotal = oldStock + added;

        const { error: invErr } = await supabase.from('Inventory')
            .update({ stock_quantity: newTotal, cost_price: parseFloat(unit_cost), price: parseFloat(new_selling_price) })
            .eq('id', inventory_id);
        if (invErr) throw invErr;

        const { data: restockBatch, error: batchErr } = await supabase.from('stock_batches').insert([{
            inventory_id, batch_qty: added, remaining_qty: added, unit_cost: parseFloat(unit_cost),
            delivery_number: String(delivery_number), stock_at_entry: oldStock
        }]).select('id').single();
        if (batchErr) throw batchErr;

        const { error: auditErr2 } = await supabase.from('audit_logs').insert([{
            performed_by: userName,
            action: 'RESTOCK_FIFO',
            dn_number: String(delivery_number),
            item_name: item.item_name,
            old_stock: oldStock,
            added_qty: added,
            new_stock: newTotal,
            batch_id: restockBatch?.id || null,
            details: `RESTOCK: ${item.item_name} | DN: ${delivery_number} | Added: ${added} units | Stock: ${oldStock} → ${newTotal} | New Cost: KES ${unit_cost} | New Price: KES ${new_selling_price}`,
            timestamp: new Date().toISOString()
        }]);
        if (auditErr2) console.error('Audit log error (RESTOCK_FIFO):', auditErr2.message);
        res.json({ success: true, message: 'Restock successful!' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/inventory/bulk-restock', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { items } = req.body;
    const userName = req.user.name;
    try {
        for (const item of items) {
            const { inventory_id, batch_qty, unit_cost, new_selling_price, delivery_number } = item;
            const { data: existing } = await supabase.from('stock_batches').select('id')
                .eq('inventory_id', inventory_id).eq('delivery_number', String(delivery_number)).maybeSingle();
            if (existing) continue;
            const { data: invItem } = await supabase.from('Inventory').select('stock_quantity, item_name').eq('id', inventory_id).single();
            const oldStock = parseInt(invItem.stock_quantity) || 0;
            const added = parseInt(batch_qty);
            const newTotal = oldStock + added;
            await supabase.from('Inventory').update({ stock_quantity: newTotal, cost_price: parseFloat(unit_cost), price: parseFloat(new_selling_price) }).eq('id', inventory_id);
            const { data: bulkBatch } = await supabase.from('stock_batches').insert([{
                inventory_id, batch_qty: added, remaining_qty: added,
                unit_cost: parseFloat(unit_cost), delivery_number: String(delivery_number),
                stock_at_entry: oldStock
            }]).select('id').single();

            const { error: auditErr3 } = await supabase.from('audit_logs').insert([{
                performed_by: userName,
                action: 'BULK_RESTOCK',
                dn_number: String(delivery_number),
                item_name: invItem.item_name,
                old_stock: oldStock,
                added_qty: added,
                new_stock: newTotal,
                batch_id: bulkBatch?.id || null,
                details: `BULK RESTOCK: ${invItem.item_name} | DN: ${delivery_number} | Added: ${added} units | Stock: ${oldStock} → ${newTotal} | Cost: KES ${unit_cost} | New Price: KES ${new_selling_price}`,
                timestamp: new Date().toISOString()
            }]);
            if (auditErr3) console.error('Audit log error (BULK_RESTOCK):', auditErr3.message);
        }
        res.json({ success: true, message: 'Bulk restock processed.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/inventory/:id', requireAuth, requireRole('admin'), async (req, res) => {
    const { id } = req.params;
    const { item_name, category, price, cost_price, stock_quantity, unit } = req.body;
    const userName = req.user.name;
    try {
        const { data: oldItem, error: fetchErr } = await supabase.from('Inventory').select('stock_quantity').eq('id', id).single();
        if (fetchErr) throw fetchErr;
        const oldStock = parseInt(oldItem?.stock_quantity || 0);
        const { error: invError } = await supabase.from('Inventory')
            .update({ item_name, category, price: parseFloat(price), cost_price: parseFloat(cost_price), stock_quantity: parseInt(stock_quantity), unit }).eq('id', id);
        if (invError) throw invError;
        await supabase.from('stock_batches').delete().eq('inventory_id', id);
        const { error: batchError } = await supabase.from('stock_batches').insert([{
            inventory_id: id, batch_qty: parseInt(stock_quantity), remaining_qty: parseInt(stock_quantity),
            unit_cost: parseFloat(cost_price), delivery_number: `MANUAL-EDIT-${Date.now()}`, stock_at_entry: oldStock
        }]);
        if (batchError) throw batchError;
        await supabase.from('audit_logs').insert([{ performed_by: userName, action: 'MANUAL_INVENTORY_EDIT', item_name, old_stock: oldStock, new_stock: parseInt(stock_quantity), details: `Admin manual reset of ${item_name}. ${oldStock} → ${stock_quantity}`, timestamp: new Date().toISOString() }]);
        res.json({ success: true, message: 'Item synchronized successfully!' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.patch('/api/inventory/update-price/:id', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { id } = req.params;
    const { newPrice } = req.body;
    const userName = req.user.name;
    try {
        const { data: item } = await supabase.from('Inventory').select('item_name, price').eq('id', id).single();
        const { error } = await supabase.from('Inventory').update({ price: parseFloat(newPrice) }).eq('id', id);
        if (error) throw error;
        await supabase.from('audit_logs').insert([{ performed_by: userName, action: 'PRICE_MARKDOWN', details: `${item.item_name}: ${item.price} → ${newPrice}`, timestamp: new Date().toISOString() }]);
        res.json({ success: true, message: 'Price updated!' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/inventory/audit-logs', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const { data, error } = await supabase.from('stock_batches').select('*, Inventory(item_name)').order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch('/api/inventory/:id', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { id } = req.params;
    const { added_quantity, delivery_note_ref } = req.body;
    const userName = req.user.name;
    try {
        const { data: item, error: fetchError } = await supabase.from('Inventory').select('item_name, stock_quantity').eq('id', id).single();
        if (fetchError || !item) throw new Error('Item not found');
        const newTotal = parseInt(item.stock_quantity) + parseInt(added_quantity || 0);
        const { error: updateError } = await supabase.from('Inventory').update({ stock_quantity: newTotal }).eq('id', id);
        if (updateError) throw updateError;
        await supabase.from('audit_logs').insert([{ performed_by: userName, action: 'RESTOCK', dn_number: String(delivery_note_ref), details: `Added ${added_quantity} to ${item.item_name}. Total: ${newTotal}`, timestamp: new Date().toISOString() }]);
        res.json({ success: true, message: `Added ${added_quantity}. Total: ${newTotal}` });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete('/api/inventory/:id', requireAuth, requireRole('admin'), async (req, res) => {
    const { id } = req.params;
    const userName = req.user.name;
    try {
        const { data: item } = await supabase.from('Inventory').select('item_name').eq('id', id).single();
        const { error } = await supabase.from('Inventory').delete().eq('id', id);
        if (error) throw error;
        await supabase.from('audit_logs').insert([{ performed_by: userName, action: 'DELETE', details: `Removed: ${item?.item_name || 'Unknown'} (ID: ${id})`, timestamp: new Date().toISOString() }]);
        res.json({ success: true, message: 'Item deleted and logged.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
// ============================================================
//  SUPPLIER ROUTES
//  Paste this block into server.js just before the app.listen()
//  line at the very bottom of the file.
// ============================================================

// ── GET all suppliers ────────────────────────────────────────────────────────
app.get('/api/suppliers', requireAuth, async (req, res) => {
    const { search, category, status } = req.query;

    try {
        let query = supabase
            .from('suppliers')
            .select('*')
            .order('name', { ascending: true });

        if (search)   query = query.ilike('name', `%${sanitize(search)}%`);
        if (category) query = query.eq('category', category);
        if (status)   query = query.eq('status', status);

        const { data, error } = await query;
        if (error) throw error;

        res.json(data || []);
    } catch (err) {
        console.error('[GET /api/suppliers]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── GET single supplier by ID ────────────────────────────────────────────────
app.get('/api/suppliers/:id', requireAuth, async (req, res) => {
    const { id } = req.params;

    try {
        const { data, error } = await supabase
            .from('suppliers')
            .select('*')
            .eq('id', id)
            .single();

        if (error || !data) return res.status(404).json({ success: false, message: 'Supplier not found.' });

        res.json(data);
    } catch (err) {
        console.error('[GET /api/suppliers/:id]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── POST create new supplier ─────────────────────────────────────────────────
app.post('/api/suppliers', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { name, contact, category, phone, email, location, payment_terms, status, notes } = req.body;

    if (!name || !name.trim()) {
        return res.status(400).json({ success: false, message: 'Supplier name is required.' });
    }
    if (!category || !category.trim()) {
        return res.status(400).json({ success: false, message: 'Category is required.' });
    }

    try {
        // Prevent duplicate supplier names (case-insensitive)
        const { data: existing } = await supabase
            .from('suppliers')
            .select('id')
            .ilike('name', name.trim())
            .maybeSingle();

        if (existing) {
            return res.status(409).json({ success: false, message: `A supplier named "${name.trim()}" already exists.` });
        }

        const { data, error } = await supabase
            .from('suppliers')
            .insert([{
                name:          name.trim(),
                contact:       contact?.trim()       || null,
                category:      category.trim(),
                phone:         phone?.trim()         || null,
                email:         email?.trim()         || null,
                location:      location?.trim()      || null,
                payment_terms: payment_terms?.trim() || null,
                status:        status || 'active',
                notes:         notes?.trim()         || null,
                balance:       0,
            }])
            .select()
            .single();

        if (error) throw error;

        // Audit log
        await supabase.from('audit_logs').insert([{
            performed_by: req.user.name,
            action:       'SUPPLIER_ADDED',
            item_name:    name.trim(),
            details:      `New supplier added: ${name.trim()} | Category: ${category} | Phone: ${phone || 'N/A'} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]).then(({ error: ae }) => { if (ae) console.error('Audit log error (SUPPLIER_ADDED):', ae.message); });

        res.status(201).json({ success: true, message: 'Supplier added successfully.', data });
    } catch (err) {
        console.error('[POST /api/suppliers]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── PUT update supplier ──────────────────────────────────────────────────────
app.put('/api/suppliers/:id', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { id } = req.params;
    const { name, contact, category, phone, email, location, payment_terms, status, notes, balance } = req.body;

    if (!name || !name.trim()) {
        return res.status(400).json({ success: false, message: 'Supplier name is required.' });
    }

    try {
        // Make sure the supplier exists
        const { data: existing, error: fetchErr } = await supabase
            .from('suppliers')
            .select('id, name')
            .eq('id', id)
            .single();

        if (fetchErr || !existing) {
            return res.status(404).json({ success: false, message: 'Supplier not found.' });
        }

        // Duplicate name check (exclude self)
        const { data: dupe } = await supabase
            .from('suppliers')
            .select('id')
            .ilike('name', name.trim())
            .neq('id', id)
            .maybeSingle();

        if (dupe) {
            return res.status(409).json({ success: false, message: `Another supplier named "${name.trim()}" already exists.` });
        }

        const updatePayload = {
            name:          name.trim(),
            contact:       contact?.trim()       || null,
            category:      category?.trim()      || null,
            phone:         phone?.trim()         || null,
            email:         email?.trim()         || null,
            location:      location?.trim()      || null,
            payment_terms: payment_terms?.trim() || null,
            status:        status || 'active',
            notes:         notes?.trim()         || null,
        };

        // Only allow balance updates from admin
        if (req.user.role.toLowerCase() === 'admin' && balance !== undefined) {
            updatePayload.balance = parseFloat(balance) || 0;
        }

        const { data, error } = await supabase
            .from('suppliers')
            .update(updatePayload)
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;

        // Audit log
        await supabase.from('audit_logs').insert([{
            performed_by: req.user.name,
            action:       'SUPPLIER_UPDATED',
            item_name:    name.trim(),
            details:      `Supplier updated: ${existing.name} → ${name.trim()} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]).then(({ error: ae }) => { if (ae) console.error('Audit log error (SUPPLIER_UPDATED):', ae.message); });

        res.json({ success: true, message: 'Supplier updated successfully.', data });
    } catch (err) {
        console.error('[PUT /api/suppliers/:id]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── DELETE supplier ──────────────────────────────────────────────────────────
app.delete('/api/suppliers/:id', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { id } = req.params;

    try {
        const { data: existing, error: fetchErr } = await supabase
            .from('suppliers')
            .select('id, name, balance')
            .eq('id', id)
            .single();

        if (fetchErr || !existing) {
            return res.status(404).json({ success: false, message: 'Supplier not found.' });
        }

        // Safety: block delete if there is an outstanding balance
        if (parseFloat(existing.balance || 0) !== 0) {
            return res.status(400).json({
                success: false,
                message: `Cannot delete "${existing.name}" — they have an outstanding balance of KES ${existing.balance}. Clear the balance first.`
            });
        }

        const { error } = await supabase
            .from('suppliers')
            .delete()
            .eq('id', id);

        if (error) throw error;

        // Audit log
        await supabase.from('audit_logs').insert([{
            performed_by: req.user.name,
            action:       'SUPPLIER_DELETED',
            item_name:    existing.name,
            details:      `Supplier deleted: ${existing.name} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]).then(({ error: ae }) => { if (ae) console.error('Audit log error (SUPPLIER_DELETED):', ae.message); });

        res.json({ success: true, message: `"${existing.name}" has been deleted.` });
    } catch (err) {
        console.error('[DELETE /api/suppliers/:id]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── PATCH update supplier balance only (admin only) ──────────────────────────
// Useful for manually adjusting what you owe a supplier
app.patch('/api/suppliers/:id/balance', requireAuth, requireRole('admin'), async (req, res) => {
    const { id } = req.params;
    const { balance, notes } = req.body;

    if (balance === undefined || balance === null) {
        return res.status(400).json({ success: false, message: 'balance is required.' });
    }

    try {
        const { data: existing, error: fetchErr } = await supabase
            .from('suppliers')
            .select('id, name, balance')
            .eq('id', id)
            .single();

        if (fetchErr || !existing) {
            return res.status(404).json({ success: false, message: 'Supplier not found.' });
        }

        const { data, error } = await supabase
            .from('suppliers')
            .update({ balance: parseFloat(balance) })
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;

        await supabase.from('audit_logs').insert([{
            performed_by: req.user.name,
            action:       'SUPPLIER_BALANCE_ADJUSTED',
            item_name:    existing.name,
            details:      `Balance adjusted for ${existing.name}: KES ${existing.balance} → KES ${balance}${notes ? ' | Note: ' + notes : ''} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]).then(({ error: ae }) => { if (ae) console.error('Audit log error (SUPPLIER_BALANCE):', ae.message); });

        res.json({ success: true, message: 'Balance updated.', data });
    } catch (err) {
        console.error('[PATCH /api/suppliers/:id/balance]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});
// ============================================================
//  PURCHASE ORDER ROUTES — with automatic supplier balance tracking
//
//  BALANCE LOGIC:
//    PO marked Sent     → supplier balance += PO total   (you now owe them)
//    PO Cancelled       → supplier balance -= PO total   (debt reversed)
//    Stock received     → no change (balance already added when Sent)
//    Supplier payment   → supplier balance -= amount paid
//
//  Paste just above app.listen() in server.js.
//  REPLACE your previous purchase order routes entirely.
// ============================================================

// ── Helper: generate PO number ────────────────────────────────────────────────
function generatePONumber() {
    const now  = new Date();
    const date = now.getFullYear().toString() +
                 String(now.getMonth() + 1).padStart(2, '0') +
                 String(now.getDate()).padStart(2, '0');
    const time = String(now.getHours()).padStart(2, '0') +
                 String(now.getMinutes()).padStart(2, '0') +
                 String(now.getSeconds()).padStart(2, '0');
    return `PO-${date}-${time}`;
}

// ── Helper: adjust supplier balance atomically ────────────────────────────────
async function adjustSupplierBalance(supplierId, delta, userName, reason) {
    const { data: supplier, error } = await supabase
        .from('suppliers').select('balance, name').eq('id', supplierId).single();
    if (error || !supplier) throw new Error('Supplier not found when adjusting balance.');

    const oldBalance = parseFloat(supplier.balance || 0);
    const newBalance = Math.round((oldBalance + delta) * 100) / 100;

    await supabase.from('suppliers')
        .update({ balance: newBalance })
        .eq('id', supplierId);

    await supabase.from('audit_logs').insert([{
        performed_by: userName,
        action:       'SUPPLIER_BALANCE_ADJUSTED',
        item_name:    supplier.name,
        details:      `${reason} | Balance: KES ${oldBalance.toFixed(2)} → KES ${newBalance.toFixed(2)} (Δ ${delta >= 0 ? '+' : ''}KES ${delta.toFixed(2)}) | By: ${userName}`,
        timestamp:    new Date().toISOString(),
    }]);

    return { oldBalance, newBalance };
}

// ── GET all purchase orders ───────────────────────────────────────────────────
app.get('/api/purchase-orders', requireAuth, async (req, res) => {
    const { status, supplier_id, from, to } = req.query;
    try {
        let query = supabase
            .from('purchase_orders')
            .select('*, purchase_order_items(*)')
            .order('created_at', { ascending: false });

        if (status)      query = query.eq('status', status);
        if (supplier_id) query = query.eq('supplier_id', supplier_id);
        if (from)        query = query.gte('order_date', from);
        if (to)          query = query.lte('order_date', to);

        const { data, error } = await query;
        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        console.error('[GET /api/purchase-orders]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── GET single purchase order ─────────────────────────────────────────────────
app.get('/api/purchase-orders/:id', requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('purchase_orders')
            .select('*, purchase_order_items(*)')
            .eq('id', req.params.id)
            .single();
        if (error || !data) return res.status(404).json({ success: false, message: 'Purchase order not found.' });
        res.json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── POST create purchase order (Draft — no balance change yet) ────────────────
app.post('/api/purchase-orders', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { supplier_id, supplier_name, expected_date, notes, items } = req.body;

    if (!supplier_id)            return res.status(400).json({ success: false, message: 'Supplier is required.' });
    if (!items || !items.length) return res.status(400).json({ success: false, message: 'Add at least one item.' });

    for (const item of items) {
        if (!item.item_name || !item.item_name.trim())
            return res.status(400).json({ success: false, message: 'All items must have a name.' });
        if (!item.qty_ordered || parseFloat(item.qty_ordered) <= 0)
            return res.status(400).json({ success: false, message: `"${item.item_name}" must have qty > 0.` });
        if (item.unit_cost === undefined || parseFloat(item.unit_cost) < 0)
            return res.status(400).json({ success: false, message: `"${item.item_name}" must have a valid unit cost.` });
    }

    try {
        const po_number    = generatePONumber();
        const total_amount = items.reduce((s, i) => s + (parseFloat(i.qty_ordered) * parseFloat(i.unit_cost)), 0);

        const { data: po, error: poErr } = await supabase
            .from('purchase_orders')
            .insert([{
                po_number,
                supplier_id:   parseInt(supplier_id),
                supplier_name: supplier_name || '',
                status:        'Draft',
                order_date:    new Date().toISOString().split('T')[0],
                expected_date: expected_date || null,
                total_amount,
                notes:         notes || null,
                created_by:    req.user.name,
            }])
            .select().single();
        if (poErr) throw poErr;

        const lineItems = items.map(i => ({
            po_id:             po.id,
            inventory_id:      i.inventory_id || null,
            item_name:         i.item_name.trim(),
            unit:              i.unit || null,
            qty_ordered:       parseFloat(i.qty_ordered),
            qty_received:      0,
            unit_cost:         parseFloat(i.unit_cost),
            new_selling_price: i.new_selling_price ? parseFloat(i.new_selling_price) : null,
        }));

        const { error: itemsErr } = await supabase.from('purchase_order_items').insert(lineItems);
        if (itemsErr) {
            await supabase.from('purchase_orders').delete().eq('id', po.id);
            throw itemsErr;
        }

        await supabase.from('audit_logs').insert([{
            performed_by: req.user.name,
            action:       'PO_CREATED',
            item_name:    po_number,
            details:      `PO ${po_number} created (Draft) for ${supplier_name} | Items: ${items.length} | Total: KES ${total_amount.toFixed(2)} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]);

        res.status(201).json({ success: true, message: 'Purchase order created.', data: po });
    } catch (err) {
        console.error('[POST /api/purchase-orders]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── PUT update PO status / notes ──────────────────────────────────────────────
//  BALANCE TRIGGERS:
//    Draft  → Sent      : balance += total_amount
//    Sent   → Cancelled : balance -= (total - amount_paid)
//    Partial→ Cancelled : balance -= (total - amount_paid)
app.put('/api/purchase-orders/:id', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { status, expected_date, notes, delivery_note } = req.body;
    const allowed = ['Draft', 'Sent', 'Cancelled'];

    try {
        const { data: po, error: fetchErr } = await supabase
            .from('purchase_orders').select('*').eq('id', req.params.id).single();
        if (fetchErr || !po) return res.status(404).json({ success: false, message: 'PO not found.' });
        if (po.status === 'Received')
            return res.status(400).json({ success: false, message: 'Cannot edit a fully received order.' });
        if (status && !allowed.includes(status))
            return res.status(400).json({ success: false, message: `Cannot set status to "${status}" via this route.` });

        // Balance adjustments on status transitions
        if (status && status !== po.status) {
            const total = parseFloat(po.total_amount || 0);

            if (po.status === 'Draft' && status === 'Sent') {
                // Sending the order — we now owe the supplier
                await adjustSupplierBalance(
                    po.supplier_id, +total, req.user.name,
                    `PO ${po.po_number} sent to ${po.supplier_name} — KES ${total.toFixed(2)} owed`
                );
            }

            if (['Sent', 'Partial'].includes(po.status) && status === 'Cancelled') {
                // Cancellation — reverse only what hasn't been paid yet
                const stillOwed = total - parseFloat(po.amount_paid || 0);
                if (stillOwed > 0) {
                    await adjustSupplierBalance(
                        po.supplier_id, -stillOwed, req.user.name,
                        `PO ${po.po_number} cancelled — reversing KES ${stillOwed.toFixed(2)} unpaid balance`
                    );
                }
            }
        }

        const { data, error } = await supabase
            .from('purchase_orders')
            .update({
                status:        status        || po.status,
                expected_date: expected_date || po.expected_date,
                notes:         notes         !== undefined ? notes : po.notes,
                delivery_note: delivery_note || po.delivery_note,
            })
            .eq('id', req.params.id)
            .select().single();
        if (error) throw error;

        await supabase.from('audit_logs').insert([{
            performed_by: req.user.name,
            action:       'PO_UPDATED',
            item_name:    po.po_number,
            details:      `PO ${po.po_number} → ${status || po.status} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]);

        res.json({ success: true, message: 'Purchase order updated.', data });
    } catch (err) {
        console.error('[PUT /api/purchase-orders/:id]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── POST receive items — restocks inventory, balance unchanged (already added on Sent) ──
app.post('/api/purchase-orders/:id/receive', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { delivery_note, items } = req.body;
    const userName = req.user.name;

    if (!delivery_note || !delivery_note.trim())
        return res.status(400).json({ success: false, message: 'Delivery Note number is required.' });
    if (!items || !items.length)
        return res.status(400).json({ success: false, message: 'No items to receive.' });

    try {
        const { data: po, error: poErr } = await supabase
            .from('purchase_orders')
            .select('*, purchase_order_items(*)')
            .eq('id', req.params.id).single();
        if (poErr || !po) return res.status(404).json({ success: false, message: 'PO not found.' });
        if (po.status === 'Cancelled') return res.status(400).json({ success: false, message: 'Cannot receive a cancelled order.' });
        if (po.status === 'Received')  return res.status(400).json({ success: false, message: 'Order already fully received.' });

        // If still Draft, auto-advance to Sent and add balance now
        if (po.status === 'Draft') {
            await adjustSupplierBalance(
                po.supplier_id,
                +parseFloat(po.total_amount || 0),
                userName,
                `PO ${po.po_number} auto-advanced Draft→Sent on first receive`
            );
            await supabase.from('purchase_orders').update({ status: 'Sent' }).eq('id', po.id);
        }

        // Check DN not already used
        const { data: existingDN } = await supabase
            .from('stock_batches').select('id')
            .eq('delivery_number', delivery_note.trim().toUpperCase()).maybeSingle();
        if (existingDN)
            return res.status(400).json({ success: false, message: `Delivery Note "${delivery_note}" already used.` });

        for (const recv of items) {
            const poItem = po.purchase_order_items.find(i => i.id === recv.po_item_id);
            if (!poItem) continue;

            const qtyToReceive = parseFloat(recv.qty_received || 0);
            if (qtyToReceive <= 0) continue;

            const remaining = parseFloat(poItem.qty_ordered) - parseFloat(poItem.qty_received);
            if (qtyToReceive > remaining)
                return res.status(400).json({
                    success: false,
                    message: `Cannot receive ${qtyToReceive} of "${poItem.item_name}" — only ${remaining} remaining.`
                });

            await supabase.from('purchase_order_items')
                .update({ qty_received: parseFloat(poItem.qty_received) + qtyToReceive })
                .eq('id', poItem.id);

            if (poItem.inventory_id) {
                const sellingPrice = recv.new_selling_price || poItem.new_selling_price || null;
                const { data: invItem, error: invErr } = await supabase
                    .from('Inventory').select('item_name, stock_quantity, price')
                    .eq('id', poItem.inventory_id).single();
                if (invErr) throw invErr;

                const oldStock = parseInt(invItem.stock_quantity) || 0;
                const newTotal = oldStock + qtyToReceive;
                const unitCost = parseFloat(poItem.unit_cost);
                const newPrice = sellingPrice ? parseFloat(sellingPrice) : parseFloat(invItem.price);

                await supabase.from('Inventory')
                    .update({ stock_quantity: newTotal, cost_price: unitCost, price: newPrice })
                    .eq('id', poItem.inventory_id);

                const { data: batch } = await supabase.from('stock_batches').insert([{
                    inventory_id:    poItem.inventory_id,
                    batch_qty:       qtyToReceive,
                    remaining_qty:   qtyToReceive,
                    unit_cost:       unitCost,
                    delivery_number: delivery_note.trim().toUpperCase(),
                    stock_at_entry:  oldStock,
                    performed_by:    userName,
                }]).select('id').single();

                await supabase.from('audit_logs').insert([{
                    performed_by: userName,
                    action:       'PO_RECEIVED',
                    dn_number:    delivery_note.trim().toUpperCase(),
                    item_name:    invItem.item_name,
                    old_stock:    oldStock,
                    added_qty:    qtyToReceive,
                    new_stock:    newTotal,
                    batch_id:     batch?.id || null,
                    details:      `PO RECEIVE: ${invItem.item_name} | PO: ${po.po_number} | DN: ${delivery_note} | Qty: +${qtyToReceive} | Stock: ${oldStock}→${newTotal} | Cost: KES ${unitCost} | Price: KES ${newPrice} | By: ${userName}`,
                    timestamp:    new Date().toISOString(),
                }]);
            }
        }

        // Recalculate PO status
        const { data: updatedItems } = await supabase
            .from('purchase_order_items').select('qty_ordered, qty_received').eq('po_id', po.id);

        const allReceived = updatedItems.every(i => parseFloat(i.qty_received) >= parseFloat(i.qty_ordered));
        const anyReceived = updatedItems.some(i  => parseFloat(i.qty_received) > 0);
        const newStatus   = allReceived ? 'Received' : anyReceived ? 'Partial' : 'Sent';

        await supabase.from('purchase_orders').update({
            status:        newStatus,
            delivery_note: delivery_note.trim().toUpperCase(),
            received_date: allReceived ? new Date().toISOString().split('T')[0] : null,
        }).eq('id', po.id);

        res.json({ success: true, message: `Stock received. PO is now ${newStatus}.`, status: newStatus });
    } catch (err) {
        console.error('[POST /api/purchase-orders/:id/receive]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── POST record payment to supplier ───────────────────────────────────────────
//  Reduces supplier balance + updates PO amount_paid
//  Body: { po_id, amount, payment_method, reference, notes }
app.post('/api/supplier-payments', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { po_id, amount, payment_method, reference, notes } = req.body;
    const userName = req.user.name;

    if (!po_id) return res.status(400).json({ success: false, message: 'po_id is required.' });
    if (!amount || parseFloat(amount) <= 0)
        return res.status(400).json({ success: false, message: 'Amount must be greater than 0.' });

    try {
        const { data: po, error: poErr } = await supabase
            .from('purchase_orders').select('*').eq('id', po_id).single();
        if (poErr || !po) return res.status(404).json({ success: false, message: 'PO not found.' });
        if (['Draft', 'Cancelled'].includes(po.status))
            return res.status(400).json({ success: false, message: `Cannot record payment on a ${po.status} order.` });

        const paying      = parseFloat(amount);
        const alreadyPaid = parseFloat(po.amount_paid || 0);
        const totalOwed   = parseFloat(po.total_amount);
        const maxPayable  = totalOwed - alreadyPaid;

        if (paying > maxPayable)
            return res.status(400).json({
                success: false,
                message: `Payment KES ${paying.toFixed(2)} exceeds outstanding KES ${maxPayable.toFixed(2)}.`
            });

        const newAmountPaid = alreadyPaid + paying;
        const newPayStatus  = newAmountPaid >= totalOwed ? 'Paid'
                            : newAmountPaid > 0          ? 'Partial'
                            :                              'Unpaid';

        // Update PO
        await supabase.from('purchase_orders')
            .update({ amount_paid: newAmountPaid, payment_status: newPayStatus })
            .eq('id', po_id);

        // Reduce supplier balance
        await adjustSupplierBalance(
            po.supplier_id, -paying, userName,
            `Payment on PO ${po.po_number} | Method: ${payment_method || 'N/A'} | Ref: ${reference || 'N/A'}`
        );

        await supabase.from('audit_logs').insert([{
            performed_by: userName,
            action:       'SUPPLIER_PAYMENT',
            item_name:    po.po_number,
            details:      `Payment KES ${paying.toFixed(2)} to ${po.supplier_name} | PO: ${po.po_number} | Method: ${payment_method || 'N/A'} | Ref: ${reference || 'N/A'} | Paid: KES ${newAmountPaid.toFixed(2)} / KES ${totalOwed.toFixed(2)} | By: ${userName}`,
            timestamp:    new Date().toISOString(),
        }]);

        res.json({
            success:           true,
            message:           `KES ${paying.toFixed(2)} payment recorded. PO payment: ${newPayStatus}.`,
            payment_status:    newPayStatus,
            amount_paid:       newAmountPaid,
            balance_remaining: totalOwed - newAmountPaid,
        });
    } catch (err) {
        console.error('[POST /api/supplier-payments]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── GET payment history for a PO ─────────────────────────────────────────────
app.get('/api/purchase-orders/:id/payments', requireAuth, async (req, res) => {
    try {
        const { data: po } = await supabase
            .from('purchase_orders').select('po_number').eq('id', req.params.id).single();
        if (!po) return res.status(404).json({ success: false, message: 'PO not found.' });

        const { data, error } = await supabase
            .from('audit_logs')
            .select('*')
            .eq('action', 'SUPPLIER_PAYMENT')
            .eq('item_name', po.po_number)
            .order('timestamp', { ascending: false });

        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── DELETE purchase order (Draft only — no balance to reverse) ────────────────
app.delete('/api/purchase-orders/:id', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const { data: po, error: fetchErr } = await supabase
            .from('purchase_orders').select('id, po_number, status').eq('id', req.params.id).single();
        if (fetchErr || !po) return res.status(404).json({ success: false, message: 'PO not found.' });
        if (po.status !== 'Draft')
            return res.status(400).json({ success: false, message: `Only Draft orders can be deleted. This PO is "${po.status}".` });

        await supabase.from('purchase_order_items').delete().eq('po_id', po.id);
        await supabase.from('purchase_orders').delete().eq('id', po.id);

        await supabase.from('audit_logs').insert([{
            performed_by: req.user.name,
            action:       'PO_DELETED',
            item_name:    po.po_number,
            details:      `PO ${po.po_number} deleted (was Draft) | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]);

        res.json({ success: true, message: `${po.po_number} deleted.` });
    } catch (err) {
        console.error('[DELETE /api/purchase-orders/:id]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});
// ── POST email purchase order to supplier ─────────────────────────────────────
// Add this inside your purchase order routes block in server.js
// Requires nodemailer already configured (it is — you use it for other emails)
//
// Body: { to, html_body, po_number, supplier_name }

// ── POST /api/purchase-orders/:id/email ──────────────────────────────────────
// Sends the PO as a PDF attachment to the supplier.
// Body: { to, po_number, supplier_name, message?, pdf_base64, pdf_filename }
// Replace your existing email route in server.js with this version.

app.post('/api/purchase-orders/:id/email', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { to, po_number, supplier_name, message, pdf_base64, pdf_filename } = req.body;
    const userName = req.user.name;

    if (!to || !to.trim())
        return res.status(400).json({ success: false, message: 'Recipient email address is required.' });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(to.trim()))
        return res.status(400).json({ success: false, message: `"${to}" is not a valid email address.` });

    if (!pdf_base64)
        return res.status(400).json({ success: false, message: 'PDF data is required.' });

    try {
        const pdfBuffer   = Buffer.from(pdf_base64, 'base64');
        const fileName    = pdf_filename || `${po_number}.pdf`;
        const customMsg   = message ? `<p style="color:#374151;font-size:14px;margin:16px 0;">${message}</p>` : '';

        await transporter.sendMail({
            from: `"Elite Hardware" <${process.env.EMAIL_USER}>`,
            to:   to.trim(),
            subject: `Purchase Order ${po_number} — Elite Hardware`,
            html: `
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8fafc;padding:0;">
                    <div style="background:#0f172a;padding:24px 32px;border-radius:12px 12px 0 0;">
                        <h1 style="color:#fff;font-size:18px;font-weight:900;margin:0;">🛠️ ELITE HARDWARE</h1>
                        <p style="color:#94a3b8;font-size:12px;margin:4px 0 0;">Purchase Order Notification</p>
                    </div>
                    <div style="background:#fff;padding:28px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;">
                        <p style="font-size:15px;color:#0f172a;font-weight:700;margin-bottom:4px;">
                            Purchase Order: <span style="color:#2563eb;">${po_number}</span>
                        </p>
                        <p style="font-size:13px;color:#475569;margin-bottom:20px;">
                            Dear <strong>${supplier_name}</strong>, please find attached the purchase order from Elite Hardware.
                        </p>
                        ${customMsg}
                        <div style="background:#f1f5f9;border-radius:10px;padding:16px 20px;margin:20px 0;">
                            <p style="font-size:12px;color:#64748b;margin:0;">
                                📎 <strong>${fileName}</strong> is attached to this email.<br>
                                Please review the order and confirm receipt at your earliest convenience.
                            </p>
                        </div>
                        <p style="font-size:11px;color:#94a3b8;margin-top:24px;padding-top:16px;border-top:1px solid #e2e8f0;">
                            This email was sent by <strong>${userName}</strong> from Elite Hardware POS.<br>
                            For queries contact us at ${process.env.EMAIL_USER}
                        </p>
                    </div>
                </div>
            `,
            attachments: [
                {
                    filename:    fileName,
                    content:     pdfBuffer,
                    contentType: 'application/pdf',
                }
            ],
        });

        await supabase.from('audit_logs').insert([{
            performed_by: userName,
            action:       'PO_EMAILED',
            item_name:    po_number,
            details:      `PO ${po_number} emailed as PDF to ${to.trim()} (${supplier_name}) | By: ${userName}`,
            timestamp:    new Date().toISOString(),
        }]);

        log.info(`[PO EMAIL] ✅ ${po_number} PDF sent to ${to.trim()} by ${userName}`);
        res.json({ success: true, message: `Purchase order PDF emailed to ${to.trim()}.` });

    } catch (err) {
        console.error('[POST /api/purchase-orders/:id/email]', err.message);
        res.status(500).json({ success: false, message: `Email failed: ${err.message}` });
    }
});
// ════════════════════════════════════════════════════════════════════════════
//  ACTIVITY TIMELINE ROUTES
//  Paste these into server.js alongside your existing supplier/PO routes
// ════════════════════════════════════════════════════════════════════════════

// ── GET activity timeline for a specific supplier ─────────────────────────────
// Returns all audit_log entries related to this supplier (by name or supplier_id)
// ordered newest-first, limited to 100 entries
app.get('/api/suppliers/:id/activity', requireAuth, async (req, res) => {
    try {
        // First get the supplier name so we can match against audit logs
        const { data: supplier, error: supErr } = await supabase
            .from('suppliers')
            .select('name')
            .eq('id', req.params.id)
            .single();

        if (supErr || !supplier)
            return res.status(404).json({ success: false, message: 'Supplier not found.' });

        const supplierName = supplier.name;

        // Fetch audit logs that mention this supplier — by action type + item_name or details
        const { data: logs, error } = await supabase
            .from('audit_logs')
            .select('id, action, item_name, details, performed_by, timestamp')
            .or(`item_name.eq."${sanitize(supplierName)}",details.ilike.%${sanitize(supplierName)}%`)
            .in('action', [
                'SUPPLIER_ADDED',
                'SUPPLIER_UPDATED',
                'SUPPLIER_DELETED',
                'SUPPLIER_BALANCE_ADJUSTED',
                'SUPPLIER_PAYMENT',
                'PO_CREATED',
                'PO_UPDATED',
                'PO_STATUS_UPDATED',
                'PO_RECEIVED',
                'PO_EMAILED',
                'PO_DELETED',
            ])
            .order('timestamp', { ascending: false })
            .limit(100);

        if (error) throw error;

        res.json(logs || []);
    } catch (err) {
        console.error('[GET /api/suppliers/:id/activity]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── GET activity timeline for a specific purchase order ───────────────────────
// Returns all audit_log entries related to this PO (by po_number in item_name or details)
// ordered oldest-first so the timeline reads chronologically top-to-bottom
app.get('/api/purchase-orders/:id/activity', requireAuth, async (req, res) => {
    try {
        // Get the PO number first
        const { data: po, error: poErr } = await supabase
            .from('purchase_orders')
            .select('po_number')
            .eq('id', req.params.id)
            .single();

        if (poErr || !po)
            return res.status(404).json({ success: false, message: 'Purchase order not found.' });

        const poNumber = po.po_number;

        const { data: logs, error } = await supabase
            .from('audit_logs')
            .select('id, action, item_name, details, performed_by, timestamp')
            .or(`item_name.eq."${sanitize(poNumber)}",details.ilike.%${sanitize(poNumber)}%`)
            .in('action', [
                'PO_CREATED',
                'PO_UPDATED',
                'PO_STATUS_UPDATED',
                'PO_RECEIVED',
                'SUPPLIER_PAYMENT',
                'PO_EMAILED',
                'PO_DELETED',
            ])
            .order('timestamp', { ascending: true })   // oldest first — reads as a story
            .limit(100);

        if (error) throw error;

        res.json(logs || []);
    } catch (err) {
        console.error('[GET /api/purchase-orders/:id/activity]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});
// ============================================================
//  7. REPORT ROUTES
// ============================================================

app.get('/api/reports/daily-summary', requireAuth, async (req, res) => {
    try {
        const { processedBy, date, from, to, month, year } = req.query;
        const role = req.user.role;
        const isPrivileged = ['admin', 'manager'].includes(role?.toLowerCase());

        let salesQuery = supabase.from('Sales')
            .select('total_amount, cost_price, quantity_sold, amount_paid, sold_by, payment_status, sale_date')
            .eq('is_voided', false);

        // Apply period filter
        if (date) {
            salesQuery = salesQuery.gte('sale_date', `${date}T00:00:00Z`).lte('sale_date', `${date}T23:59:59Z`);
        } else if (from && to) {
            salesQuery = salesQuery.gte('sale_date', `${from}T00:00:00Z`).lte('sale_date', `${to}T23:59:59Z`);
        } else if (month && year) {
            const mm = month.padStart(2,'0'), lastDay = new Date(year, month, 0).getDate();
            salesQuery = salesQuery.gte('sale_date', `${year}-${mm}-01T00:00:00Z`).lte('sale_date', `${year}-${mm}-${lastDay}T23:59:59Z`);
        }
        // if none → all time (no filter)

        if (!isPrivileged && processedBy) salesQuery = salesQuery.eq('sold_by', processedBy);

        const { data: allSales, error: salesError } = await salesQuery;
        if (salesError) throw salesError;

        // Expenses — also filter by period
        let expQuery = supabase.from('expenses').select('amount');
        if (date) {
            expQuery = expQuery.gte('expense_date', `${date}T00:00:00Z`).lte('expense_date', `${date}T23:59:59Z`);
        } else if (from && to) {
            expQuery = expQuery.gte('expense_date', `${from}T00:00:00Z`).lte('expense_date', `${to}T23:59:59Z`);
        } else if (month && year) {
            const mm = month.padStart(2,'0'), lastDay = new Date(year, month, 0).getDate();
            expQuery = expQuery.gte('expense_date', `${year}-${mm}-01T00:00:00Z`).lte('expense_date', `${year}-${mm}-${lastDay}T23:59:59Z`);
        }
        const { data: allExpenses, error: expError } = await expQuery;
        if (expError) throw expError;

        let realizedSales = 0, realizedCogs = 0, totalOwed = 0, totalExpenses = 0;
        allSales?.forEach(s => {
            const total = parseFloat(s.total_amount || 0), paid = parseFloat(s.amount_paid || 0);
            const cost = parseFloat(s.cost_price || 0) * parseInt(s.quantity_sold || 0);
            if (total - paid > 0) totalOwed += (total - paid);
            realizedSales += paid;
            if (paid >= total && total > 0) realizedCogs += cost;
            else if (paid > 0 && total > 0) realizedCogs += cost * (paid / total);
        });
        allExpenses?.forEach(e => { totalExpenses += parseFloat(e.amount || 0); });

        const txCount = allSales?.length || 0;
        const avgTx   = txCount > 0 ? realizedSales / txCount : 0;
        res.json({ totalSales: realizedSales, totalExpenses, netProfit: isPrivileged ? (realizedSales - realizedCogs - totalExpenses) : null, totalOwed, txCount, avgTx, totalCogs: realizedCogs });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/api/reports/sales', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { date, month, year, method } = req.query;
    try {
        let query = supabase.from('Sales').select('*, payments(mpesa_code, amount, payment_method)').eq('is_voided', false).order('sale_date', { ascending: false });
        if (date && date !== '') {
            query = query.gte('sale_date', `${date}T00:00:00Z`).lte('sale_date', `${date}T23:59:59Z`);
        } else if (month && year) {
            const mm = month.padStart(2, '0'), lastDay = new Date(year, month, 0).getDate();
            query = query.gte('sale_date', `${year}-${mm}-01T00:00:00Z`).lte('sale_date', `${year}-${mm}-${lastDay}T23:59:59Z`);
        }
        if (method && method !== '') query = method === 'Credit' ? query.in('payment_status', ['Credit', 'Partial']) : query.eq('payment_status', method);
        const { data, error } = await query;
        if (error) throw error;
        const reports = data.map(sale => {
            const rev = parseFloat(sale.total_amount || 0), paid = parseFloat(sale.amount_paid || 0);
            const cogs = parseFloat(sale.cost_price || 0) * parseInt(sale.quantity_sold || 0);
            const ratio = rev > 0 ? paid / rev : 0;
            return { ...sale, profit: Math.max(0, (rev - cogs) * ratio), total_cost: cogs, remaining_balance: rev - paid };
        });
        res.json(reports);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/reports/debtors', requireAuth, async (req, res) => {
    try {
        const { processedBy } = req.query;
        const role = req.user.role;
        let query = supabase.from('Sales').select('id, customer_name, item_name, total_amount, amount_paid, sale_date, sold_by').neq('payment_status', 'Paid').eq('is_voided', false).order('sale_date', { ascending: false });
        if (role?.toLowerCase() === 'cashier' && processedBy) query = query.eq('sold_by', processedBy);
        const { data, error } = await query;
        if (error) throw error;
        res.json(data.filter(d => (parseFloat(d.total_amount) - parseFloat(d.amount_paid)) > 0));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/reports/debt-status', requireAuth, requireRole('admin', 'manager', 'cashier'), async (req, res) => {
    try {
        const { date } = req.query;
        const isCashier = req.user.role?.toLowerCase() === 'cashier';
        let query = supabase.from('Sales')
            .select('customer_name, customer_phone, total_amount, amount_paid, payment_status, sale_date, sold_by')
            .in('payment_status', ['Credit', 'Partial', 'credit', 'partial', 'Unpaid'])
            .eq('is_voided', false);
        if (date) query = query.gte('sale_date', `${date}T00:00:00.000Z`).lte('sale_date', `${date}T23:59:59.999Z`);
        // Cashiers only see debts from their own sales
        if (isCashier) query = query.eq('sold_by', req.user.name);
        const { data, error } = await query;
        if (error) throw error;
        const consolidated = data.reduce((acc, sale) => {
            const name = (sale.customer_name || 'Walking Customer').trim();
            const phone = (sale.customer_phone || 'No Phone').trim();
            const key = `${name}-${phone}`.toLowerCase();
            const balance = (parseFloat(sale.total_amount) || 0) - (parseFloat(sale.amount_paid) || 0);
            if (balance > 0.1) {
                if (!acc[key]) acc[key] = { name, phone, total_debt: 0 };
                acc[key].total_debt += balance;
            }
            return acc;
        }, {});
        res.json(Object.values(consolidated));
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/reports/payments', requireAuth, requireRole('admin', 'manager', 'cashier'), async (req, res) => {
    try {
        const { date, month, year, method } = req.query;
        const isCashier  = req.user.role?.toLowerCase() === 'cashier';
        const cashierName = req.user.name;

        let dateFilter = {};
        if (date && date !== '') {
            dateFilter = { gte: `${date}T00:00:00Z`, lte: `${date}T23:59:59Z` };
        } else if (month && year) {
            const mm = month.padStart(2, '0'), lastDay = new Date(year, month, 0).getDate();
            dateFilter = { gte: `${year}-${mm}-01T00:00:00Z`, lte: `${year}-${mm}-${lastDay}T23:59:59Z` };
        }

        if (isCashier) {
            // Step 1: Get all sale IDs belonging to this cashier
            const { data: cashierSales, error: salesErr } = await supabase
                .from('Sales')
                .select('id')
                .eq('sold_by', cashierName)
                .eq('is_voided', false);

            if (salesErr) throw salesErr;
            const saleIds = (cashierSales || []).map(s => s.id);

            // Step 2: Query payments matching this cashier's sales
            // Use sale_id.in() for sales they processed + received_by for any direct entries
            // Cashier name is quoted to handle names with spaces
            let query = supabase
                .from('payments')
                .select('*, Sales!left(customer_name, customer_phone, item_name)')
                .order('created_at', { ascending: false });

            if (saleIds.length > 0) {
                query = query.or(`received_by.eq."${cashierName}",sale_id.in.(${saleIds.join(',')})`);
            } else {
                query = query.eq('received_by', cashierName);
            }

            if (dateFilter.gte) query = query.gte('created_at', dateFilter.gte).lte('created_at', dateFilter.lte);
            if (method && method !== '') query = query.eq('payment_method', method);

            const { data, error } = await query;
            if (error) throw error;
            return res.json(data.map(p => ({
                ...p,
                customer_name: p.Sales?.customer_name || p.customer_name || 'Debt Customer',
                item_name:     p.Sales?.item_name     || 'Debt Repayment'
            })));
        }

        // Admin/Manager — see everything
        let query = supabase
            .from('payments')
            .select('*, Sales!left(customer_name, customer_phone, item_name)')
            .order('created_at', { ascending: false });
        if (dateFilter.gte) query = query.gte('created_at', dateFilter.gte).lte('created_at', dateFilter.lte);
        if (method && method !== '') query = query.eq('payment_method', method);

        const { data, error } = await query;
        if (error) throw error;
        res.json(data.map(p => ({
            ...p,
            customer_name: p.Sales?.customer_name || p.customer_name || 'Debt Customer',
            item_name:     p.Sales?.item_name     || 'Debt Repayment'
        })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/reports/expenses', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { date, month, year } = req.query;
    try {
        let query = supabase.from('expenses').select('*').order('expense_date', { ascending: false });
        if (date) {
            query = query.gte('expense_date', `${date}T00:00:00Z`).lte('expense_date', `${date}T23:59:59Z`);
        } else if (month && year) {
            const mm = month.padStart(2, '0'), lastDay = new Date(year, month, 0).getDate();
            query = query.gte('expense_date', `${year}-${mm}-01T00:00:00Z`).lte('expense_date', `${year}-${mm}-${lastDay}T23:59:59Z`);
        }
        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/reports/profit-loss', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { month, year } = req.query;
    const mm = String(month).padStart(2, '0'), lastDay = new Date(year, month, 0).getDate();
    const startISO = `${year}-${mm}-01T00:00:00.000Z`, endISO = `${year}-${mm}-${lastDay}T23:59:59.999Z`;
    try {
        const { data: sales, error: sErr } = await supabase.from('Sales').select('*').eq('is_voided', false).gte('sale_date', startISO).lte('sale_date', endISO);
        if (sErr) throw sErr;
        let totalSales = 0, totalCogs = 0, unpaidDebts = 0;
        sales.forEach(s => {
            const amt = parseFloat(s.total_amount) || 0, cogs = (parseFloat(s.cost_price) || 0) * (parseInt(s.quantity_sold) || 0);
            const status = (s.payment_status || '').toLowerCase().trim();
            totalSales += amt; totalCogs += cogs;
            if (status === 'credit' || status === 'unpaid') unpaidDebts += amt;
        });
        const { data: expenses } = await supabase.from('expenses').select('amount').gte('expense_date', startISO).lte('expense_date', endISO);
        const totalExpenses = (expenses || []).reduce((s, e) => s + (parseFloat(e.amount) || 0), 0);
        const grossProfit = totalSales - totalCogs, netProfit = grossProfit - totalExpenses;
        res.json({ totalSales, unpaidDebts, totalCogs, grossProfit, totalExpenses, netProfit });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// ============================================================
//  STOCK MOVEMENT REPORT
//  Opening → Stock In → Sold → Adjustments → Closing
// ============================================================
app.get('/api/reports/stock-movement', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { from, to } = req.query;
    try {
        // 1. All inventory items
        const { data: inventory, error: invErr } = await supabase
            .from('Inventory')
            .select('id, item_name, category, unit, stock_quantity')
            .order('item_name', { ascending: true });
        if (invErr) throw invErr;

        // 2. All stock batches (restocks) within period
        let batchQuery = supabase.from('stock_batches').select('inventory_id, batch_qty, created_at');
        if (from) batchQuery = batchQuery.gte('created_at', `${from}T00:00:00.000Z`);
        if (to)   batchQuery = batchQuery.lte('created_at', `${to}T23:59:59.999Z`);
        const { data: batches, error: batchErr } = await batchQuery;
        if (batchErr) throw batchErr;

        // 3. All sales within period
        let salesQuery = supabase.from('Sales').select('item_name, quantity_sold, sale_date').eq('is_voided', false);
        if (from) salesQuery = salesQuery.gte('sale_date', `${from}T00:00:00.000Z`);
        if (to)   salesQuery = salesQuery.lte('sale_date', `${to}T23:59:59.999Z`);
        const { data: sales, error: salesErr } = await salesQuery;
        if (salesErr) throw salesErr;

        // 4. Audit log adjustments in period (MANUAL_INVENTORY_EDIT)
        let auditQuery = supabase.from('audit_logs')
            .select('item_name, old_stock, new_stock, action, timestamp')
            .eq('action', 'MANUAL_INVENTORY_EDIT');
        if (from) auditQuery = auditQuery.gte('timestamp', `${from}T00:00:00.000Z`);
        if (to)   auditQuery = auditQuery.lte('timestamp', `${to}T23:59:59.999Z`);
        const { data: audits } = await auditQuery;

        // 5. Map stock_in per inventory_id from batches
        const stockInMap = {};
        (batches || []).forEach(b => {
            stockInMap[b.inventory_id] = (stockInMap[b.inventory_id] || 0) + (parseInt(b.batch_qty) || 0);
        });

        // 6. Map qty_sold per item_name from sales
        const soldMap = {};
        (sales || []).forEach(s => {
            const key = (s.item_name || '').trim().toLowerCase();
            soldMap[key] = (soldMap[key] || 0) + (parseInt(s.quantity_sold) || 0);
        });

        // 7. Map manual adjustments per item_name
        const adjustMap = {};
        (audits || []).forEach(a => {
            const key = (a.item_name || '').trim().toLowerCase();
            const diff = (parseInt(a.new_stock) || 0) - (parseInt(a.old_stock) || 0);
            adjustMap[key] = (adjustMap[key] || 0) + diff;
        });

        // 8. Build movement rows per item
        const result = inventory.map(item => {
            const key      = item.item_name.trim().toLowerCase();
            const stockIn  = stockInMap[item.id]  || 0;
            const qtySold  = soldMap[key]          || 0;
            const adjusts  = adjustMap[key]        || 0;
            const closing  = parseInt(item.stock_quantity) || 0;
            // Opening = closing - stockIn + sold - adjustments
            const opening  = Math.max(0, closing - stockIn + qtySold - adjusts);

            return {
                item_name:     item.item_name,
                category:      item.category,
                unit:          item.unit,
                opening_stock: opening,
                stock_in:      stockIn,
                qty_sold:      qtySold,
                adjustments:   adjusts,
                closing_stock: closing
            };
        });

        res.json(result);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ============================================================
//  STOCK VALUATION REPORT
//  Current stock quantity × cost price & selling price
// ============================================================
app.get('/api/reports/stock-valuation', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const { data: inventory, error } = await supabase
            .from('Inventory')
            .select('id, item_name, category, unit, stock_quantity, cost_price, price')
            .order('category', { ascending: true });
        if (error) throw error;

        const result = inventory.map(item => {
            const qty        = parseFloat(item.stock_quantity) || 0;
            const costPrice  = parseFloat(item.cost_price)     || 0;
            const sellPrice  = parseFloat(item.price)          || 0;
            return {
                item_name:     item.item_name,
                category:      item.category,
                unit:          item.unit,
                stock_quantity: qty,
                cost_price:    costPrice,
                selling_price: sellPrice,
                cost_value:    Math.round(qty * costPrice),
                retail_value:  Math.round(qty * sellPrice)
            };
        });

        res.json(result);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});


// ── FULL DEBTORS REPORT (aging, consolidation + drill-down) ─────────────────
app.get('/api/reports/debtors-full', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { phone, detail } = req.query;
    try {
        // DRILL-DOWN: individual transactions for one customer (by phone or name)
        if (phone && detail) {
            let q = supabase
                .from('Sales')
                .select('id, item_name, sale_date, total_amount, amount_paid, payment_status, sold_by, customer_name, customer_phone')
                .eq('is_voided', false)
                .in('payment_status', ['Credit', 'Partial', 'credit', 'partial', 'Unpaid'])
                .order('sale_date', { ascending: true });

            // Search by phone OR name
            const isPhone = /^\d{7,}$/.test(phone.replace(/\s/g,''));
            if (isPhone) {
                q = q.ilike('customer_phone', `%${sanitize(phone)}%`);
            } else {
                q = q.ilike('customer_name', `%${sanitize(phone)}%`);
            }

            const { data, error } = await q;
            if (error) throw error;
            return res.json(data.filter(d => (parseFloat(d.total_amount) - parseFloat(d.amount_paid || 0)) > 0));
        }

        // FULL REPORT: consolidate per customer
        const { data, error } = await supabase
            .from('Sales')
            .select('customer_name, customer_phone, total_amount, amount_paid, payment_status, sale_date, item_name')
            .eq('is_voided', false)
            .in('payment_status', ['Credit', 'Partial', 'credit', 'partial', 'Unpaid'])
            .order('sale_date', { ascending: false });
        if (error) throw error;

        const map = {};
        data.forEach(sale => {
            const balance = (parseFloat(sale.total_amount) || 0) - (parseFloat(sale.amount_paid) || 0);
            if (balance <= 0) return;
            const ph   = (sale.customer_phone || 'No Phone').trim();
            const name = (sale.customer_name  || 'Walk-In Customer').trim();
            if (!map[ph]) {
                map[ph] = { name, phone: ph, total_invoiced: 0, total_paid: 0, balance: 0, txn_count: 0, last_purchase: sale.sale_date };
            }
            map[ph].total_invoiced += parseFloat(sale.total_amount) || 0;
            map[ph].total_paid     += parseFloat(sale.amount_paid)  || 0;
            map[ph].balance        += balance;
            map[ph].txn_count      += 1;
            if (new Date(sale.sale_date) > new Date(map[ph].last_purchase)) {
                map[ph].last_purchase = sale.sale_date;
            }
        });

        const result = Object.values(map).sort((a, b) => b.balance - a.balance);
        res.json(result);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/reports/debt-logs', requireAuth, async (req, res) => {
    const { date, processedBy } = req.query;
    const role = req.user.role?.toLowerCase();
    try {
        let query = supabase.from('debt_payments').select('*').order('payment_date', { ascending: false });
        if (date && date !== '') query = query.gte('payment_date', `${date}T00:00:00.000Z`).lte('payment_date', `${date}T23:59:59.999Z`);
        // Cashiers only see their own logs — enforced server-side
        if (role === 'cashier') {
            const name = req.user.name;
            if (name) query = query.eq('processed_by', name);
        } else if (processedBy) {
            query = query.eq('processed_by', processedBy);
        }
        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
//  BULK PRODUCT IMPORT (CSV/EXCEL)
// ============================================================
app.post('/api/inventory/bulk-import', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { items } = req.body;
    const userName  = req.user.name; // always from verified token
    if (!Array.isArray(items) || !items.length)
        return res.status(400).json({ success: false, message: 'No items provided.' });

    const results = { success: [], failed: [] };

    for (const row of items) {
        const { itemName, category, unit, costPrice, sellingPrice, stockQty, deliveryNote } = row;

        // Validate required fields
        if (!itemName || !sellingPrice || !stockQty || !deliveryNote) {
            results.failed.push({ itemName: itemName || '?', reason: 'Missing required fields (name, selling price, qty, DN)' });
            continue;
        }
        const price = parseFloat(sellingPrice);
        const cost  = parseFloat(costPrice || 0);
        const qty   = parseInt(stockQty);
        const dn    = String(deliveryNote).trim().toUpperCase();

        if (isNaN(price) || price <= 0) { results.failed.push({ itemName, reason: 'Invalid selling price' }); continue; }
        if (isNaN(qty)   || qty   <= 0) { results.failed.push({ itemName, reason: 'Invalid quantity' });      continue; }

        try {
            // Check duplicate DN in stock_batches (same as single product route)
            const { data: existing } = await supabase.from('stock_batches')
                .select('delivery_number').eq('delivery_number', dn).maybeSingle();
            if (existing) { results.failed.push({ itemName, reason: `DN ${dn} already exists` }); continue; }

            // Insert inventory item — same fields as single product route
            const { data: newItem, error: invErr } = await supabase.from('Inventory').insert([{
                item_name:      itemName.trim(),
                category:       category   || 'General',
                unit:           unit       || 'PCS',
                cost_price:     cost,
                price:          price,
                stock_quantity: qty
            }]).select().single();
            if (invErr) throw new Error(invErr.message);

            // Insert stock batch — same fields as single product route
            const { data: newBatch, error: batchErr } = await supabase.from('stock_batches').insert([{
                inventory_id:    newItem.id,
                batch_qty:       qty,
                remaining_qty:   qty,
                unit_cost:       cost,
                delivery_number: dn,
                stock_at_entry:  0,
                performed_by:    userName
            }]).select('id').single();
            if (batchErr) {
                // Rollback inventory insert if batch fails
                await supabase.from('Inventory').delete().eq('id', newItem.id);
                throw new Error(batchErr.message);
            }

            // Audit log
            await supabase.from('audit_logs').insert([{
                performed_by: userName,
                action:       'INITIAL_STOCK',
                dn_number:    dn,
                item_name:    itemName.trim(),
                old_stock:    0,
                added_qty:    qty,
                new_stock:    qty,
                batch_id:     newBatch?.id || null,
                details:      `BULK IMPORT: ${itemName} | Category: ${category || 'General'} | Unit: ${unit || 'PCS'} | Qty: ${qty} | Cost: KES ${cost} | Selling: KES ${price} | DN: ${dn}`,
                timestamp:    new Date().toISOString()
            }]);

            results.success.push({ itemName, dn });
        } catch (err) {
            results.failed.push({ itemName, reason: err.message });
        }
    }

    res.json({
        success:  true,
        imported: results.success.length,
        failed:   results.failed.length,
        results
    });
});

// ============================================================
//  8. SELL ROUTE
// ============================================================
app.post('/api/sell', requireAuth, validateBody({
    itemId:        { type: 'number',  required: true, min: 1 },
    quantity:      { type: 'number',  required: true, min: 1 },
    price:         { type: 'number',  required: true, min: 0 },
    paymentMethod: { type: 'string',  required: true, enum: ['Cash', 'M-Pesa', 'Credit'] },
}), async (req, res) => {
    // FIX: Removed 'price' and 'itemName' from destructuring — these are now fetched from DB
    // Never trust client-supplied price. A cashier could send price=1 for a KES 1000 item.
    let { itemId, quantity, paymentMethod, mpesaId, mpesaCode, customerName, amountPaid } = req.body;
    const soldBy = req.user.name; // always from verified token, not client

    // FIX: Validate quantity is a positive integer
    const qty = parseInt(quantity);
    if (!qty || qty <= 0 || !Number.isInteger(qty)) {
        return res.status(400).json({ success: false, message: 'Quantity must be a positive whole number.' });
    }
    if (qty > 10000) {
        return res.status(400).json({ success: false, message: 'Quantity exceeds maximum allowed per transaction (10,000). Please split into multiple sales.' });
    }
    quantity = qty;

    // FIX: Validate amountPaid is non-negative
    const paidNow = Math.max(0, parseFloat(amountPaid) || 0);

    let linkedPhone = (mpesaId && mpesaId.trim() !== '') ? mpesaId.trim() : null;
    if ((paymentMethod === 'M-Pesa' || paymentMethod === 'Credit') && !linkedPhone) {
        return res.status(400).json({ success: false, message: 'Phone number required.' });
    }
    if (paymentMethod === 'M-Pesa' && (!mpesaCode || mpesaCode.trim() === '')) {
        return res.status(400).json({ success: false, message: 'M-Pesa Code required.' });
    }
    try {
        // Fetch item details for price and name (read-only — safe before the atomic decrement)
        const { data: item, error: fetchError } = await supabase.from('Inventory').select('stock_quantity, item_name, price, digitax_item_id').eq('id', itemId).single();
        if (fetchError || !item) throw new Error('Item not found.');

        // Use server-side values only
        const price    = item.price;       // from DB, not client
        const itemName = item.item_name;   // from DB, not client

        const { data: batches, error: batchErr } = await supabase.from('stock_batches').select('*')
            .eq('inventory_id', itemId).gt('remaining_qty', 0).order('created_at', { ascending: true });
        if (batchErr) throw batchErr;

        let remainingToDrain = quantity, totalCost = 0;
        for (const batch of batches) {
            if (remainingToDrain <= 0) break;
            const take = Math.min(batch.remaining_qty, remainingToDrain);
            const newQty = batch.remaining_qty - take;
            totalCost += take * parseFloat(batch.unit_cost || 0);
            await supabase.from('stock_batches').update({ remaining_qty: newQty }).eq('id', batch.id);
            if (newQty === 0) {
                const next = batches[batches.indexOf(batch) + 1];
                transporter.sendMail({ from: process.env.EMAIL_USER, to: process.env.EMAIL_USER, subject: `📦 BATCH FINISHED: ${itemName}`, text: `Batch for "${itemName}" at KES ${batch.unit_cost} depleted.\nNext: ${next ? 'KES ' + next.unit_cost : 'NO STOCK LEFT'}` }, e => { if (e) log.error('Batch email failed:', e); });
            }
            remainingToDrain -= take;
        }

        const totalAmount = quantity * price;
        const avgCost = totalCost / quantity;

        if (linkedPhone) {
            const { data: cust } = await supabase.from('customers').select('name, total_debt').eq('phone', linkedPhone).single();
            if (!cust) await supabase.from('customers').insert({ phone: linkedPhone, name: customerName || 'New Customer' });
            if (paymentMethod === 'Credit') {
                const newDebt = (parseFloat(cust?.total_debt || 0)) + (totalAmount - paidNow);
                await supabase.from('customers').update({ total_debt: newDebt }).eq('phone', linkedPhone);
            }
        }

        // Generate unique document numbers server-side
        const today = new Date();
        const datePart = today.getFullYear().toString() +
            String(today.getMonth() + 1).padStart(2, '0') +
            String(today.getDate()).padStart(2, '0');
        const dayStart = `${datePart.slice(0,4)}-${datePart.slice(4,6)}-${datePart.slice(6,8)}T00:00:00Z`;

        const { count: todayCount } = await supabase
            .from('Sales').select('*', { count: 'exact', head: true })
            .gte('sale_date', dayStart);
        const seq = String((todayCount || 0) + 1).padStart(4, '0');

        const isCredit = paymentMethod === 'Credit';

        // Cash/M-Pesa sales get a receipt number; credit sales do NOT (no payment received yet)
        const receiptNumber  = isCredit ? null : 'REC-' + datePart + '-' + seq;

        // Credit sales get invoice + delivery note numbers instead
        const invoiceNumber  = isCredit ? 'INV-' + datePart + '-' + seq : null;
        const dnNumber       = isCredit ? 'DN-'  + datePart + '-' + seq : null;

        const { data: saleData, error: insertError } = await supabase.from('Sales').insert([{
            item_name: itemName, quantity_sold: quantity, unit_price: price, total_amount: totalAmount,
            amount_paid: paidNow, cost_price: avgCost, profit: totalAmount - totalCost,
            payment_status: paidNow >= totalAmount ? 'Paid' : (paidNow > 0 ? 'Partial' : 'Credit'),
            is_credit_sale: isCredit,
            customer_name: customerName || 'Walk-in', customer_phone: linkedPhone,
            sold_by: soldBy, sale_date: new Date().toISOString(),
            receipt_number: receiptNumber,
            invoice_number: invoiceNumber,
            dn_number:      dnNumber
        }]).select();
        if (insertError) throw insertError;

        if (paidNow > 0) {
            // Derive true method from data — if mpesaCode present it's M-Pesa regardless of what frontend sent
            const storedMethod = paymentMethod === 'Credit' ? 'Cash'
                               : (mpesaCode && mpesaCode.trim()) ? 'M-Pesa'
                               : (paymentMethod || 'Cash');
            const { error: payErr } = await supabase.from('payments').insert([{ sale_id: saleData[0].id, amount: paidNow, payment_method: storedMethod, mpesa_code: mpesaCode || null, received_by: soldBy, customer_name: customerName || 'Walk-in', created_at: new Date().toISOString() }]);
            if (payErr) log.warn('Payment log write failed', payErr);
            if (paymentMethod === 'Credit' || totalAmount > paidNow) {
                const { error: debtErr } = await supabase.from('debt_payments').insert([{ sale_id: saleData[0].id, amount_paid: paidNow, payment_method: paymentMethod || 'Cash', mpesa_id: mpesaCode || null, processed_by: soldBy, customer_name: customerName || 'New Customer', customer_phone: linkedPhone, payment_date: new Date().toISOString() }]);
                if (debtErr) log.warn('Debt log write failed', debtErr);
            }
        }

        // ATOMIC stock decrement via RPC — prevents race condition where two cashiers
        // both pass the stock check and oversell the same item simultaneously.
        // The DB function locks the row, checks stock, and decrements in one transaction.
        const { data: newStockData, error: rpcError } = await supabase.rpc('decrement_stock', {
            p_item_id:  itemId,
            p_quantity: quantity
        });
        if (rpcError) throw new Error(rpcError.message);
        const newStock = newStockData;

        if (newStock <= 10) transporter.sendMail({ from: process.env.EMAIL_USER, to: process.env.EMAIL_USER, subject: `⚠️ LOW STOCK: ${itemName}`, text: `${itemName} is down to ${newStock} units.` }, e => { if (e) log.warn('Stock alert email failed', e); });

        // ── Submit to KRA via DigiTax (non-blocking) ──
        let kraReceiptNo = null, kraQrUrl = null;
        const etims = await submitSaleToEtims({ invoiceNumber: invoiceNumber || receiptNumber, receiptNumber, itemName, quantity, unitPrice: item.price, paymentMethod, customerName: customerName || null, customerPin: null, digitaxItemId: item.digitax_item_id || null });
        if (etims) {
            kraReceiptNo = etims.kraReceiptNo;
            kraQrUrl     = etims.kraQrUrl;
            if (kraReceiptNo || kraQrUrl) {
                await supabase.from('Sales').update({ kra_receipt_no: kraReceiptNo || null, kra_qr_url: kraQrUrl || null }).eq('id', saleData[0].id);
            }
        }

        res.json({ success: true, message: `Sale recorded. Stock: ${newStock}`, receiptNumber, invoiceNumber, dnNumber, saleId: saleData[0].id, kraReceiptNo, kraQrUrl });
    } catch (err) {
        log.error('Sale error', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ============================================================
//  9. DEBT CLEARANCE
// ============================================================
app.post('/api/clear-debt', requireAuth, validateBody({
    saleId:        { type: 'string', required: true },
    paymentAmount: { type: 'number', required: true, min: 0.01 },
    paymentMethod: { type: 'string', required: true, enum: ['Cash', 'M-Pesa'] },
}), async (req, res) => {
    const { saleId, paymentAmount, paymentMethod, mpesaId } = req.body;
    const processedBy = req.user.name;
    const userRole    = req.user.role?.toLowerCase();

    if (!saleId || !paymentAmount) return res.status(400).json({ success: false, message: 'Missing Sale ID or Amount.' });

    // FIX: Validate payment amount is a positive number
    const amountToPay = parseFloat(paymentAmount);
    if (isNaN(amountToPay) || amountToPay <= 0) {
        return res.status(400).json({ success: false, message: 'Payment amount must be a positive number.' });
    }
    if (amountToPay > 10000000) {
        return res.status(400).json({ success: false, message: 'Payment amount exceeds maximum allowed.' });
    }

    try {
        const { data: sale, error: getErr } = await supabase.from('Sales').select('*, customer_phone').eq('id', saleId).single();
        if (getErr || !sale) throw new Error('Sale record not found.');

        // FIX: Cashiers can only clear debt on their own sales — prevents clearing a friend's debt
        if (userRole === 'cashier' && sale.sold_by !== processedBy) {
            return res.status(403).json({ success: false, message: 'Access denied. You can only process payments for your own sales.' });
        }

        const currentPaid = parseFloat(sale.amount_paid || 0), total = parseFloat(sale.total_amount);
        const updatedPaid = currentPaid + amountToPay;

        // Generate a PAY- receipt number and stamp it on the sale record
        const now        = new Date();
        const datePart   = now.getFullYear().toString() +
                           String(now.getMonth() + 1).padStart(2, '0') +
                           String(now.getDate()).padStart(2, '0');
        const timePart   = String(now.getHours()).padStart(2, '0') +
                           String(now.getMinutes()).padStart(2, '0') +
                           String(now.getSeconds()).padStart(2, '0');
        const payReceiptNumber = 'PAY-' + datePart + '-' + timePart;

        const { error: updateErr } = await supabase.from('Sales').update({
            amount_paid:    updatedPaid,
            payment_status: updatedPaid >= total ? 'Paid' : 'Partial',
            receipt_number: payReceiptNumber   // stamp receipt number now that payment is received
        }).eq('id', saleId);
        if (updateErr) throw updateErr;
        if (sale.customer_phone) {
            const { data: cust } = await supabase.from('customers').select('total_debt').eq('phone', sale.customer_phone).single();
            await supabase.from('customers').update({ total_debt: Math.max(0, (parseFloat(cust?.total_debt || 0)) - amountToPay) }).eq('phone', sale.customer_phone);
        }
        await supabase.from('payments').insert([{ sale_id: saleId, amount: amountToPay, payment_method: paymentMethod, mpesa_code: mpesaId || null, received_by: processedBy, customer_name: sale.customer_name, created_at: new Date().toISOString() }]);
        await supabase.from('debt_payments').insert([{ sale_id: saleId, amount_paid: amountToPay, payment_method: paymentMethod, mpesa_id: mpesaId || null, processed_by: processedBy, customer_name: sale.customer_name, customer_phone: sale.customer_phone, payment_date: new Date().toISOString() }]);
        res.json({ success: true, message: `KES ${amountToPay} recorded.`, receiptNumber: payReceiptNumber });
    } catch (err) {
        log.error('Payment error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ============================================================
//  10. VOID / EDIT TRANSACTION
// ============================================================

// GET /api/sales/:id — fetch a single sale for the void/edit modal
app.get('/api/sales/:id', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('Sales')
            .select('*')
            .eq('id', req.params.id)
            .single();
        if (error || !data) return res.status(404).json({ success: false, message: 'Sale not found.' });
        res.json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/sales/:id/void — void a transaction (admin/manager only)
app.post('/api/sales/:id/void', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { reason } = req.body;
    const voidedBy = req.user.name;

    if (!reason || reason.trim().length < 3) {
        return res.status(400).json({ success: false, message: 'A void reason is required.' });
    }

    try {
        const { data: sale, error: fetchErr } = await supabase
            .from('Sales').select('*').eq('id', req.params.id).single();
        if (fetchErr || !sale) return res.status(404).json({ success: false, message: 'Sale not found.' });
        if (sale.is_voided) return res.status(400).json({ success: false, message: 'This transaction has already been voided.' });

        // Restore stock
        const { data: item } = await supabase
            .from('Inventory').select('stock_quantity').eq('item_name', sale.item_name).single();
        if (item) {
            await supabase.from('Inventory')
                .update({ stock_quantity: item.stock_quantity + sale.quantity_sold })
                .eq('item_name', sale.item_name);
        }

        // Reverse customer debt if credit sale
        if (sale.customer_phone && (sale.payment_status === 'Credit' || sale.payment_status === 'Partial')) {
            const debtToReverse = parseFloat(sale.total_amount) - parseFloat(sale.amount_paid || 0);
            if (debtToReverse > 0) {
                const { data: cust } = await supabase
                    .from('customers').select('total_debt').eq('phone', sale.customer_phone).single();
                if (cust) {
                    await supabase.from('customers')
                        .update({ total_debt: Math.max(0, parseFloat(cust.total_debt || 0) - debtToReverse) })
                        .eq('phone', sale.customer_phone);
                }
            }
        }

        // Mark voided — never delete, always keep audit trail
        const { error: voidErr } = await supabase.from('Sales').update({
            is_voided: true,
            voided_by: voidedBy,
            void_reason: reason.trim(),
            voided_at: new Date().toISOString()
        }).eq('id', req.params.id);
        if (voidErr) throw voidErr;

        // Write audit log entry
        await supabase.from('audit_logs').insert([{
            performed_by: voidedBy,
            action:       'VOID_SALE',
            item_name:    sale.item_name,
            old_stock:    item ? item.stock_quantity : null,
            added_qty:    sale.quantity_sold,
            new_stock:    item ? item.stock_quantity + sale.quantity_sold : null,
            details:      'VOID — ' + sale.item_name + ' | Qty: ' + sale.quantity_sold + ' | Amount: KES ' + sale.total_amount + ' | Customer: ' + (sale.customer_name || 'N/A') + ' | Reason: ' + reason.trim() + ' | Voided by: ' + voidedBy,
            timestamp:    new Date().toISOString()
        }]);

        res.json({ success: true, message: 'Transaction voided and stock restored.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PATCH /api/sales/:id/edit — edit customer details or payment method only
app.patch('/api/sales/:id/edit', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { customerName, customerPhone, paymentMethod, editNotes } = req.body;
    const editedBy = req.user.name;

    try {
        const { data: sale, error: fetchErr } = await supabase
            .from('Sales').select('*').eq('id', req.params.id).single();
        if (fetchErr || !sale) return res.status(404).json({ success: false, message: 'Sale not found.' });
        if (sale.is_voided) return res.status(400).json({ success: false, message: 'Cannot edit a voided transaction.' });

        // Only allow safe fields — never price, quantity, or item
        const updates = {
            last_edited_by: editedBy,
            last_edited_at: new Date().toISOString()
        };
        if (customerName && customerName.trim()) updates.customer_name = customerName.trim();
        if (customerPhone && customerPhone.trim()) updates.customer_phone = customerPhone.trim();
        if (editNotes !== undefined) updates.edit_notes = editNotes.trim();
        if (paymentMethod) {
            await supabase.from('payments')
                .update({ payment_method: paymentMethod })
                .eq('sale_id', req.params.id);
        }

        const { error: updateErr } = await supabase.from('Sales').update(updates).eq('id', req.params.id);
        if (updateErr) throw updateErr;

        res.json({ success: true, message: 'Transaction updated.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/sales/voided/list — get all voided transactions
app.get('/api/sales/voided/list', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('Sales').select('*').eq('is_voided', true).order('voided_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ============================================================
//  11. EMPLOYEES + MISC
// ============================================================
app.post('/api/employees', requireAuth, requireRole('admin'), async (req, res) => {
    const { name, employeeId, pin, role } = req.body;
    if (!pin || String(pin).length < 4) return res.status(400).json({ success: false, message: 'PIN must be at least 4 digits.' });
    try {
        const hashedPin = await bcrypt.hash(String(pin), 10);
        const { error } = await supabase.from('employees').insert([{ name, emp_id: employeeId.toUpperCase(), pin: hashedPin, role }]);
        if (error) throw error;
        res.json({ success: true, message: 'Staff created securely!' });
    } catch {
        res.status(500).json({ success: false, message: 'ID already exists or database error.' });
    }
});

app.get('/api/customers/:phone', requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('customers').select('name, total_debt').eq('phone', req.params.phone).single();
        if (error) return res.status(404).json({ message: 'Not found' });
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/expenses', requireAuth, requireRole('admin', 'manager'), validateBody({
    description: { type: 'string', required: true, maxLen: 255 },
    amount:      { type: 'number', required: true, min: 0.01 },
    category:    { type: 'string', maxLen: 100 },
}), async (req, res) => {
    const { description, category, amount } = req.body;
    const spentBy = req.user.name;
    try {
        const { error } = await supabase.from('expenses').insert([{ description, category, amount: parseFloat(amount), spent_by: spentBy, expense_date: new Date().toISOString() }]);
        if (error) throw error;
        res.json({ success: true, message: 'Expense recorded!' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ============================================================
//  11. STAFF MANAGEMENT — list, deactivate, PIN reset
// ============================================================

// GET all staff (admin only)
app.get('/api/employees', requireAuth, requireRole('admin'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('employees')
            .select('id, name, emp_id, role, is_active')
            .order('name', { ascending: true });
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PATCH deactivate/reactivate staff (admin only)
app.patch('/api/employees/:id/status', requireAuth, requireRole('admin'), async (req, res) => {
    const id = isNaN(req.params.id) ? req.params.id : parseInt(req.params.id);
    const { is_active } = req.body;

    console.log('[STATUS] id:', id, 'type:', typeof id, 'is_active:', is_active);

    if (typeof is_active !== 'boolean') {
        return res.status(400).json({ success: false, message: 'is_active must be true or false.' });
    }

    try {
        // Prevent admin from deactivating themselves
        const { data: target } = await supabase.from('employees').select('emp_id, role').eq('id', id).single();
        if (target?.emp_id === req.user.empId) {
            return res.status(403).json({ success: false, message: 'You cannot deactivate your own account.' });
        }

        const { data: updated, error } = await supabase
            .from('employees')
            .update({ is_active })
            .eq('id', id)
            .select('id, name');
        console.log('[STATUS] Update result:', updated, 'Error:', error);
        if (error) throw error;
        if (!updated || updated.length === 0) {
            return res.status(500).json({ success: false, message: 'Update ran but no rows changed. Check Supabase RLS policies.' });
        }
        res.json({ success: true, message: `Staff account ${is_active ? 'activated' : 'deactivated'} successfully.` });
    } catch (err) {
        log.error('[STATUS] Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// PATCH reset staff PIN (admin only)
app.patch('/api/employees/:id/reset-pin', requireAuth, requireRole('admin'), async (req, res) => {
    const id = isNaN(req.params.id) ? req.params.id : parseInt(req.params.id);
    const { newPin } = req.body;

    console.log('[PIN RESET] id:', id, 'type:', typeof id, 'newPin received:', !!newPin);

    if (!newPin || String(newPin).length < 4) {
        return res.status(400).json({ success: false, message: 'New PIN must be at least 4 digits.' });
    }

    try {
        // First verify employee exists
        const { data: emp, error: findErr } = await supabase
            .from('employees').select('id, name, emp_id').eq('id', id).single();
        console.log('[PIN RESET] Found employee:', emp, 'Find error:', findErr);
        if (findErr || !emp) {
            return res.status(404).json({ success: false, message: `Employee id=${id} not found. DB error: ${findErr?.message}` });
        }

        const hashedPin = await bcrypt.hash(String(newPin), 10);
        const { data: updated, error } = await supabase
            .from('employees')
            .update({ pin: hashedPin })
            .eq('id', id)
            .select('id, name');
        console.log('[PIN RESET] Update result:', updated, 'Update error:', error);
        if (error) throw error;
        if (!updated || updated.length === 0) {
            return res.status(500).json({ success: false, message: 'Update ran but no rows changed. Check Supabase RLS policies.' });
        }
        res.json({ success: true, message: `PIN reset for ${emp.name}.` });
    } catch (err) {
        log.error('[PIN RESET] Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// Block login for deactivated staff — patch requireAuth to check is_active
// This is enforced at login: check is_active before issuing token

// ============================================================

// ============================================================
//  12. RETURNS & EXCHANGE ROUTES — admin & manager only
// ============================================================

app.post('/api/returns/exchange', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { originalReceipt, originalSaleId, customerName, customerPhone,
            returnedItemId, returnedQuantity, returnReason,
            replacementItemId, replacementQuantity,
            sellingPriceOriginal, notes } = req.body;
    const processedBy = req.user.name;
    const processedRole = req.user.role;

    if (!returnedItemId || !replacementItemId || !returnReason)
        return res.status(400).json({ success: false, message: 'returnedItemId, replacementItemId and returnReason are required.' });
    if (!['damaged','wrong_item','other'].includes(returnReason))
        return res.status(400).json({ success: false, message: 'returnReason must be: damaged, wrong_item or other.' });

    const retQty = parseInt(returnedQuantity) || 1;
    const repQty = parseInt(replacementQuantity) || 1;

    try {
        const { data: retItem, error: retErr } = await supabase
            .from('Inventory').select('id,item_name,stock_quantity,cost_price').eq('id', returnedItemId).single();
        if (retErr || !retItem)
            return res.status(404).json({ success: false, message: 'Returned item not found.' });

        const { data: repItem, error: repErr } = await supabase
            .from('Inventory').select('id,item_name,stock_quantity,cost_price').eq('id', replacementItemId).single();
        if (repErr || !repItem)
            return res.status(404).json({ success: false, message: 'Replacement item not found.' });

        if (parseInt(repItem.stock_quantity) < repQty)
            return res.status(400).json({ success: false, message: 'Not enough stock for replacement. Available: ' + repItem.stock_quantity + ' ' + repItem.item_name + '.' });

        const costWrittenOff = parseFloat(retItem.cost_price || 0) * retQty;
        const retOldStock    = parseInt(retItem.stock_quantity);
        const retNewStock    = returnReason === 'damaged' ? retOldStock : retOldStock + retQty;
        const repOldStock    = parseInt(repItem.stock_quantity);
        const repNewStock    = repOldStock - repQty;

        if (returnReason !== 'damaged') {
            const { error: inErr } = await supabase.from('Inventory').update({ stock_quantity: retNewStock }).eq('id', returnedItemId);
            if (inErr) throw inErr;
        }

        const { error: outErr } = await supabase.from('Inventory').update({ stock_quantity: repNewStock }).eq('id', replacementItemId);
        if (outErr) throw outErr;

        let expenseId = null;
        if (returnReason === 'damaged' && costWrittenOff > 0) {
            const { data: exp, error: expErr } = await supabase.from('expenses').insert([{
                description:  'Exchange Write-off — ' + retItem.item_name + ' (returned damaged, qty: ' + retQty + ')',
                category:     'Damaged Goods',
                amount:       costWrittenOff,
                spent_by:     processedBy,
                expense_date: new Date().toISOString()
            }]).select('id').single();
            if (expErr) console.error('[RETURNS] Expense error:', expErr.message);
            else expenseId = exp && exp.id;
        }

        const auditRows = [
            {
                performed_by: processedBy,
                action:       returnReason === 'damaged' ? 'DAMAGE_WRITEOFF' : 'EXCHANGE_IN',
                item_name:    retItem.item_name,
                old_stock:    retOldStock, added_qty: returnReason === 'damaged' ? 0 : retQty, new_stock: retNewStock,
                details:      'EXCHANGE — ' + retItem.item_name + ' returned (' + returnReason.toUpperCase() + '). Customer: ' + (customerName||'N/A') + ' | Receipt: ' + (originalReceipt||'N/A') + ' | By: ' + processedBy,
                timestamp:    new Date().toISOString()
            },
            {
                performed_by: processedBy,
                action:       'EXCHANGE_OUT',
                item_name:    repItem.item_name,
                old_stock:    repOldStock, added_qty: -repQty, new_stock: repNewStock,
                details:      'EXCHANGE — ' + repItem.item_name + ' issued as replacement for ' + retItem.item_name + '. Customer: ' + (customerName||'N/A') + ' | By: ' + processedBy,
                timestamp:    new Date().toISOString()
            }
        ];
        if (returnReason === 'damaged' && costWrittenOff > 0) {
            auditRows.push({
                performed_by: processedBy,
                action:       'DAMAGE_WRITEOFF',
                item_name:    retItem.item_name,
                old_stock:    retOldStock, added_qty: 0, new_stock: retOldStock,
                details:      'DAMAGE WRITE-OFF — KES ' + costWrittenOff + ' expense logged for ' + retItem.item_name + ' (x' + retQty + '). Expense ID: ' + (expenseId||'N/A'),
                timestamp:    new Date().toISOString()
            });
        }
        await supabase.from('audit_logs').insert(auditRows);

        const { data: rec, error: recErr } = await supabase.from('returns_log').insert([{
            original_receipt: originalReceipt||null, original_sale_id: originalSaleId||null,
            customer_name: customerName||null, customer_phone: customerPhone||null,
            returned_item_id: returnedItemId, returned_item_name: retItem.item_name,
            returned_quantity: retQty, return_reason: returnReason,
            replacement_item_id: replacementItemId, replacement_item_name: repItem.item_name,
            replacement_quantity: repQty,
            cost_price_written_off: costWrittenOff,
            selling_price_original: parseFloat(sellingPriceOriginal||0),
            processed_by: processedBy, processed_by_role: processedRole,
            expense_id: expenseId, notes: notes||null
        }]).select('id').single();
        if (recErr) throw recErr;

        // ── Notify KRA via DigiTax eTIMS ────────────────────────────────────
        // Credit Note  → customer return (wrong_item / other) — reverses original sale
        // Debit Note   → damaged goods write-off — notifies KRA of stock loss
        let kraReturnRef = null, kraReturnQrUrl = null;
        try {
            const now      = new Date();
            const date     = `${String(now.getDate()).padStart(2,'0')}/${String(now.getMonth()+1).padStart(2,'0')}/${now.getFullYear()}`;
            const time     = now.toLocaleTimeString('en-US', { hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:true });
            const returnRef = `RET-${Date.now()}`;

            // Credit note for customer return; debit note for damaged goods
            const noteType = returnReason === 'damaged' ? 'debit_note' : 'credit_note';
            const sellingPrice = parseFloat(sellingPriceOriginal || retItem.cost_price || 0);

            const payload = {
                trader_invoice_number: returnRef,
                original_invoice_number: originalReceipt || null,
                note_type:   noteType,
                date,
                time,
                reason:      returnReason === 'damaged'    ? 'Damaged goods write-off'
                           : returnReason === 'wrong_item' ? 'Wrong item returned'
                           : 'Customer return',
                customer_pin:  null,
                customer_name: customerName || null,
                sale_items: [{
                    item_name:     retItem.item_name,
                    quantity:      retQty,
                    unit_price:    sellingPrice,
                    tax_type_code: 'A',
                    discount_rate: 0
                }]
            };

            const etimsRes = await fetch(`${DIGITAX_BASE_URL}/${noteType === 'credit_note' ? 'credit-notes' : 'debit-notes'}`, {
                method:  'POST',
                headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
                body:    JSON.stringify(payload),
                signal:  AbortSignal.timeout(10000)
            });
            const etimsData = await etimsRes.json();

            if (etimsRes.ok) {
                kraReturnRef   = etimsData?.data?.receipt_number || returnRef;
                kraReturnQrUrl = etimsData?.data?.etims_url      || null;

                // Save KRA ref back to returns_log
                await supabase.from('returns_log')
                    .update({ kra_return_ref: kraReturnRef, kra_return_qr_url: kraReturnQrUrl })
                    .eq('id', rec.id);

                log.info(`[eTIMS] ✅ ${noteType} submitted to KRA`, { ref: kraReturnRef, reason: returnReason });
            } else {
                log.warn('[eTIMS] Return note rejected by DigiTax', { status: etimsRes.status, body: etimsData });
            }
        } catch (etimsErr) {
            log.warn('[eTIMS] Return eTIMS submission failed (return still saved):', etimsErr.message);
        }

        res.json({
            success: true,
            message: 'Exchange processed. ' + retItem.item_name + ' replaced with ' + repItem.item_name + '.' +
                     (returnReason === 'damaged' ? ' KES ' + costWrittenOff + ' written off as expense.' : ''),
            returnId:      rec && rec.id,
            expenseId,
            kraReturnRef,
            kraReturnQrUrl,
            etimsSubmitted: !!kraReturnRef
        });
    } catch (err) {
        log.error('[RETURNS] Exchange error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/returns', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { from, to, staff, reason, page, search } = req.query;
    const perPage = 20, pageNum = parseInt(page) || 1;
    try {
        let q = supabase.from('returns_log').select('*', { count: 'exact' }).order('created_at', { ascending: false });
        if (from)   q = q.gte('created_at', from + 'T00:00:00Z');
        if (to)     q = q.lte('created_at', to   + 'T23:59:59Z');
        if (staff)  q = q.ilike('processed_by', `%${sanitize(staff)}%`);
        if (reason) q = q.eq('return_reason', reason);
        // Search by customer name, phone, or original receipt number
        if (search) {
            const s = sanitize(search);
            q = q.or(`customer_name.ilike.%${s}%,customer_phone.ilike.%${s}%,original_receipt.ilike.%${s}%`);
        }
        const start = (pageNum - 1) * perPage;
        const { data, count, error } = await q.range(start, start + perPage - 1);
        if (error) throw error;
        res.json({ returns: data||[], totalCount: count||0, totalPages: Math.ceil((count||0)/perPage), page: pageNum });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/returns/summary', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { month, year } = req.query;
    try {
        let q = supabase.from('returns_log').select('return_reason,cost_price_written_off,created_at');
        if (month && year) {
            const mm = String(month).padStart(2,'0'), lastDay = new Date(year, month, 0).getDate();
            q = q.gte('created_at', year + '-' + mm + '-01T00:00:00Z')
                 .lte('created_at', year + '-' + mm + '-' + lastDay + 'T23:59:59Z');
        }
        const { data, error } = await q;
        if (error) throw error;
        const s = (data||[]).reduce((acc,r) => {
            acc.totalExchanges++;
            acc.totalCostAbsorbed += parseFloat(r.cost_price_written_off||0);
            if (r.return_reason==='damaged')    acc.damagedCount++;
            if (r.return_reason==='wrong_item') acc.wrongItemCount++;
            if (r.return_reason==='other')      acc.otherCount++;
            return acc;
        }, { totalExchanges:0, totalCostAbsorbed:0, damagedCount:0, wrongItemCount:0, otherCount:0 });
        res.json(s);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/returns/search-sale', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { q } = req.query;
    if (!q) return res.status(400).json({ success: false, message: 'Query q is required.' });
    try {
        const { data, error } = await supabase.from('Sales')
            .select('id,receipt_number,item_name,quantity_sold,unit_price,total_amount,amount_paid,customer_name,customer_phone,sale_date,payment_status')
            .or(`customer_name.ilike.%${q}%,customer_phone.ilike.%${q}%,receipt_number.ilike.%${q}%`)
            .eq('is_voided', false)
            .order('sale_date', { ascending: false })
            .limit(10);
        if (error) throw error;
        res.json(data||[]);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ╔══════════════════════════════════════════════════════════════╗
// ║              M-PESA STK PUSH INTEGRATION                     ║
// ╚══════════════════════════════════════════════════════════════╝
const MPESA_CONSUMER_KEY    = process.env.MPESA_CONSUMER_KEY    || 'wSlDsjWgrLN4Ty7AX5uNfFPuQvXGK6DufIwTpoZPKx12qfSO';
const MPESA_CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET || 'QjY88Izo25zGza9m4ilv4tetjv02cbbhwVDy6GArmUC4KfVlYGdwEaxuQ2zcfxcK';
const MPESA_SHORTCODE       = process.env.MPESA_SHORTCODE       || '174379';
const MPESA_PASSKEY         = process.env.MPESA_PASSKEY         || 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919';
const MPESA_CALLBACK_URL    = process.env.MPESA_CALLBACK_URL    || 'https://uninfiltrated-persistent-jewel.ngrok-free.dev/api/mpesa/callback';
const MPESA_BASE_URL        = 'https://sandbox.safaricom.co.ke'; // Change to https://api.safaricom.co.ke for live

// ── Supabase-persisted M-Pesa helpers (survives server restarts) ──────────────
// Requires table: pending_mpesa (checkout_id TEXT PK, status TEXT, phone TEXT,
//   amount INT, context JSONB, mpesa_code TEXT, result_desc TEXT, created_at TIMESTAMPTZ)
async function mpesaSet(checkoutId, fields) {
    const { error } = await supabase
        .from('pending_mpesa')
        .upsert({ checkout_id: checkoutId, ...fields }, { onConflict: 'checkout_id' });
    if (error) log.error('mpesaSet failed', error, { checkoutId });
}
async function mpesaGet(checkoutId) {
    const { data, error } = await supabase
        .from('pending_mpesa')
        .select('*')
        .eq('checkout_id', checkoutId)
        .maybeSingle(); // maybeSingle returns null instead of error when not found
    if (error) log.error('mpesaGet failed', error, { checkoutId });
    return data || null;
}
async function mpesaDel(checkoutId) {
    await supabase.from('pending_mpesa').delete().eq('checkout_id', checkoutId);
}

// ── M-Pesa token cache — token is valid for 3600s, refresh 5min before expiry ──
let _mpesaToken    = null;
let _mpesaTokenExp = 0;   // Unix ms when token expires

async function getMpesaToken() {
    const now = Date.now();
    // Return cached token if it's still valid (with 5-minute buffer)
    if (_mpesaToken && now < _mpesaTokenExp - 5 * 60 * 1000) {
        return _mpesaToken;
    }
    const auth = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString('base64');
    let res;
    try {
        res = await fetch(`${MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials`, {
            headers: { Authorization: `Basic ${auth}` },
            signal: AbortSignal.timeout(10000)
        });
    } catch (fetchErr) {
        const hint = fetchErr.cause?.code || fetchErr.code || fetchErr.name || '';
        if (hint === 'ENOTFOUND' || hint === 'EAI_AGAIN')
            throw new Error(`Cannot reach Safaricom — DNS failure (${hint}). Check internet/VPN.`);
        if (hint === 'ECONNREFUSED')
            throw new Error(`Safaricom connection refused (${hint}). Check firewall/proxy.`);
        if (hint === 'TimeoutError' || hint === 'AbortError')
            throw new Error('Safaricom token request timed out.');
        throw new Error(`Safaricom fetch failed: ${fetchErr.message}`);
    }
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Safaricom token error ${res.status}: ${body}`);
    }
    const data = await res.json();
    if (!data.access_token) throw new Error('Safaricom returned no access_token. Check Consumer Key/Secret.');
    _mpesaToken    = data.access_token;
    _mpesaTokenExp = now + (parseInt(data.expires_in) || 3600) * 1000;
    console.log('[MPESA] 🔑 Token refreshed, valid for', Math.round((parseInt(data.expires_in)||3600)/60), 'min');
    return _mpesaToken;
}

app.post('/api/mpesa/stk-push', requireAuth, async (req, res) => {
    const { phone, amount, accountRef, context } = req.body;
    let msisdn = String(phone).replace(/\s/g, '');
    if (msisdn.startsWith('0'))       msisdn = '254' + msisdn.slice(1);
    if (msisdn.startsWith('+'))       msisdn = msisdn.slice(1);
    if (!/^2547\d{8}$/.test(msisdn)) return res.status(400).json({ success: false, message: 'Invalid phone number. Use format 07XXXXXXXX' });
    const amountInt = Math.ceil(parseFloat(amount));
    if (!amountInt || amountInt < 1) return res.status(400).json({ success: false, message: 'Invalid amount' });
    try {
        const token     = await getMpesaToken();
        const timestamp = new Date().toISOString().replace(/[-T:.Z]/g, '').slice(0, 14);
        const password  = Buffer.from(`${MPESA_SHORTCODE}${MPESA_PASSKEY}${timestamp}`).toString('base64');
        const body = {
            BusinessShortCode: MPESA_SHORTCODE, Password: password, Timestamp: timestamp,
            TransactionType: 'CustomerPayBillOnline', Amount: amountInt,
            PartyA: msisdn, PartyB: MPESA_SHORTCODE, PhoneNumber: msisdn,
            CallBackURL: MPESA_CALLBACK_URL,
            AccountReference: accountRef || 'EliteHardware', TransactionDesc: 'Payment for goods'
        };
        const stkRes  = await fetch(`${MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const stkData = await stkRes.json();
        if (stkData.ResponseCode !== '0') return res.status(400).json({ success: false, message: stkData.errorMessage || stkData.ResponseDescription || 'STK push failed' });
        // Persist to Supabase so server restarts don't lose pending transactions
        await mpesaSet(stkData.CheckoutRequestID, {
            status: 'pending', phone: msisdn, amount: amountInt,
            context: context || {}, created_at: new Date().toISOString()
        });
        log.info(`[MPESA STK] ✅ Pending: ${stkData.CheckoutRequestID}`);
        res.json({ success: true, checkoutRequestId: stkData.CheckoutRequestID, message: 'STK push sent.' });
    } catch (err) {
        console.error('[MPESA STK]', err.message);
        res.status(500).json({ success: false, message: 'M-Pesa error: ' + err.message });
    }
});

app.post('/api/mpesa/callback', async (req, res) => {
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    try {
        console.log('[MPESA CALLBACK] Received:', JSON.stringify(req.body, null, 2));
        const body    = req.body?.Body?.stkCallback;
        if (!body)    return;
        const checkId = body.CheckoutRequestID;
        const code    = body.ResultCode;
        const pending = await mpesaGet(checkId);
        if (!pending) return;
        if (code === 0) {
            const items     = body.CallbackMetadata?.Item || [];
            const get       = name => items.find(i => i.Name === name)?.Value;
            const mpesaCode = get('MpesaReceiptNumber');
            const amount    = get('Amount');
            const phone     = get('PhoneNumber');
            await mpesaSet(checkId, { ...pending, status: 'confirmed', mpesa_code: mpesaCode, amount, phone });
            log.info(`[MPESA]✅ Payment confirmed: ${mpesaCode} KES ${amount} from ${phone}`);
        } else if (code === 1037) {
            log.info('[MPESA]⚠️ Sandbox timeout (1037) — keeping pending for manual test');
        } else if (code === 1032) {
            await mpesaSet(checkId, { ...pending, status: 'cancelled', result_desc: body.ResultDesc || 'Cancelled by user' });
            log.info(`[MPESA]🚫 Cancelled by customer: ${checkId}`);
        } else if (code === 1) {
            await mpesaSet(checkId, { ...pending, status: 'insufficient_funds', result_desc: body.ResultDesc || 'Insufficient funds' });
            log.info(`[MPESA]💸 Insufficient funds: ${checkId}`);
        } else {
            await mpesaSet(checkId, { ...pending, status: 'failed', result_desc: body.ResultDesc });
            log.info(`[MPESA]❌ Payment failed (code ${code}): ${body.ResultDesc}`);
        }
    } catch (err) { console.error('[MPESA CALLBACK ERROR]', err.message); }
});

app.get('/api/mpesa/status/:checkoutId', requireAuth, async (req, res) => {
    try {
        // Prevent 304 caching — status changes and browser cache would hide updates
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.set('Pragma', 'no-cache');
        const tx = await mpesaGet(req.params.checkoutId);
        if (!tx) {
            log.warn('STK status check — transaction not found', { checkoutId: req.params.checkoutId });
            return res.status(404).json({ success: false, status: 'not_found', message: 'Transaction not found — may have expired or not yet saved' });
        }
        res.json({ success: true, status: tx.status, mpesaCode: tx.mpesa_code || null, amount: tx.amount, phone: tx.phone, resultDesc: tx.result_desc || null });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── STK Query — ask Safaricom directly (fallback when callback unreachable) ──
app.get('/api/mpesa/query/:checkoutId', requireAuth, async (req, res) => {
    const checkoutId = req.params.checkoutId;
    try {
        const token     = await getMpesaToken();
        const timestamp = new Date().toISOString().replace(/[-T:.Z]/g,'').slice(0,14);
        const password  = Buffer.from(MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).toString('base64');
        const qRes = await fetch(MPESA_BASE_URL + '/mpesa/stkpushquery/v1/query', {
            method: 'POST',
            headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
            body: JSON.stringify({ BusinessShortCode: MPESA_SHORTCODE, Password: password, Timestamp: timestamp, CheckoutRequestID: checkoutId }),
            signal: AbortSignal.timeout(10000)
        });
        const qData = await qRes.json();
        console.log('[MPESA QUERY]', checkoutId, qData.ResultCode, qData.ResultDesc);
        const rc = parseInt(qData.ResultCode);
        const desc = qData.ResultDesc || '';
        const pending = await mpesaGet(checkoutId);
        if (rc === 0) {
            if (pending && pending.status !== 'confirmed') await mpesaSet(checkoutId, { ...pending, status: 'confirmed' });
            return res.json({ success: true, status: 'confirmed', resultDesc: desc });
        }
        if (rc === 1032) {
            if (pending && pending.status === 'pending') await mpesaSet(checkoutId, { ...pending, status: 'cancelled', result_desc: desc });
            return res.json({ success: true, status: 'cancelled', resultDesc: 'Customer cancelled the payment' });
        }
        if (rc === 1) {
            if (pending && pending.status === 'pending') await mpesaSet(checkoutId, { ...pending, status: 'insufficient_funds', result_desc: desc });
            return res.json({ success: true, status: 'insufficient_funds', resultDesc: 'Insufficient M-Pesa balance' });
        }
        if (rc === 1037 || (qData.errorCode && qData.errorCode === '500.001.1001'))
            return res.json({ success: true, status: 'pending', resultDesc: desc });
        if (pending && pending.status === 'pending') await mpesaSet(checkoutId, { ...pending, status: 'failed', result_desc: desc });
        return res.json({ success: true, status: 'failed', resultDesc: desc });
    } catch (err) {
        console.error('[MPESA QUERY]', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// Clean up stale pending_mpesa rows older than 10 minutes every minute
setInterval(async () => {
    const cutoff = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    await supabase.from('pending_mpesa').delete().lt('created_at', cutoff).eq('status', 'pending');
}, 60 * 1000);

// ╔══════════════════════════════════════════════════════════════╗
// ║         C2B — REMOTE DEBT PAYMENTS VIA TILL NUMBER          ║
// ╚══════════════════════════════════════════════════════════════╝

// ── Register C2B URLs with Safaricom (run once) ───────────────────────────────
app.post('/api/c2b/register', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const token   = await getMpesaToken();
        const body    = {
            ShortCode:       MPESA_SHORTCODE,
            ResponseType:    'Completed',
            ConfirmationURL: `${MPESA_CALLBACK_URL.replace('/api/mpesa/callback', '')}/api/c2b/confirmation`,
            ValidationURL:   `${MPESA_CALLBACK_URL.replace('/api/mpesa/callback', '')}/api/c2b/validation`
        };
        const r    = await fetch(`${MPESA_BASE_URL}/mpesa/c2b/v1/registerurl`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await r.json();
        console.log('[C2B REGISTER]', data);
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── Safaricom C2B Validation (approve all payments) ───────────────────────────
app.post('/api/c2b/validation', (req, res) => {
    console.log('[C2B VALIDATION]', JSON.stringify(req.body));
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
});

// ── Safaricom C2B Confirmation (payment received) ─────────────────────────────
app.post('/api/c2b/confirmation', async (req, res) => {
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

    try {
        const p            = req.body;
        const phone        = String(p.MSISDN || '').replace(/^254/, '0');
        const amount       = parseFloat(p.TransAmount || 0);
        const mpesaCode    = p.TransID       || null;
        const accountRef   = p.BillRefNumber || null;
        const firstName    = p.FirstName     || '';
        const lastName     = p.LastName      || '';
        const customerName = `${firstName} ${lastName}`.trim() || 'Unknown';

        log.info(`[C2B]💰 Received KES ${amount} from ${phone} (${mpesaCode})`);
        if (!phone || amount <= 0) return;

        const now      = new Date();
        const datePart = now.getFullYear().toString() + String(now.getMonth()+1).padStart(2,'0') + String(now.getDate()).padStart(2,'0');
        const timePart = String(now.getHours()).padStart(2,'0') + String(now.getMinutes()).padStart(2,'0') + String(now.getSeconds()).padStart(2,'0');

        // ── Find active debts for this phone (FIFO) ───────────────────────────
        const { data: debts } = await supabase
            .from('Sales')
            .select('id, item_name, total_amount, amount_paid, customer_name')
            .eq('customer_phone', phone)
            .eq('is_voided', false)
            .in('payment_status', ['Credit', 'Partial', 'credit', 'partial', 'Unpaid'])
            .order('sale_date', { ascending: true });

        const activeDebts = (debts || []).filter(d =>
            (parseFloat(d.total_amount) - parseFloat(d.amount_paid || 0)) > 0
        );

        // ── No debt — store as unmatched for cashier to handle ────────────────
        if (activeDebts.length === 0) {
            await supabase.from('c2b_payments').insert([{
                phone, amount, mpesa_code: mpesaCode, account_ref: accountRef,
                customer_name: customerName, status: 'unmatched',
                amount_applied: 0, amount_excess: amount,
                created_at: now.toISOString()
            }]);
            log.info(`[C2B]⚠️ No debts for ${phone} — stored as unmatched`);
            return;
        }

        // ── Has debt — apply FIFO first ───────────────────────────────────────
        let remaining    = amount;
        let totalApplied = 0;

        for (const debt of activeDebts) {
            if (remaining <= 0) break;
            const balance  = parseFloat(debt.total_amount) - parseFloat(debt.amount_paid || 0);
            const applyAmt = Math.min(remaining, balance);
            const newPaid  = parseFloat(debt.amount_paid || 0) + applyAmt;
            const newStatus = newPaid >= parseFloat(debt.total_amount) ? 'Paid' : 'Partial';
            const payRef   = 'PAY-' + datePart + '-' + timePart + '-C2B';

            await supabase.from('Sales').update({
                amount_paid:    newPaid,
                payment_status: newStatus,
                receipt_number: newStatus === 'Paid' ? payRef : null
            }).eq('id', debt.id);

            await supabase.from('payments').insert([{
                sale_id: debt.id, amount: applyAmt, payment_method: 'M-Pesa',
                mpesa_code: mpesaCode, received_by: 'C2B-AUTO',
                customer_name: debt.customer_name || customerName,
                created_at: now.toISOString()
            }]);

            await supabase.from('debt_payments').insert([{
                sale_id: debt.id, amount_paid: applyAmt, payment_method: 'M-Pesa',
                mpesa_id: mpesaCode, processed_by: 'C2B-AUTO',
                customer_name: debt.customer_name || customerName,
                customer_phone: phone, payment_date: now.toISOString()
            }]);

            log.info(`[C2B]✅ Applied KES ${applyAmt} to "${debt.item_name}" → ${newStatus}`);
            totalApplied += applyAmt;
            remaining    -= applyAmt;
        }

        // Update customer total_debt
        const { data: cust } = await supabase.from('customers').select('total_debt').eq('phone', phone).single();
        if (cust) await supabase.from('customers').update({
            total_debt: Math.max(0, parseFloat(cust.total_debt || 0) - totalApplied)
        }).eq('phone', phone);

        // ── Store in c2b_payments — with excess flagged for cashier ──────────
        const status = remaining > 0 ? 'excess' : 'debt_cleared';
        await supabase.from('c2b_payments').insert([{
            phone, amount, mpesa_code: mpesaCode, account_ref: accountRef,
            customer_name: activeDebts[0]?.customer_name || customerName,
            status, amount_applied: totalApplied, amount_excess: remaining,
            created_at: now.toISOString()
        }]);

        if (remaining > 0) {
            log.info(`[C2B]ℹ️ KES ${remaining} excess after clearing all debts — cashier to link to new goods`);
        } else {
            log.info(`[C2B]✅ All debts cleared for ${phone}`);
        }

    } catch (err) {
        console.error('[C2B CONFIRMATION ERROR]', err.message);
    }
});

// ── Cashier marks unmatched/excess C2B as goods purchase ─────────────────────
app.post('/api/c2b/resolve-goods', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { c2bId, notes } = req.body;
    if (!c2bId) return res.status(400).json({ success: false, message: 'c2bId required' });
    try {
        const { error } = await supabase.from('c2b_payments').update({
            status: 'goods_purchase', resolved_by: req.user.name,
            resolved_at: new Date().toISOString(), notes: notes || null
        }).eq('id', c2bId);
        if (error) throw error;
        res.json({ success: true, message: 'Marked as goods purchase' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── Cashier applies unmatched/excess C2B to a specific debtor (different number) ──
app.post('/api/c2b/resolve-debt', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { c2bId, debtorPhone } = req.body;
    if (!c2bId || !debtorPhone) return res.status(400).json({ success: false, message: 'c2bId and debtorPhone required' });
    try {
        // Get the C2B payment
        const { data: c2b, error: c2bErr } = await supabase.from('c2b_payments').select('*').eq('id', c2bId).single();
        if (c2bErr || !c2b) return res.status(404).json({ success: false, message: 'C2B payment not found' });

        const amount = parseFloat(c2b.amount_excess > 0 ? c2b.amount_excess : c2b.amount);

        // Find debts for the linked debtor phone — FIFO
        const { data: debts } = await supabase
            .from('Sales')
            .select('id, item_name, total_amount, amount_paid, customer_name')
            .eq('customer_phone', debtorPhone)
            .eq('is_voided', false)
            .in('payment_status', ['Credit', 'Partial', 'credit', 'partial', 'Unpaid'])
            .order('sale_date', { ascending: true });

        const activeDebts = (debts || []).filter(d =>
            (parseFloat(d.total_amount) - parseFloat(d.amount_paid || 0)) > 0
        );
        if (!activeDebts.length) return res.status(404).json({ success: false, message: `No outstanding debts found for ${debtorPhone}` });

        let remaining = amount, totalApplied = 0;
        const now      = new Date();
        const datePart = now.getFullYear().toString() + String(now.getMonth()+1).padStart(2,'0') + String(now.getDate()).padStart(2,'0');
        const timePart = String(now.getHours()).padStart(2,'0') + String(now.getMinutes()).padStart(2,'0') + String(now.getSeconds()).padStart(2,'0');

        for (const debt of activeDebts) {
            if (remaining <= 0) break;
            const balance   = parseFloat(debt.total_amount) - parseFloat(debt.amount_paid || 0);
            const applyAmt  = Math.min(remaining, balance);
            const newPaid   = parseFloat(debt.amount_paid || 0) + applyAmt;
            const newStatus = newPaid >= parseFloat(debt.total_amount) ? 'Paid' : 'Partial';
            const payRef    = 'PAY-' + datePart + '-' + timePart + '-C2B';

            await supabase.from('Sales').update({
                amount_paid: newPaid, payment_status: newStatus,
                receipt_number: newStatus === 'Paid' ? payRef : null
            }).eq('id', debt.id);

            await supabase.from('payments').insert([{
                sale_id: debt.id, amount: applyAmt, payment_method: 'M-Pesa',
                mpesa_code: c2b.mpesa_code, received_by: req.user.name,
                customer_name: debt.customer_name, created_at: now.toISOString()
            }]);

            await supabase.from('debt_payments').insert([{
                sale_id: debt.id, amount_paid: applyAmt, payment_method: 'M-Pesa',
                mpesa_id: c2b.mpesa_code, processed_by: req.user.name,
                customer_name: debt.customer_name, customer_phone: debtorPhone,
                payment_date: now.toISOString()
            }]);

            totalApplied += applyAmt;
            remaining    -= applyAmt;
        }

        // Update debtor's total_debt
        const { data: cust } = await supabase.from('customers').select('total_debt').eq('phone', debtorPhone).single();
        if (cust) await supabase.from('customers').update({
            total_debt: Math.max(0, parseFloat(cust.total_debt || 0) - totalApplied)
        }).eq('phone', debtorPhone);

        // Mark C2B as resolved
        await supabase.from('c2b_payments').update({
            status: 'debt_payment', resolved_by: req.user.name,
            resolved_at: now.toISOString(),
            notes: `Linked to debtor ${debtorPhone} — KES ${totalApplied} applied`
        }).eq('id', c2bId);

        log.info(`[C2B DEBT] ✅ KES ${totalApplied} applied to ${debtorPhone} via C2B from ${c2b.phone}`);
        res.json({ success: true, applied: totalApplied, remaining });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
app.post('/api/c2b/resolve-ignore', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { c2bId, notes } = req.body;
    if (!c2bId) return res.status(400).json({ success: false, message: 'c2bId required' });
    try {
        const { error } = await supabase.from('c2b_payments').update({
            status: 'ignored', resolved_by: req.user.name,
            resolved_at: new Date().toISOString(), notes: notes || null
        }).eq('id', c2bId);
        if (error) throw error;
        res.json({ success: true, message: 'Payment ignored' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ── Get pending/recent C2B payments for dashboard ─────────────────────────────
app.get('/api/c2b/payments', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('c2b_payments')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(20);
        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.listen(PORT, () => log.info(`🚀 Elite Hardware POS running on http://localhost:${PORT}`));
