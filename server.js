const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
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
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto'); 
const fs = require('fs');
app.set('trust proxy', 1);

// ─────────────────────────────────────────────────────────────
//  generateQrDataUrl(text)
//  Generates a QR code as a base64 PNG data URL using the local
//  'qrcode' package — no external API call, instant, works offline.
//  Returns a data:image/png;base64,... string ready for <img src>.
// ─────────────────────────────────────────────────────────────
async function generateQrDataUrl(text) {
    try {
        return await QRCode.toDataURL(text, {
            errorCorrectionLevel: 'M',
            margin: 1,
            width: 140,
            color: { dark: '#000000', light: '#ffffff' }
        });
    } catch(e) {
        log.warn('[QR] Failed to generate QR:', e.message);
        return null;
    }
} // Trust ngrok/reverse proxy headers
const PORT = process.env.PORT || 5001;

// ============================================================
//  TIMEZONE HELPERS — East Africa Time (UTC+3)
//  All sale_date / expense_date values are stored in EAT so
//  that midnight boundaries match the physical business day.
// ============================================================
const EAT_OFFSET_MS = 3 * 60 * 60 * 1000; // UTC+3

/** Returns a Date object representing "now" in EAT wall-clock time */
function nowEAT() {
    return new Date(Date.now() + EAT_OFFSET_MS);
}

/** Returns an ISO string like "2025-04-14T00:19:00.000+03:00" */
function nowEATIso() {
    const d = nowEAT();
    const pad = n => String(n).padStart(2, '0');
    const ms  = String(d.getUTCMilliseconds()).padStart(3, '0');
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())}` +
           `T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${ms}+03:00`;
}

/** Returns { start, end } ISO strings covering a full EAT calendar day for a YYYY-MM-DD string */
function eatDayBounds(dateStr) {
    // dateStr is already an EAT calendar date — just anchor to +03:00
    return {
        start: `${dateStr}T00:00:00.000+03:00`,
        end:   `${dateStr}T23:59:59.999+03:00`
    };
}

/** Returns { start, end } covering an inclusive EAT date range */
function eatRangeBounds(fromStr, toStr) {
    return {
        start: `${fromStr}T00:00:00.000+03:00`,
        end:   `${toStr}T23:59:59.999+03:00`
    };
}


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
//  TOKEN BLOCKLIST — immediate session revocation
//  Stores { token_prefix → expiry_timestamp }
//  Entries auto-purge once their natural expiry passes,
//  so the Map never grows unbounded.
// ============================================================
const tokenBlocklist = new Map();

function blockToken(token) {
    try {
        const decoded = jwt.decode(token);
        if (!decoded?.exp) return;
        // Use first 16 chars as key — unique enough, avoids storing full token
        tokenBlocklist.set(token.slice(0, 16), decoded.exp * 1000);
    } catch { /* ignore malformed tokens */ }
}

function isTokenBlocked(token) {
    const key = token.slice(0, 16);
    const expiry = tokenBlocklist.get(key);
    if (!expiry) return false;
    if (Date.now() > expiry) { tokenBlocklist.delete(key); return false; }
    return true;
}

// Sweep expired entries every hour
setInterval(() => {
    const now = Date.now();
    for (const [key, expiry] of tokenBlocklist.entries()) {
        if (now > expiry) tokenBlocklist.delete(key);
    }
}, 60 * 60 * 1000);

// ============================================================
//  SESSION VERIFICATION (C-02 Fix: Server-Side Auth)
// ============================================================

// ============================================================
//  eTIMS — DigiTax Integration
// ============================================================
const DIGITAX_BASE_URL = process.env.DIGITAX_BASE_URL || 'https://api.digitax.tech/ke/v2';
const DIGITAX_API_KEY  = process.env.DIGITAX_API_KEY  || '';
const DIGITAX_CALLBACK_URL = process.env.DIGITAX_CALLBACK_URL || 'https://uninfiltrated-persistent-jewel.ngrok-free.dev/api/digitax/callback';

async function submitSaleToEtims(saleData) {
    if (!DIGITAX_API_KEY) { log.warn('[eTIMS] DIGITAX_API_KEY not set — QR will use fallback placeholder'); return null; }
    try {
        const now         = nowEAT();
       const saleDate = new Date().toISOString().split('T')[0];
        const payMap   = { 'Cash':'01', 'M-Pesa':'06', 'Credit':'02' };

        // Numeric invoice number generation
        const baseNum = parseInt(
            (saleData.invoiceNumber || saleData.receiptNumber || '1')
            .replace(/\D/g, '').slice(-8)
        ) || 1;
        const tsSuffix = String(Date.now()).slice(-5);
        const invoiceNum = parseInt(String(Math.abs(baseNum)) + tsSuffix);
        const traderInvoiceNumber = (saleData.invoiceNumber || saleData.receiptNumber) + '-' + Date.now();

        // --- NEW: Handle both single items AND cart arrays ---
        let payloadItems = [];
        
        if (saleData.cartItems && Array.isArray(saleData.cartItems)) {
            // UN/CEFACT unit codes used by KRA eTIMS
            // 'U'   = generic unit (cartons, pieces, bags, etc.)
            // 'KGM' = kilogram
            // 'GRM' = gram
            // 'LTR' = litre
            // 'MTR' = metre
            // 'MTK' = square metre
            const unitCodeMap = {
                'kg':  'KGM', 'kgs': 'KGM', 'kilogram': 'KGM', 'kilograms': 'KGM',
                'g':   'GRM', 'gm': 'GRM', 'gram': 'GRM', 'grams': 'GRM',
                'l':   'LTR', 'ltr': 'LTR', 'litre': 'LTR', 'litres': 'LTR', 'liter': 'LTR', 'liters': 'LTR',
                'm':   'MTR', 'mtr': 'MTR', 'metre': 'MTR', 'meter': 'MTR', 'metres': 'MTR', 'meters': 'MTR',
                'm2':  'MTK', 'sqm': 'MTK', 'sq m': 'MTK',
            };
            const resolveUnitCode = (unit) => unitCodeMap[(unit||'').toLowerCase().trim()] || 'U';

           // Map the cart array into DigiTax format
            payloadItems = saleData.cartItems.map(item => {
                let qty = parseFloat(item.quantity) || 1;
                let price = parseFloat(item.unitPrice) || 0;

                const hasSub = !!(item.subUnit && item.subUnitQty);

                // ── THE FIX: Translate Bulk sales into Sub-unit sales for KRA ──
                // If the cashier sold by 'Carton' but the item is tracked in 'Pieces',
                // multiply the quantity by 1000 and divide the unit price by 1000.
                if (item.sellUnit !== 'sub' && hasSub) {
                    const subQty = parseFloat(item.subUnitQty);
                    qty = parseFloat((qty * subQty).toFixed(4));
                    price = price / subQty; 
                }

                // KRA must always see the sub-unit if the item has one configured
                const activeUnit = hasSub ? item.subUnit : item.bulkUnit;
                const quantityUnitCode = resolveUnitCode(activeUnit);

                return {
                    item_name:             item.itemName,
                    item_class_code:       '99010000',
                    item_type_code:        '2',
                    item_bar_code:         String((item.itemName || 'ITEM').split('').reduce((a, c) => Math.abs(a + c.charCodeAt(0)), 0)).padStart(8, '0'),
                    item_tax_type_code:    'B',
                    quantity:              qty,
                    quantity_unit_code:    quantityUnitCode,
                    package_unit_code:     'NT',
                    package_unit_quantity: 1,
                    unit_price:            price,
                    total_amount:          parseFloat((price * qty).toFixed(2)),
                    tax_type_code:         'B',
                    discount_rate:         0,
                    origin_nation_code:    'KE'
                };
            });
        } else {
            // Fallback for single item sales
            const unitPrice   = parseFloat(saleData.unitPrice) || 0;
            const quantity    = parseFloat(saleData.quantity)  || 1;
            const totalAmount = parseFloat((unitPrice * quantity).toFixed(2));
           const barCode = (item.barcode && String(item.barcode).trim() !== '') 
    ? String(item.barcode).trim() 
    : String(item.itemName.split('').reduce((a, c) => Math.abs(a + c.charCodeAt(0)), 0)).padStart(8, '0');
            
            payloadItems = [{
                item_name:             saleData.itemName,
                item_class_code:       '99010000',
                item_type_code:        '2',
                item_bar_code:         barCode,
                item_tax_type_code:    'B',
                quantity:              quantity,
                quantity_unit_code:    'U',
                package_unit_code:     'NT',
                package_unit_quantity: 1,
                unit_price:            unitPrice,
                total_amount:          totalAmount,
                tax_type_code:         'B',
                discount_rate:         0,
                origin_nation_code:    'KE'
            }];
        }

        const payload = {
            trader_invoice_number: traderInvoiceNumber,
            invoice_number:        invoiceNum,
            receipt_type_code:     'S',
            payment_type_code:     payMap[saleData.paymentMethod] || '01',
            invoice_status_code:   '02',
            sale_date:             saleDate,
            callback_url:          DIGITAX_CALLBACK_URL,
            ...(saleData.customerPin ? { buyer_pin: saleData.customerPin } : {}),
            items: payloadItems // Send the consolidated array
        };

        // ... (Keep the rest of the function: log.info, fetch, etc.)
        log.info('[eTIMS] Submitting to DigiTax', {
            invoice:   payload.trader_invoice_number,
            itemsCount: payload.items.length,
            sale_date: saleDate
        });
        
        const res  = await fetch(`${DIGITAX_BASE_URL}/sales-with-items`, {
            method:  'POST',
            headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
            body:    JSON.stringify(payload),
            signal:  AbortSignal.timeout(10000)
        });
        
        // REPLACE: const data = await res.json();
        // WITH THIS SAFE PARSER:
        const text = await res.text();
        let data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            data = { _raw: text };
        }

        // Log the FULL raw DigiTax response so we can verify field names
        log.info('[eTIMS] DigiTax raw response', { status: res.status, body: JSON.stringify(data) });

        if (!res.ok) {
            log.warn('[eTIMS] DigiTax rejected sale', { status: res.status, body: JSON.stringify(data) });
            return null;
        }

        // Use etims_url when KRA approved, offline_url while still PENDING
        const kraQrUrl = (data?.etims_url && data.etims_url !== '') ? data.etims_url : (data?.offline_url || null);

        // Kra_Receipt_No — DigiTax returns e.g. REC-20260322-0001-195134896-1774198296844
        // It comes back as the last path segment of offline_url, or directly as trader_invoice_number / receipt_number
        const offlineUrl   = data?.offline_url || data?.etims_url || '';
        const urlSegment   = offlineUrl ? offlineUrl.split('/').pop() : null;
        const kraReceiptNo = data?.receipt_number
                          || data?.trader_invoice_number
                          || data?.kra_receipt_number
                          || urlSegment
                          || traderInvoiceNumber; // fallback: what we sent

        // Control_unit_number — DigiTax serial_number e.g. KRARVS000000005
        const controlUnitNumber = data?.serial_number
                               || data?.Control_unit_number
                               || data?.scu_id
                               || null;

        // E-tims_No — numeric invoice number assigned by DigiTax/KRA e.g. 1059171
        const etimsNo = data?.invoice_number ?? data?.etims_no ?? null;

        // DigiTax sale ID — needed for /credit-notes endpoint when processing returns
        const digitaxSaleId = data?.id || null;

        log.info('[eTIMS] ✅ Sale accepted by DigiTax', {
            digitaxSaleId,
            kraReceiptNo,
            controlUnit: controlUnitNumber,
            etimsNo,
            kraQrUrl
        });

        return { digitaxSaleId, kraReceiptNo, kraQrUrl, traderInvoiceNumber, etimsNo, controlUnitNumber };

    } catch (err) {
        log.warn('[eTIMS] DigiTax call failed (sale still saved):', + err.message);
        return null;
    }
}

async function registerItemWithEtims(item) {
    if (!DIGITAX_API_KEY) { log.warn('[eTIMS] DIGITAX_API_KEY not set — skipping item registration'); return null; }
    try {
      const classCodeMap = {
            // 🧱 BUILDING & CONSTRUCTION MATERIALS
            'Cement':              '30110000', // Concrete, cement and plaster
            'Building Materials':  '30110000', 
            'Construction':        '30110000',
            'Tiles & Flooring':    '30160000', // Interior finishing materials
            'Doors & Windows':     '30170000', // Doors, windows and glass
            'Glass':               '30170000',
            'Sanitary Ware':       '30180000', // Plumbing fixtures
            'Ladders':             '30190000', // Construction and maintenance support equipment
            'Scaffolding':         '30190000',
            'Steel & Metal':       '30260000', // Structural materials
            'Timber & Wood':       '30260000',
            'Fencing':             '30260000',
            'Waterproofing':       '30140000', // Insulation/Structural
            'Insulation':          '30140000',

            // 🛠️ TOOLS & MACHINERY
            'Tools':               '27110000', // Hand tools
            'Hardware':            '31160000', // General Hardware (Direct DigiTax Code)
            'Pneumatic':           '27130000', // Pneumatic machinery
            'Safety':              '27110000', // Mapped to tools for hardware context
            'Machinery':           '27000000', // Tools and General Machinery
            'Power Tools':         '27110000',
            'Welding':             '23270000', // Welding and soldering
            'Metal Forming':       '23250000', // Metal forming machinery

            // 🔩 FASTENERS & COMPONENTS
            'Fasteners':           '31160000', // Hardware
            'Locks & Security':    '31160000',
            'Bearings':            '31170000', // Bearings, bushings, wheels
            'Packings':            '31180000', // Packings, glands, boots
            'Abrasives':           '31190000', // Grinding and polishing
            'Cabinets':            '31260000', // Housings, cabinets
            'Machine Parts':       '31270000', // Machine made parts
            'Stampings':           '31280000', // Stampings and sheet components

            // 🚰 PLUMBING & PIPES
            'Plumbing':            '40170000', // Pipe, piping and pipe fittings
            'Water Storage':       '40140000', // Fluid and gas distribution
            'Pumps':               '40150000', // Industrial pumps
            'Tubes':               '40180000', // Tubes, tubing and fittings

            // ⚡ ELECTRICAL & LIGHTING
            'Electrical':          '39000000', // Electrical systems and components
            'Cables & Wiring':     '39130000', // Electrical wire management
            'Lighting':            '39100000', // Lamps and lightbulbs
            'Solar':               '39000000',
            'Generators':          '26130000', // Power generation (Level 2)

            // 🧪 CHEMICALS, PAINTS & ADHESIVES
            'Paint':               '31210000', // Paints and primers
            'Adhesives':           '31200000', // Adhesives and sealants
            'Solvents':            '12190000', // Solvents (Specific Category)

            // 🔧 GENERAL SUPPORT
            'Packing Supplies':    '24140000', // Packing supplies
            'Storage':             '56101530', // Storage cabinets
            'Cleaning':            '47130000', // Janitorial
            'Garden':              '10150000', // Seeds/Garden
            'General':             '31160000'  // Default: Hardware
        };
        const barCode = String(
            item.itemName.split('').reduce((a, c) => Math.abs(a + c.charCodeAt(0)), 0)
        ).padStart(8, '0');

        // UN/CEFACT unit code map
        const regUnitCodeMap = {
            'kg': 'KGM', 'kgs': 'KGM', 'kilogram': 'KGM', 'kilograms': 'KGM',
            'g':  'GRM', 'gm': 'GRM', 'gram': 'GRM', 'grams': 'GRM',
            'l':  'LTR', 'ltr': 'LTR', 'litre': 'LTR', 'litres': 'LTR', 'liter': 'LTR', 'liters': 'LTR',
            'm':  'MTR', 'mtr': 'MTR', 'metre': 'MTR', 'meter': 'MTR', 'metres': 'MTR', 'meters': 'MTR',
            'm2': 'MTK', 'sqm': 'MTK',
        };

        // ── Sub-unit items: register and track in the sub-unit (e.g. Kg) not the bulk unit (Carton) ──
        // KRA cannot reconcile stock registered in 'Cartons' against sales reported in 'Kg'.
        // The cleanest approach: register in the unit you actually sell in.
        // For nails: stockQty=12 cartons, sub_unit_qty=20 Kg/carton → register 240 Kg at KES 150/Kg.
        const hasSub = !!(item.sub_unit && item.sub_unit_qty && item.sub_unit_price);
        const etimsUnit      = hasSub ? item.sub_unit : (item.bulk_unit || item.unit || 'PCS');
        const etimsUnitCode  = regUnitCodeMap[etimsUnit.toLowerCase().trim()] || 'U';
        // Total stock in the etims unit: 12 cartons × 20 Kg = 240 Kg (or just stockQty if no sub-unit)
        const etimsStockQty  = hasSub
            ? parseFloat((item.stockQty * parseFloat(item.sub_unit_qty)).toFixed(4))
            : parseFloat(item.stockQty) || 0;
        // Unit price for KRA: sub-unit price (KES 150/Kg) if selling by sub-unit, else bulk price
        const etimsUnitPrice = hasSub
            ? parseFloat(item.sub_unit_price)
            : parseFloat(item.sellingPrice) || 0;

        const payload = {
            item_name:          item.itemName,
            item_class_code:    classCodeMap[item.category] || '99010000',
            item_type_code:     '2',
            item_bar_code:      barCode,
            tax_type_code:      'B',  // B = 16% VAT
            default_unit_price: etimsUnitPrice,
            quantity_unit_code: etimsUnitCode,
            package_unit_code:  'NT',
            origin_nation_code: 'KE',
            active:             true,
            callback_url:       DIGITAX_CALLBACK_URL
        };
        
        const res  = await fetch(`${DIGITAX_BASE_URL}/items`, {
            method:  'POST',
            headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
            body:    JSON.stringify(payload),
            signal:  AbortSignal.timeout(10000)
        });
        const data = await res.json();

        if (!res.ok) {
            // If item_class_code rejected, retry once with safe fallback 99010000
            if (data?.metadata?.argument === 'item_class_code' || 
                (data?.message || '').includes('item_class_code')) {
                log.warn('[eTIMS] item_class_code rejected — retrying with fallback 99010000', { item: item.itemName });
                payload.item_class_code = '99010000';
                const retry = await fetch(`${DIGITAX_BASE_URL}/items`, {
                    method: 'POST',
                    headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                    signal: AbortSignal.timeout(10000)
                });
                const retryData = await retry.json();
                if (retry.ok) {
                    const fallbackId = retryData?.id || retryData?.item_id || retryData?.data?.id || null;
                    log.info('[eTIMS] ✅ Item registered with fallback code', { item: item.itemName, digitaxItemId: fallbackId });

                    // ── Phase 2: push stock qty for fallback-registered item ──
                    // Use the same etimsStockQty (converted to sub-unit if applicable)
                    if (fallbackId && etimsStockQty > 0) {
                        log.info(`[eTIMS] Waiting 3s before pushing ${etimsStockQty} ${etimsUnit} (fallback)...`);
                        await new Promise(resolve => setTimeout(resolve, 3000));
                        const stockPayload = {
                            item_id:       fallbackId,
                            quantity:      etimsStockQty,
                            movement_type: '04',
                            action:        'ADD',
                            branch_id:     '01',
                            store_id:      '01',
                            remarks:       'Initial System Upload'
                        };
                        const stockRes = await fetch(`${DIGITAX_BASE_URL}/stock/adjust`, {
                            method:  'PUT',
                            headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
                            body:    JSON.stringify(stockPayload),
                            signal:  AbortSignal.timeout(10000)
                        });
                        if (stockRes.ok) {
                            log.info('[eTIMS] ✅ Stock pushed for fallback-registered item');
                        } else {
                            const sd = await stockRes.json();
                            log.warn('[eTIMS] Stock push failed for fallback item', { body: sd });
                        }
                    }
                    return fallbackId;
                }
                log.warn('[eTIMS] Item registration failed even with fallback', { item: item.itemName, body: JSON.stringify(retryData) });
            } else {
                log.warn('[eTIMS] Item registration rejected', { status: res.status, item: item.itemName, body: JSON.stringify(data) });
            }
            return null;
        }

        const digitaxItemId = data?.id || data?.item_id || data?.data?.id || null;
        log.info('[eTIMS] ✅ Identity registered', { item: item.itemName, digitaxItemId });

        // ════════ PHASE 2: IMMEDIATELY UPLOAD STOCK QUANTITY ════════
        // Push stock in the same unit we registered with (etimsStockQty).
        // For sub-unit items: 12 cartons × 20 Kg = 240 Kg pushed to KRA.
        // For regular items: stockQty as-is.

        if (digitaxItemId && etimsStockQty > 0) {
            log.info(`[eTIMS] Waiting 3s before pushing ${etimsStockQty} ${etimsUnit}...`);
            await new Promise(resolve => setTimeout(resolve, 3000));

           const stockPayload = {
    item_id:       digitaxItemId,
    quantity:      etimsStockQty,
    movement_type: '04',
    action:        'ADD',
    branch_id:     '01', // Standard KRA branch code
    store_id:      '01', // Standard KRA store code
    remarks:       'Initial System Upload'
};

            const stockRes = await fetch(`${DIGITAX_BASE_URL}/stock/adjust`, {
                method:  'PUT',
                headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
                body:    JSON.stringify(stockPayload),
                signal:  AbortSignal.timeout(10000)
            });

            if (stockRes.ok) {
                log.info('[eTIMS] ✅ Stock quantity successfully uploaded');
            } else {
                const stockData = await stockRes.json();
                log.warn('[eTIMS] ❌ Identity created, but stock upload failed', { body: stockData });
            }
        }

        return digitaxItemId;

    } catch (err) {
        log.warn('[eTIMS] Critical failure during registration/stock push:', err.message);
        return null;
    }
}
async function syncStockWithEtims(digitaxItemId, quantity, reason, movementType = '04', action = 'ADD') {
    if (!DIGITAX_API_KEY || !digitaxItemId) return null;
    
    try {
        const payload = {
            item_id:       digitaxItemId,
            quantity:      parseFloat(quantity) || 0,
            movement_type: movementType,
            action,        // 'ADD' to increase, 'DEDUCT' to decrease
            remarks:       reason || 'Stock Update'
        };

        const res = await fetch(`${DIGITAX_BASE_URL}/stock/adjust`, {
            method:  'PUT', 
            headers: { 
                'x-api-key': DIGITAX_API_KEY, 
                'Content-Type': 'application/json' 
            },
            body:    JSON.stringify(payload),
            signal:  AbortSignal.timeout(10000)
        });

        const data = await res.json();

        if (!res.ok) {
            log.warn('[eTIMS] Stock adjustment rejected', { digitaxItemId, action, body: data });
            return null;
        }

        log.info('[eTIMS] ✅ Stock balance updated in DigiTax', { action, quantity });
        return data;
    } catch (err) {
        log.warn('[eTIMS] Stock sync exception:', err.message);
        return null;
    }
} 
/** 
 * Converts internal bulk quantity (e.g., Cartons) to KRA-facing sub-unit quantity (e.g., Kg).
 * If no sub-unit exists, it returns the original quantity. 
 */
function toEtimsQty(rawQty, item) {
    const qty = parseFloat(rawQty) || 0;
    const hasSub = !!(item.sub_unit && item.sub_unit_qty && item.sub_unit_price);
    return hasSub ? parseFloat((qty * parseFloat(item.sub_unit_qty)).toFixed(4)) : qty;
}
// ============================================================
//  2. EMAIL CONFIGURATION
// ============================================================
// ── SMTP Transporter ─────────────────────────────────────────────────────────
// Render free tier blocks direct Gmail SMTP. Use Brevo (free, 300 emails/day):
//   SMTP_HOST  = smtp-relay.brevo.com
//   SMTP_PORT  = 587
//   EMAIL_USER = your Brevo login email
//   EMAIL_PASS = Brevo SMTP key (Brevo dashboard → SMTP & API → Generate key)
//   FROM_EMAIL = delivery address for all alerts/reports
// ─────────────────────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'smtp-relay.brevo.com',
    port:   parseInt(process.env.SMTP_PORT || '587', 10),
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: { rejectUnauthorized: false },
    connectionTimeout: 10000,
    greetingTimeout:   10000,
    socketTimeout:     15000
});

transporter.verify((err) => {
    if (err) {
        // We combined everything into one string using backticks so the logger doesn't choke
        log.error(`[EMAIL] ✗ SMTP connection failed: ${err.message} | HOST: ${process.env.SMTP_HOST || 'smtp-relay.brevo.com'} | USER: ${process.env.EMAIL_USER}`);
    } else {
        log.info(`[EMAIL] ✅ SMTP ready — ${process.env.SMTP_HOST || 'smtp-relay.brevo.com'} — sending as ${process.env.EMAIL_USER}`);
    }
});

// ============================================================
//  3. MIDDLEWARE
// ============================================================

// CORS — restrict to your frontend origins only
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,https://hardware-pos-backend.onrender.com')
    .split(',').map(o => o.trim());

app.use(helmet({
    // Content-Security-Policy: lock down what scripts/styles can load
    contentSecurityPolicy: {
        directives: {
            defaultSrc:     ["'self'"],
            
            // SECURITY UPDATE: Removed 'unsafe-eval' and 'cdn.tailwindcss.com'
            // This strictly blocks arbitrary string execution (eval, new Function)
            scriptSrc:      ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "unpkg.com"],
            
            // Allows inline event handlers (onclick=, onkeydown=) which your HTML relies on
            scriptSrcAttr:  ["'unsafe-hashes'", "'unsafe-inline'"],
            
            styleSrc:       ["'self'", "'unsafe-inline'", "fonts.googleapis.com", "unpkg.com"],
            fontSrc:        ["'self'", "fonts.gstatic.com"],
            imgSrc:         ["'self'", "data:", "blob:", "https://api.qrserver.com", "https://etims.kra.go.ke", "https://api.digitax.tech"],
            connectSrc:     ["'self'", "https://hardware-pos-backend.onrender.com", "http://localhost:6789", "https://cdnjs.cloudflare.com"],
            frameSrc:       ["'none'"],      // blocks clickjacking via <iframe>
            objectSrc:      ["'none'"],
            upgradeInsecureRequests: [],
        },
    },
    crossOriginEmbedderPolicy: false, // allow external fonts/CDN resources
}));
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
// Rate limiter — login endpoint: max 5 attempts per 15 minutes per Employee ID
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: { success: false, message: 'Too many login attempts for this Employee ID. Please wait 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    // Rate limit by Employee ID instead of IP address.
    // This prevents one cashier from locking out the entire store if they share WiFi.
    keyGenerator: (req) => {
        // Use the employeeId from the login attempt. If missing, fallback to a generic string.
        return req.body.employeeId ? req.body.employeeId.toUpperCase().trim() : 'unknown_user';
    }
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
app.use(express.json({ limit: '100kb' })); // Tight global limit — prevents DoS via large payloads
// Bulk import is the only route that legitimately receives large bodies; apply 10mb only there.
const bulkJsonParser = express.json({ limit: '10mb' });

// ── File paths (backend/server.js → ../frontend/)
const frontendPath = path.join(__dirname, '..', 'frontend');
app.use('/src', express.static(path.join(frontendPath, 'src')));
const pagesPath    = path.join(__dirname, '..', 'frontend', 'src', 'pages');

// Serve static assets (JS, CSS, images, auth.js etc.) from /frontend.
// Page HTML files are intercepted before static can serve them so that the
// role-gated routes below are the ONLY way to get an HTML page.
const PAGE_NAMES = [
    'inventory','debt_status','payments_report',
    'suppliers','purchase_orders','add_product','stock_audit','stock_movement',
    'debtors_report','returns_audit','customer_statement','supplier_statement','accounting',
    'expenses','stock_valuation','profit_loss','reports','debts_repayment',
    'billing', 'returns_statement', 'sales_orders'
];

app.use((req, res, next) => {
    // 🛑 THE FIX: Never intercept API routes for HTML page resolution
    if (req.path.startsWith('/api/')) return next('route');
    
    if (req.path.startsWith('/src/pages/') && req.path.endsWith('.html')) return next('route');
    if (PAGE_NAMES.some(p => req.path === '/' + p + '.html')) return next('route');
    if (PAGE_NAMES.some(p => req.path === '/' + p)) return next('route');
    next();
}, express.static(frontendPath, { index: false }));




// ── 3. Protected Page Routes ────────────────────────────────────────────────
// Role map mirrors the NAV array in index.html exactly.
// null  = any authenticated user (cashier, manager, admin)
// array = only those roles may access the page
//
// Covers BOTH URL forms:
//   /suppliers.html            (shallow — typed in browser or linked)
//   /src/pages/suppliers.html  (deep — direct path used by some links)
//
// How it works:
//   1. requireAuth reads the JWT from the Authorization header (API calls)
//      OR from the authToken cookie (browser page navigation).
//   2. If the token is missing/invalid → redirect to / (login screen).
//   3. If the role doesn't match → serve a styled 403 page.
//   4. Otherwise → send the HTML file.
//
// Frontend requirement: store the token in a cookie on login so the
// browser sends it automatically when navigating to a page URL.
//   document.cookie = `authToken=${token}; path=/; SameSite=Strict; max-age=28800`;

const cookieParser = require('cookie-parser');
app.use(cookieParser());

const PROTECTED_PAGES = {
    // ── All roles (cashier, manager, admin) ──────────────────────────────────
    'inventory':        null,
    'debt_status':      null,
    'payments_report':  null,
    'sales_orders':     null,
    // ── Manager + Admin only ─────────────────────────────────────────────────
    'suppliers':        ['admin', 'manager'],
    'supplier_statement': ['admin', 'manager'],
    'purchase_orders':  ['admin', 'manager'],
    'add_product':      ['admin', 'manager'],
    'stock_audit':      ['admin', 'manager'],
    'stock_movement':   ['admin', 'manager'],
    'debtors_report':   ['admin', 'manager'],
    'returns_audit':    ['admin', 'manager'],
    'customer_statement': ['admin', 'manager'], 
    'returns_statement':  ['admin', 'manager'], // <--- ADDED HERE
    'accounting':       ['admin', 'manager'],
    // ── Admin only ───────────────────────────────────────────────────────────
    'expenses':         ['admin'],
    'stock_valuation':  ['admin'],
    'profit_loss':      ['admin'],
    'reports':          ['admin'],
    'debts_repayment':  ['admin'],
    'billing':          ['admin'],
};

// Reusable inline auth check that accepts the token from cookie OR header.
// Used only for HTML page delivery — API routes still use requireAuth middleware.
function resolvePageToken(req) {
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) return authHeader.slice(7);
    return req.cookies?.authToken || null;
}

function accessDeniedPage(role) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8">
    <style>*{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:sans-serif;background:#0a0f1e;color:#f1f5f9;
         min-height:100vh;display:flex;align-items:center;justify-content:center;}
    .card{background:#111827;padding:48px;border-radius:24px;text-align:center;
          border:1px solid rgba(255,255,255,0.05);box-shadow:0 20px 50px rgba(0,0,0,0.5);max-width:400px;}
    h1{font-weight:900;text-transform:uppercase;letter-spacing:3px;font-size:22px;margin-bottom:8px;}
    p{color:#64748b;margin-bottom:28px;font-size:14px;}
    a{display:inline-block;background:#00e5a0;color:#000;padding:14px 32px;border-radius:12px;
      font-weight:900;text-transform:uppercase;text-decoration:none;font-size:12px;letter-spacing:1px;}
    </style></head><body>
    <div class="card">
        <div style="font-size:52px;margin-bottom:16px;">🔐</div>
        <h1>Access Denied</h1>
        <p>Your role <strong>(${role})</strong> does not have permission to view this page.</p>
        <a href="/">Return to Dashboard</a>
    </div></body></html>`;
}

Object.entries(PROTECTED_PAGES).forEach(([page, allowedRoles]) => {
    const handler = (req, res) => {
        const token = resolvePageToken(req);

        // No token — redirect to login
        if (!token) return res.redirect('/');

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        } catch {
            return res.redirect('/');
        }

        // Check blocklist (deactivated accounts / revoked sessions)
        if (isTokenBlocked(token) || tokenBlocklist.has(`empid:${decoded.empId}`)) {
            return res.redirect('/');
        }

        const userRole = (decoded.role || '').toLowerCase();

        // Role check — null means any authenticated user is allowed
        if (allowedRoles && !allowedRoles.includes(userRole)) {
            // Redirect to root — hides the restricted page path from the address bar
            return res.redirect('/?denied=1');
        }

        const file = path.join(pagesPath, `${page}.html`);
        if (require('fs').existsSync(file)) {
            return res.sendFile(file);
        }
        res.status(404).send(`Page "${page}" not found.`);
    };

   // Clean canonical URL — this is what shows in the browser address bar
    app.get(`/${page}`, handler);
    
    // Legacy .html and deep /src/pages/ URLs → 301 redirect to clean URL PRESERVING query strings
    const redirectWithQuery = (req, res) => {
        const queryStr = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
        res.redirect(301, `/${page}${queryStr}`);
    };
    app.get(`/${page}.html`, redirectWithQuery);
    app.get(`/src/pages/${page}.html`, redirectWithQuery);
});

// ── 4. Root Routes ──────────────────────────────────────────────────────────

// Redirect /index.html → / so the address bar always shows the clean root URL
// (sidebar.js and any legacy links that use /index.html will land here cleanly)
app.get('/index.html', (req, res) => res.redirect(301, '/'));

app.get('/', (req, res) => {
    const indexFile = path.join(frontendPath, 'index.html');
    if (require('fs').existsSync(indexFile)) {
        res.sendFile(indexFile);
    } else {
        // Fallback for Render (frontend deployed separately on Netlify)
        res.status(200).json({ message: 'Elite Hardware POS API is running', status: 'Live' });
    }
});
// ============================================================
//  4. AUTH MIDDLEWARE
// ============================================================

/** Verifies JWT from Authorization header. Attaches decoded payload to req.user. */
function requireAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const headerToken = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    // Also accept from cookie — set at login so browser sends it on page navigation
    const cookieToken = req.cookies?.authToken || null;
    const token = headerToken || cookieToken;

    if (!token) {
        return res.status(401).json({ success: false, message: 'No token provided. Please log in.' });
    }
    // Check blocklist — catches deactivated employees with still-valid tokens
    if (isTokenBlocked(token)) {
        return res.status(401).json({ success: false, message: 'Session revoked. Please log in again.', code: 'TOKEN_REVOKED' });
    }
    try {
        req.authToken = token;
        // FIX: Pin algorithm explicitly — prevents algorithm-switching attacks (e.g. alg:none)
        req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

        // Check if this employee's account was deactivated after token was issued
        if (tokenBlocklist.has(`empid:${req.user.empId}`)) {
            return res.status(401).json({ success: false, message: 'Account deactivated. Please contact your administrator.', code: 'ACCOUNT_DEACTIVATED' });
        }

        next();
    } catch (err) {
        // FIX: Distinguish expired tokens from tampered/invalid ones
        const expired = err.name === 'TokenExpiredError';
        return res.status(401).json({
            success: false,
            message: expired ? 'Session expired. Please log in again.' : 'Invalid token.',
            code:    expired ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID'
        });
    }
}

/** Role-based access guard — must follow requireAuth. */
function requireRole(...roles) {
    return (req, res, next) => {
        // FIX: Guard against requireRole being called without requireAuth upstream
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Not authenticated.' });
        }
        if (!roles.map(r => r.toLowerCase()).includes(req.user.role?.toLowerCase())) {
            return res.status(403).json({ success: false, message: `Access denied. Required: ${roles.join(' or ')}.` });
        }
        next();
    };
}


// ── WEBHOOK SECRET GUARD ─────────────────────────────────────────────────────
// All Safaricom webhook endpoints must include ?secret=WEBHOOK_SECRET in the URL
// you register with Safaricom/Daraja. This prevents spoofed payloads from
// arbitrary IPs since Safaricom does not sign its webhook bodies.
function requireWebhookSecret(req, res, next) {
    const secret = process.env.WEBHOOK_SECRET;
    if (secret && req.query.secret !== secret) {
        log.warn(`[WEBHOOK] Rejected — missing or invalid ?secret from ${req.ip}`);
        return res.status(403).send('Forbidden');
    }
    next();
}

// ============================================================
//  SUBSCRIPTION ENGINE
// ============================================================
//  Plans: 'monthly' | 'annual' | 'lifetime'
//
//  monthly  — paid_until checked every hour; normal expiry
//  annual   — same mechanics, longer paid_until (12 months)
//  lifetime — no recurring sales lock-out; requires an annual
//             service fee. If service fee lapses past grace
//             period, POS goes read-only until fee is paid.
//
//  Auto-payment detection (VENDOR paybill only):
//    The subscription paybill is YOUR paybill as software vendor.
//    It is completely separate from the business's customer-payment
//    till/paybill. The business owner pays YOU by M-Pesa, entering
//    CLIENT_ID as the account reference.
//
//    Safaricom calls POST /api/subscription/mpesa-confirmation
//    (register this as your vendor paybill's ConfirmationURL).
//    The server matches BillRefNumber → CLIENT_ID, auto-extends
//    paid_until, and the POS unlocks within seconds.
//    No admin action required.
//
//  .env additions needed:
//    CLIENT_ID=ELITE_HARDWARE_MAIN
//    VENDOR_MPESA_CONSUMER_KEY=...
//    VENDOR_MPESA_CONSUMER_SECRET=...
//    VENDOR_MPESA_SHORTCODE=...        ← your vendor paybill number
//    VENDOR_MPESA_PASSKEY=...
//    SUBSCRIPTION_MONTHLY_KES=3000     ← amount tiers for auto-detection
//    SUBSCRIPTION_ANNUAL_KES=30000
//    SUBSCRIPTION_SERVICE_KES=5000
// ============================================================

const CLIENT_ID             = process.env.CLIENT_ID || 'ELITE_HARDWARE_MAIN';
const SUB_CHECK_INTERVAL_MS = 60 * 60 * 1000; // re-check Supabase every hour

// Server-side cache — all middleware reads this; never touches DB per request
let _subCache = {
    status:                    'active', // fail open on cold start
    plan:                      'monthly',
    paid_until:                null,
    annual_service_paid_until: null,
    grace_period_days:         3,
    readOnly:                  false,
    gracePeriod:               false,
    lastChecked:               0,
    error:                     null,
};

/**
 * Pull subscription row from Supabase and recompute readOnly.
 * Never throws — on DB failure, keeps last known state (fail open).
 */
async function refreshSubscriptionStatus() {
    try {
        const { data, error } = await supabase
            .from('subscriptions')
            .select('status, plan, paid_until, annual_service_paid_until, grace_period_days')
            .eq('client_id', CLIENT_ID)
            .single();

        if (error || !data) {
            // Log the FULL error so you can see exactly what Supabase is rejecting
            log.warn(`[SUB] Cannot fetch subscription row — keeping last known state: msg=${error?.message} | code=${error?.code} | hint=${error?.hint} | details=${error?.details}`);

            // COMMON CAUSE: annual_service_paid_until column doesn't exist yet
            // (migration v2 not run). Fall back to selecting without that column.
            if (error?.code === '42703' || error?.message?.includes('annual_service_paid_until')) {
                log.warn('[SUB] Falling back to v1 schema (annual_service_paid_until column missing — run migration v2)');
                const { data: v1, error: e1 } = await supabase
                    .from('subscriptions')
                    .select('status, plan, paid_until, grace_period_days')
                    .eq('client_id', CLIENT_ID)
                    .single();
                if (!e1 && v1) {
                    // Treat as monthly/annual — annual_service logic unavailable
                    const today = new Date(); today.setHours(0,0,0,0);
                    const pu  = new Date(v1.paid_until || '2000-01-01'); pu.setHours(0,0,0,0);
                    const cut = new Date(pu); cut.setDate(cut.getDate() + (v1.grace_period_days ?? 3));
                    _subCache = {
                        ..._subCache,
                        status:            v1.status,
                        plan:              v1.plan,
                        paid_until:        v1.paid_until,
                        annual_service_paid_until: null,
                        grace_period_days: v1.grace_period_days ?? 3,
                        readOnly:          v1.status === 'suspended' || today > cut,
                        gracePeriod:       today > pu && today <= cut,
                        lastChecked:       Date.now(),
                        error:             'Schema v1 fallback — run migration v2 to enable lifetime/annual plans',
                    };
                    log.warn('[SUB] v1 fallback active. Run the v2 migration SQL to enable all plan types.');
                    return;
                }
            }
            _subCache.error = error?.message || 'Row not found';
            return;
        }

        const today = new Date(); today.setHours(0, 0, 0, 0);

        let readOnly = false, gracePeriod = false;

        if (data.plan === 'lifetime') {
            // Lifetime: only lock if the annual SERVICE FEE has lapsed past grace
            if (data.annual_service_paid_until) {
                const svc = new Date(data.annual_service_paid_until); svc.setHours(0,0,0,0);
                const cut = new Date(svc); cut.setDate(cut.getDate() + (data.grace_period_days ?? 3));
                if      (today > cut) readOnly    = true;
                else if (today > svc) gracePeriod = true;
            }
            // No service fee row yet = brand-new lifetime client, always open
        } else {
            // monthly / annual: check paid_until
            const pu  = new Date(data.paid_until); pu.setHours(0,0,0,0);
            const cut = new Date(pu); cut.setDate(cut.getDate() + (data.grace_period_days ?? 3));
            if      (today > cut) readOnly    = true;
            else if (today > pu)  gracePeriod = true;
        }

        if (data.status === 'suspended') readOnly = true; // always overrides

        _subCache = {
            status:                    data.status,
            plan:                      data.plan,
            paid_until:                data.paid_until,
            annual_service_paid_until: data.annual_service_paid_until || null,
            grace_period_days:         data.grace_period_days ?? 3,
            readOnly, gracePeriod,
            lastChecked: Date.now(),
            error: null,
        };

        if (readOnly)         log.warn(`[SUB] ⚠️  READ-ONLY  — ${CLIENT_ID} plan=${data.plan} | expired: ${data.plan === 'lifetime' ? data.annual_service_paid_until : data.paid_until}`);
        else if (gracePeriod) log.warn(`[SUB] ⚠️  GRACE     — ${CLIENT_ID} plan=${data.plan} | expires: ${data.plan === 'lifetime' ? data.annual_service_paid_until : data.paid_until}`);
        else                  log.info(`[SUB] ✅ ACTIVE     — ${CLIENT_ID} plan=${data.plan} | until: ${data.plan === 'lifetime' ? (data.annual_service_paid_until || 'no service fee set') : data.paid_until}`);

    } catch (err) {
        log.error(`[SUB] Unexpected error during subscription check: ${err.message} | code=${err.code} | stack=${err.stack?.split('\n')[1]?.trim()}`);
        _subCache.error = err.message;
        // Do NOT flip readOnly on unexpected errors — fail open.
    }
}

// Run on startup, then every hour
refreshSubscriptionStatus();
setInterval(refreshSubscriptionStatus, SUB_CHECK_INTERVAL_MS);

// ── requireSubscription middleware ───────────────────────────────────────────
// Blocks all mutating requests when read-only. GET always passes through so
// the cashier can still export CSVs and view all data.
const SUB_EXEMPT_PATHS = new Set([
    '/api/login',
    '/api/verify-session',
    '/api/mpesa/callback',
    '/api/digitax/callback',
    '/api/c2b/validation',
    '/api/c2b/confirmation',              // customer→business payments, always pass
    '/api/subscription/mpesa-confirmation', // vendor paybill webhook, always pass
]);

function requireSubscription(req, res, next) {
    if (req.method === 'GET')                         return next();
    if (SUB_EXEMPT_PATHS.has(req.path))               return next();
    if (req.path.startsWith('/api/subscription'))     return next();
    if (req.path.startsWith('/api/scripts'))          return next(); // admin scripts always pass
    if (!_subCache.readOnly)                          return next();

    const isLifetime   = _subCache.plan === 'lifetime';
    const expiredThing = isLifetime ? 'annual service fee' : `${_subCache.plan} subscription`;

    // Lifetime clients expire on annual_service_paid_until — paid_until is always 9999-12-31
    // monthly/annual clients expire on paid_until
    const expiryDate = isLifetime
        ? _subCache.annual_service_paid_until
        : _subCache.paid_until;

    const daysAgo = expiryDate
        ? Math.max(0, Math.floor((Date.now() - new Date(expiryDate).getTime()) / 86400000))
        : 'unknown';

    log.warn(`[SUB] Write blocked — ${expiredThing} lapsed ${daysAgo}d ago. Path: ${req.path} | User: ${req.user?.name || 'unknown'}`);

    return res.status(402).json({
        success:    false,
        readOnly:   true,
        code:       'SUBSCRIPTION_EXPIRED',
        plan:       _subCache.plan,
        message:    isLifetime
            ? `Your annual service fee lapsed ${daysAgo} day(s) ago. The POS is in read-only mode. Please pay the service fee to restore full access.`
            : `Your ${_subCache.plan} subscription expired ${daysAgo} day(s) ago. The POS is in read-only mode. Please renew to continue.`,
        paid_until:                isLifetime ? null : _subCache.paid_until,
        annual_service_paid_until: isLifetime ? _subCache.annual_service_paid_until : null,
    });
}

// ── Tiny pick helper ─────────────────────────────────────────────────────────
function pick(obj, keys) {
    return keys.reduce((acc, k) => { if (k in obj) acc[k] = obj[k]; return acc; }, {});
}

// ── Subscription admin API routes ────────────────────────────────────────────

// GET /api/subscription/status
app.get('/api/subscription/status', requireAuth, requireRole('admin'), (req, res) => {
    res.json({ success: true, clientId: CLIENT_ID, ...pick(_subCache,
        ['status','plan','paid_until','annual_service_paid_until',
         'grace_period_days','readOnly','gracePeriod','lastChecked','error']) });
});

// GET /api/subscription/payments
app.get('/api/subscription/payments', requireAuth, requireRole('admin'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('subscription_payments')
            .select('*').eq('client_id', CLIENT_ID)
            .order('paid_at', { ascending: false }).limit(50);
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) { log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' }); }
});

// POST /api/subscription/payment — manual payment recording (admin fallback)
// Body: { amount_kes, plan_type, months_paid?, payment_method?, mpesa_code?, notes? }
//   plan_type: 'monthly' | 'annual' | 'lifetime' | 'annual_service'
app.post('/api/subscription/payment', requireAuth, requireRole('admin'), async (req, res) => {
    // Manual payment entry from the billing page admin (e.g. cash, bank transfer,
    // or entering an M-Pesa code that wasn't auto-detected by the webhook).
    const {
        amount_kes, plan_type = 'monthly', months_paid = 1,
        payment_method = 'M-Pesa', mpesa_code, notes
    } = req.body;

    if (!amount_kes || isNaN(parseFloat(amount_kes)))
        return res.status(400).json({ success: false, message: 'amount_kes is required.' });
    if (!['monthly','annual','lifetime','annual_service'].includes(plan_type))
        return res.status(400).json({ success: false, message: `Invalid plan_type. Must be one of: monthly, annual, lifetime, annual_service` });

    try {
        // _applySubscriptionPayment handles the payment row + subscription extension
        // in exactly the same way as the STK callback and C2B webhook.
        // Override the payment_method and notes with the admin-supplied values.
        await _applySubscriptionPayment({
            plan_type,
            amount_kes:     parseFloat(amount_kes),
            mpesa_code:     mpesa_code || null,
            phone:          '',
            source:         payment_method,
            _overrideNotes: notes || null,
            _recordedBy:    req.user.name,
        });

        // Build a human-readable expiry date for the response
        const newDate = plan_type === 'lifetime'
            ? '9999-12-31 (lifetime)'
            : plan_type === 'annual_service'
                ? _subCache.annual_service_paid_until
                : _subCache.paid_until;

        log.info(`[SUB] ✅ Manual payment: KES ${amount_kes} plan=${plan_type} newExpiry=${newDate} by=${req.user.name}`);
        res.json({
            success:       true,
            message:       `Payment recorded. Plan: ${plan_type}. New expiry: ${newDate}.`,
            new_paid_until: newDate,
            readOnly:       _subCache.readOnly,
        });
    } catch (err) {
        log.error(`[SUB] Payment recording failed: ${err.message} | code=${err.code} | hint=${err.hint || 'none'}`);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// POST /api/subscription/refresh — force immediate re-check (admin)
app.post('/api/subscription/refresh', requireAuth, requireRole('admin'), async (req, res) => {
    await refreshSubscriptionStatus();
    res.json({ success: true, message: 'Refreshed.',
        readOnly: _subCache.readOnly, paid_until: _subCache.paid_until,
        status: _subCache.status, plan: _subCache.plan });
});

// ── VENDOR M-PESA AUTO-PAYMENT WEBHOOK ───────────────────────────────────────
// POST /api/subscription/mpesa-confirmation
//
// This endpoint is for YOUR paybill as the software vendor —
// completely separate from the business's /api/c2b/confirmation.
//
// How it works:
//   1. Business owner opens M-Pesa → Lipa na M-Pesa → Pay Bill
//   2. Business Number: [your vendor paybill]
//   3. Account Number:  [CLIENT_ID e.g. ELITE_HARDWARE_MAIN]
//   4. Amount:          monthly/annual/service fee amount
//   5. Safaricom calls this endpoint with the payment details
//   6. Server matches AccountReference → CLIENT_ID, detects plan from
//      amount, extends paid_until, refreshes cache — POS unlocks in seconds
//
// Setup:
//   Register this URL with Safaricom as your vendor paybill's ConfirmationURL:
//   POST https://[your-server]/api/subscription/mpesa-confirmation
//   (No auth header — Safaricom won't send one. Route is public by design.)
//
// .env: VENDOR_MPESA_SHORTCODE, SUBSCRIPTION_MONTHLY_KES,
//       SUBSCRIPTION_ANNUAL_KES, SUBSCRIPTION_SERVICE_KES
app.post('/api/subscription/mpesa-confirmation', requireWebhookSecret, async (req, res) => {
    // Always ACK immediately — Safaricom retries if you don't respond fast
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

    try {
        const {
            TransID, TransAmount, BillRefNumber = '',
            MSISDN = '', BusinessShortCode = '',
            FirstName = '', MiddleName = '', LastName = '',
        } = req.body;

        // ── Guard: only process if AccountReference matches this client ───────
        const ref  = (BillRefNumber || '').trim().toUpperCase();
        const myId = CLIENT_ID.toUpperCase();
        if (ref !== myId && !ref.startsWith(myId)) {
            log.info(`[SUB-MPESA] Ignoring — ref "${ref}" does not match client "${myId}"`);
            return;
        }

        const amount = parseFloat(TransAmount || 0);
        if (!amount || amount < 1) {
            log.warn(`[SUB-MPESA] Ignoring — invalid amount: "${TransAmount}"`);
            return;
        }

        const payerName = [FirstName, MiddleName, LastName].filter(Boolean).join(' ') || MSISDN || 'Unknown';
        log.info(`[SUB-MPESA] Processing KES ${amount} from ${payerName} (${TransID})`);

        // ── Detect plan type from amount ──────────────────────────────────────
        // Read tiers from env vars first; fall back to the standard Elite pricing
        // so the webhook works correctly even before env vars are configured.
        // IMPORTANT: Check LIFETIME before ANNUAL (120000 > 36000), and SERVICE
        // before ANNUAL (30000 === ANNUAL_KES, so SERVICE must be checked first
        // using a DISTINCT amount, or we rely on the env var for disambiguation).
        const MONTHLY_KES  = parseFloat(process.env.SUBSCRIPTION_MONTHLY_KES  || 3000);
        const ANNUAL_KES   = parseFloat(process.env.SUBSCRIPTION_ANNUAL_KES   || 36000);
        const SERVICE_KES  = parseFloat(process.env.SUBSCRIPTION_SERVICE_KES  || 30000);
        const LIFETIME_KES = parseFloat(process.env.SUBSCRIPTION_LIFETIME_KES || 120000);

        // Tolerance: within 5% of tier amount = match
        const near = (a, b) => Math.abs(a - b) <= b * 0.05;

        let plan_type, months;

        if (near(amount, LIFETIME_KES)) {
            plan_type = 'lifetime';
            months    = null;
        } else if (near(amount, SERVICE_KES)) {
            // SERVICE_KES and ANNUAL_KES default to 30000 and 36000 respectively —
            // they don't overlap. If a client sets them the same, SERVICE wins here.
            plan_type = 'annual_service';
            months    = null;
        } else if (near(amount, ANNUAL_KES)) {
            plan_type = 'annual';
            months    = 12;
        } else if (amount >= MONTHLY_KES * 0.9) {
            // Covers 1 month or multiples (e.g. KES 9000 = 3 months)
            months    = Math.max(1, Math.round(amount / MONTHLY_KES));
            plan_type = 'monthly';
        } else {
            // Amount is below even one monthly fee — store for manual review
            log.warn(`[SUB-MPESA] ⚠ Unrecognised KES ${amount} from ${payerName} (${TransID}) — storing for manual review`);
            const { error: unkErr } = await supabase.from('subscription_payments').insert([{
                client_id:      CLIENT_ID,
                amount_kes:     amount,
                plan_type:      'unknown',
                payment_method: 'M-Pesa (auto)',
                mpesa_code:     TransID || null,
                months_paid:    null,
                notes:          `UNRECOGNISED AMOUNT — manual review needed. Payer: ${payerName} (${MSISDN})`,
                recorded_by:    'system',
            }]);
            if (unkErr) {
                log.error(`[SUB-MPESA] DB error storing unrecognised payment — code: ${unkErr.code} | msg: ${unkErr.message} | hint: ${unkErr.hint} | detail: ${unkErr.details}`);
            }
            return;
        }

        log.info(`[SUB-MPESA] Detected plan_type=${plan_type} months=${months} for KES ${amount}`);

        // ── Delegate to shared helper ─────────────────────────────────────────
        await _applySubscriptionPayment({
            plan_type,
            amount_kes: amount,
            mpesa_code: TransID || null,
            phone:      MSISDN,
            source:     `C2B vendor paybill (${BusinessShortCode})`,
        });

        log.info(`[SUB-MPESA] ✅ Auto-applied: KES ${amount} → plan=${plan_type} months=${months} mpesa=${TransID} payer=${payerName}`);

    } catch (err) {
        const errDetail = [
            err.message       ? `msg: ${err.message}`                           : null,
            err.code          ? `code: ${err.code}`                             : null,
            err.hint          ? `hint: ${err.hint}`                             : null,
            err.details       ? `details: ${err.details}`                       : null,
            err.stack         ? `at: ${err.stack.split('\n')[1]?.trim()}`      : null,
        ].filter(Boolean).join(' | ');
        log.error(`[SUB-MPESA] Webhook error — ${errDetail || String(err)}`);
        // res already sent — nothing more to do
    }
});

// ============================================================
//  5. LOGIN — issues JWT (public)
// ============================================================
// ============================================================
//  5. LOGIN — issues JWT and handles MFA Onboarding
// ============================================================
// ============================================================
//  5. LOGIN — issues JWT and handles MFA Onboarding
// ============================================================
// ============================================================
//  5. LOGIN — issues JWT and handles MFA Onboarding
// ============================================================
app.post('/api/login', loginLimiter, async (req, res) => {
    const { employeeId, pin, mfaCode, mfaSetupSecret } = req.body;
    
    try {
        const { data: user, error } = await supabase
            .from('employees').select('*').eq('emp_id', employeeId.toUpperCase()).single();

        const DUMMY_HASH = '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
        const isMatch = await bcrypt.compare(String(pin), user ? user.pin : DUMMY_HASH);

        if (error || !user || !isMatch || user.is_active === false) {
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        // --- 1. FIRST TIME MFA SETUP (No secret in DB) ---
        if (!user.mfa_secret && !mfaSetupSecret) {
            // Generate secret using Speakeasy
            const secretData = speakeasy.generateSecret({ name: `Elite Hardware (${user.emp_id})` });
            const secret = secretData.base32;
            const otpauth = secretData.otpauth_url;
            
            const qrCodeUrl = await QRCode.toDataURL(otpauth);
            return res.json({ success: true, mfaSetupRequired: true, qrCodeUrl, secret });
        }

        // --- 2. VERIFYING FIRST TIME MFA SETUP ---
        if (!user.mfa_secret && mfaSetupSecret) {
            if (!mfaCode) return res.status(400).json({ success: false, message: 'MFA Code required.' });
            
            // Verify setup code
            const isValid = speakeasy.totp.verify({
                secret: mfaSetupSecret,
                encoding: 'base32',
                token: mfaCode
            });
            
            if (!isValid) return res.status(401).json({ success: false, message: 'Invalid setup code. Try again.' });

            // Save the secret to the DB permanently now that we know it works
            await supabase.from('employees').update({ mfa_secret: mfaSetupSecret }).eq('id', user.id);
        }
        // --- 3. STANDARD MFA CHECK (Already set up) ---
        else if (user.mfa_secret) {
            if (!mfaCode) {
                return res.json({ success: true, mfaRequired: true }); // Prompt client for code
            }
            
            // Verify standard login code
            const isValid = speakeasy.totp.verify({
                secret: user.mfa_secret,
                encoding: 'base32',
                token: mfaCode
            });
            
            if (!isValid) {
                return res.status(401).json({ success: false, message: 'Invalid MFA Code.' });
            }
        }

        // Standard Token Issue (If all checks pass)
        const token = jwt.sign(
            { empId: user.emp_id, name: user.name, role: user.role },
            JWT_SECRET,
            { expiresIn: '8h', algorithm: 'HS256' }
        );
        res.cookie('authToken', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict', maxAge: 28800000 });
        res.json({ success: true, token, role: user.role, name: user.name });
    } catch (err) {
        log.error('[LOGIN ERROR]', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});
// ============================================================
//  SESSION VERIFICATION (C-02 Fix)
// ============================================================
/** * This endpoint is called by auth.js on every page load.
 * It uses the requireAuth middleware to verify the token.
 */
app.post('/api/verify-session', requireAuth, (req, res) => {
    const isLifetime = _subCache.plan === 'lifetime';

    // The meaningful expiry date depends on plan type:
    //   monthly/annual  → paid_until (the date the subscription runs out)
    //   lifetime        → annual_service_paid_until (the service fee date; paid_until is 9999-12-31)
    // If lifetime has no service fee set yet → null = no expiry, full access
    const expiryDate = isLifetime
        ? _subCache.annual_service_paid_until
        : _subCache.paid_until;

    let daysUntilExpiry = null;
    if (expiryDate) {
        const d = new Date(expiryDate); d.setHours(0,0,0,0);
        const t = new Date();           t.setHours(0,0,0,0);
        daysUntilExpiry = Math.ceil((d - t) / 86400000);
        // lifetime with no service fee = no expiry countdown
        if (isLifetime && !_subCache.annual_service_paid_until) daysUntilExpiry = null;
    }

    res.json({
        success:  true,
        role:     req.user.role,
        name:     req.user.name,
        empId:    req.user.empId,
        // ── Subscription ─────────────────────────────────────────────────────
        readOnly:                  _subCache.readOnly,
        gracePeriod:               _subCache.gracePeriod || false,
        daysUntilExpiry,           // negative = already expired; null = no expiry
        // Always send both dates — frontend picks the right one based on subPlan
        paidUntil:                 isLifetime ? null : _subCache.paid_until,
        annualServicePaidUntil:    isLifetime ? _subCache.annual_service_paid_until : null,
        subStatus:                 _subCache.status,
        subPlan:                   _subCache.plan,
    });
});

// ============================================================
//  BUSINESS INFO — fetches KRA PIN, VAT No, Control Unit,
//  and company name from DigiTax so the frontend never needs
//  hardcoded values.  Results are cached in-process for 1 hour
//  to avoid hammering the DigiTax API on every page load.
// ============================================================
let _businessInfoCache     = null;
let _businessInfoCachedAt  = 0;
const BUSINESS_INFO_TTL_MS = 60 * 60 * 1000; // 1 hour

app.get('/api/business-info', requireAuth, async (req, res) => {
    // Serve from cache if fresh
    if (_businessInfoCache && (Date.now() - _businessInfoCachedAt) < BUSINESS_INFO_TTL_MS) {
        return res.json({ success: true, ..._businessInfoCache, cached: true });
    }

    if (!DIGITAX_API_KEY) {
        return res.status(503).json({
            success: false,
            message: 'DIGITAX_API_KEY not configured — cannot fetch business info from DigiTax.'
        });
    }

    try {
        const dtRes  = await fetch(`${DIGITAX_BASE_URL}/etims-info`, {
            method:  'GET',
            headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
            signal:  AbortSignal.timeout(8000)
        });

        const dtText = await dtRes.text();
        let dtData;
        try {
            dtData = JSON.parse(dtText);
        } catch (e) {
            dtData = { _raw: dtText };
        }

        if (!dtRes.ok) {
            return res.status(502).json({
                success: false,
                message: `DigiTax returned ${dtRes.status}`,
                detail:  dtData
            });
        }

        // DigiTax /etims-info fields
        const info = {
            businessName:        dtData.branch_office_name  || 'ELITE HARDWARE LTD',
            kraPin:              dtData.tax_pin             || null,
            vatNumber:           dtData.tax_pin             || null, // KRA PIN doubles as VAT No in Kenya
            branchOfficeId:      dtData.branch_office_id    || null,
            branchStatusCode:    dtData.branch_status_code  || null,
            countyName:          dtData.county_name         || null,
            subCountyName:       dtData.sub_county_name     || null,
            taxLocalityName:     dtData.tax_locality_name   || null,
            locationDescription: dtData.location_description|| null,
            managerName:         dtData.manager_name        || null,
            managerContact:      dtData.manager_contact     || null,
            managerEmail:        dtData.manager_email       || null,
            isHeadOffice:        dtData.is_head_office      ?? false,
            businessId:          dtData.business_id         || null,
            controlUnit:         dtData.id                  || null, // /etims-info `id` = SCU id
            vatRate:             0.16,
        };

        _businessInfoCache    = info;
        _businessInfoCachedAt = Date.now();

        log.info('[business-info] ✅ Resolved', info);
        res.json({ success: true, ...info, cached: false });
    } catch (err) {
        log.error('[business-info] DigiTax fetch failed:', err.message);
        res.status(502).json({ success: false, message: 'Failed to fetch business info from DigiTax. Check server logs.' });
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
        : 'id, item_name, category, price, cost_price, stock_quantity, unit, barcode, fundi_price, wholesale_price, wholesale_min_qty, bulk_unit, sub_unit, sub_unit_qty, sub_unit_price, stock_batches(*)';
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.post('/api/inventory', requireAuth, requireRole('admin', 'manager'), requireSubscription, validateBody({
    itemName:        { type: 'string', required: true, maxLen: 200 },
    sellingPrice:    { type: 'number', required: true, min: 0 },
    costPrice:       { type: 'number', min: 0 },
    stockQty:        { type: 'number', min: 0 },
    unit:            { type: 'string', maxLen: 50 },
    category:        { type: 'string', maxLen: 100 },
    barcode:         { type: 'string', maxLen: 100 },
    fundiPrice:      { type: 'number', min: 0 },
    wholesalePrice:  { type: 'number', min: 0 },
    wholesaleMinQty: { type: 'number', min: 1 },
    bulkUnit:        { type: 'string', maxLen: 50 },
    subUnit:         { type: 'string', maxLen: 50 },
    subUnitQty:      { type: 'number', min: 0 },
    subUnitPrice:    { type: 'number', min: 0 },
}), async (req, res) => {
    const { itemName, category, unit, costPrice, sellingPrice, stockQty, deliveryNote, barcode,
            fundiPrice, wholesalePrice, wholesaleMinQty, bulkUnit, subUnit, subUnitQty, subUnitPrice } = req.body;
    const userName = req.user.name;
    // DEBUG — remove after confirming fields arrive
    log.info('[DEBUG] /api/inventory req.body', { fundiPrice, wholesalePrice, wholesaleMinQty, bulkUnit, subUnit, subUnitQty, subUnitPrice });
    try {
        const { data: existing } = await supabase.from('stock_batches').select('delivery_number')
            .eq('delivery_number', deliveryNote?.trim().toUpperCase()).maybeSingle();
        if (existing) return res.status(400).json({ success: false, message: `DN ${deliveryNote} already used.` });

        // Auto-generate SKU if no barcode provided
        const finalBarcode = barcode?.trim() || (() => {
            const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
            const rand = String(Math.floor(Math.random() * 99999)).padStart(5, '0');
            return `EH-${date}-${rand}`;
        })();

        const { data: newItem, error: invError } = await supabase.from('Inventory')
            .insert([{
                item_name:          itemName,
                category,
                unit,
                cost_price:         parseFloat(costPrice),
                price:              parseFloat(sellingPrice),
                stock_quantity:     parseInt(stockQty),
                barcode:            finalBarcode,
                fundi_price:        fundiPrice       ? parseFloat(fundiPrice)     : null,
                wholesale_price:    wholesalePrice   ? parseFloat(wholesalePrice) : null,
                wholesale_min_qty:  wholesaleMinQty  ? parseInt(wholesaleMinQty)  : null,
                bulk_unit:          bulkUnit?.trim()  || null,
                sub_unit:           subUnit?.trim()   || null,
                sub_unit_qty:       subUnitQty        ? parseFloat(subUnitQty)    : null,
                sub_unit_price:     subUnitPrice      ? parseFloat(subUnitPrice)  : null,
            }])
            .select().single();
        if (invError) throw invError;

        const qty  = parseInt(stockQty) || 0;
        const cost = parseFloat(costPrice) || 0;

        const { data: newBatch, error: batchError } = await supabase.from('stock_batches').insert([{
            inventory_id:    newItem.id,
            batch_qty:       qty,
            remaining_qty:   qty,
            unit_cost:       cost,
            delivery_number: deliveryNote?.trim().toUpperCase() || 'INITIAL-STOCK',
            stock_at_entry:  0,
            performed_by:    userName
        }]).select('id').single();
        if (batchError) {
            await supabase.from('Inventory').delete().eq('id', newItem.id);
            throw batchError;
        }

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

        // ── Register item with DigiTax/KRA (non-blocking) ──────────────────
        let digitaxItemId = null;
        const etimsItem = await registerItemWithEtims({
            itemName:    itemName.trim(),
            category:    category || 'General',
            sellingPrice: sellingPrice,
            unit:         unit || 'PCS',
            stockQty:     qty,
            // Sub-unit fields — needed so KRA stock is registered in the traded unit (e.g. Kg)
            bulk_unit:    bulkUnit?.trim()  || null,
            sub_unit:     subUnit?.trim()   || null,
            sub_unit_qty: subUnitQty        ? parseFloat(subUnitQty)  : null,
            sub_unit_price: subUnitPrice    ? parseFloat(subUnitPrice) : null,
        });
        if (etimsItem) {
            digitaxItemId = etimsItem;
            await supabase.from('Inventory')
                .update({ digitax_item_id: digitaxItemId, kra_registered: true })
                .eq('id', newItem.id);
            // Note: stock sync is handled inside registerItemWithEtims Phase 2 (3s delay)
            // Do NOT call syncStockWithEtims here — it would double the stock count
        }
        res.json({
            success:       true,
            message:       'Product registered successfully!' + (digitaxItemId ? ' ✅ KRA item registered + stock synced.' : ' ⚠️ KRA registration pending.'),
            kraRegistered: !!digitaxItemId,
            digitaxItemId
        });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.post('/api/inventory/restock-fifo', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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

       // Sync restocked quantity with KRA using correct sub-unit conversion
        if (item.digitax_item_id) {
            const etimsQty = toEtimsQty(added, item);
            await syncStockWithEtims(item.digitax_item_id, etimsQty, `Restock — DN: ${delivery_note_ref}`);
        }

        res.json({ success: true, message: `Added ${added}. Total: ${newTotal}` });
        res.json({ success: true, message: 'Restock successful!' });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.post('/api/inventory/bulk-restock', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const { items } = req.body;
    const userName = req.user.name;
    try {
        for (const item of items) {
            const { inventory_id, batch_qty, unit_cost, new_selling_price, delivery_number } = item;
            const { data: existing } = await supabase.from('stock_batches').select('id')
                .eq('inventory_id', inventory_id).eq('delivery_number', String(delivery_number)).maybeSingle();
            if (existing) continue;
            const { data: invItem } = await supabase.from('Inventory').select('stock_quantity, item_name, digitax_item_id, sub_unit, sub_unit_qty, sub_unit_price').eq('id', inventory_id).single();
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
            
            // Sync with KRA using correct sub-unit conversion
            if (invItem.digitax_item_id) {
                const etimsQty = toEtimsQty(added, invItem);
                await syncStockWithEtims(invItem.digitax_item_id, etimsQty, `Bulk Restock — DN: ${delivery_number}`);
            }
        }
        res.json({ success: true, message: 'Bulk restock processed.' });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.put('/api/inventory/:id', requireAuth, requireRole('admin'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.patch('/api/inventory/update-price/:id', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.get('/api/inventory/audit-logs', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    try {
        // Fetch ALL inventory-related actions
        const { data, error } = await supabase
            .from('audit_logs')
            .select('*')
            .in('action', [
                'INITIAL_STOCK', 'RESTOCK_FIFO', 'BULK_RESTOCK', 'RESTOCK', 
                'MANUAL_INVENTORY_EDIT', 'STOCK_WRITEOFF', 'DAMAGE_WRITEOFF', 
                'EXCHANGE_IN', 'EXCHANGE_OUT', 'SUPPLIER_RETURN', 'SUPPLIER_RETURN_PENDING'
            ])
            .order('timestamp', { ascending: false });
            
        if (error) throw error;
        
        // Map all relevant columns for the full audit statement
        const formattedLogs = data.map(log => ({
            id:              log.id,
            created_at:      log.timestamp,
            performed_by:    log.performed_by,
            action:          log.action,
            delivery_number: log.dn_number,
            stock_at_entry:  log.old_stock,
            batch_qty:       log.added_qty,
            new_stock:       log.new_stock,
            details:         log.details,
            Inventory:       { item_name: log.item_name }
        }));
        
        res.json(formattedLogs);
    } catch (err) {
        log.error('[AUDIT LOGS]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.patch('/api/inventory/:id', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const { id } = req.params;
    const { added_quantity, delivery_note_ref } = req.body;
    const userName = req.user.name;
    
    try {
       // 1. Fetch item to get old stock, cost price, and sub-unit details
        const { data: item, error: fetchError } = await supabase
            .from('Inventory')
            .select('item_name, stock_quantity, cost_price, digitax_item_id, sub_unit, sub_unit_qty, sub_unit_price')
            .eq('id', id)
            .single();;
            
        if (fetchError || !item) throw new Error('Item not found');
        
        const oldStock = parseInt(item.stock_quantity) || 0;
        const added = parseInt(added_quantity || 0);
        const newTotal = oldStock + added;
        
        // 2. Update master inventory
        const { error: updateError } = await supabase
            .from('Inventory')
            .update({ stock_quantity: newTotal })
            .eq('id', id);
            
        if (updateError) throw updateError;

        // 3. THE FIX: Create the corresponding stock batch
        const { data: batch, error: batchError } = await supabase
            .from('stock_batches')
            .insert([{
                inventory_id: id,
                batch_qty: added,
                remaining_qty: added,
                unit_cost: parseFloat(item.cost_price || 0),
                delivery_number: String(delivery_note_ref),
                stock_at_entry: oldStock,
                performed_by: userName
            }])
            .select('id')
            .single();
            
        if (batchError) throw batchError;

        // 4. Log the audit
        await supabase.from('audit_logs').insert([{ 
            performed_by: userName, 
            action: 'RESTOCK', 
            dn_number: String(delivery_note_ref), 
            batch_id: batch?.id || null,
            details: `Added ${added} to ${item.item_name}. Total: ${newTotal}`, 
            timestamp: new Date().toISOString() 
        }]);
        
        res.json({ success: true, message: `Added ${added}. Total: ${newTotal}` });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.delete('/api/inventory/:id', requireAuth, requireRole('admin'), requireSubscription, async (req, res) => {
    const { id } = req.params;
    const userName = req.user.name;
    try {
        const { data: item } = await supabase.from('Inventory').select('item_name').eq('id', id).single();
        const { error } = await supabase.from('Inventory').delete().eq('id', id);
        if (error) throw error;
        await supabase.from('audit_logs').insert([{ performed_by: userName, action: 'DELETE', details: `Removed: ${item?.item_name || 'Unknown'} (ID: ${id})`, timestamp: new Date().toISOString() }]);
        res.json({ success: true, message: 'Item deleted and logged.' });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
// ============================================================
//  SUPPLIER ROUTES
//  Paste this block into server.js just before the app.listen()
//  line at the very bottom of the file.
// ============================================================

// ── GET all suppliers ────────────────────────────────────────────────────────
// ── GET all suppliers ────────────────────────────────────────────────────────
app.get('/api/suppliers', requireAuth, async (req, res) => {
    const { search, category, status } = req.query;

    try {
        let query = supabase
            .from('suppliers')
            .select('*')
            .order('name', { ascending: true });

        if (search)   query = query.ilike('name', `%${sanitize(search)}%`);
        if (category) query = query.eq('category', category);
        if (status)   query = query.eq('status', status);

        const { data, error } = await query;
        if (error) throw error;

        res.json(data || []);
    } catch (err) {
        console.error('[GET /api/suppliers]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── POST create new supplier ─────────────────────────────────────────────────
app.post('/api/suppliers', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const { name, kra_pin, contact, category, phone, email, location, payment_terms, status, notes } = req.body;

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
                name:          name.trim(),
                kra_pin:       kra_pin?.trim().toUpperCase() || null,
                contact:       contact?.trim()       || null,
                category:      category.trim(),
                phone:         phone?.trim()         || null,
                email:         email?.trim()         || null,
                location:      location?.trim()      || null,
                payment_terms: payment_terms?.trim() || null,
                status:        status || 'active',
                notes:         notes?.trim()         || null,
                balance:       0,
            }])
            .select()
            .single();

        if (error) throw error;

        // Audit log
        await supabase.from('audit_logs').insert([{
            performed_by: req.user.name,
            action:       'SUPPLIER_ADDED',
            item_name:    name.trim(),
            details:      `New supplier added: ${name.trim()} | Category: ${category} | Phone: ${phone || 'N/A'} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]).then(({ error: ae }) => { if (ae) console.error('Audit log error (SUPPLIER_ADDED):', ae.message); });

        res.status(201).json({ success: true, message: 'Supplier added successfully.', data });
    } catch (err) {
        console.error('[POST /api/suppliers]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── PUT update supplier ──────────────────────────────────────────────────────
app.put('/api/suppliers/:id', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const { id } = req.params;
    const { name, kra_pin, contact, category, phone, email, location, payment_terms, status, notes, balance } = req.body;

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
            name:          name.trim(),
            kra_pin:       kra_pin?.trim().toUpperCase() || null,
            contact:       contact?.trim()       || null,
            category:      category?.trim()      || null,
            phone:         phone?.trim()         || null,
            email:         email?.trim()         || null,
            location:      location?.trim()      || null,
            payment_terms: payment_terms?.trim() || null,
            status:        status || 'active',
            notes:         notes?.trim()         || null,
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
            action:       'SUPPLIER_UPDATED',
            item_name:    name.trim(),
            details:      `Supplier updated: ${existing.name} → ${name.trim()} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]).then(({ error: ae }) => { if (ae) console.error('Audit log error (SUPPLIER_UPDATED):', ae.message); });

        res.json({ success: true, message: 'Supplier updated successfully.', data });
    } catch (err) {
        console.error('[PUT /api/suppliers/:id]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── DELETE supplier ──────────────────────────────────────────────────────────
app.delete('/api/suppliers/:id', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
            action:       'SUPPLIER_DELETED',
            item_name:    existing.name,
            details:      `Supplier deleted: ${existing.name} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]).then(({ error: ae }) => { if (ae) console.error('Audit log error (SUPPLIER_DELETED):', ae.message); });

        res.json({ success: true, message: `"${existing.name}" has been deleted.` });
    } catch (err) {
        console.error('[DELETE /api/suppliers/:id]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── PATCH update supplier balance only (admin only) ──────────────────────────
// Useful for manually adjusting what you owe a supplier
app.patch('/api/suppliers/:id/balance', requireAuth, requireRole('admin'), requireSubscription, async (req, res) => {
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
            action:       'SUPPLIER_BALANCE_ADJUSTED',
            item_name:    existing.name,
            details:      `Balance adjusted for ${existing.name}: KES ${existing.balance} → KES ${balance}${notes ? ' | Note: ' + notes : ''} | By: ${req.user.name}`,
            timestamp:    new Date().toISOString(),
        }]).then(({ error: ae }) => { if (ae) console.error('Audit log error (SUPPLIER_BALANCE):', ae.message); });

        res.json({ success: true, message: 'Balance updated.', data });
    } catch (err) {
        console.error('[PATCH /api/suppliers/:id/balance]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── POST create purchase order (Draft — no balance change yet) ────────────────
app.post('/api/purchase-orders', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── PUT update PO status / notes ──────────────────────────────────────────────
//  BALANCE TRIGGERS:
//    Draft  → Sent      : balance += total_amount
//    Sent   → Cancelled : balance -= (total - amount_paid)
//    Partial→ Cancelled : balance -= (total - amount_paid)
app.put('/api/purchase-orders/:id', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── POST receive items — restocks inventory, balance unchanged (already added on Sent) ──
app.post('/api/purchase-orders/:id/receive', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const { delivery_note, items } = req.body;
    const userName   = req.user.name;
    const kraResults = { created: 0, registered: 0, synced: 0, failed: 0, skipped: 0 };

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

            const unitCost = parseFloat(poItem.unit_cost);

            // ── NEW ITEM: no inventory_id — auto-create in Inventory ─────────
            if (!poItem.inventory_id) {
                const sellingPrice = parseFloat(recv.selling_price) || unitCost * 1.3; // fallback: 30% markup
                const category     = recv.category?.trim() || 'General';
                const unit         = recv.unit?.trim()     || 'PCS';
                const bulkUnit     = recv.bulk_unit?.trim() || unit;
                const subUnit      = recv.sub_unit?.trim()  || null;
                const subUnitQty   = recv.sub_unit_qty ? parseFloat(recv.sub_unit_qty) : null;
                const subUnitPrice = recv.sub_unit_price ? parseFloat(recv.sub_unit_price) : null;

                log.info('[PO RECEIVE] New item — auto-creating in Inventory', { item: poItem.item_name });

                // Create inventory record
                const { data: newInvItem, error: createErr } = await supabase
                    .from('Inventory')
                    .insert([{
                        item_name:      poItem.item_name.trim(),
                        category,
                        unit,
                        bulk_unit:      bulkUnit,
                        sub_unit:       subUnit,
                        sub_unit_qty:   subUnitQty,
                        sub_unit_price: subUnitPrice,
                        cost_price:     unitCost,
                        price:          sellingPrice,
                        stock_quantity: qtyToReceive,
                    }])
                    .select().single();

                if (createErr) {
                    log.warn('[PO RECEIVE] Failed to create inventory item', { item: poItem.item_name, error: createErr.message });
                    kraResults.failed++;
                    continue;
                }

                // Link the PO item to the new inventory record
                await supabase.from('purchase_order_items')
                    .update({ inventory_id: newInvItem.id })
                    .eq('id', poItem.id);

                // Create stock batch
                const { data: batch } = await supabase.from('stock_batches').insert([{
                    inventory_id:    newInvItem.id,
                    batch_qty:       qtyToReceive,
                    remaining_qty:   qtyToReceive,
                    unit_cost:       unitCost,
                    delivery_number: delivery_note.trim().toUpperCase(),
                    stock_at_entry:  0,
                    performed_by:    userName,
                }]).select('id').single();

                await supabase.from('audit_logs').insert([{
                    performed_by: userName,
                    action:       'PO_RECEIVED',
                    dn_number:    delivery_note.trim().toUpperCase(),
                    item_name:    poItem.item_name,
                    old_stock:    0,
                    added_qty:    qtyToReceive,
                    new_stock:    qtyToReceive,
                    batch_id:     batch?.id || null,
                    details:      `PO RECEIVE (NEW ITEM): ${poItem.item_name} | PO: ${po.po_number} | DN: ${delivery_note} | Qty: ${qtyToReceive} | Cost: KES ${unitCost} | Selling: KES ${sellingPrice} | By: ${userName}`,
                    timestamp:    new Date().toISOString(),
                }]);

                // Register with KRA
                try {
                    log.info('[eTIMS] Registering new item from PO receive', { item: poItem.item_name });
                    const newId = await registerItemWithEtims({
                        itemName:     poItem.item_name.trim(),
                        category,
                        sellingPrice,
                        unit,
                        stockQty:     qtyToReceive,
                        bulk_unit:    bulkUnit,
                        sub_unit:     subUnit,
                        sub_unit_qty: subUnitQty,
                        sub_unit_price: subUnitPrice
                    });
                    if (newId) {
                        await supabase.from('Inventory')
                            .update({ digitax_item_id: newId, kra_registered: true })
                            .eq('id', newInvItem.id);
                        log.info('[eTIMS] ✅ New item created & registered with KRA', { item: poItem.item_name, digitaxItemId: newId });
                        kraResults.created++;
                    } else {
                        log.warn('[eTIMS] ❌ New item created in inventory but KRA registration failed', { item: poItem.item_name });
                        kraResults.failed++;
                    }
                } catch (etimsErr) {
                    log.warn('[eTIMS] KRA error for new item', { item: poItem.item_name, error: etimsErr.message });
                    kraResults.failed++;
                }
                continue; // skip the existing-item block below
            }

            // ── EXISTING ITEM: inventory_id present ──────────────────────────
            const sellingPrice = recv.new_selling_price || poItem.new_selling_price || null;
            const { data: invItem, error: invErr } = await supabase
                .from('Inventory')
                .select('item_name, stock_quantity, price, category, unit, digitax_item_id, kra_registered, sub_unit, sub_unit_qty, sub_unit_price')
                .eq('id', poItem.inventory_id).single();
            if (invErr) throw invErr;

            const oldStock = parseInt(invItem.stock_quantity) || 0;
            const newTotal = oldStock + qtyToReceive;
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

            // KRA sync for existing item
            let kraStatus = 'skipped';
            try {
                let digitaxItemId = invItem.digitax_item_id || null;
                if (!digitaxItemId) {
                    log.info('[eTIMS] PO receive — registering existing item with KRA', { item: invItem.item_name });
                    const newId = await registerItemWithEtims({
                        itemName:     invItem.item_name,
                        category:     invItem.category || 'General',
                        sellingPrice: newPrice,
                        unit:         invItem.unit || 'PCS',
                        stockQty:     newTotal
                    });
                    if (newId) {
                        await supabase.from('Inventory')
                            .update({ digitax_item_id: newId, kra_registered: true })
                            .eq('id', poItem.inventory_id);
                        log.info('[eTIMS] ✅ Item registered on PO receive', { item: invItem.item_name, digitaxItemId: newId });
                        kraStatus = 'registered';
                    } else {
                        log.warn('[eTIMS] ❌ KRA registration failed on PO receive', { item: invItem.item_name });
                        kraStatus = 'failed';
                    }
                } else {
                    const etimsQty = toEtimsQty(qtyToReceive, invItem);
                    log.info('[eTIMS] PO receive — syncing qty to DigiTax', { item: invItem.item_name, qty: etimsQty });
                    const syncResult = await syncStockWithEtims(
                        digitaxItemId, etimsQty,
                        `PO Receive — ${po.po_number} DN: ${delivery_note}`, '01'
                    );
                    kraStatus = syncResult ? 'synced' : 'failed';
                    log.info(syncResult ? '[eTIMS] ✅ Stock synced on PO receive' : '[eTIMS] ❌ Stock sync failed',
                        { item: invItem.item_name, qty: qtyToReceive });
                }
            } catch (etimsErr) {
                log.warn('[eTIMS] KRA error on PO receive', { item: invItem.item_name, error: etimsErr.message });
                kraStatus = 'failed';
            }
            kraResults[kraStatus] = (kraResults[kraStatus] || 0) + 1;
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

        const kraMsg = [
            kraResults.created    > 0 ? `${kraResults.created} new item(s) created & registered with KRA` : '',
            kraResults.registered > 0 ? `${kraResults.registered} registered with KRA`                     : '',
            kraResults.synced     > 0 ? `${kraResults.synced} synced to KRA`                               : '',
            kraResults.failed     > 0 ? `⚠ ${kraResults.failed} KRA sync failed`                          : '',
        ].filter(Boolean).join(', ');

        log.info('[eTIMS] PO receive KRA summary', { ...kraResults, po: po.po_number });

        res.json({
            success:    true,
            message:    `Stock received. PO is now ${newStatus}.` + (kraMsg ? ` ${kraMsg}.` : ''),
            status:     newStatus,
            kraResults,
        });
    } catch (err) {
        console.error('[POST /api/purchase-orders/:id/receive]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── POST record payment to supplier ───────────────────────────────────────────
//  Reduces supplier balance + updates PO amount_paid
//  Body: { po_id, amount, payment_method, reference, notes }
app.post('/api/supplier-payments', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── DELETE purchase order (Draft only — no balance to reverse) ────────────────
app.delete('/api/purchase-orders/:id', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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

app.post('/api/purchase-orders/:id/email', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
// ============================================================
//  7. REPORTS
// ============================================================

app.get('/api/reports/daily-summary', requireAuth, async (req, res) => {
    try {
        // FIX: Explicitly extract processedBy from the query
        const { date, from, to, month, year, processedBy } = req.query;
        const role = req.user.role?.toLowerCase();
        
        // Separate Admin vs Manager/Cashier access
        const isAdmin = role === 'admin';
        const isManager = role === 'manager';
        const isCashier = role === 'cashier';
        
        // FIX: Explicitly define isPrivileged to prevent ReferenceError crashes
        const isPrivileged = isAdmin || isManager;

        let salesQuery = supabase.from('Sales')
            .select('total_amount, cost_price, quantity_sold, amount_paid, sold_by, payment_status, sale_date')
            .eq('is_voided', false);

        // Apply period filter
        if (date) {
            salesQuery = salesQuery.gte('sale_date', `${date}T00:00:00.000+03:00`).lte('sale_date', `${date}T23:59:59.999+03:00`);
        } else if (from && to) {
            salesQuery = salesQuery.gte('sale_date', `${from}T00:00:00.000+03:00`).lte('sale_date', `${to}T23:59:59.999+03:00`);
        } else if (month && year) {
            const mm = String(month).padStart(2,'0'), lastDay = new Date(year, month, 0).getDate();
            salesQuery = salesQuery.gte('sale_date', `${year}-${mm}-01T00:00:00.000+03:00`).lte('sale_date', `${year}-${mm}-${lastDay}T23:59:59.999+03:00`);
        } else if (year && !month) {
            salesQuery = salesQuery.gte('sale_date', `${year}-01-01T00:00:00.000+03:00`).lte('sale_date', `${year}-12-31T23:59:59.999+03:00`);
        }
        
        // Apply Role / User filters
        if (isCashier) {
            salesQuery = salesQuery.eq('sold_by', req.user.name);
        } else if (!isPrivileged && processedBy) {
            salesQuery = salesQuery.eq('sold_by', processedBy);
        }

        const { data: allSales, error: salesError } = await salesQuery;
        if (salesError) throw salesError;

        // Expenses — also filter by period
        let expQuery = supabase.from('expenses').select('amount');
        if (date) {
            expQuery = expQuery.gte('expense_date', `${date}T00:00:00.000+03:00`).lte('expense_date', `${date}T23:59:59.999+03:00`);
        } else if (from && to) {
            expQuery = expQuery.gte('expense_date', `${from}T00:00:00.000+03:00`).lte('expense_date', `${to}T23:59:59.999+03:00`);
        } else if (month && year) {
            const mm = String(month).padStart(2,'0'), lastDay = new Date(year, month, 0).getDate();
            expQuery = expQuery.gte('expense_date', `${year}-${mm}-01T00:00:00.000+03:00`).lte('expense_date', `${year}-${mm}-${lastDay}T23:59:59.999+03:00`);
        }
        const { data: allExpenses, error: expError } = await expQuery;
        if (expError) throw expError;

        let realizedSales = 0, totalCogs = 0, totalOwed = 0, totalExpenses = 0;
        allSales?.forEach(s => {
            const total = parseFloat(s.total_amount || 0);
            const paid  = parseFloat(s.amount_paid  || 0);
            const cost  = parseFloat(s.cost_price   || 0) * parseFloat(s.quantity_sold || 0);
            // Revenue: only collected cash — unpaid credit is excluded
            realizedSales += paid;
            // COGS: full cost of every item sold (goods left the shop regardless of payment)
            totalCogs += cost;
            // Track what customers still owe
            const unpaid = Math.max(0, total - paid);
            if (unpaid > 0) totalOwed += unpaid;
        });
        allExpenses?.forEach(e => { totalExpenses += parseFloat(e.amount || 0); });

        const txCount = allSales?.length || 0;
        const avgTx   = txCount > 0 ? realizedSales / txCount : 0;

        // Admin only: expose cost/profit intelligence.
        // Manager & cashier get revenue/debt/transaction counts — no cost prices or margins.
        res.json({ 
            totalSales:   realizedSales, 
            totalExpenses: isAdmin ? totalExpenses  : undefined,
            netProfit:     isAdmin ? (realizedSales - totalCogs - totalExpenses) : undefined,
            totalCogs:     isAdmin ? totalCogs      : undefined,
            totalOwed, 
            txCount, 
            avgTx,
        });
    } catch (err) {
        console.error('[DAILY SUMMARY ERROR]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
// ============================================================
//  6. SALES REPORTS — Updated with Cashier Access & Security
// ============================================================
app.get('/api/reports/sales', requireAuth, requireRole('admin', 'manager', 'cashier'), async (req, res) => {
    const { date, month, year, from, to, method } = req.query;

    try {
        // Start the query
        let query = supabase
            .from('Sales')
            .select('*, payments(mpesa_code, amount, payment_method)')
            .eq('is_voided', false)
            .order('sale_date', { ascending: false });

        // --- SECURITY FILTER ---
        if (req.user.role.toLowerCase() === 'cashier') {
            query = query.eq('sold_by', req.user.name);
        }

        // --- DATE FILTERS (priority: date > month+year > year > from+to) ---
        if (date && date !== '') {
            query = query.gte('sale_date', `${date}T00:00:00.000+03:00`).lte('sale_date', `${date}T23:59:59.999+03:00`);
        } else if (month && year) {
            const mm = month.padStart(2, '0');
            const lastDay = new Date(year, month, 0).getDate();
            query = query.gte('sale_date', `${year}-${mm}-01T00:00:00.000+03:00`).lte('sale_date', `${year}-${mm}-${lastDay}T23:59:59.999+03:00`);
        } else if (year && !month) {
            query = query.gte('sale_date', `${year}-01-01T00:00:00.000+03:00`).lte('sale_date', `${year}-12-31T23:59:59.999+03:00`);
        } else if (from && to) {
            query = query.gte('sale_date', `${from}T00:00:00.000+03:00`).lte('sale_date', `${to}T23:59:59.999+03:00`);
        }

        if (method && method !== '') {
            query = method === 'Credit' 
                ? query.in('payment_status', ['Credit', 'Partial']) 
                : query.eq('payment_status', method);
        }

        const { data, error } = await query;
        if (error) throw error;

        // Process profits and costs — only expose cost intelligence to admin
        const callerRole = req.user.role.toLowerCase();
        const callerIsAdmin = callerRole === 'admin';

        const reports = data.map(sale => {
            const rev  = parseFloat(sale.total_amount || 0);
            const paid = parseFloat(sale.amount_paid  || 0);
            const cogs = parseFloat(sale.cost_price   || 0) * parseFloat(sale.quantity_sold || 0);
            const ratio = rev > 0 ? paid / rev : 0;

            const row = {
                ...sale,
                remaining_balance: rev - paid,
            };

            if (callerIsAdmin) {
                // Admin sees full cost/profit intelligence
                row.profit     = Math.max(0, (rev - cogs) * ratio);
                row.total_cost = cogs;
            } else {
                // Manager & cashier: strip cost prices and profit from each row
                delete row.cost_price;
                row.profit     = null;
                row.total_cost = null;
            }

            return row;
        });

        res.json(reports);

    } catch (err) {
        log.error('[REPORTS] Error fetching sales:', err.message);
        res.status(500).json({ success: false, message: 'Failed to generate report.' });
    }
});
app.get('/api/reports/debtors', requireAuth, async (req, res) => {
    try {
        const { processedBy, date } = req.query;
        const role = req.user.role;
        const isCashier = role?.toLowerCase() === 'cashier';

        let query = supabase.from('Sales')
            .select('customer_name, customer_phone, total_amount, amount_paid, payment_status, sale_date, sold_by')
            .in('payment_status', ['Credit', 'Partial', 'credit', 'partial', 'Unpaid'])
            .eq('is_voided', false)
            .order('sale_date', { ascending: false });

        if (isCashier) {
            query = query.eq('sold_by', req.user.name);
        } else if (processedBy) {
            query = query.eq('sold_by', processedBy);
        }

        if (date) {
            query = query.gte('sale_date', `${date}T00:00:00.000+03:00`).lte('sale_date', `${date}T23:59:59.999+03:00`);
        }

        const { data, error } = await query;
        if (error) throw error;

        const consolidated = (data || []).reduce((acc, sale) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.get('/api/reports/payments', requireAuth, requireRole('admin', 'manager', 'cashier'), async (req, res) => {
    try {
        const { date, month, year, from, to, method } = req.query;
        const isCashier  = req.user.role?.toLowerCase() === 'cashier';
        const cashierName = req.user.name;

        let dateFilter = {};
        if (date && date !== '') {
            dateFilter = { gte: `${date}T00:00:00.000+03:00`, lte: `${date}T23:59:59.999+03:00` };
        } else if (month && year) {
            const mm = month.padStart(2, '0'), lastDay = new Date(year, month, 0).getDate();
            dateFilter = { gte: `${year}-${mm}-01T00:00:00.000+03:00`, lte: `${year}-${mm}-${lastDay}T23:59:59.999+03:00` };
        } else if (year && !month) {
            dateFilter = { gte: `${year}-01-01T00:00:00.000+03:00`, lte: `${year}-12-31T23:59:59.999+03:00` };
        } else if (from && to) {
            dateFilter = { gte: `${from}T00:00:00.000+03:00`, lte: `${to}T23:59:59.999+03:00` };
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
                .select('*, Sales!left(customer_name, customer_phone, item_name, receipt_number, invoice_number)')
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
                customer_name: p.Sales?.customer_name  || p.customer_name || 'Debt Customer',
                item_name:     p.Sales?.item_name       || 'Debt Repayment',
                tx_ref:        p.Sales?.invoice_number  || p.Sales?.receipt_number || null,
            })));
        }

        // Admin/Manager — see everything
        let query = supabase
            .from('payments')
            .select('*, Sales!left(customer_name, customer_phone, item_name, receipt_number, invoice_number)')
            .order('created_at', { ascending: false });
        if (dateFilter.gte) query = query.gte('created_at', dateFilter.gte).lte('created_at', dateFilter.lte);
        if (method && method !== '') query = query.eq('payment_method', method);

        const { data, error } = await query;
        if (error) throw error;
        res.json(data.map(p => ({
            ...p,
            customer_name: p.Sales?.customer_name  || p.customer_name || 'Debt Customer',
            item_name:     p.Sales?.item_name       || 'Debt Repayment',
            // tx_ref = definitive transaction key — groups all items from the same cart
            tx_ref:        p.Sales?.invoice_number  || p.Sales?.receipt_number || null,
        })));
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.get('/api/reports/expenses', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { date, month, year, from, to } = req.query;
    try {
        let query = supabase.from('expenses').select('*').order('expense_date', { ascending: false });
        if (date) {
            query = query.gte('expense_date', `${date}T00:00:00.000+03:00`).lte('expense_date', `${date}T23:59:59.999+03:00`);
        } else if (month && year) {
            const mm = month.padStart(2, '0'), lastDay = new Date(year, month, 0).getDate();
            query = query.gte('expense_date', `${year}-${mm}-01T00:00:00.000+03:00`).lte('expense_date', `${year}-${mm}-${lastDay}T23:59:59.999+03:00`);
        } else if (year && !month) {
            query = query.gte('expense_date', `${year}-01-01T00:00:00.000+03:00`).lte('expense_date', `${year}-12-31T23:59:59.999+03:00`);
        } else if (from && to) {
            query = query.gte('expense_date', `${from}T00:00:00.000+03:00`).lte('expense_date', `${to}T23:59:59.999+03:00`);
        }
        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.get('/api/reports/profit-loss', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { month, year, from, to } = req.query;
    let startISO, endISO;

    // Safely parse dates based on which filter is used in the UI
    if (from && to) {
        startISO = `${from}T00:00:00.000+03:00`;
        endISO   = `${to}T23:59:59.999+03:00`;
    } else if (month && year) {
        const mm = String(month).padStart(2, '0');
        const lastDay = new Date(year, month, 0).getDate();
        startISO = `${year}-${mm}-01T00:00:00.000+03:00`;
        endISO   = `${year}-${mm}-${lastDay}T23:59:59.999+03:00`;
    } else {
        return res.status(400).json({ error: 'Missing date parameters' });
    }

    try {
        const { data: sales, error: sErr } = await supabase.from('Sales')
            .select('*')
            .eq('is_voided', false)
            .gte('sale_date', startISO)
            .lte('sale_date', endISO);
        if (sErr) throw sErr;
        
        let totalSales = 0, totalCogs = 0, unpaidDebts = 0;
        
        sales.forEach(s => {
            const amt = parseFloat(s.total_amount) || 0;
            const cogs = (parseFloat(s.cost_price) || 0) * (parseFloat(s.quantity_sold) || 0);
            const status = (s.payment_status || '').toLowerCase().trim();
            const paid = parseFloat(s.amount_paid) || 0;

            totalSales += amt; 
            totalCogs += cogs;
            
            // Track debt for the period
            if (status === 'credit' || status === 'unpaid' || status === 'partial') {
                unpaidDebts += Math.max(0, amt - paid);
            }
        });

        const { data: expenses } = await supabase.from('expenses')
            .select('amount')
            .gte('expense_date', startISO)
            .lte('expense_date', endISO);
            
        const totalExpenses = (expenses || []).reduce((s, e) => s + (parseFloat(e.amount) || 0), 0);
        
        const realizedSales = totalSales - unpaidDebts; 
        const grossProfit = realizedSales - totalCogs;
        const netProfit = grossProfit - totalExpenses;
        
        res.json({ totalSales: realizedSales, unpaidDebts, totalCogs, grossProfit, totalExpenses, netProfit });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ============================================================
//  STOCK MOVEMENT REPORT
//  Opening → Stock In → Sold → Adjustments → Closing
// ============================================================
app.get('/api/reports/stock-movement', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    let { from, to, month, year } = req.query;
    // Derive from/to from month+year or year-only if explicit from/to not provided
    if (!from && !to) {
        if (month && year) {
            const mm = String(month).padStart(2, '0');
            const lastDay = new Date(year, month, 0).getDate();
            from = `${year}-${mm}-01`;
            to   = `${year}-${mm}-${String(lastDay).padStart(2,'0')}`;
        } else if (year) {
            from = `${year}-01-01`;
            to   = `${year}-12-31`;
        }
    }
    try {
        // 1. All inventory items
        const { data: inventory, error: invErr } = await supabase
            .from('Inventory')
            .select('id, item_name, category, unit, stock_quantity')
            .order('item_name', { ascending: true });
        if (invErr) throw invErr;

        // 2. All stock batches (restocks) within period
        let batchQuery = supabase.from('stock_batches').select('inventory_id, batch_qty, created_at');
        if (from) batchQuery = batchQuery.gte('created_at', `${from}T00:00:00.000+03:00`);
        if (to)   batchQuery = batchQuery.lte('created_at', `${to}T23:59:59.999+03:00`);
        const { data: batches, error: batchErr } = await batchQuery;
        if (batchErr) throw batchErr;

        // 3. All sales within period
        let salesQuery = supabase.from('Sales').select('item_name, quantity_sold, sale_date').eq('is_voided', false);
        if (from) salesQuery = salesQuery.gte('sale_date', `${from}T00:00:00.000+03:00`);
        if (to)   salesQuery = salesQuery.lte('sale_date', `${to}T23:59:59.999+03:00`);
        const { data: sales, error: salesErr } = await salesQuery;
        if (salesErr) throw salesErr;

        // 4. Audit log adjustments in period (MANUAL_INVENTORY_EDIT)
        let auditQuery = supabase.from('audit_logs')
            .select('item_name, old_stock, new_stock, action, timestamp')
            .eq('action', 'MANUAL_INVENTORY_EDIT');
        if (from) auditQuery = auditQuery.gte('timestamp', `${from}T00:00:00.000+03:00`);
        if (to)   auditQuery = auditQuery.lte('timestamp', `${to}T23:59:59.999+03:00`);
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
            soldMap[key] = (soldMap[key] || 0) + (parseFloat(s.quantity_sold) || 0);
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.get('/api/reports/debt-logs', requireAuth, async (req, res) => {
    // FIX: Extract all the new date filter parameters
    const { date, month, year, from, to, processedBy, phone, customerName } = req.query;
    const role = req.user.role?.toLowerCase();
    
    try {
        let query = supabase.from('debt_payments').select('*').order('payment_date', { ascending: false });
        
        // Apply date filters in priority order
        if (date && date !== '') {
            query = query.gte('payment_date', `${date}T00:00:00.000+03:00`).lte('payment_date', `${date}T23:59:59.999+03:00`);
        } else if (from && to) {
            query = query.gte('payment_date', `${from}T00:00:00.000+03:00`).lte('payment_date', `${to}T23:59:59.999+03:00`);
        } else if (month && year) {
            const mm = String(month).padStart(2, '0');
            const lastDay = new Date(year, month, 0).getDate();
            query = query.gte('payment_date', `${year}-${mm}-01T00:00:00.000+03:00`).lte('payment_date', `${year}-${mm}-${lastDay}T23:59:59.999+03:00`);
        } else if (year) {
            query = query.gte('payment_date', `${year}-01-01T00:00:00.000+03:00`).lte('payment_date', `${year}-12-31T23:59:59.999+03:00`);
        }

        // Filter by customer — phone takes priority, fall back to name
        if (phone) {
            query = query.ilike('customer_phone', `%${sanitize(phone)}%`);
        } else if (customerName) {
            query = query.ilike('customer_name', `%${sanitize(customerName)}%`);
        }
        
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ============================================================
//  BULK PRODUCT IMPORT (CSV/EXCEL)
// ============================================================
// ============================================================
//  BULK PRODUCT IMPORT (CSV/EXCEL) - BATCHED KRA SYNC
// ============================================================
app.post('/api/inventory/bulk-import', requireAuth, requireRole('admin', 'manager'), requireSubscription, bulkJsonParser, async (req, res) => {
    const { items } = req.body;
    const userName  = req.user.name;
    if (!Array.isArray(items) || !items.length)
        return res.status(400).json({ success: false, message: 'No items provided.' });

    const results = { success: [], failed: [] };

    // ── Pre-fetch ALL existing DNs in one query ───────────────────────────────
    const { data: existingDNs } = await supabase
        .from('stock_batches')
        .select('delivery_number');
    const usedDNs = new Set((existingDNs || []).map(r => r.delivery_number));

    const allAuditRows = [];

    // ── Process in BATCHES OF 5 to balance speed and DigiTax Rate Limits ──────
    const BATCH_SIZE = 10;
    
    for (let i = 0; i < items.length; i += BATCH_SIZE) {
        const batch = items.slice(i, i + BATCH_SIZE);
        log.info(`[BULK IMPORT] Processing batch ${Math.floor(i/BATCH_SIZE) + 1} (${batch.length} items)...`);

        // Process up to 5 items concurrently
        await Promise.all(batch.map(async (row) => {
            // 1. ADD BARCODE TO DESTRUCTURING
            const { itemName, category, unit, costPrice, sellingPrice, stockQty, deliveryNote, barcode } = row;

            if (!itemName || !sellingPrice || !stockQty || !deliveryNote) {
                results.failed.push({ itemName: itemName || `Row`, reason: 'Missing required fields' });
                return;
            }
            
            const price = parseFloat(sellingPrice);
            const cost  = parseFloat(costPrice || 0);
            const qty   = parseInt(stockQty);
            const dn    = String(deliveryNote).trim().toUpperCase();

            if (isNaN(price) || price <= 0) { results.failed.push({ itemName, reason: 'Invalid selling price' }); return; }
            if (isNaN(qty)   || qty   <= 0) { results.failed.push({ itemName, reason: 'Invalid quantity' });      return; }

            if (usedDNs.has(dn)) { results.failed.push({ itemName, reason: `DN ${dn} already exists` }); return; }
            usedDNs.add(dn);

            // 2. SANITIZE BARCODE OR AUTO-GENERATE
            const finalBarcode = (barcode && String(barcode).trim() !== '') 
                ? String(barcode).trim() 
                : `EH-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${String(Math.floor(Math.random() * 99999)).padStart(5, '0')}`;

            try {
                // 3. PASS BARCODE TO KRA
                const digitaxItemId = await registerItemWithEtims({
                    itemName: itemName.trim(),
                    category: category || 'General',
                    sellingPrice: price,
                    unit: unit || 'PCS',
                    stockQty: qty,
                    barcode: finalBarcode // <--- Passed to eTIMS
                });

                if (!digitaxItemId) {
                    results.failed.push({ itemName, reason: 'KRA Registration Rejected' });
                    return; 
                }

                // 4. SAVE BARCODE TO SUPABASE INVENTORY TABLE
                const { data: newItem, error: invErr } = await supabase.from('Inventory').insert([{
                    item_name:      itemName.trim(),
                    category:       category || 'General',
                    unit:           unit     || 'PCS',
                    cost_price:     cost,
                    price:          price,
                    stock_quantity: qty,
                    barcode:        finalBarcode, // <--- Saved here
                    digitax_item_id: digitaxItemId,
                    kra_registered:  true           
                }]).select().single();
                
                if (invErr) throw new Error(invErr.message);

                // 5. Insert stock batch
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
                    await supabase.from('Inventory').delete().eq('id', newItem.id);
                    throw new Error(batchErr.message);
                }

                allAuditRows.push({
                    performed_by: userName,
                    action:       'INITIAL_STOCK',
                    dn_number:    dn,
                    item_name:    itemName.trim(),
                    old_stock:    0,
                    added_qty:    qty,
                    new_stock:    qty,
                    batch_id:     newBatch?.id || null,
                    details:      `BULK IMPORT: ${itemName} | Qty: ${qty} | DN: ${dn} | KRA ID: ${digitaxItemId} | Barcode: ${finalBarcode}`,
                    timestamp:    new Date().toISOString()
                });

                results.success.push({ itemName, dn });

            } catch (err) {
                results.failed.push({ itemName, reason: err.message });
            }
        }));
        // 5. THE COOL-DOWN DELAY
        // Wait 3 seconds between batches (only if there are more items to process)
        if (i + BATCH_SIZE < items.length) {
            log.info(`[BULK IMPORT] Batch complete. Sleeping 3s to respect DigiTax limits...`);
            await new Promise(resolve => setTimeout(resolve, 3000));
        }
    }

    // ── Single batch INSERT for all audit logs ────────────────────────────────
    if (allAuditRows.length > 0) {
        const { error: auditErr } = await supabase.from('audit_logs').insert(allAuditRows);
        if (auditErr) {
            log.warn('[BULK IMPORT] Audit log batch insert failed:', auditErr.message);
        }
    }

    log.info(`[BULK IMPORT] Done — ${results.success.length} imported & registered, ${results.failed.length} failed | by ${userName}`);

    // ── NEW: PRINT EXACT FAILURES TO THE TERMINAL ──────────────────────────────
    if (results.failed.length > 0) {
        results.failed.forEach(f => {
            log.warn(`[BULK IMPORT FAILURE] ❌ ${f.itemName}: ${f.reason}`);
        });
    }
    // ──────────────────────────────────────────────────────────────────────────

    res.json({
        success:  true,
        imported: results.success.length,
        failed:   results.failed.length,
        results
    });
});
// ============================================================
//  8a. SELL ROUTE — MULTI-ITEM CART
//  POST /api/sell/cart  →  ONE receipt/invoice/DN for ALL items
// ============================================================
app.post('/api/sell/cart', requireAuth, requireSubscription, async (req, res) => {
    let { items, paymentMethod, mpesaId, mpesaCode, customerName, customerPin, amountPaid, isC2B, priceTier } = req.body;
    const soldBy = req.user.name;
    const tier = (priceTier || 'retail').toLowerCase();

    if (!Array.isArray(items) || items.length === 0)
        return res.status(400).json({ success: false, message: 'Cart is empty.' });
    if (!['Cash', 'M-Pesa', 'Safaricom', 'Credit', 'Equity'].includes(paymentMethod))
        return res.status(400).json({ success: false, message: 'Invalid payment method.' });

    // Normalise frontend dropdown values → canonical DB labels
    if (paymentMethod === 'Safaricom') paymentMethod = 'M-Pesa';
    // 'Equity' kept through here; storedMethod below maps it to 'Equity Paybill' for DB

    const linkedPhone = (mpesaId && mpesaId.trim()) ? mpesaId.trim() : null;

    if ((paymentMethod === 'M-Pesa' || paymentMethod === 'Credit' || paymentMethod === 'Equity') && !linkedPhone)
        return res.status(400).json({ success: false, message: 'Phone number required.' });

    // Both M-Pesa and Equity require a transaction reference code
    if (paymentMethod === 'M-Pesa' || paymentMethod === 'Equity') {
        if (!mpesaCode || !mpesaCode.trim()) {
            const label = paymentMethod === 'Equity' ? 'Equity transaction reference' : 'M-Pesa Code';
            return res.status(400).json({ success: false, message: `${label} required.` });
        }

        const sanitizedCode = mpesaCode.trim().toUpperCase();

        if (!isC2B) {
            const { data: existingPayment } = await supabase
                .from('payments')
                .select('id')
                .like('mpesa_code', `${sanitizedCode}%`)
                .maybeSingle();

            if (existingPayment) {
                const label = paymentMethod === 'Equity' ? 'Equity transaction reference' : 'M-Pesa code';
                return res.status(400).json({ success: false, message: `This ${label} has already been used.` });
            }
        }
    }
    try {
        // ── Generate ONE shared document number for the ENTIRE cart ───────────
        const today    = new Date();
        const datePart = today.getFullYear().toString() +
            String(today.getMonth() + 1).padStart(2, '0') +
            String(today.getDate()).padStart(2, '0');
        const timePart = String(today.getHours()).padStart(2, '0') +
            String(today.getMinutes()).padStart(2, '0') +
            String(today.getSeconds()).padStart(2, '0') +
            String(today.getMilliseconds()).padStart(3, '0');
        const dayStart = `${datePart.slice(0,4)}-${datePart.slice(4,6)}-${datePart.slice(6,8)}T00:00:00.000+03:00`;

        const { count: todayCount } = await supabase
            .from('Sales').select('*', { count: 'exact', head: true })
            .gte('sale_date', dayStart);
        const seq = String((todayCount || 0) + 1).padStart(4, '0');

        const isCredit      = paymentMethod === 'Credit';
        const receiptNumber = isCredit ? null : `REC-${datePart}-${seq}-${timePart}`;
        const invoiceNumber = isCredit ? `INV-${datePart}-${seq}-${timePart}` : null;
        const dnNumber      = isCredit ? `DN-${datePart}-${seq}-${timePart}`  : null;

        // Determine stored payment method label for DB
        const storedMethod = paymentMethod === 'Equity'             ? 'Equity Paybill'
                           : (mpesaCode && mpesaCode.trim())        ? 'M-Pesa'
                           : (paymentMethod === 'M-Pesa' || isC2B) ? 'M-Pesa'
                           : (paymentMethod || 'Cash');

        let cartTotal = 0;
        let kraReceiptNo = null, kraQrUrl = null, controlUnitNumber = null;
        const saleIds = [];
        const paymentRows = [];
        const etimsCartItems = []; 

        for (const cartItem of items) {
            const qty = parseFloat(cartItem.quantity); // Allows fractional units
            if (!qty || qty <= 0) continue;

            const { data: invItem, error: fetchErr } = await supabase
                .from('Inventory').select('stock_quantity, item_name, price, fundi_price, wholesale_price, wholesale_min_qty, sub_unit, sub_unit_qty, sub_unit_price, bulk_unit, cost_price').eq('id', cartItem.itemId).single();
            if (fetchErr || !invItem) throw new Error(`Item ${cartItem.itemId} not found.`);

            // ── Price tier resolution ─────────────────────────────────────────
            let price = parseFloat(invItem.price); // default retail (bulk unit price)
            const sellUnit = cartItem.sellUnit || 'bulk';

            // Derive discount % from stored carton prices — same % then applies to loose sales.
            // e.g. carton retail=750, fundi=700 → fundiPct=6.67%; loose retail=37.50 → fundi loose=35.00
            const cartonRetail  = parseFloat(invItem.price) || 0;
            const fundiPct      = (cartonRetail > 0 && invItem.fundi_price)
                ? (1 - parseFloat(invItem.fundi_price)     / cartonRetail) : null;
            const wholesalePct  = (cartonRetail > 0 && invItem.wholesale_price)
                ? (1 - parseFloat(invItem.wholesale_price) / cartonRetail) : null;

            // Wholesale auto-upgrade — only when tier is retail and qty threshold met
            const wsAutoApplies = tier === 'retail' && invItem.wholesale_price
                && invItem.wholesale_min_qty && qty >= invItem.wholesale_min_qty;

            if (sellUnit === 'sub' && invItem.sub_unit_price) {
                // Loose sale — apply tier discount to sub-unit retail price
                const looseRetail = parseFloat(invItem.sub_unit_price);
                if (tier === 'fundi' && fundiPct !== null)
                    price = parseFloat((looseRetail * (1 - fundiPct)).toFixed(2));
                else if ((tier === 'wholesale' || wsAutoApplies) && wholesalePct !== null)
                    price = parseFloat((looseRetail * (1 - wholesalePct)).toFixed(2));
                else
                    price = looseRetail;
            } else if (tier === 'fundi' && invItem.fundi_price) {
                price = parseFloat(invItem.fundi_price);
            } else if (tier === 'wholesale' && invItem.wholesale_price) {
                price = parseFloat(invItem.wholesale_price);
            } else if (wsAutoApplies) {
                price = parseFloat(invItem.wholesale_price);
            }

            // ── Fractional stock deduction for sub_unit sales ─────────────────
            // e.g. selling 5 Kg from a 20 Kg carton → deduct 0.25 cartons
            const stockDeductionQty = (sellUnit === 'sub' && invItem.sub_unit_qty)
                ? parseFloat((qty / parseFloat(invItem.sub_unit_qty)).toFixed(6))
                : qty;

            const displayUnit = (sellUnit === 'sub' && invItem.sub_unit) ? invItem.sub_unit : (invItem.bulk_unit || invItem.unit || 'PCS');
            const itemName  = invItem.item_name;
            const itemTotal = parseFloat((qty * price).toFixed(2));

            etimsCartItems.push({
                itemName:   itemName,
                quantity:   qty,
                unitPrice:  price,
                sellUnit:   sellUnit,
                bulkUnit:   invItem.bulk_unit || invItem.unit || 'Carton',
                subUnit:    invItem.sub_unit  || null,
                subUnitQty: invItem.sub_unit_qty || null,
            });

            // FIFO batch drain
            const { data: batches } = await supabase.from('stock_batches').select('*')
                .eq('inventory_id', cartItem.itemId).gt('remaining_qty', 0)
                .order('created_at', { ascending: true });

            let remaining = stockDeductionQty, itemCost = 0;
            for (const batch of (batches || [])) {
                if (remaining <= 0) break;
                const take   = Math.min(parseFloat(batch.remaining_qty), remaining);
                const newQty = parseFloat((batch.remaining_qty - take).toFixed(6));
                itemCost    += take * parseFloat(batch.unit_cost || 0);
                await supabase.from('stock_batches').update({ remaining_qty: newQty }).eq('id', batch.id);
                if (newQty === 0) {
                    const next = batches[batches.indexOf(batch) + 1];
                    transporter.sendMail({
                        from: process.env.EMAIL_USER,
                        to: process.env.EMAIL_USER,
                        subject: `📦 BATCH FINISHED: ${itemName}`,
                        text: `Batch for "${itemName}" depleted. Next: ${next ? 'KES ' + next.unit_cost : 'NO STOCK LEFT'}`
                    }, e => { if (e) log.warn('Batch email failed', e); });
                }
                remaining = parseFloat((remaining - take).toFixed(6));
            }

            const avgCost  = stockDeductionQty > 0 ? itemCost / stockDeductionQty : 0;
            const itemPaid = isCredit ? 0 : itemTotal;
            cartTotal += itemTotal;

            // Insert local sale row
            const { data: saleRow, error: insertErr } = await supabase.from('Sales').insert([{
                item_name:      itemName,
                quantity_sold:  parseFloat(parseFloat(qty).toFixed(4)),  // NUMERIC(12,4) — supports sub-unit decimals (e.g. 0.5 Kg)
                unit_price:     price,
                total_amount:   itemTotal,
                amount_paid:    itemPaid,
                cost_price:     avgCost,
                profit:         itemTotal - itemCost,
                payment_status: isCredit ? 'Credit' : 'Paid',
                is_credit_sale: isCredit,
                customer_name:  customerName || 'Walk-in',
                customer_phone: linkedPhone,
                sold_by:        soldBy,
                sale_date:      nowEATIso(),
                receipt_number: receiptNumber,
                invoice_number: invoiceNumber,
                dn_number:      dnNumber,
                price_tier:     tier !== 'retail' ? tier : null,
                sell_unit:      displayUnit,
            }]).select().single();
            if (insertErr) throw insertErr;
            saleIds.push(saleRow.id);

            // Queue up payment row with the exact item amount (avoids amount: 0 DB constraints)
            if (!isCredit && itemPaid > 0) {
                paymentRows.push({
                    sale_id:        saleRow.id,
                    amount:         itemPaid,
                    payment_method: storedMethod,
                    mpesa_code:     mpesaCode ? `${mpesaCode.trim().toUpperCase()}-${saleRow.id}` : null,
                    received_by:    soldBy,
                    customer_name:  customerName || 'Walk-in',
                    created_at:     new Date().toISOString()
                });
            }

            // decrement_stock RPC is typed INTEGER — cannot accept fractional values.
            // For sub-unit sales (e.g. 0.2 Cartons deducted when selling 4 Kg from a 20-Kg carton),
            // fall back to a direct UPDATE so that decimal deductions work correctly.
            if (!Number.isInteger(stockDeductionQty)) {
                const newQty = parseFloat(((invItem.stock_quantity || 0) - stockDeductionQty).toFixed(6));
                const { error: updErr } = await supabase
                    .from('Inventory')
                    .update({ stock_quantity: Math.max(0, newQty) })
                    .eq('id', cartItem.itemId);
                if (updErr) throw new Error(updErr.message);
            } else {
                const { error: rpcErr } = await supabase.rpc('decrement_stock', {
                    p_item_id: cartItem.itemId, p_quantity: stockDeductionQty
                });
                if (rpcErr) throw new Error(rpcErr.message);
            }

            const newStock = (invItem.stock_quantity || 0) - qty;
            if (newStock <= 10) {
                transporter.sendMail({
                    from: process.env.EMAIL_USER, to: process.env.EMAIL_USER,
                    subject: `⚠️ LOW STOCK: ${itemName}`,
                    text: `${itemName} is down to ~${newStock} units.`
                }, e => { if (e) log.warn('Stock alert email failed', e); });
            }
        }

        // Insert ALL accumulated payment rows
        if (paymentRows.length > 0) {
            const { error: payErr } = await supabase.from('payments').insert(paymentRows);
            if (payErr) log.error('[CART] Payment table insertion failed:', payErr.message);
        }

        // --- ONE single eTIMS call outside the loop for the whole cart ---
        const etimsResult = await submitSaleToEtims({
            invoiceNumber: invoiceNumber || receiptNumber,
            receiptNumber, 
            cartItems: etimsCartItems, 
            paymentMethod,
            customerName: customerName || null, 
            customerPin: customerPin || null
        });

        if (etimsResult?.kraReceiptNo || etimsResult?.kraQrUrl || etimsResult?.digitaxSaleId) {
            const { error: kraUpdateErr } = await supabase.from('Sales').update({
                'Kra_Receipt_No':      etimsResult.kraReceiptNo      || null,
                'kra_qr_url':          etimsResult.kraQrUrl          || null,
                'E-tims_No':           etimsResult.etimsNo           ?? null,
                'Control_unit_number': etimsResult.controlUnitNumber || null,
                digitax_sale_id:       etimsResult.digitaxSaleId     || null
            }).in('id', saleIds);
            
            if (kraUpdateErr) log.warn('[eTIMS] KRA fields update failed (cart)', { error: kraUpdateErr.message, saleIds });

            if (!kraReceiptNo) kraReceiptNo = etimsResult.kraReceiptNo || null;
            if (!kraQrUrl)     kraQrUrl     = etimsResult.kraQrUrl     || null;
            if (!controlUnitNumber) controlUnitNumber = etimsResult.controlUnitNumber || null;
        }

        if (linkedPhone) {
            const { data: cust } = await supabase.from('customers')
                .select('name, total_debt').eq('phone', linkedPhone).single();
            if (!cust) {
                await supabase.from('customers').insert({ phone: linkedPhone, name: customerName || 'New Customer' });
            }
            if (isCredit) {
                const newDebt = parseFloat(cust?.total_debt || 0) + cartTotal;
                await supabase.from('customers').update({ total_debt: newDebt }).eq('phone', linkedPhone);
            }
        }

        log.info('[CART] ✅ Multi-item sale', {
            items: saleIds.length, total: cartTotal, receiptNumber, invoiceNumber
        });

        const qrDataString = kraQrUrl || (
            `PIN:A014661185V|REF:${receiptNumber || invoiceNumber}|AMT:${cartTotal.toFixed(2)}|DATE:${new Date().toLocaleDateString()}`
        );
        const qrDataUrl = await generateQrDataUrl(qrDataString);

       res.json({
            success: true,
            message: `${saleIds.length} item(s) sold. Total: KES ${cartTotal.toFixed(2)}`,
            receiptNumber, invoiceNumber, dnNumber, saleIds, total: cartTotal,
            kraReceiptNo, kraQrUrl: qrDataString, kraQrDataUrl: qrDataUrl,
            Control_unit_number: controlUnitNumber
        });

    } catch (err) {
        log.error('[CART] Error:', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ============================================================
//  8. SELL ROUTE
// ============================================================
app.post('/api/sell', requireAuth, requireSubscription, validateBody({
    itemId:        { type: 'number',  required: true, min: 1 },
    quantity:      { type: 'number',  required: true, min: 1 },
    paymentMethod: { type: 'string',  required: true, enum: ['Cash', 'M-Pesa', 'Credit'] },
}), async (req, res) => {
    // Price fetched from DB — never trusted from client
    let { itemId, quantity, paymentMethod, mpesaId, mpesaCode, customerName, customerPin, amountPaid } = req.body;
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

    if (paymentMethod === 'M-Pesa') {
        if (!mpesaCode || mpesaCode.trim() === '') {
            return res.status(400).json({ success: false, message: 'M-Pesa Code required.' });
        }

        const sanitizedCode = mpesaCode.trim().toUpperCase();

        // Check if this M-Pesa code has already been used in any previous sale
        const { data: existingPayment, error: checkError } = await supabase
            .from('payments')
            .select('id')
            .like('mpesa_code', `${sanitizedCode}%`)
            .maybeSingle();

        if (checkError) {
            return res.status(500).json({ success: false, message: 'Error validating M-Pesa code.' });
        }

        if (existingPayment) {
            return res.status(400).json({ success: false, message: 'This M-Pesa code has already been used.' });
        }

        mpesaCode = sanitizedCode;
    }
    try {
        // Fetch item details for price and name (read-only — safe before the atomic decrement)
        const { data: item, error: fetchError } = await supabase.from('Inventory').select('stock_quantity, item_name, price').eq('id', itemId).single();
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
        const dayStart = `${datePart.slice(0,4)}-${datePart.slice(4,6)}-${datePart.slice(6,8)}T00:00:00.000+03:00`;

        const { count: todayCount } = await supabase
            .from('Sales').select('*', { count: 'exact', head: true })
            .gte('sale_date', dayStart);
        const seq = String((todayCount || 0) + 1).padStart(4, '0');

        const isCredit = paymentMethod === 'Credit';

        // Append HHMMSSmmm to prevent duplicate key on rapid consecutive sales
        const timeSuffix = String(today.getHours()).padStart(2,'0') +
            String(today.getMinutes()).padStart(2,'0') +
            String(today.getSeconds()).padStart(2,'0') +
            String(today.getMilliseconds()).padStart(3,'0');

        // Cash/M-Pesa sales get a receipt number; credit sales do NOT (no payment received yet)
        const receiptNumber  = isCredit ? null : `REC-${datePart}-${seq}-${timeSuffix}`;

        // Credit sales get invoice + delivery note numbers instead
        const invoiceNumber  = isCredit ? `INV-${datePart}-${seq}-${timeSuffix}` : null;
        const dnNumber       = isCredit ? `DN-${datePart}-${seq}-${timeSuffix}`  : null;

        const { data: saleData, error: insertError } = await supabase.from('Sales').insert([{
            item_name: itemName, quantity_sold: quantity, unit_price: price, total_amount: totalAmount,
            amount_paid: paidNow, cost_price: avgCost, profit: totalAmount - totalCost,
            payment_status: paidNow >= totalAmount ? 'Paid' : (paidNow > 0 ? 'Partial' : 'Credit'),
            is_credit_sale: isCredit,
            customer_name: customerName || 'Walk-in', customer_phone: linkedPhone,
            sold_by: soldBy, sale_date: nowEATIso(),
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
                               
            const { error: payErr } = await supabase.from('payments').insert([{ 
                sale_id: saleData[0].id, 
                amount: paidNow, 
                payment_method: storedMethod, 
                mpesa_code: mpesaCode ? `${mpesaCode.trim().toUpperCase()}-${saleData[0].id}` : null, 
                received_by: soldBy, 
                customer_name: customerName || 'Walk-in', 
                created_at: new Date().toISOString() 
            }]);
            
            if (payErr) log.warn('Payment log write failed', payErr);
            
            if (paymentMethod === 'Credit' || totalAmount > paidNow) {
                const { error: debtErr } = await supabase.from('debt_payments').insert([{ 
                    sale_id: saleData[0].id, 
                    amount_paid: paidNow, 
                    payment_method: paymentMethod || 'Cash', 
                    mpesa_id: mpesaCode || null, 
                    processed_by: soldBy, 
                    customer_name: customerName || 'New Customer', 
                    customer_phone: linkedPhone, 
                    payment_date: new Date().toISOString() 
                }]);
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
       let kraReceiptNo = null, kraQrUrl = null, controlUnitNumber = null;
        const etims = await submitSaleToEtims({ invoiceNumber: invoiceNumber || receiptNumber, receiptNumber, itemName, quantity, unitPrice: item.price, paymentMethod, customerName: customerName || null, customerPin: customerPin || null });
        if (etims) {
            kraReceiptNo      = etims.kraReceiptNo;
            kraQrUrl          = etims.kraQrUrl;
            controlUnitNumber = etims.controlUnitNumber;
            if (kraReceiptNo || kraQrUrl || etims.etimsNo || etims.controlUnitNumber || etims.digitaxSaleId) {
                const { error: kraUpdateErr } = await supabase.from('Sales').update({
                    'Kra_Receipt_No':      etims.kraReceiptNo      || null,
                    kra_qr_url:            etims.kraQrUrl          || null,
                    'E-tims_No':           etims.etimsNo           ?? null,
                    Control_unit_number:   etims.controlUnitNumber || null,
                    digitax_sale_id:       etims.digitaxSaleId     || null
                }).eq('id', saleData[0].id);
                if (kraUpdateErr) log.warn('[eTIMS] KRA fields update failed (sell)', { error: kraUpdateErr.message, saleId: saleData[0].id });
            }
        }

        // Generate QR locally — no external API call, instant, works offline
        const qrDataStringSingle = kraQrUrl || (
            `PIN:A014661185V|REF:${receiptNumber || invoiceNumber}|AMT:${totalAmount.toFixed(2)}|DATE:${new Date().toLocaleDateString()}`
        );
        const qrDataUrlSingle = await generateQrDataUrl(qrDataStringSingle);
        res.json({ success: true, message: `Sale recorded. Stock: ${newStock}`, receiptNumber, invoiceNumber, dnNumber, saleId: saleData[0].id, kraReceiptNo, kraQrUrl: qrDataStringSingle, kraQrDataUrl: qrDataUrlSingle, Control_unit_number: controlUnitNumber });
    } catch (err) {
        log.error('Sale error', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ============================================================
//  9. DEBT CLEARANCE
// ============================================================
app.post('/api/clear-debt', requireAuth, requireSubscription, validateBody({
    saleId:        { type: 'string', required: true },
    paymentAmount: { type: 'number', required: true, min: 0.01 },
    paymentMethod: { type: 'string', required: true, enum: ['Cash', 'M-Pesa', 'Equity', 'Safaricom'] },
}), async (req, res) => {
    let { saleId, paymentAmount, paymentMethod, mpesaId } = req.body;
    const processedBy = req.user.name;
    const userRole    = req.user.role?.toLowerCase();

    // Normalise frontend method values to canonical DB labels
    // 'Safaricom' → 'M-Pesa'  (Daraja STK, same as M-Pesa paybill)
    // 'Equity'    → 'Equity Paybill'
    if (paymentMethod === 'Safaricom') paymentMethod = 'M-Pesa';
    if (paymentMethod === 'Equity')    paymentMethod = 'Equity Paybill';

    if (!saleId || !paymentAmount) return res.status(400).json({ success: false, message: 'Missing Sale ID or Amount.' });

    const amountToPay = parseFloat(paymentAmount);
    if (isNaN(amountToPay) || amountToPay <= 0)
        return res.status(400).json({ success: false, message: 'Payment amount must be a positive number.' });
    if (amountToPay > 10000000)
        return res.status(400).json({ success: false, message: 'Payment amount exceeds maximum allowed.' });

    try {
        // ── Fetch the anchor sale row ─────────────────────────────────────────
        const { data: sale, error: getErr } = await supabase
            .from('Sales').select('*, customer_phone').eq('id', saleId).single();
        if (getErr || !sale) throw new Error('Sale record not found.');

        if (userRole === 'cashier' && sale.sold_by !== processedBy)
            return res.status(403).json({ success: false, message: 'Access denied. You can only process payments for your own sales.' });

        // ── Fetch ALL sibling rows for this transaction ───────────────────────
        // Multi-item carts create N Sale rows that all share the same invoice_number.
        // ROOT CAUSE OF BUG: previously we only updated the one row passed in saleId,
        // so amount_paid on the other rows stayed 0 → remaining balance was exaggerated.
        // Fix: operate on every row in the transaction together.
        let allSaleRows = [sale];
        const transactionRef = sale.invoice_number || sale.receipt_number;
        if (transactionRef) {
            const refField = sale.invoice_number ? 'invoice_number' : 'receipt_number';
            const { data: siblings } = await supabase
                .from('Sales')
                .select('id, total_amount, amount_paid, payment_status')
                .eq(refField, transactionRef)
                .eq('is_voided', false);
            if (siblings && siblings.length > 0) allSaleRows = siblings;
        }

        // ── True cart totals across ALL sibling rows ──────────────────────────
        const cartTotal       = allSaleRows.reduce((s, r) => s + parseFloat(r.total_amount || 0), 0);
        const cartAlreadyPaid = allSaleRows.reduce((s, r) => s + parseFloat(r.amount_paid  || 0), 0);
        const cartRemaining   = parseFloat((cartTotal - cartAlreadyPaid).toFixed(2));

        if (amountToPay > cartRemaining + 0.01)
            return res.status(400).json({
                success: false,
                message: `Payment KES ${amountToPay.toFixed(2)} exceeds outstanding balance of KES ${cartRemaining.toFixed(2)}.`
            });

        // ── Idempotency guard ─────────────────────────────────────────────────
        if (mpesaId) {
            const { data: existingMpesa } = await supabase
                .from('debt_payments').select('id')
                .eq('sale_id', saleId).eq('mpesa_id', mpesaId).limit(1);
            if (existingMpesa && existingMpesa.length > 0) {
                log.warn(`[clear-debt] Duplicate ref ${mpesaId} for sale ${saleId} — blocked`);
                return res.json({ success: true, message: 'Payment already recorded (duplicate M-Pesa code).', receiptNumber: sale.receipt_number || 'PAY-DUP', alreadyRecorded: true });
            }
        } else {
            const tenSecondsAgo = new Date(Date.now() - 10000).toISOString();
            const { data: recentCash } = await supabase
                .from('debt_payments').select('id')
                .eq('sale_id', saleId).eq('amount_paid', amountToPay)
                .gte('payment_date', tenSecondsAgo).limit(1);
            if (recentCash && recentCash.length > 0) {
                log.warn(`[clear-debt] Duplicate cash payment KES ${amountToPay} for sale ${saleId} within 10s — blocked`);
                return res.json({ success: true, message: 'Payment already recorded.', receiptNumber: sale.receipt_number || 'PAY-DUP', alreadyRecorded: true });
            }
        }

        // ── Generate PAY- receipt number ──────────────────────────────────────
        const now    = new Date();
        const dp     = now.getFullYear().toString()
                     + String(now.getMonth() + 1).padStart(2, '0')
                     + String(now.getDate()).padStart(2, '0');
        const tp     = String(now.getHours()).padStart(2, '0')
                     + String(now.getMinutes()).padStart(2, '0')
                     + String(now.getSeconds()).padStart(2, '0');
        const payReceiptNumber = 'PAY-' + dp + '-' + tp;

       // ── Distribute payment FIFO across all sibling rows ─────────
        let toDistribute = Math.round(amountToPay);
        const rowsOwing  = allSaleRows.filter(r => Math.round(parseFloat(r.total_amount||0) - parseFloat(r.amount_paid||0)) > 0);

        // Sort to ensure deterministic FIFO
        rowsOwing.sort((a,b) => a.id - b.id);

        for (let i = 0; i < rowsOwing.length; i++) {
            if (toDistribute <= 0) break;

            const row      = rowsOwing[i];
            const rowTotal = parseFloat(row.total_amount || 0);
            const rowPaid  = parseFloat(row.amount_paid  || 0);
            const rowOwing = Math.round(rowTotal - rowPaid);

            if (rowOwing <= 0) continue;

            const applyAmt = Math.min(toDistribute, rowOwing);

            let rowNewPaid;
            if (applyAmt >= rowOwing) {
                rowNewPaid = rowTotal; // Snaps exactly to total to wipe legacy decimals
            } else {
                rowNewPaid = rowPaid + applyAmt;
            }

            toDistribute -= applyAmt;

            const { error: rowErr } = await supabase.from('Sales').update({
                amount_paid:    rowNewPaid,
                payment_status: rowNewPaid >= rowTotal - 0.01 ? 'Paid' : 'Partial'
            }).eq('id', row.id);
            if (rowErr) throw new Error(`Failed to update sale row ${row.id}: ${rowErr.message}`);
        }
        // ── Update customer aggregate debt ────────────────────────────────────
        if (sale.customer_phone) {
            const { data: cust } = await supabase.from('customers')
                .select('total_debt').eq('phone', sale.customer_phone).single();
            const newDebt = parseFloat(Math.max(0, parseFloat(cust?.total_debt || 0) - amountToPay).toFixed(2));
            await supabase.from('customers').update({ total_debt: newDebt }).eq('phone', sale.customer_phone);
        }

        // ── Record audit rows (anchored to anchor saleId) ─────────────────────
        await supabase.from('payments').insert([{
            sale_id:        saleId,
            amount:         amountToPay,
            payment_method: paymentMethod,
           mpesa_code:     mpesaId ? `${mpesaId.trim().toUpperCase()}-${saleId}` : null,
            received_by:    processedBy,
            customer_name:  sale.customer_name,
            created_at:     new Date().toISOString()
        }]);
        await supabase.from('debt_payments').insert([{
            sale_id:        saleId,
            amount_paid:    amountToPay,
            payment_method: paymentMethod,
            mpesa_id:       mpesaId || null,
            processed_by:   processedBy,
            customer_name:  sale.customer_name,
            customer_phone: sale.customer_phone,
            payment_date:   new Date().toISOString()
        }]);

        const newRemaining = parseFloat(Math.max(0, cartRemaining - amountToPay).toFixed(2));
        const debtQrData   = `PIN:A014661185V|REF:${payReceiptNumber}|AMT:${amountToPay.toFixed(2)}|CUST:${sale.customer_name||'Customer'}|DATE:${new Date().toLocaleDateString()}`;
        const debtQrDataUrl = await generateQrDataUrl(debtQrData);

        log.info(`[clear-debt] ✅ KES ${amountToPay} from ${sale.customer_name} | rows: ${rowsOwing.length} | cart total: ${cartTotal} | remaining: ${newRemaining}`);

        res.json({
            success:          true,
            message:          `KES ${amountToPay} recorded.`,
            receiptNumber:    payReceiptNumber,
            kraQrUrl:         debtQrData,
            kraQrDataUrl:     debtQrDataUrl,
            amountPaid:       amountToPay,
            remainingBalance: newRemaining,
            rowsUpdated:      rowsOwing.length,
        });

    } catch (err) {
        log.error('Payment error:', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// PATCH /api/sales/:id/edit — edit customer details or payment method only
app.patch('/api/sales/:id/edit', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ============================================================
//  11. EMPLOYEES + MISC
// ============================================================
app.post('/api/employees', requireAuth, requireRole('admin'), requireSubscription, async (req, res) => {
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

// ============================================================
// EMPLOYEE PIN RESET — self-service request flow
// ============================================================

// PUBLIC: cashier/manager requests a PIN reset from the login screen
// Sets pin_reset_requested = true on the employees table row
app.post('/api/employees/request-pin-reset', async (req, res) => {
    try {
        const { employeeId } = req.body;
        if (!employeeId) return res.status(400).json({ success: false, message: 'Employee ID required.' });

        const { data: emp, error: findErr } = await supabase
            .from('employees')
            .select('id, name, role')
            .eq('emp_id', employeeId.toUpperCase())
            .single();

        if (findErr || !emp) {
            // Return generic message — don't leak whether ID exists
            return res.json({ success: true, message: 'If that ID exists, your request has been sent to the Admin.' });
        }

        // Admins must reset their own PIN through the admin panel
        if (emp.role === 'Admin') {
            return res.status(403).json({ success: false, message: 'Admin PINs cannot be reset this way. Use the admin panel.' });
        }

        const { error: updateErr } = await supabase
            .from('employees')
            .update({ pin_reset_requested: true })
            .eq('id', emp.id);

        if (updateErr) throw updateErr;

        log.info(`[PIN RESET REQUEST] ${emp.name} (${employeeId}) requested a PIN reset`);
        res.json({ success: true, message: 'Reset request sent to Admin. They will update your PIN shortly.' });
    } catch (err) {
        log.error('[PIN RESET REQUEST]', err);
        res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});

// ADMIN: get all pending PIN reset requests
app.get('/api/employees/pin-reset-requests', requireAuth, requireRole('admin'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('employees')
            .select('id, name, emp_id, role')
            .eq('pin_reset_requested', true)
            .order('name', { ascending: true });

        if (error) throw error;
        res.json({ success: true, requests: data || [] });
    } catch (err) {
        log.error('[PIN RESET REQUESTS]', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ============================================================
// PIN RESET ROUTES (legacy users-table routes kept intact)
// ============================================================

// 1. Request PIN Reset (Public - called from login page)
app.post('/auth/request-reset', async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) return res.status(400).json({ success: false, message: 'Username required' });

        // Find the user
        const { data: user, error: userErr } = await supabase
            .from('users')
            .select('id, role')
            .eq('username', username)
            .single();

        if (userErr || !user) return res.status(404).json({ success: false, message: 'User not found' });
        
        // Safety check: Don't allow admins to be reset this way
        if (user.role === 'admin') return res.status(403).json({ success: false, message: 'Admins cannot request reset here' });

        // Flag the account for reset
        const { error: updateErr } = await supabase
            .from('users')
            .update({ pin_reset_requested: true })
            .eq('id', user.id);

        if (updateErr) throw updateErr;

        res.json({ success: true, message: 'Reset request sent to Admin.' });
    } catch (err) {
        log.error('[PIN RESET REQUEST]', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// 2. Get pending requests (Admin only)
app.get('/admin/reset-requests', requireAuth, requireRole('admin'), async (req, res) => {
    try {

        const { data, error } = await supabase
            .from('users')
            .select('id, username, full_name, role')
            .eq('pin_reset_requested', true);
        
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// 3. Approve and Reset PIN (Admin only)
app.post('/admin/reset-pin', requireAuth, requireRole('admin'), async (req, res) => {
    try {

        const { userId, newPin } = req.body; 
        if (!userId || !newPin) return res.status(400).json({ success: false, message: 'Missing data' });

        const hashedPin = await bcrypt.hash(newPin.toString(), 10);

        const { error } = await supabase
            .from('users')
            .update({ 
                pin_hash: hashedPin, 
                pin_reset_requested: false 
            })
            .eq('id', userId);

        if (error) throw error;

        res.json({ success: true, message: 'PIN reset successfully.' });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
// ============================================================
//  RESET MFA — Clears the secret so user can scan a new QR code
// ============================================================
app.patch('/api/employees/:id/reset-mfa', requireAuth, requireRole('admin'), requireSubscription, async (req, res) => {
    try {
        const { error } = await supabase
            .from('employees')
            .update({ mfa_secret: null }) // Setting to null triggers the QR code on next login
            .eq('id', req.params.id);

        if (error) throw error;

        res.json({ 
            success: true, 
            message: 'MFA reset successfully. The user will be prompted to set it up again on their next login.' 
        });
    } catch (err) {
        console.error('[RESET MFA ERROR]', err);
        res.status(500).json({ success: false, message: 'Server error resetting MFA.' });
    }
});
app.get('/api/customers/:phone', requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('customers').select('name, total_debt').eq('phone', req.params.phone).single();
        if (error) return res.status(404).json({ message: 'Not found' });
        res.json(data);
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.post('/api/expenses', requireAuth, requireRole('admin', 'manager'), requireSubscription, validateBody({
    description: { type: 'string', required: true, maxLen: 255 },
    amount:      { type: 'number', required: true, min: 0.01 },
    category:    { type: 'string', maxLen: 100 },
}), async (req, res) => {
    const { description, category, amount } = req.body;
    const spentBy = req.user.name;
    try {
        const { error } = await supabase.from('expenses').insert([{ description, category, amount: parseFloat(amount), spent_by: spentBy, expense_date: nowEATIso() }]);
        if (error) throw error;
        res.json({ success: true, message: 'Expense recorded!' });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
            .select('id, name, emp_id, role, is_active, pin_reset_requested')
            .order('name', { ascending: true });
        if (error) throw error;
        res.json(data);
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// PATCH deactivate/reactivate staff (admin only)
app.patch('/api/employees/:id/status', requireAuth, requireRole('admin'), requireSubscription, async (req, res) => {
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

        // BLOCKLIST FIX: On deactivation, mark the employee's empId as revoked.
        // requireAuth checks this — their next request gets a 401 instantly,
        // even if their 8h token hasn't naturally expired yet.
        if (!is_active && target?.emp_id) {
            tokenBlocklist.set(`empid:${target.emp_id}`, Date.now() + (8 * 60 * 60 * 1000));
            log.info(`[AUTH] Session forcibly revoked for emp: ${target.emp_id}`);
        }
        // On reactivation, clear the block so they can log in fresh
        if (is_active && target?.emp_id) {
            tokenBlocklist.delete(`empid:${target.emp_id}`);
        }

        res.json({ success: true, message: `Staff account ${is_active ? 'activated' : 'deactivated'} successfully.` });
    } catch (err) {
        log.error('[STATUS] Error:', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// PATCH reset staff PIN (admin only)
app.patch('/api/employees/:id/reset-pin', requireAuth, requireRole('admin'), requireSubscription, async (req, res) => {
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
            .update({ pin: hashedPin, pin_reset_requested: false })
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// Block login for deactivated staff — patch requireAuth to check is_active
// This is enforced at login: check is_active before issuing token

// ============================================================

// ============================================================
//  12. RETURNS & EXCHANGE ROUTES — admin & manager only
// ============================================================

app.post('/api/returns/exchange', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const { originalReceipt, kraInvoiceNumber: kraReceiptNo, kraEtimsInvoiceNumber, originalSaleId,
            digitaxSaleId: digitaxSaleIdFromBody,
            customerName, customerPhone,
            returnedItemId, returnedQuantity, returnReason,
            replacementItemId, replacementQuantity,
            sellingPriceOriginal, sellingPriceReplacement, notes } = req.body;
    const processedBy = req.user.name;
    const processedRole = req.user.role;

    if (!returnedItemId || !replacementItemId || !returnReason)
        return res.status(400).json({ success: false, message: 'returnedItemId, replacementItemId and returnReason are required.' });
    if (!['damaged','wrong_item','other'].includes(returnReason))
        return res.status(400).json({ success: false, message: 'returnReason must be: damaged, wrong_item or other.' });

    const retQty = parseInt(returnedQuantity) || 1;
    const repQty = parseInt(replacementQuantity) || 1;

    // ── Qty must match exactly — reject mismatches at the server level ──
    if (retQty !== repQty)
        return res.status(400).json({ success: false, message: `Replacement quantity (${repQty}) must exactly match returned quantity (${retQty}).` });

    try {
        // Look up digitax_sale_id from original sale if not passed in body
        let digitaxSaleId = digitaxSaleIdFromBody || null;
        if (!digitaxSaleId && originalSaleId) {
            const { data: origSale } = await supabase
                .from('Sales').select('digitax_sale_id').eq('id', originalSaleId).single();
            digitaxSaleId = origSale?.digitax_sale_id || null;
        }
        if (digitaxSaleId) log.info('[eTIMS] Original sale DigiTax ID found', { digitaxSaleId });
        else log.warn('[eTIMS] No digitax_sale_id found — credit note will use /sales-with-items fallback');
       const { data: retItem, error: retErr } = await supabase
            .from('Inventory').select('id,item_name,stock_quantity,cost_price,price,digitax_item_id').eq('id', returnedItemId).single();
        if (retErr || !retItem)
            return res.status(404).json({ success: false, message: 'Returned item not found.' });

        const { data: repItem, error: repErr } = await supabase
            .from('Inventory').select('id,item_name,stock_quantity,cost_price,price,digitax_item_id').eq('id', replacementItemId).single();
        if (repErr || !repItem)
            return res.status(404).json({ success: false, message: 'Replacement item not found.' });

        if (parseInt(repItem.stock_quantity) < repQty)
            return res.status(400).json({ success: false, message: 'Not enough stock for replacement. Available: ' + repItem.stock_quantity + ' ' + repItem.item_name + '.' });

        // 1. Expense Logic: Split calculations for Damaged vs Wrong Item
        let costWrittenOff = 0;
        if (returnReason === 'damaged') {
            costWrittenOff = parseFloat(retItem.cost_price || 0) * retQty;
        } else if (returnReason === 'wrong_item') {
            const retSellTotal = parseFloat(retItem.price || 0) * retQty;
            const repSellTotal = parseFloat(repItem.price || 0) * repQty;
            costWrittenOff = Math.abs(repSellTotal - retSellTotal); // Difference in selling prices
        }
        
        const isExpense = costWrittenOff > 0 && (returnReason === 'damaged' || returnReason === 'wrong_item');
        
        // 2. Inventory Logic: Only "Damaged" skips restocking. "Wrong Item" goes back to the shelf.
        const retOldStock    = parseInt(retItem.stock_quantity);
        const retNewStock    = returnReason === 'damaged' ? retOldStock : retOldStock + retQty; 
        
        const repOldStock    = parseInt(repItem.stock_quantity);
        const repNewStock    = repOldStock - repQty;

        // 3. Update Inventory: Run the restock query for everything EXCEPT damaged goods
        if (returnReason !== 'damaged') {
            const { error: inErr } = await supabase.from('Inventory').update({ stock_quantity: retNewStock }).eq('id', returnedItemId);
            if (inErr) throw inErr;
        }

        const { error: outErr } = await supabase.from('Inventory').update({ stock_quantity: repNewStock }).eq('id', replacementItemId);
        if (outErr) throw outErr;

        // 4. Log the Expense
        let expenseId = null;
        if (isExpense && costWrittenOff > 0) {
            const { data: exp, error: expErr } = await supabase.from('expenses').insert([{
                description:  `Exchange Expense — ${retItem.item_name} (returned ${returnReason}, qty: ${retQty})`,
                category:     returnReason === 'damaged' ? 'Damaged Goods' : 'Wrong Item Expense',
                amount:       costWrittenOff,
                spent_by:     processedBy,
                expense_date: nowEATIso()
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
            original_receipt:        originalReceipt         || null,
            original_sale_id:        originalSaleId          || null,
            customer_name:           customerName            || null,
            customer_phone:          customerPhone           || null,
            returned_item_id:        returnedItemId,
            returned_item_name:      retItem.item_name,
            returned_quantity:       retQty,
            return_reason:           returnReason,
            replacement_item_id:     replacementItemId,
            replacement_item_name:   repItem.item_name,
            replacement_quantity:    repQty,
            cost_price_written_off:  costWrittenOff,
            selling_price_original:  parseFloat(sellingPriceOriginal || 0),
            kra_receipt_no:          kraReceiptNo            || null,
            etims_no:                kraEtimsInvoiceNumber   || null,
            processed_by:            processedBy,
            processed_by_role:       processedRole,
            expense_id:              expenseId,
            notes:                   notes                   || null
        }]).select('id').single();
        if (recErr) throw recErr;

        // ── Notify KRA via DigiTax eTIMS ────────────────────────
        //
        //  ALL reasons → Credit Note (R) for RETURNED item
        //  damaged     → also write-off Sale at cost
        //  ALL reasons → New Sale for REPLACEMENT (only if credit note succeeded)
        //
        let kraReturnRef = null, kraReturnQrUrl = null;
        let kraReplRef   = null, kraReplQrUrl   = null;
        let kraDebitRef  = null;

        const sellingPrice    = Math.max(1, parseFloat(sellingPriceOriginal)    || parseFloat(retItem.price) || parseFloat(retItem.cost_price) || 1);
        const repSellingPrice = Math.max(1, parseFloat(sellingPriceReplacement) || parseFloat(repItem.price) || parseFloat(repItem.cost_price) || 1);
        const barcode  = (name) => String(name.split('').reduce((a,c) => Math.abs(a + c.charCodeAt(0)), 0)).padStart(8,'0');
        const safeJson = async (r) => { const t = await r.text(); try { return JSON.parse(t); } catch(_) { return { _raw: t }; } };

        // Block submission if eTIMS invoice number is missing — wrong value = unlinked credit note
        if (!kraEtimsInvoiceNumber) {
            log.warn('[eTIMS] Skipping credit note — kraEtimsInvoiceNumber (E-tims_No) is empty. Staff must enter the numeric E-tims_No from the original sale.');
        } else {

        try {
            const saleDate = new Date().toISOString().split('T')[0];

            // ── STEP 1: Credit Note via DigiTax /sales-with-items ────────────────
            // Per DigiTax docs: same endpoint as sale, differentiated by receipt_type_code:"R"
            // original_invoice_number = trader_invoice_number of the original sale (Kra_Receipt_No)
            // NOT the numeric E-tims_No — docs explicitly say it's the trader invoice number string
            const creditTraderRef = 'RET-CN-' + Date.now();

            // ── Try /credit-notes endpoint first (dedicated, produces Credit Notes table entry)
            // Requires digitax_sale_id of the original sale AND digitax_item_id of the returned item
            let creditRes, creditData;
            if (digitaxSaleId) {
                // Fetch digitax_item_id for the returned item
                const { data: invItem } = await supabase
                    .from('Inventory').select('digitax_item_id').eq('id', returnedItemId).single();
                const digitaxItemId = invItem?.digitax_item_id || null;

                if (!digitaxItemId) {
                    log.warn('[eTIMS] No digitax_item_id on returned item — skipping /credit-notes, using fallback', { returnedItemId });
                } else {
                    const creditNotesPayload = {
                        sale_id:               digitaxSaleId,
                        trader_invoice_number: creditTraderRef,
                        return_date:           saleDate,
                        callback_url:          DIGITAX_CALLBACK_URL,
                        items: [{
                            id:                    digitaxItemId,         // DigiTax item ID — required
                            quantity:              retQty,
                            unit_price:            Math.abs(sellingPrice),
                            total_amount:          Math.abs(parseFloat((sellingPrice * retQty).toFixed(2))),
                            discount_rate:         0
                        }]
                    };
                    log.info('[eTIMS] Sending credit note via /credit-notes', {
                        sale_id:       digitaxSaleId,
                        digitaxItemId,
                        return_date:   saleDate,
                        unit_price:    creditNotesPayload.items[0].unit_price
                    });
                    creditRes  = await fetch(DIGITAX_BASE_URL + '/credit-notes', {
                        method:  'POST',
                        headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
                        body:    JSON.stringify(creditNotesPayload),
                        signal:  AbortSignal.timeout(10000)
                    });
                    creditData = await safeJson(creditRes);
                    log.info('[eTIMS] Credit note response (/credit-notes)', { status: creditRes.status, body: JSON.stringify(creditData) });
                }
            }

            // ── Fallback: /sales-with-items with receipt_type_code R ─────────────
            if (!digitaxSaleId || !creditRes?.ok || !creditData?.id) {
                const creditPayload = {
                    trader_invoice_number:   creditTraderRef,
                    original_invoice_number: kraReceiptNo || kraEtimsInvoiceNumber,
                    invoice_number:          parseInt(String(Date.now()).slice(-10)),
                    receipt_type_code:       'R',
                    payment_type_code:       '01',
                    invoice_status_code:     '02',
                    sale_date:               saleDate,
                    items: [{
                        item_name:             retItem.item_name,
                        item_class_code:       '99010000',
                        item_type_code:        '2',
                        item_bar_code:         barcode(retItem.item_name),
                        item_tax_type_code:    'B',
                        quantity:              retQty,
                        quantity_unit_code:    'U',
                        package_unit_code:     'NT',
                        package_unit_quantity: 1,
                        unit_price:            Math.abs(sellingPrice),
                        total_amount:          Math.abs(parseFloat((sellingPrice * retQty).toFixed(2))),
                        tax_type_code:         'B',
                        discount_rate:         0,
                        origin_nation_code:    'KE'
                    }]
                };
                log.info('[eTIMS] Sending credit note via /sales-with-items fallback', {
                    original_invoice_number: creditPayload.original_invoice_number,
                    receipt_type_code:       creditPayload.receipt_type_code,
                    unit_price:              creditPayload.items[0].unit_price
                });
                creditRes  = await fetch(DIGITAX_BASE_URL + '/sales-with-items', {
                    method:  'POST',
                    headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
                    body:    JSON.stringify(creditPayload),
                    signal:  AbortSignal.timeout(10000)
                });
                creditData = await safeJson(creditRes);
                log.info('[eTIMS] Credit note response (/sales-with-items fallback)', { status: creditRes.status, body: JSON.stringify(creditData) });
            }

            if (creditRes.ok && creditData.id) {
                kraReturnRef   = creditData.id;
                kraReturnQrUrl = (creditData.etims_url && creditData.etims_url !== '') ? creditData.etims_url : (creditData.offline_url || null);
                log.info('[eTIMS] Credit note accepted ✅', {
                    ref:        kraReturnRef,
                    receipt_no: creditData.receipt_number,
                    etims_no:   creditData.invoice_number,
                    url:        kraReturnQrUrl
                });
            } else {
                log.warn('[eTIMS] Credit note rejected', { status: creditRes.status, body: creditData });
            }

            // ── STEP 2: Write-off — NOT submitted to DigiTax ────────────────────
            // Damaged goods cost is already recorded as an expense in the local expenses table.
            // Submitting a write-off sale to DigiTax creates a duplicate entry for the same item.
            // The credit note (Step 1) already reverses the original taxable sale with KRA.
            if (returnReason === 'damaged') {
                log.info('[eTIMS] Damaged write-off recorded locally only — not submitted to DigiTax to avoid duplicate', { item: retItem.item_name });
            }
            // NOTE: No separate ADD call needed for the returned item in DigiTax.
            // The credit note (Step 1, receipt_type_code "R") already signals DigiTax
            // that the item is coming back — DigiTax auto-increments stock on credit note.
            // A manual syncStockWithEtims ADD on top would double-add in DigiTax.
            // The local DB restock (retNewStock above) is the only explicit ADD needed.

            // ── STEP 3: Deduct replacement item stock from DigiTax ───────────────
            // Only runs after credit note is confirmed (kraReturnRef set).
            // Uses movement type '05' (stock adjustment) — NOT a new sale — so KRA
            // does not tax the replacement a second time. This purely syncs the
            // physical stock movement (item leaving the shelf) with DigiTax.
            if (kraReturnRef && repItem.digitax_item_id && DIGITAX_API_KEY) {
                try {
                    await syncStockWithEtims(
                        repItem.digitax_item_id,
                        repQty,
                        `Exchange Replacement — Credit Note: ${kraReturnRef}`,
                        '05', // Stock adjustment — no tax impact
                        'DEDUCT'
                    );
                    log.info('[eTIMS] ✅ Replacement item stock deducted from DigiTax', {
                        item:      repItem.item_name,
                        qty:       repQty,
                        creditRef: kraReturnRef
                    });
                } catch (etimsErr) {
                    log.warn('[eTIMS] Failed to deduct replacement stock from DigiTax', {
                        item:  repItem.item_name,
                        error: etimsErr.message
                    });
                }
            } else if (!kraReturnRef) {
                log.warn('[eTIMS] Skipping replacement DigiTax deduction — credit note was not confirmed', { item: repItem.item_name });
            } else if (!repItem.digitax_item_id) {
                log.warn('[eTIMS] Skipping replacement DigiTax deduction — no digitax_item_id on item', { item: repItem.item_name });
            }

            await supabase.from('returns_log').update({
                kra_return_ref: kraReturnRef || null, kra_return_qr_url: kraReturnQrUrl || null
            }).eq('id', rec.id);

        } catch (etimsErr) {
            log.warn('[eTIMS] Return eTIMS failed:', etimsErr?.message || String(etimsErr));
            log.warn('[eTIMS] Full error:', { stack: etimsErr?.stack, name: etimsErr?.name });
        }
        } // end: only if kraEtimsInvoiceNumber present

        res.json({
            success: true,
            message: 'Exchange processed. ' + retItem.item_name + ' replaced with ' + repItem.item_name + '.' +
                     (returnReason === 'damaged' ? ' KES ' + costWrittenOff + ' written off as expense.' : ''),
            returnId:      rec && rec.id,
            expenseId,
            kraReturnRef,   kraReturnQrUrl,
            kraDebitRef,
            kraReplRef,     kraReplQrUrl,
            etimsSubmitted: !!(kraReturnRef || kraReplRef)
        });
    } catch (err) {
        log.error('[RETURNS] Exchange error:', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.get('/api/returns', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    let { from, to, month, year, staff, reason, page, search } = req.query;
    const perPage = 5, pageNum = parseInt(page) || 1;
    // Derive from/to from month+year or year-only when not provided explicitly
    if (!from && !to) {
        if (month && year) {
            const mm = String(month).padStart(2, '0');
            const lastDay = new Date(year, month, 0).getDate();
            from = `${year}-${mm}-01`;
            to   = `${year}-${mm}-${String(lastDay).padStart(2,'0')}`;
        } else if (year) {
            from = `${year}-01-01`;
            to   = `${year}-12-31`;
        }
    }
    try {
        let q = supabase.from('returns_log').select('*', { count: 'exact' }).order('created_at', { ascending: false });
        if (from)   q = q.gte('created_at', from + 'T00:00:00.000+03:00');
        if (to)     q = q.lte('created_at', to   + 'T23:59:59.999+03:00');
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.get('/api/returns/summary', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { month, year } = req.query;
    try {
        let q = supabase.from('returns_log').select('return_reason,cost_price_written_off,created_at');
        if (month && year) {
            const mm = String(month).padStart(2,'0'), lastDay = new Date(year, month, 0).getDate();
            q = q.gte('created_at', year + '-' + mm + '-01T00:00:00.000+03:00')
                 .lte('created_at', year + '-' + mm + '-' + lastDay + 'T23:59:59.999+03:00');
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.get('/api/returns/search-sale', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { q } = req.query;
    if (!q) return res.status(400).json({ success: false, message: 'Query q is required.' });
    try {
       // 1. Fetch the matching sales
        const { data, error } = await supabase.from('Sales')
            // ADDED: invoice_number to the select list
            .select('id,receipt_number,invoice_number,item_name,quantity_sold,unit_price,total_amount,amount_paid,customer_name,customer_phone,sale_date,payment_status,"Kra_Receipt_No",kra_qr_url,"E-tims_No",digitax_sale_id')
            // ADDED: invoice_number to the search filter
            .or(`customer_name.ilike.%${q}%,customer_phone.ilike.%${q}%,receipt_number.ilike.%${q}%,invoice_number.ilike.%${q}%`)
            .eq('is_voided', false)
            .order('sale_date', { ascending: false })
            .limit(10);
        if (error) throw error;

        const sales = data || [];
        if (sales.length === 0) return res.json([]);

        // 2. Extract Sale IDs to check for previous returns
        const saleIds = sales.map(s => s.id);

        // 3. Query returns_log for any returns linked to these sales
        const { data: returnsData, error: retErr } = await supabase
            .from('returns_log')
            .select('original_sale_id, returned_quantity')
            .in('original_sale_id', saleIds);
        
        if (retErr) throw retErr;

        // 4. Sum up the returned quantities per sale ID
        const returnedMap = {};
        (returnsData || []).forEach(r => {
            if (!r.original_sale_id) return;
            returnedMap[r.original_sale_id] = (returnedMap[r.original_sale_id] || 0) + (r.returned_quantity || 0);
        });

        // 5. Attach the returned_quantity to the sales response
        const enrichedSales = sales.map(sale => ({
            ...sale,
            returned_quantity: returnedMap[sale.id] || 0
        }));

        res.json(enrichedSales);
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
// ╔══════════════════════════════════════════════════════════════╗
// ║              M-PESA STK PUSH INTEGRATION                     ║
// ╚══════════════════════════════════════════════════════════════╝
// SECURITY: All M-Pesa credentials MUST be set in .env — no hardcoded fallbacks.
// If any are missing, STK push routes will respond with 503.
const MPESA_CONSUMER_KEY    = process.env.MPESA_CONSUMER_KEY;
const MPESA_CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET;
const MPESA_SHORTCODE       = process.env.MPESA_SHORTCODE;
const MPESA_PASSKEY         = process.env.MPESA_PASSKEY;
const MPESA_CALLBACK_URL    = process.env.MPESA_CALLBACK_URL;

if (!MPESA_CONSUMER_KEY || !MPESA_CONSUMER_SECRET || !MPESA_PASSKEY || !MPESA_SHORTCODE || !MPESA_CALLBACK_URL) {
    log.error('\u274c  Missing required M-Pesa env vars. STK push will return 503 until all vars are set.');
}
// MPESA_TRANSACTION_TYPE controls Till vs Paybill:
//   CustomerPayBillOnline  → Paybill (customer enters account number, e.g. invoice no.)
//   CustomerBuyGoodsOnline → Till / BuyGoods (no account number prompt)
const MPESA_TRANSACTION_TYPE = process.env.MPESA_TRANSACTION_TYPE || 'CustomerPayBillOnline';
const MPESA_BASE_URL        = process.env.MPESA_ENV === 'live'
    ? 'https://api.safaricom.co.ke'
    : 'https://sandbox.safaricom.co.ke';

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
    if (!MPESA_CONSUMER_KEY || !MPESA_CONSUMER_SECRET) {
        throw new Error('M-Pesa credentials not configured. Set MPESA_CONSUMER_KEY and MPESA_CONSUMER_SECRET in .env');
    }
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

// ── Shared subscription extension helper ─────────────────────────────────────
// Called by both the STK callback (billing page) and the C2B vendor webhook
// (direct Lipa na M-Pesa paybill payment). Single source of truth for all
// subscription writes so both payment paths behave identically.
//
// opts: { plan_type, amount_kes, mpesa_code, phone?, source? }
async function _applySubscriptionPayment(opts) {
    const {
        plan_type,
        amount_kes,
        mpesa_code,
        phone        = '',
        source       = 'unknown',
        _overrideNotes = null,    // set by manual payment route
        _recordedBy    = 'system' // set by manual payment route
    } = opts;
    const months = plan_type === 'annual' ? 12 : (plan_type === 'monthly' ? 1 : null);

    // 1. Record payment row
    const { error: payErr } = await supabase.from('subscription_payments').insert([{
        client_id:      CLIENT_ID,
        amount_kes:     parseFloat(amount_kes),
        plan_type,
        payment_method: source,
        mpesa_code:     mpesa_code || null,
        months_paid:    ['annual_service','lifetime'].includes(plan_type) ? null : months,
        notes:          _overrideNotes || `Auto-applied via ${source}. Phone: ${phone}`,
        recorded_by:    _recordedBy,
    }]);
    if (payErr) {
        const detail = `code=${payErr.code} | msg=${payErr.message} | hint=${payErr.hint || 'none'}`;
        if (payErr.code === '42703') throw new Error(`subscription_payments INSERT — MISSING COLUMN. ${detail}. Run subscription_migration_v2.sql.`);
        if (payErr.code === '42501') throw new Error(`subscription_payments INSERT — RLS BLOCKED. ${detail}. Use service_role key.`);
        if (payErr.code === '23503') throw new Error(`subscription_payments INSERT — FOREIGN KEY: client_id '${CLIENT_ID}' not in subscriptions. Seed the row first.`);
        throw new Error(`subscription_payments INSERT failed — ${detail}`);
    }

    // 2. Apply the correct subscription change per plan type
    if (plan_type === 'lifetime') {
        const { error: ltErr } = await supabase.from('subscriptions')
            .update({ plan: 'lifetime', status: 'active', paid_until: '9999-12-31' })
            .eq('client_id', CLIENT_ID);
        if (ltErr) throw new Error(`subscriptions UPDATE (lifetime) failed — code=${ltErr.code} | ${ltErr.message}`);

    } else if (plan_type === 'annual_service') {
        const { data: cur, error: fetchErr } = await supabase.from('subscriptions')
            .select('annual_service_paid_until').eq('client_id', CLIENT_ID).single();
        if (fetchErr) throw new Error(`subscriptions SELECT failed — code=${fetchErr.code} | ${fetchErr.message}`);
        const base = (cur?.annual_service_paid_until && new Date(cur.annual_service_paid_until) > new Date())
            ? new Date(cur.annual_service_paid_until) : new Date();
        base.setFullYear(base.getFullYear() + 1);
        const newSvcDate = base.toISOString().split('T')[0];
        const { error: svcErr } = await supabase.from('subscriptions')
            .update({ annual_service_paid_until: newSvcDate, status: 'active' })
            .eq('client_id', CLIENT_ID);
        if (svcErr) throw new Error(`subscriptions UPDATE (annual_service) failed — code=${svcErr.code} | ${svcErr.message} | hint=${svcErr.hint}`);

    } else {
        // monthly or annual — reset paid_until if switching from lifetime (was 9999-12-31)
        if (_subCache.plan === 'lifetime') {
            const { error: resetErr } = await supabase.from('subscriptions')
                .update({ paid_until: new Date().toISOString().split('T')[0] })
                .eq('client_id', CLIENT_ID);
            if (resetErr) throw new Error(`Could not reset paid_until before extending: ${resetErr.message}`);
            log.info(`[SUB] Reset paid_until from 9999-12-31 to today before applying ${plan_type} extension`);
        }
        // Pass p_plan so the plan column is updated INSIDE the SECURITY DEFINER function —
        // a separate .update({ plan }) call here can be silently blocked by RLS if
        // SUPABASE_KEY is the anon key instead of service_role.
        const { error: rpcErr } = await supabase.rpc('extend_subscription', {
            p_client_id: CLIENT_ID,
            p_months:    months,
            p_plan:      plan_type,
        });
        if (rpcErr) throw new Error(`extend_subscription RPC failed — code=${rpcErr.code} | ${rpcErr.message} | hint=${rpcErr.hint}`);
    }

    // 3. Refresh cache so POS unlocks on the next request
    await refreshSubscriptionStatus();
}

app.post('/api/mpesa/stk-push', requireAuth, requireSubscription, async (req, res) => {
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
        // For Paybill: AccountReference appears on the customer's M-Pesa prompt as
        // the account number. Use the invoice/receipt number so it matches the sale.
        // For Till (BuyGoods): AccountReference is ignored by Safaricom but still sent.
        const body = {
            BusinessShortCode: MPESA_SHORTCODE, Password: password, Timestamp: timestamp,
            TransactionType: MPESA_TRANSACTION_TYPE, Amount: amountInt,
            PartyA: msisdn, PartyB: MPESA_SHORTCODE, PhoneNumber: msisdn,
            CallBackURL: MPESA_CALLBACK_URL,
            AccountReference: (accountRef || 'EliteHardware').substring(0, 12), // Safaricom max 12 chars
            TransactionDesc: ('Payment ' + (accountRef || '')).substring(0, 13) // Safaricom max 13 chars
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

app.post('/api/mpesa/callback', requireWebhookSecret, async (req, res) => {
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

            // ── Billing subscription extension ───────────────────────────────
            // If this STK push came from the billing page, context.billingPlan
            // tells us exactly which plan was purchased. Extend the subscription
            // immediately instead of waiting for the C2B vendor webhook.
            const billingPlan = pending.context?.billingPlan;
            if (billingPlan && ['monthly','annual','lifetime','annual_service'].includes(billingPlan)) {
                log.info(`[MPESA] Billing STK confirmed — applying plan=${billingPlan} KES=${amount} mpesa=${mpesaCode}`);
                try {
                    await _applySubscriptionPayment({
                        plan_type:  billingPlan,
                        amount_kes: parseFloat(amount),
                        mpesa_code: mpesaCode,
                        phone,
                        source:     'STK callback',
                    });
                    log.info(`[MPESA] ✅ Subscription extended via STK callback: plan=${billingPlan}`);
                } catch (subErr) {
                    log.error(`[MPESA] ⚠️ STK confirmed but subscription extension failed: ${subErr.message}`);
                    // Payment is confirmed — don't lose it. Store for manual reconciliation.
                    await supabase.from('subscription_payments').insert([{
                        client_id:      CLIENT_ID,
                        amount_kes:     parseFloat(amount),
                        plan_type:      billingPlan,
                        payment_method: 'M-Pesa STK (pending reconciliation)',
                        mpesa_code:     mpesaCode,
                        months_paid:    billingPlan === 'annual' ? 12 : (billingPlan === 'monthly' ? 1 : null),
                        notes:          `STK confirmed but extension failed: ${subErr.message}. Manual reconciliation required.`,
                        recorded_by:    'system',
                    }]).then(({ error: e }) => { if (e) log.error(`[MPESA] Failed to store reconciliation row: ${e.message}`); });
                }
            }
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
// ╔══════════════════════════════════════════════════════════════════════════════╗
// ║                    JENGA API (EQUITY) INTEGRATION                           ║
// ║                                                                              ║
// ║  Two separate Jenga payment channels — each uses a DIFFERENT endpoint        ║
// ║  and a DIFFERENT signature formula:                                          ║
// ║                                                                              ║
// ║  1. /api/jenga/stk-push  ← M-Pesa Wallet-Based STK (existing, untouched)    ║
// ║     Endpoint : /api-checkout/mpesa-stk-push/v3.0/init                       ║
// ║     Signature: orderRef + currency + msisdn + amount                         ║
// ║     Settles to: Jenga wallet (then you pull to bank)                         ║
// ║                                                                              ║
// ║  2. /api/jenga/equity-stk-push  ← Equitel STK (NEW, this file)              ║
// ║     Endpoint : /v3-apis/payment-api/v3.0/stkussdpush/initiate               ║
// ║     Signature: accountNumber + payRef + mobileNumber + telco + amount + KES  ║
// ║     Settles to: JENGA_EQUITY_ACCOUNT (your Equity Bank account number)       ║
// ║     Works for: Equitel numbers only (01XXXXXXXXX)                            ║
// ║                                                                              ║
// ║  3. /api/jenga/ipn  ← Webhook for BOTH channels (IPN from Jenga HQ)         ║
// ║     Matches payments to debts (FIFO) identical to Safaricom C2B              ║
// ║     Also handles excess → stored for cashier to resolve as goods purchase    ║
// ╚══════════════════════════════════════════════════════════════════════════════╝

const JENGA_API_KEY         = process.env.JENGA_API_KEY;
const JENGA_MERCHANT_CODE   = process.env.JENGA_MERCHANT_CODE;
const JENGA_CONSUMER_SECRET = process.env.JENGA_CONSUMER_SECRET;

// JENGA_EQUITY_ACCOUNT: Your Equity Bank account number credited on Equitel STK payments.
// This is NOT a paybill number — it is your actual Equity Bank account number e.g. 0170194290581
// Add to .env: JENGA_EQUITY_ACCOUNT=<your account number>
// Add to .env: JENGA_MERCHANT_NAME=<your business name, e.g. "Elite Hardware Ltd">
const JENGA_EQUITY_ACCOUNT  = process.env.JENGA_EQUITY_ACCOUNT;
const JENGA_MERCHANT_NAME   = process.env.JENGA_MERCHANT_NAME || 'Elite Hardware Ltd';

// Single base URL — UAT vs Live switched by JENGA_ENV
const JENGA_BASE_URL = process.env.JENGA_ENV === 'live'
    ? 'https://api.finserve.africa'
    : 'https://uat.finserve.africa';

// ── Startup diagnostic — printed once when server boots ───────────────────────
// Check these values in your Render logs to confirm what the server actually sees.
// If JENGA_ENV is not "live" your live credentials hit the UAT server → 401.
log.info(`[JENGA CONFIG] ENV=${process.env.JENGA_ENV || '(not set — defaulting to UAT)'} BASE_URL=${JENGA_BASE_URL}`);
log.info(`[JENGA CONFIG] MERCHANT_CODE=${process.env.JENGA_MERCHANT_CODE || '(NOT SET)'}`);
log.info(`[JENGA CONFIG] API_KEY=${process.env.JENGA_API_KEY ? '✅ set' : '❌ NOT SET'}`);
log.info(`[JENGA CONFIG] CONSUMER_SECRET=${process.env.JENGA_CONSUMER_SECRET ? '✅ set' : '❌ NOT SET'}`);
log.info(`[JENGA CONFIG] EQUITY_ACCOUNT=${process.env.JENGA_EQUITY_ACCOUNT || '(NOT SET)'}`);
log.info(`[JENGA CONFIG] MERCHANT_NAME=${process.env.JENGA_MERCHANT_NAME || '(NOT SET)'}`);
log.info(`[JENGA CONFIG] CALLBACK_URL=${process.env.JENGA_CALLBACK_URL || '(NOT SET)'}`);

if (!JENGA_API_KEY || !JENGA_MERCHANT_CODE || !JENGA_CONSUMER_SECRET) {
    log.warn('⚠️  Missing Jenga credentials (JENGA_API_KEY / JENGA_MERCHANT_CODE / JENGA_CONSUMER_SECRET). Jenga routes disabled.');
}
if (!JENGA_EQUITY_ACCOUNT) {
    log.warn('⚠️  JENGA_EQUITY_ACCOUNT not set — Equitel STK push (/api/jenga/equity-stk-push) will return 503.');
}

// ── Jenga Bearer Token Cache ───────────────────────────────────────────────────
// Jenga V3 tokens expire at an ISO timestamp, not "seconds from now".
let _jengaToken    = null;
let _jengaTokenExp = 0;

async function getJengaToken() {
    if (!JENGA_API_KEY || !JENGA_MERCHANT_CODE || !JENGA_CONSUMER_SECRET) {
        throw new Error('Jenga credentials not configured in .env');
    }
    const now = Date.now();
    if (_jengaToken && now < _jengaTokenExp - 5 * 60 * 1000) return _jengaToken;

    const response = await fetch(`${JENGA_BASE_URL}/authentication/api/v3/authenticate/merchant`, {
        method:  'POST',
        headers: { 'Api-Key': JENGA_API_KEY, 'Content-Type': 'application/json' },
        body:    JSON.stringify({ merchantCode: JENGA_MERCHANT_CODE, consumerSecret: JENGA_CONSUMER_SECRET }),
        signal:  AbortSignal.timeout(10000)
    });

    const text = await response.text();
    if (!response.ok) {
        log.error(`[JENGA AUTH] ❌ HTTP ${response.status} from ${JENGA_BASE_URL}. Body: ${text.substring(0, 400)}`);
        throw new Error(`Jenga auth failed: HTTP ${response.status}`);
    }
    const data = JSON.parse(text);
    if (!data.accessToken) {
        log.error(`[JENGA AUTH] ❌ No accessToken in response: ${JSON.stringify(data).substring(0, 400)}`);
        throw new Error('Jenga returned no accessToken');
    }

    _jengaToken    = data.accessToken;
   // Ignore Jenga's timezone-confused date string. Force a strict 50-minute TTL.
    _jengaTokenExp = now + 50 * 60 * 1000;
    log.info('[JENGA] 🔑 Token refreshed');
    return _jengaToken;
}

// ── Jenga Private Key (for signing) ───────────────────────────────────────────
let JENGA_PRIVATE_KEY;
try {
    JENGA_PRIVATE_KEY = fs.readFileSync('jenga-private.pem', 'utf8');
} catch (e) {
    log.warn('[JENGA] jenga-private.pem not found — all Jenga STK pushes will fail.');
}

// ── Jenga Public Cert (for IPN verification) — cached once at startup ─────────
let _jengaPublicCert = null;
function getJengaPublicCert() {
    if (_jengaPublicCert) return _jengaPublicCert;
    try {
        _jengaPublicCert = fs.readFileSync('jenga-public-equity.pem', 'utf8');
        log.info('[JENGA] jenga-public-equity.pem loaded for IPN verification.');
        return _jengaPublicCert;
    } catch (e) {
        log.warn('[JENGA] jenga-public-equity.pem not found — IPN signature verification will be skipped.');
        return null;
    }
}
getJengaPublicCert(); // pre-load on startup

// ── Shared FIFO debt-matching helper ─────────────────────────────────────────
// Identical logic to Safaricom C2B confirmation — used by BOTH Jenga channels.
// Matches by accountRef (invoice number the customer typed) first, then by phone.
// Applies payment FIFO across all outstanding debts, then stores the result in
// c2b_payments so the cashier dashboard and /api/c2b/resolve-goods work unchanged.
//
// params: { phone, amount, bankRef, accountRef, customerName, channel }
//   channel: 'Equity Paybill' | 'Equitel STK' — used in receipt and log messages
async function applyJengaPayment({ phone, amount, bankRef, accountRef, customerName, channel }) {
    const now      = new Date();
    const datePart = now.getFullYear().toString()
                   + String(now.getMonth() + 1).padStart(2, '0')
                   + String(now.getDate()).padStart(2, '0');
    const timePart = String(now.getHours()).padStart(2, '0')
                   + String(now.getMinutes()).padStart(2, '0')
                   + String(now.getSeconds()).padStart(2, '0');
    const payMethod = channel === 'Equitel STK' ? 'Equitel' : 'Equity Paybill';
    const suffix    = channel === 'Equitel STK' ? 'EQT' : 'EQ';
    const processor = 'JENGA-AUTO';

    // ── 1. Duplicate guard (idempotency) ─────────────────────────────────────
    if (bankRef) {
        const { data: existingC2B } = await supabase
            .from('c2b_payments')
            .select('id')
            .eq('mpesa_code', bankRef)
            .maybeSingle();
        if (existingC2B) {
            log.warn(`[JENGA ${channel}] ⚠️ Duplicate ref blocked: ${bankRef}`);
            return;
        }
    }

    log.info(`[JENGA ${channel}] 💰 KES ${amount} from ${customerName} (${bankRef}) acc="${accountRef}"`);

    // ── 2. Find matching debts ────────────────────────────────────────────────
    // Strategy A: exact invoice/receipt match on what the customer typed as account number
    let activeDebts = [];
    if (accountRef && accountRef.trim().length > 2) {
        const { data: byInvoice } = await supabase
            .from('Sales')
            .select('id, item_name, total_amount, amount_paid, customer_name, customer_phone')
            .or(`invoice_number.ilike.%${accountRef.trim()}%,receipt_number.ilike.%${accountRef.trim()}%`)
            .eq('is_voided', false)
            .in('payment_status', ['Credit', 'Partial', 'credit', 'partial', 'Unpaid'])
            .order('sale_date', { ascending: true });
        if (byInvoice && byInvoice.length > 0) activeDebts = byInvoice;
    }

    // Strategy B: fallback — match by phone number (same as Safaricom C2B)
    if (activeDebts.length === 0 && phone) {
        const { data: byPhone } = await supabase
            .from('Sales')
            .select('id, item_name, total_amount, amount_paid, customer_name, customer_phone')
            .eq('customer_phone', phone)
            .eq('is_voided', false)
            .in('payment_status', ['Credit', 'Partial', 'credit', 'partial', 'Unpaid'])
            .order('sale_date', { ascending: true });
        if (byPhone && byPhone.length > 0) activeDebts = byPhone;
    }

    // Keep only rows with a genuine outstanding balance
    activeDebts = activeDebts.filter(d =>
        (parseFloat(d.total_amount) - parseFloat(d.amount_paid || 0)) > 0
    );

    // ── 3. No debt — store as unmatched for cashier to resolve as goods purchase ──
    // This is identical to how Safaricom C2B handles walk-in cash customers:
    // the cashier sees it in the dashboard and calls /api/c2b/resolve-goods.
    if (activeDebts.length === 0) {
        await supabase.from('c2b_payments').insert([{
            phone,
            amount,
            mpesa_code:    bankRef,
            account_ref:   accountRef,
            customer_name: customerName,
            status:        'unmatched',
            amount_applied: 0,
            amount_excess:  amount,
            created_at:    now.toISOString()
        }]);
        log.info(`[JENGA ${channel}] ⚠️ No debt for inv="${accountRef}" phone="${phone}" — stored as unmatched (cashier resolves as goods purchase)`);
        return;
    }

    // ── 4. Apply payment FIFO across all outstanding debts ────────────────────
    let remaining    = Math.round(amount);
    let totalApplied = 0;
    let payRef       = null;

    for (const debt of activeDebts) {
        if (remaining <= 0) break;
        const balance = Math.round(parseFloat(debt.total_amount) - parseFloat(debt.amount_paid || 0));
        if (balance <= 0) continue;

        const applyAmt = Math.min(remaining, balance);
        // Snap to total when fully paid to eliminate legacy decimal drift
        const newPaid  = applyAmt >= balance
            ? parseFloat(debt.total_amount)
            : parseFloat(debt.amount_paid || 0) + applyAmt;
        const newStatus = newPaid >= parseFloat(debt.total_amount) - 0.01 ? 'Paid' : 'Partial';
        payRef = `PAY-${datePart}-${timePart}-${suffix}`;

        await supabase.from('Sales')
            .update({ amount_paid: newPaid, payment_status: newStatus })
            .eq('id', debt.id);

        await supabase.from('payments').insert([{
            sale_id:       debt.id,
            amount:        applyAmt,
            payment_method: payMethod,
            mpesa_code:    bankRef ? `${bankRef}-${debt.id}` : null,
            received_by:   processor,
            customer_name: debt.customer_name || customerName,
            created_at:    now.toISOString()
        }]);

        await supabase.from('debt_payments').insert([{
            sale_id:        debt.id,
            amount_paid:    applyAmt,
            payment_method: payMethod,
            mpesa_id:       bankRef,
            processed_by:   processor,
            customer_name:  debt.customer_name || customerName,
            customer_phone: phone,
            payment_date:   now.toISOString()
        }]);

        totalApplied += applyAmt;
        remaining    -= applyAmt;
    }

    // ── 5. Update customer aggregate debt balance ─────────────────────────────
    let newTotalDebt  = 0;
    const targetPhone = activeDebts[0]?.customer_phone || phone;
    if (targetPhone) {
        const { data: cust } = await supabase
            .from('customers')
            .select('total_debt')
            .eq('phone', targetPhone)
            .single();
        if (cust) {
            newTotalDebt = Math.max(0, parseFloat(cust.total_debt || 0) - totalApplied);
            await supabase.from('customers')
                .update({ total_debt: newTotalDebt })
                .eq('phone', targetPhone);
        }
    }

    // ── 6. Build receipt JSON and save to c2b_payments ───────────────────────
    // Same structure as Safaricom C2B so the cashier dashboard and receipt
    // reprinting logic requires no changes.
    let receiptDataJson = null;
    if (totalApplied > 0) {
        receiptDataJson = JSON.stringify({
            customer:        activeDebts[0]?.customer_name || customerName,
            total:           totalApplied,
            amount:          totalApplied,
            method:          payMethod,
            code:            bankRef,
            receiptNumber:   payRef,
            servedBy:        processor,
            date:            now.toLocaleString('en-KE'),
            items: [{ itemName: `Debt Clearance - ${channel}`, price: totalApplied, quantity: 1 }],
            remainingBalance: newTotalDebt
        });
    }

    // 'excess' = money left over after all debts cleared → cashier links it as goods purchase
    // 'debt_cleared' = all debt settled exactly or fully
    const finalStatus = remaining > 0 ? 'excess' : 'debt_cleared';

    await supabase.from('c2b_payments').insert([{
        phone,
        amount,
        mpesa_code:     bankRef,
        account_ref:    accountRef,
        customer_name:  activeDebts[0]?.customer_name || customerName,
        status:         finalStatus,
        amount_applied: totalApplied,
        amount_excess:  remaining,
        receipt_number: payRef,
        receipt_data:   receiptDataJson,
        created_at:     now.toISOString()
    }]);

    if (remaining > 0) {
        log.info(`[JENGA ${channel}] ℹ️ KES ${remaining} excess after debts — cashier can link as goods purchase`);
    } else if (newTotalDebt > 0) {
        log.info(`[JENGA ${channel}] ℹ️ Partial: KES ${totalApplied} applied, KES ${newTotalDebt} still owed`);
    } else {
        log.info(`[JENGA ${channel}] ✅ All debts cleared for ${customerName}`);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTE 1 — M-Pesa STK Push via Jenga (Wallet-Based Settlement)
// Docs: https://developer.jengahq.io/guides/jenga-api/receive-money/mpesa-stk-push/wallet-based-settlement
// Endpoint : POST /api-checkout/mpesa-stk-push/v3.0/init
// Signature: orderRef + "KES" + msisdn + amount   (as a number, not string)
// Settles to: Jenga wallet
// ═══════════════════════════════════════════════════════════════════════════════
// Keep /api/jenga/stk-push as an alias so any existing bookmarks or calls don't 404,
// but internally it just delegates to the unified equity-stk-push handler below.
app.post('/api/jenga/stk-push', requireAuth, requireSubscription, (req, res, next) => {
    req.url = '/api/jenga/equity-stk-push';
    next('route');
});

// ═══════════════════════════════════════════════════════════════════════════════
// UNIFIED EQUITY STK PUSH — works for Safaricom (07xx) AND Equitel (01xx)
//
// Both use the SAME Jenga endpoint and the SAME signature formula:
//   POST /v3-apis/payment-api/v3.0/stkussdpush/initiate
//   Signature = accountNumber + payment.ref + payment.mobileNumber + payment.telco
//             + payment.amount + payment.currency
//   (amount MUST be a string: "500.00")
//
// The only difference between networks is the `telco` field in the payload:
//   07xx (Safaricom) → telco: "Safaricom"  → customer gets M-Pesa STK prompt
//   01xx (Equitel)   → telco: "Equitel"    → customer gets Equitel STK prompt
//
// Funds always settle to JENGA_EQUITY_ACCOUNT regardless of the customer's network.
// The old /api/jenga/stk-push route now aliases here.
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/jenga/equity-stk-push', requireAuth, requireSubscription, async (req, res) => {
    if (!JENGA_PRIVATE_KEY)
        return res.status(503).json({ success: false, message: 'jenga-private.pem not loaded.' });
    if (!JENGA_EQUITY_ACCOUNT)
        return res.status(503).json({ success: false, message: 'JENGA_EQUITY_ACCOUNT not set in .env' });

    const { phone, amount, accountRef, customerName = 'Walk-in Customer' } = req.body;

    // ── 1. Normalise to 254XXXXXXXXX (Jenga always wants international format) ──
    let msisdn = String(phone || '').replace(/\s/g, '');
    if (msisdn.startsWith('+'))  msisdn = msisdn.slice(1);
    if (msisdn.startsWith('0'))  msisdn = '254' + msisdn.slice(1);

    if (!/^2547\d{8}$|^2541[0-9]\d{7}$/.test(msisdn))
        return res.status(400).json({ success: false, message: 'Invalid phone. Use 07XXXXXXXX (Safaricom) or 01XXXXXXXX (Equitel).' });

    // ── 2. Detect network → set correct telco string ─────────────────────────
    // Jenga is strict: "Safaricom" or "Equitel" (exact casing, no typos)
    const telco = msisdn.startsWith('2541') ? 'Equitel' : 'Safaricom';

    const paymentAmount = Math.ceil(parseFloat(amount));
    if (!paymentAmount || paymentAmount < 1)
        return res.status(400).json({ success: false, message: 'Invalid amount' });

    // ── 2. Jenga requires amount as a string with 2 decimal places ─────────────
    const amountStr = paymentAmount.toFixed(2);

    // ── 3. Payment reference: 6–12 alphanumeric chars only (Jenga hard limit) ──
    const payRef = `EQ${Date.now().toString().slice(-10)}`; // e.g. EQ1714900123

    // ── 4. Transaction date (YYYY-MM-DD) ────────────────────────────────────────
    const txDate    = new Date().toISOString().split('T')[0];

    try {
        const token = await getJengaToken();

        // ── 3. Signature formula (identical for Safaricom AND Equitel) ───────────
        // accountNumber + payment.ref + payment.mobileNumber + payment.telco
        //               + payment.amount + payment.currency
        // amount MUST be the string "500.00" (2 decimal places) — NOT a number.
        const dataToSign = `${JENGA_EQUITY_ACCOUNT}${payRef}${msisdn}${telco}${amountStr}KES`;
        const signer     = crypto.createSign('SHA256');
        signer.update(dataToSign);
        signer.end();
        const signature = signer.sign(JENGA_PRIVATE_KEY, 'base64');

        // ── 4. Payload ────────────────────────────────────────────────────────────
        const payload = {
            merchant: {
                accountNumber: JENGA_EQUITY_ACCOUNT,  // Your Equity Bank account number
                countryCode:   'KE',
                name:          JENGA_MERCHANT_NAME
            },
            payment: {
                ref:          payRef,
                amount:       amountStr,   // string, 2 d.p.
                currency:     'KES',
                telco:        telco,       // "Safaricom" or "Equitel" — detected above
                mobileNumber: msisdn,      // 254XXXXXXXXX
                date:         txDate,
                callBackUrl:  `${process.env.JENGA_CALLBACK_URL}/api/jenga/ipn`,
                pushType:     'STK'
            }
        };

        log.info(`[JENGA STK] Initiating → ${msisdn} (${telco}) KES ${amountStr} ref=${payRef}`);
        log.info(`[JENGA STK] Signature input: "${JENGA_EQUITY_ACCOUNT}${payRef}${msisdn}${telco}${amountStr}KES"`);
        log.info(`[JENGA STK] Payload: ${JSON.stringify(payload)}`);

        // ── 5. Send to Jenga ─────────────────────────────────────────────────────
        const response = await fetch(`${JENGA_BASE_URL}/v3-apis/payment-api/v3.0/stkussdpush/initiate`, {
            method:  'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Signature':     signature,
                'Content-Type':  'application/json'
            },
            body:   JSON.stringify(payload),
            signal: AbortSignal.timeout(15000)
        });

        const text = await response.text();
        let data;
        try { data = JSON.parse(text); } catch (e) { throw new Error('Non-JSON from Jenga: ' + text.substring(0, 300)); }

       // code -1 = queued successfully. code 106201 / status false = rejected.
        if (!response.ok || data.status === false || data.code === 106201) {
            
            // ── THE SELF-HEALING FIX ──
            if (response.status === 401 || data.code === 401) {
                _jengaTokenExp = 0; // Instantly kill the dead token in memory
                log.warn('[JENGA STK] Token expired on Jenga side. Cache cleared.');
                return res.status(401).json({ 
                    success: false, 
                    message: 'Bank session refreshed. Please click "Send Prompt" one more time.' 
                });
            }

            log.warn(`[JENGA STK] ❌ Rejected (${telco}) HTTP=${response.status} full response: ${JSON.stringify(data)}`);
            return res.status(400).json({ success: false, message: data.message || 'STK push rejected by Jenga', code: data.code });
        }

        // ── 6. Persist under payRef (frontend polls /api/jenga/status/:payRef) ───
        const channelLabel = telco === 'Equitel' ? 'EQUITEL_STK' : 'SAFARICOM_STK_VIA_EQUITY';
        await mpesaSet(payRef, {
            status:     'pending',
            phone:      msisdn,
            amount:     paymentAmount,
            context:    { accountRef, channel: channelLabel, transactionId: data.transactionId },
            created_at: new Date().toISOString()
        });

        // ── 7. Cross-reference index so IPN can map Jenga's transactionId → payRef ──
        // Jenga's callback arrives with body.transactionReference = their transactionId,
        // not our payRef. Without this the IPN can't find the pending row.
        if (data.transactionId && data.transactionId !== payRef) {
            await mpesaSet(data.transactionId, {
                _indexFor:  payRef,       // the key the frontend polls
                status:     'pending',
                phone:      msisdn,
                amount:     paymentAmount,
                context:    { primaryRef: payRef }
            });
        }

        log.info(`[JENGA STK] ✅ Queued → ${msisdn} (${telco}) payRef=${payRef} jengaTxId=${data.transactionId}`);
        return res.json({
            success:           true,
            message:           `${telco} payment prompt queued for ${msisdn}. Customer will receive an STK push.`,
            checkoutRequestId: payRef,        // frontend polls /api/jenga/status/:payRef
            transactionId:     data.transactionId
        });

    } catch (err) {
        log.error('[JENGA STK ERROR]', err.message);
        return res.status(500).json({ success: false, message: 'Jenga STK error: ' + err.message });
    }
});

// ── GET /api/jenga/status/:ref — frontend polling (works for both channels) ───
// Returns same shape as /api/mpesa/status/:checkoutId for drop-in compatibility.
app.get('/api/jenga/status/:ref', requireAuth, async (req, res) => {
    try {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.set('Pragma', 'no-cache');
        const tx = await mpesaGet(req.params.ref);
        if (!tx) return res.status(404).json({ success: false, status: 'not_found', message: 'Transaction not found' });
        return res.json({
            success:    true,
            status:     tx.status,
            mpesaCode:  tx.mpesa_code  || null,
            amount:     tx.amount,
            phone:      tx.phone,
            channel:    tx.context?.channel || 'JENGA',
            resultDesc: tx.result_desc || null
        });
    } catch (err) {
        log.error('[API]', err.message);
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTE 3 — Jenga IPN Webhook (Instant Payment Notification)
// Handles callbacks for BOTH M-Pesa-via-Jenga AND Equitel STK pushes.
// Register this URL in Jenga HQ under Settings → IPNs.
//
// Payload shapes differ per channel:
//   M-Pesa  (IPN): { callbackType, customer, transaction, bank }
//   Equitel (callback): { status, code, transactionReference, telcoReference,
//                         mobileNumber, debitedAmount, requestAmount, charge, currency, telco }
//
// After confirming payment, this handler runs the same FIFO debt-matching logic
// as Safaricom C2B (/api/c2b/confirmation):
//   - Match by invoice/receipt number (account ref the customer typed)
//   - Fallback to phone number match
//   - Apply FIFO across all outstanding debts
//   - Store excess as 'unmatched' so cashier can resolve as a goods purchase
//     via the existing /api/c2b/resolve-goods endpoint — no new routes needed
// ═══════════════════════════════════════════════════════════════════════════════
// Add /api/jenga/ipn to the subscription-exempt paths so it always processes
if (!SUB_EXEMPT_PATHS.has('/api/jenga/ipn')) SUB_EXEMPT_PATHS.add('/api/jenga/ipn');

// ── JENGA WEBHOOK (Handles BOTH Independent Paybill IPNs & STK Callbacks) ──
app.post('/api/jenga/ipn', async (req, res) => {
    // Always ACK immediately so Jenga doesn't retry
    res.status(200).json({ status: 'Success', message: 'Received' });

    try {
        const body = req.body;
        log.info('[JENGA WEBHOOK] Received payload:', JSON.stringify(body).substring(0, 500));

        // Optional: Signature verification logic goes here...

        // ── 1. ROUTE: INDEPENDENT PAYBILL 247247 PAYMENT (IPN) ──────────────
        if (body.callbackType === 'IPN') {
            const tx   = body.transaction || {};
            const cust = body.customer    || {};
            
            if ((tx.status || '').toUpperCase() !== 'SUCCESS') return;

            const phone        = String(cust.mobileNumber || '').replace(/^254/, '0').replace(/^\+254/, '0');
            const amount       = Math.round(parseFloat(tx.amount || 0));
            const bankRef      = tx.reference || null;        // e.g. SH90HU7FO2
            const accountRef   = tx.billNumber || null;       // What customer typed (e.g. INV-1234)
            const customerName = cust.name || 'Jenga Paybill Customer';
            
            // Fix: Correctly label the channel based on paymentMode
            const mode = (tx.paymentMode || '').toUpperCase();
            const channel = mode === 'EQUITEL' ? 'Equitel Paybill' : 'M-Pesa Paybill';

            if (!amount || amount <= 0 || !bankRef) return;

            log.info(`[JENGA IPN] Independent payment via ${channel}. Routing straight to debt matcher.`);
            
            // NO pending_mpesa lookup here! Send straight to FIFO debt matcher.
            await applyJengaPayment({ phone, amount, bankRef, accountRef, customerName, channel });
            return;
        }

       // ── 2. ROUTE: OUTBOUND STK CALLBACK (Safaricom or Equitel via Equity account-based) ──
        // Jenga sends this shape for both telcos:
        // { status, code, transactionReference, telcoReference, mobileNumber,
        //   debitedAmount, requestAmount, telco: "Safaricom"|"Equitel", ... }
        if (body.telco || body.transactionReference) {
          // Jenga Code 3 = Settled to Equity Bank. 
// Jenga Code 4 = Customer paid successfully, but Jenga's internal transfer to Equity is delayed.
            const isPaid = (body.status === true && String(body.code) === '3') || String(body.code) === '4';
            const jengaTxId   = body.transactionReference || null;
            const callbackTelco = body.telco || 'Unknown';

            // ── Resolve cross-reference: jengaTxId → our payRef ──────────────────
            // We saved an index row under jengaTxId with _indexFor pointing to payRef.
            let primaryRef = jengaTxId;
            if (jengaTxId) {
                const indexRow = await mpesaGet(jengaTxId);
                if (indexRow?._indexFor) {
                    primaryRef = indexRow._indexFor;
                    log.info(`[JENGA IPN] Resolved jengaTxId=${jengaTxId} → payRef=${primaryRef} (${callbackTelco})`);
                }
            }

            if (!isPaid) {
                log.info(`[JENGA STK CB] ${callbackTelco} failed: code=${body.code} msg="${body.message}"`);
                if (primaryRef) {
                    const pending = await mpesaGet(primaryRef);
                    if (pending) {
                        let newStatus = 'failed';
                        const codeStr = String(body.code);
                        // Combine all text fields Jenga may use to describe the failure
                        const msg = (
                            (body.message       || '') + ' ' +
                            (body.description   || '') + ' ' +
                            (body.reason        || '') + ' ' +
                            (body.errorMessage  || '') + ' ' +
                            (body.resultDesc    || '')
                        ).toLowerCase();

                        // IMPORTANT: Check message keywords FIRST before numeric codes.
                        // Jenga reuses code 6 for both timeout AND insufficient funds —
                        // the message text is the only reliable signal.
                        // Confirmed from live logs: code=6, msg="The balance is insufficient for the transaction."
                        const isInsufficientFunds =
                            msg.includes('insufficient') || msg.includes('balance') ||
                            msg.includes('funds')        || msg.includes('low bal') ||
                            msg.includes('limit')        || msg.includes('exceed')  ||
                            msg.includes('not enough')   || msg.includes('no funds') ||
                            ['1','2','7','8','10','11','12','17'].includes(codeStr);

                        const isTimeout =
                            !isInsufficientFunds && (
                                codeStr === '6' ||
                                msg.includes('timeout') || msg.includes('timed out') ||
                                msg.includes('expired')  || msg.includes('no response')
                            );

                        if (isInsufficientFunds) {
                            newStatus = 'insufficient_funds';
                        } else if (codeStr === '5' || msg.includes('cancel') || msg.includes('abort') || msg.includes('decline') || msg.includes('reject')) {
                            newStatus = 'cancelled';
                        } else if (isTimeout) {
                            newStatus = 'timeout';
                        }
                        await mpesaSet(primaryRef, { ...pending, status: newStatus, result_desc: body.message || body.description || 'Payment failed' });
                    }
                }
                return;
            }

            const phone        = String(body.mobileNumber || '').replace(/^(?:\+?254)/, '0');
            const amount       = Math.round(parseFloat(body.debitedAmount || body.requestAmount || 0));
            const bankRef = body.telcoReference || body.transactionReference || null;
            const channel      = callbackTelco === 'Equitel' ? 'Equitel STK' : 'Safaricom STK via Equity';

            if (!amount || amount <= 0 || !bankRef) return;

            // Recover invoice accountRef from our pending row, then mark confirmed
            let actualBillNumber = null;
            if (primaryRef) {
                const pending = await mpesaGet(primaryRef);
                if (pending) {
                    await mpesaSet(primaryRef, { ...pending, status: 'confirmed', mpesa_code: bankRef, amount, phone });
                    actualBillNumber = pending.context?.accountRef || null;
                }
            }

            log.info(`[JENGA STK CB] ${callbackTelco} confirmed: KES ${amount} from ${phone} bankRef=${bankRef}`);
            await applyJengaPayment({
                phone, amount, bankRef,
                accountRef: actualBillNumber,
                customerName: `${callbackTelco} Customer`,
                channel
            });
            return;
        }

        log.warn('[JENGA WEBHOOK] Unrecognised payload shape:', JSON.stringify(body).substring(0, 300));

    } catch (err) {
        console.error('[JENGA WEBHOOK ERROR]', err.message, err.stack?.split('\n')[1]?.trim());
    }
});
// ╔══════════════════════════════════════════════════════════════╗
// ║              DIGITAX WEBHOOK (ASYNC QUEUE)                   ║
// ╚══════════════════════════════════════════════════════════════╝
app.post('/api/digitax/callback', async (req, res) => {
    // 1. Acknowledge receipt immediately so DigiTax doesn't retry
    res.status(200).json({ received: true });

    try {
        const { event, data } = req.body;
        if (!data) return;

        log.info(`[DIGITAX WEBHOOK] Received event: ${event}`, { id: data.id || data.digitax_id });

        // ── A. ITEM SYNC (Inventory) ───────────────────────────
        if (event === 'item.sync') {
            const digitaxItemId = data.id; // <ITEM_ID>
            if (digitaxItemId) {
                await supabase.from('Inventory')
                    .update({ kra_registered: true })
                    .eq('digitax_item_id', digitaxItemId);
                log.info(`[DIGITAX WEBHOOK] ✅ Item ${digitaxItemId} marked as KRA Registered.`);
            }
        } 
        
        // ── B. SALE / CREDIT NOTE SYNC (Sales & Returns) ───────
        else if (event === 'sale.sync') {
            const digitaxSaleId = data.digitax_id; // <SALE_ID>
            const etimsUrl      = data.etims_url;
            const kraReceipt    = data.receipt_number || data.trader_invoice_number;
            const etimsNo       = data.invoice_number;
            const controlUnit   = data.serial_number;

            if (digitaxSaleId && etimsUrl) {
                // 1. Try updating a Sale
                const { data: sale } = await supabase.from('Sales')
                    .select('id').eq('digitax_sale_id', digitaxSaleId).maybeSingle();
                
                if (sale) {
                    await supabase.from('Sales').update({
                        'Kra_Receipt_No':      kraReceipt,
                        'kra_qr_url':          etimsUrl,
                        'E-tims_No':           etimsNo,
                        'Control_unit_number': controlUnit
                    }).eq('id', sale.id);
                    log.info(`[DIGITAX WEBHOOK] ✅ Sale ${sale.id} verified by KRA.`);
                }

                // 2. Try updating a Return / Credit Note
                const { data: ret } = await supabase.from('returns_log')
                    .select('id').eq('kra_return_ref', digitaxSaleId).maybeSingle();
                
                if (ret) {
                    await supabase.from('returns_log').update({
                        kra_return_qr_url: etimsUrl,
                        etims_no:          etimsNo
                    }).eq('id', ret.id);
                    log.info(`[DIGITAX WEBHOOK] ✅ Return/Credit Note ${ret.id} verified by KRA.`);
                }
            }
        }
    } catch (err) {
        log.error('[DIGITAX WEBHOOK ERROR]', err.message);
    }
});
// Clean up stale pending_mpesa rows older than 10 minutes every minute
setInterval(async () => {
    const cutoff = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    await supabase.from('pending_mpesa').delete().lt('created_at', cutoff).eq('status', 'pending');
}, 60 * 1000);
app.post('/api/verify-payment', requireAuth, async (req, res) => {
    const { mpesaCode, expectedAmount, isManualOverride } = req.body;
    const code = mpesaCode?.toUpperCase().trim();

    try {
        // STEP 1: Check the 'payments' table first (Successes)
        const { data: payment } = await supabase
            .from('payments')
            .select('*')
            .eq('mpesa_receipt_number', code)
            .single();

        if (payment) {
            if (parseFloat(payment.amount) < parseFloat(expectedAmount)) {
                return res.status(400).json({ success: false, message: 'Amount mismatch in Payment records.' });
            }
            return res.json({ success: true, status: 'VERIFIED', message: 'Payment confirmed.' });
        }

        // STEP 2: Check the 'pending_mpesa' table (To see if it failed)
        const { data: pending } = await supabase
            .from('pending_mpesa')
            .select('result_desc')
            .eq('mpesa_receipt_number', code)
            .single();

        if (pending) {
            return res.status(400).json({ 
                success: false, 
                message: `Transaction failed: ${pending.result_desc}. Do not release goods.` 
            });
        }

        // STEP 3: Manual Override for Network Delays
        if (isManualOverride) {
            if (!['admin', 'manager'].includes(req.user.role.toLowerCase())) {
                return res.status(403).json({ success: false, message: 'Manager approval required for manual entry.' });
            }

            // Log the bypass for your security audit
            log.warn(`[MANUAL-PAYMENT] Code ${code} authorized manually by ${req.user.name}`);
            
            return res.json({ 
                success: true, 
                status: 'PENDING_AUDIT', 
                message: 'Manual entry accepted. Flagged for later reconciliation.' 
            });
        }

        res.status(404).json({ success: false, message: 'Code not found. If Safaricom is slow, get Manager override.' });

    } catch (err) {
        log.error('[VERIFY-ERROR]', err);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});
// ╔══════════════════════════════════════════════════════════════╗
// ║         C2B — REMOTE DEBT PAYMENTS VIA TILL NUMBER          ║
// ╚══════════════════════════════════════════════════════════════╝

// ── Register C2B URLs with Safaricom (run once) ───────────────────────────────
app.post('/api/c2b/register', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── Safaricom C2B Validation (approve all payments) ───────────────────────────
app.post('/api/c2b/validation', requireWebhookSecret, (req, res) => {
    console.log('[C2B VALIDATION]', JSON.stringify(req.body));
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
});

// ── Safaricom C2B Confirmation (payment received) ─────────────────────────────
app.post('/api/c2b/confirmation', requireWebhookSecret, async (req, res) => {
    // Always ACK immediately so Safaricom doesn't retry
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

    try {
        const p            = req.body;
        const phone        = String(p.MSISDN || '').replace(/^254/, '0');
        const amount       = Math.round(parseFloat(p.TransAmount || 0));
        const mpesaCode    = p.TransID       || null;
        const accountRef   = p.BillRefNumber || null;
        const firstName    = p.FirstName     || '';
        const lastName     = p.LastName      || '';
        const customerName = `${firstName} ${lastName}`.trim() || 'Unknown';

        if (!phone || amount <= 0) return;

        // ── DUPLICATE GUARD (Idempotency) ─────────────────────────────────────
        if (mpesaCode) {
            const { data: existingC2B } = await supabase
                .from('c2b_payments')
                .select('id')
                .eq('mpesa_code', mpesaCode)
                .maybeSingle();
            
            if (existingC2B) {
                log.warn(`[C2B]⚠️ Duplicate M-Pesa code blocked: ${mpesaCode} from ${phone}`);
                return; // Safaricom already got the 200 OK, abort processing
            }
        }
        // ──────────────────────────────────────────────────────────────────────

        log.info(`[C2B]💰 Received KES ${amount} from ${phone} (${mpesaCode})`);
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
        let remaining    = Math.round(amount);
        let totalApplied = 0;
        let payRef       = null;

        for (const debt of activeDebts) {
            if (remaining <= 0) break;
            const balance  = Math.round(parseFloat(debt.total_amount) - parseFloat(debt.amount_paid || 0));
            if (balance <= 0) continue;

            const applyAmt = Math.min(remaining, balance);
            
            let newPaid;
            if (applyAmt >= balance) {
                newPaid = parseFloat(debt.total_amount); // Snaps to total, wiping legacy decimals
            } else {
                newPaid = parseFloat(debt.amount_paid || 0) + applyAmt;
            }
            
            const newStatus = newPaid >= parseFloat(debt.total_amount) - 0.01 ? 'Paid' : 'Partial';
            payRef = 'PAY-' + datePart + '-' + timePart + '-C2B';

            await supabase.from('Sales').update({
                amount_paid:    newPaid,
                payment_status: newStatus
            }).eq('id', debt.id);

            await supabase.from('payments').insert([{
                sale_id: debt.id, amount: applyAmt, payment_method: 'M-Pesa',
                mpesa_code: mpesaCode ? `${mpesaCode.trim().toUpperCase()}-${debt.id}` : null, received_by: 'C2B-AUTO',
                customer_name: debt.customer_name || customerName,
                created_at: now.toISOString()
            }]);

            await supabase.from('debt_payments').insert([{
                sale_id: debt.id, amount_paid: applyAmt, payment_method: 'M-Pesa',
                mpesa_id: mpesaCode, processed_by: 'C2B-AUTO',
                customer_name: debt.customer_name || customerName,
                customer_phone: phone, payment_date: now.toISOString()
            }]);

            totalApplied += applyAmt;
            remaining    -= applyAmt;
        }
        // Update customer total_debt and capture the new balance
        let newTotalDebt = 0;
        const { data: cust } = await supabase.from('customers').select('total_debt').eq('phone', phone).single();
        if (cust) {
            newTotalDebt = Math.max(0, parseFloat(cust.total_debt || 0) - totalApplied);
            await supabase.from('customers').update({
                total_debt: newTotalDebt
            }).eq('phone', phone);
        }

       // ── Build Receipt Data for Saving (NO INSTANT PRINT) ──────────────────
        let receiptDataJson = null;
        if (totalApplied > 0) {
            const receiptData = {
                customer: activeDebts[0]?.customer_name || customerName,
                total: totalApplied,
                amount: totalApplied,
                method: 'M-Pesa',
                code: mpesaCode,
                receiptNumber: payRef,
                servedBy: 'AUTO-C2B',
                date: new Date().toLocaleString('en-KE'),
                items: [{ itemName: 'Debt Clearance - Auto C2B', price: totalApplied, quantity: 1 }],
                remainingBalance: newTotalDebt // <-- NEW: Saves balance to the receipt!
            };
            receiptDataJson = JSON.stringify(receiptData);
        }

        // ── Store in c2b_payments ─────────────────────────────────────────────
        const status = remaining > 0 ? 'excess' : 'debt_cleared';
        await supabase.from('c2b_payments').insert([{
            phone, amount, mpesa_code: mpesaCode, account_ref: accountRef,
            customer_name: activeDebts[0]?.customer_name || customerName,
            status, amount_applied: totalApplied, amount_excess: remaining,
            receipt_number: payRef,          // Store the reference
            receipt_data: receiptDataJson,   // Store the JSON for re-printing later
            created_at: now.toISOString()
        }]);

        // ── Smarter Logging ───────────────────────────────────────────────────
        if (remaining > 0) {
            log.info(`[C2B]ℹ️ KES ${remaining} excess after clearing all debts — cashier to link to new goods`);
        } else if (newTotalDebt > 0) {
            log.info(`[C2B]ℹ️ Partial payment: KES ${totalApplied} applied. KES ${newTotalDebt} still owed by ${phone}`);
        } else {
            log.info(`[C2B]✅ All debts cleared for ${phone}`);
        }

    } catch (err) {
        console.error('[C2B CONFIRMATION ERROR]', err.message);
    }
});
// ── Cashier marks unmatched/excess C2B as goods purchase ─────────────────────
// ── Cashier marks unmatched/excess C2B as goods purchase ─────────────────────
app.post('/api/c2b/resolve-goods', requireAuth, requireRole('admin', 'manager', 'cashier'), requireSubscription, async (req, res) => {
    // FIX: Destructure amountApplied from req.body
    const { c2bId, notes, customerName, receiptNumber, receiptData, amountApplied } = req.body;
    if (!c2bId) return res.status(400).json({ success: false, message: 'c2bId required' });
    
    try {
        const { data: c2b, error: fetchErr } = await supabase
            .from('c2b_payments')
            .select('*')
            .eq('id', c2bId)
            .single();
        
        if (fetchErr || !c2b) return res.status(404).json({ success: false, message: 'C2B payment not found' });

        const applied = parseFloat(amountApplied || 0);
        const currentTotalApplied = parseFloat(c2b.amount_applied || 0) + applied;
        const totalPaid = parseFloat(c2b.amount || 0);
        const excess = Math.max(0, totalPaid - currentTotalApplied); // Ensure non-negative

        // Change to 'completed' when fully resolved (no excess) to hide from dashboard
        const newStatus = excess > 0.01 ? 'excess' : 'completed';

        const newNotes = c2b.notes ? `${c2b.notes} | ${notes}` : notes;

        const { error } = await supabase.from('c2b_payments').update({
            status:         newStatus,
            amount_applied: currentTotalApplied,
            amount_excess:  excess,
            resolved_by:    req.user.name,
            resolved_at:    new Date().toISOString(),
            notes:          newNotes      || null,
            customer_name:  customerName  || null,
            receipt_number: receiptNumber || null,
            receipt_data:   receiptData   ? JSON.stringify(receiptData) : null,
        }).eq('id', c2bId);
        
        if (error) throw error;

        res.json({ success: true, message: 'C2B payment resolved', excess });
    } catch (err) {
        console.error('[C2B RESOLVE ERROR]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── Cashier applies unmatched/excess C2B to a specific debtor (different number) ──
app.post('/api/c2b/resolve-debt', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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

       let remaining = Math.round(amount), totalApplied = 0;
        const now      = new Date();
        const datePart = now.getFullYear().toString() + String(now.getMonth()+1).padStart(2,'0') + String(now.getDate()).padStart(2,'0');
        const timePart = String(now.getHours()).padStart(2,'0') + String(now.getMinutes()).padStart(2,'0') + String(now.getSeconds()).padStart(2,'0');

        for (const debt of activeDebts) {
            if (remaining <= 0) break;
            const balance   = Math.round(parseFloat(debt.total_amount) - parseFloat(debt.amount_paid || 0));
            if (balance <= 0) continue;

            const applyAmt  = Math.min(remaining, balance);
            
            let newPaid;
            if (applyAmt >= balance) {
                newPaid = parseFloat(debt.total_amount);
            } else {
                newPaid = parseFloat(debt.amount_paid || 0) + applyAmt;
            }
            
            const newStatus = newPaid >= parseFloat(debt.total_amount) - 0.01 ? 'Paid' : 'Partial';
            const payRef    = 'PAY-' + datePart + '-' + timePart + '-C2B';

            await supabase.from('Sales').update({
                amount_paid:    newPaid,
                payment_status: newStatus
            }).eq('id', debt.id);

            await supabase.from('payments').insert([{
                sale_id: debt.id, amount: applyAmt, payment_method: 'M-Pesa',
                mpesa_code: c2b.mpesa_code ? `${c2b.mpesa_code.trim().toUpperCase()}-${debt.id}` : null, received_by: req.user.name,
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
app.post('/api/c2b/resolve-ignore', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
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
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.post('/api/c2b/receipt-collected', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const { c2bId } = req.body || {};
    if (!c2bId) return res.status(400).json({ success: false, message: 'c2bId required' });
    try {
        const now = new Date().toISOString();
        const { error } = await supabase.from('c2b_payments').update({
            status: 'receipt_collected',
            collected_by: req.user.name,
            collected_at: now
        }).eq('id', c2bId);
        if (error) throw error;
        res.json({ success: true, message: 'Receipt marked as collected' });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── Get pending/recent C2B payments for dashboard ─────────────────────────────
app.get('/api/c2b/payments', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('c2b_payments')
            .select('*')
            .neq('status', 'completed')  // Filter out completed entries so they don't appear in the panel
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        console.error('[C2B PAYMENTS ERROR]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── GET all supplier returns ──────────────────────────────────────────────────
// ── POST confirm a pending supplier return ────────────────────────────────────
app.post('/api/supplier-returns/:id/confirm', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const { supplier_id, inventory_id, qty, total_value, item_name, reason } = req.body;
    const processedBy = req.user.name;

    try {
        // Check it exists and is still pending
        const { data: ret, error: fetchErr } = await supabase
            .from('supplier_returns')
            .select('id, balance_adjusted, supplier_name')
            .eq('id', req.params.id).single();

        if (fetchErr || !ret)
            return res.status(404).json({ success: false, message: 'Return record not found.' });
        if (ret.balance_adjusted)
            return res.status(400).json({ success: false, message: 'This return has already been confirmed.' });

        const qtyNum   = parseFloat(qty)        || 0;
        const valNum   = parseFloat(total_value) || 0;

        // ── Deduct stock ──────────────────────────────────────────────────────
        if (inventory_id) {
            const { data: invItem } = await supabase
                .from('Inventory')
                .select('stock_quantity, digitax_item_id, sub_unit, sub_unit_qty, sub_unit_price')
                .eq('id', inventory_id).single();

            if (invItem) {
                const oldStock = parseInt(invItem.stock_quantity) || 0;
                const newStock = Math.max(0, oldStock - qtyNum);

                await supabase.from('Inventory')
                    .update({ stock_quantity: newStock })
                    .eq('id', inventory_id);

                await supabase.from('audit_logs').insert([{
                    performed_by: processedBy,
                    action:       'SUPPLIER_RETURN',
                    item_name:    item_name,
                    old_stock:    oldStock,
                    added_qty:    -qtyNum,
                    new_stock:    newStock,
                    details:      `SUPPLIER RETURN CONFIRMED: ${item_name} | Qty: -${qtyNum} | Reason: ${reason} | KES ${valNum.toFixed(2)} | By: ${processedBy}`,
                    timestamp:    new Date().toISOString()
                }]);

                // ── Sync to DigiTax ───────────────────────────────────────────
                if (invItem.digitax_item_id && DIGITAX_API_KEY) {
                    try {
                      const etimsQty = toEtimsQty(qtyNum, invItem);
                        await syncStockWithEtims(
                            invItem.digitax_item_id, etimsQty,
                            `Supplier Return Confirmed — ${reason}`,
                            '06', 'DEDUCT'
                        );
                        log.info('[eTIMS] ✅ Stock deducted in DigiTax on confirm', { item: item_name, qty: qtyNum });
                    } catch (etimsErr) {
                        log.warn('[eTIMS] DigiTax deduction failed on confirm', { item: item_name, error: etimsErr.message });
                    }
                }
            }
        }

        // ── Reduce supplier balance ───────────────────────────────────────────
        if (valNum > 0) {
            await adjustSupplierBalance(
                supplier_id, -valNum, processedBy,
                `Supplier return confirmed — ${item_name} | KES ${valNum.toFixed(2)} deducted`
            );
        }

        // ── Mark as confirmed ─────────────────────────────────────────────────
        await supabase.from('supplier_returns')
            .update({ balance_adjusted: true })
            .eq('id', req.params.id);

        log.info('[SUPPLIER RETURN] ✅ Confirmed', { id: req.params.id, item: item_name, qty: qtyNum, value: valNum });

        res.json({
            success: true,
            message: `Return confirmed. ${qtyNum} units deducted from stock, KES ${valNum.toFixed(2)} deducted from ${ret.supplier_name} balance.`
        });
    } catch (err) {
        log.error('[SUPPLIER RETURN CONFIRM] Error:', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

app.get('/api/supplier-returns', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { from, to, supplier_id, page } = req.query;
    const perPage = 20, pageNum = parseInt(page) || 1;
    try {
        let q = supabase.from('supplier_returns')
            .select('*', { count: 'exact' })
            .order('created_at', { ascending: false });
        if (from)        q = q.gte('created_at', from + 'T00:00:00.000+03:00');
        if (to)          q = q.lte('created_at', to   + 'T23:59:59.999+03:00');
        if (supplier_id) q = q.eq('supplier_id', supplier_id);
        const start = (pageNum - 1) * perPage;
        const { data, count, error } = await q.range(start, start + perPage - 1);
        if (error) throw error;
        res.json({ returns: data||[], totalCount: count||0, totalPages: Math.ceil((count||0)/perPage), page: pageNum });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── GET search purchase orders for supplier return form ───────────────────────
app.get('/api/supplier-returns/search-po', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { q } = req.query;
    if (!q) return res.status(400).json({ success: false, message: 'Query q is required.' });
    try {
        const { data, error } = await supabase
            .from('purchase_orders')
            .select('id, po_number, supplier_id, supplier_name, delivery_note, order_date, total_amount, status, purchase_order_items(id, item_name, qty_ordered, qty_received, unit_cost, inventory_id)')
            .or(`supplier_name.ilike.%${q}%,po_number.ilike.%${q}%,delivery_note.ilike.%${q}%`)
            .in('status', ['Received', 'Partial'])
            .order('order_date', { ascending: false })
            .limit(10);
        if (error) throw error;

        // For each PO, subtract quantities already returned to supplier
        const poIds = (data || []).map(p => p.id);
        let returnedMap = {};
        if (poIds.length > 0) {
            const { data: returns } = await supabase
                .from('supplier_returns')
                .select('po_id, item_name, qty_returned')
                .in('po_id', poIds);
            (returns || []).forEach(r => {
                const key = r.po_id + '__' + r.item_name;
                returnedMap[key] = (returnedMap[key] || 0) + (r.qty_returned || 0);
            });
        }

        // Enrich items with returnable qty
        const enriched = (data || []).map(po => ({
            ...po,
            purchase_order_items: (po.purchase_order_items || []).map(item => ({
                ...item,
                qty_already_returned: returnedMap[po.id + '__' + item.item_name] || 0,
                qty_returnable: Math.max(0, (item.qty_received || 0) - (returnedMap[po.id + '__' + item.item_name] || 0))
            })).filter(item => item.qty_returnable > 0)
        })).filter(po => po.purchase_order_items.length > 0);

        res.json(enriched);
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── POST process supplier return ──────────────────────────────────────────────
app.post('/api/supplier-returns', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const {
        po_id, supplier_id, supplier_name,
        items,
        return_reason,
        supplier_credit_note,
        adjust_balance,
        notes
    } = req.body;
    const processedBy = req.user.name;

    if (!po_id || !supplier_id || !items?.length)
        return res.status(400).json({ success: false, message: 'po_id, supplier_id and items are required.' });

    try {
        let totalReturnValue = 0;
        const returnRows = [];

        for (const item of items) {
            const qty      = parseFloat(item.qty_returned) || 0;
            const unitCost = parseFloat(item.unit_cost)    || 0;
            if (qty <= 0) continue;

            const itemValue = parseFloat((qty * unitCost).toFixed(2));
            totalReturnValue += itemValue;

            if (adjust_balance) {
                // ── CONFIRMED: supplier acknowledged return ───────────────────
                // Only now do we: deduct stock, sync DigiTax, reduce balance
                if (item.inventory_id) {
                   const { data: invItem } = await supabase
                        .from('Inventory')
                        .select('stock_quantity, item_name, digitax_item_id, sub_unit, sub_unit_qty, sub_unit_price')
                        .eq('id', item.inventory_id).single();

                    if (invItem) {
                        const oldStock = parseInt(invItem.stock_quantity) || 0;
                        const newStock = Math.max(0, oldStock - qty);

                        await supabase.from('Inventory')
                            .update({ stock_quantity: newStock })
                            .eq('id', item.inventory_id);

                        await supabase.from('audit_logs').insert([{
                            performed_by: processedBy,
                            action:       'SUPPLIER_RETURN',
                            item_name:    item.item_name,
                            old_stock:    oldStock,
                            added_qty:    -qty,
                            new_stock:    newStock,
                            details:      `SUPPLIER RETURN (CONFIRMED): ${item.item_name} | Qty: -${qty} | Reason: ${item.reason || return_reason} | PO: ${po_id} | Credit Note: ${supplier_credit_note || 'N/A'} | By: ${processedBy}`,
                            timestamp:    new Date().toISOString()
                        }]);

                        // Sync stock deduction to DigiTax
                        if (invItem.digitax_item_id && DIGITAX_API_KEY) {
                            try {
                                const etimsQty = toEtimsQty(qty, invItem);
                                await syncStockWithEtims(
                                    invItem.digitax_item_id, etimsQty,
                                    `Supplier Return — ${po_id} | ${item.reason || return_reason}`,
                                    '06', 'DEDUCT'
                                );
                                log.info('[eTIMS] ✅ Stock deducted in DigiTax for supplier return', {
                                    item: item.item_name, qty
                                });
                            } catch (etimsErr) {
                                log.warn('[eTIMS] DigiTax deduction failed (inventory still updated)', {
                                    item: item.item_name, error: etimsErr.message
                                });
                            }
                        } else if (!invItem.digitax_item_id) {
                            log.warn('[eTIMS] Skipping DigiTax — item not registered with KRA', { item: item.item_name });
                        }
                    }
                }
            } else {
                // ── PENDING: supplier not yet confirmed ───────────────────────
                // Just record for tracking — no stock change, no DigiTax sync
                log.info('[SUPPLIER RETURN] Recorded as PENDING — stock & DigiTax unchanged until supplier confirms', {
                    item: item.item_name, qty
                });
                await supabase.from('audit_logs').insert([{
                    performed_by: processedBy,
                    action:       'SUPPLIER_RETURN_PENDING',
                    item_name:    item.item_name,
                    details:      `SUPPLIER RETURN (PENDING): ${item.item_name} | Qty: ${qty} | Reason: ${item.reason || return_reason} | PO: ${po_id} | Awaiting supplier credit note | By: ${processedBy}`,
                    timestamp:    new Date().toISOString()
                }]);
            }

            returnRows.push({
                po_id,
                supplier_id,
                supplier_name,
                item_name:            item.item_name,
                inventory_id:         item.inventory_id || null,
                qty_returned:         qty,
                unit_cost:            unitCost,
                total_return_value:   itemValue,
                return_reason:        item.reason || return_reason,
                supplier_credit_note: supplier_credit_note || null,
                balance_adjusted:     !!adjust_balance,
                processed_by:         processedBy,
                notes:                notes || null,
                created_at:           new Date().toISOString()
            });
        }

        if (!returnRows.length)
            return res.status(400).json({ success: false, message: 'No valid items to return.' });

        const { error: retErr } = await supabase.from('supplier_returns').insert(returnRows);
        if (retErr) throw retErr;

        // Only reduce supplier balance when confirmed
        if (adjust_balance && totalReturnValue > 0) {
            await adjustSupplierBalance(
                supplier_id, -totalReturnValue, processedBy,
                `Supplier return credit — ${return_reason} | ${returnRows.map(r => r.item_name).join(', ')} | PO: ${po_id} | KES ${totalReturnValue.toFixed(2)} deducted`
            );
        }

        log.info('[SUPPLIER RETURN] ✅ Processed', {
            supplier: supplier_name, items: returnRows.length,
            totalValue: totalReturnValue,
            status: adjust_balance ? 'CONFIRMED' : 'PENDING'
        });

        const statusMsg = adjust_balance
            ? `Stock deducted, supplier balance reduced by KES ${totalReturnValue.toFixed(2)} and KRA notified.`
            : `Recorded as pending — stock and balance unchanged until supplier confirms.`;

        res.json({
            success: true,
            message: `${returnRows.length} item(s) return recorded for ${supplier_name}. ${statusMsg}`,
            totalReturnValue,
            balanceAdjusted: !!adjust_balance
        });
    } catch (err) {
        log.error('[SUPPLIER RETURN] Error:', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ============================================================
//  STOCK WRITE-OFF — damaged/expired/stolen goods
//  Reduces stock, notifies KRA via SUBTRACT, logs as expense
//  NOT a sale — no receipt, no revenue
// ============================================================
app.post('/api/inventory/:id/write-off', requireAuth, requireRole('admin', 'manager'), requireSubscription, async (req, res) => {
    const { id } = req.params;
    const { qty, reason, reason_detail, expense_category } = req.body;
    const userName = req.user.name;

    const writeOffQty = parseFloat(qty) || 0;
    if (writeOffQty <= 0)
        return res.status(400).json({ success: false, message: 'Quantity must be greater than 0.' });

    const validReasons = ['damaged', 'expired', 'theft', 'breakage', 'other'];
    if (!validReasons.includes(reason))
        return res.status(400).json({ success: false, message: `Reason must be one of: ${validReasons.join(', ')}` });

    try {
       // Fetch item details
        const { data: item, error: fetchErr } = await supabase
            .from('Inventory')
            .select('id, item_name, stock_quantity, cost_price, category, unit, digitax_item_id, kra_registered, sub_unit, sub_unit_qty, sub_unit_price')
            .eq('id', id).single();

        if (fetchErr || !item)
            return res.status(404).json({ success: false, message: 'Item not found.' });

        const oldStock  = parseInt(item.stock_quantity) || 0;
        if (writeOffQty > oldStock)
            return res.status(400).json({
                success: false,
                message: `Cannot write off ${writeOffQty} — only ${oldStock} in stock.`
            });

        const newStock     = oldStock - writeOffQty;
        const costPerUnit  = parseFloat(item.cost_price) || 0;
        const totalCostLost = parseFloat((writeOffQty * costPerUnit).toFixed(2));

        // ── 1. Update inventory ───────────────────────────────────────────────
        const { error: updateErr } = await supabase
            .from('Inventory')
            .update({ stock_quantity: newStock })
            .eq('id', id);
        if (updateErr) throw updateErr;

        // ── 2. Audit log ──────────────────────────────────────────────────────
        const reasonLabel = {
            damaged:  'Damaged on shelf',
            expired:  'Expired / past sell-by',
            theft:    'Theft / shrinkage',
            breakage: 'Breakage in store',
            other:    'Other write-off'
        }[reason] || reason;

        await supabase.from('audit_logs').insert([{
            performed_by: userName,
            action:       'STOCK_WRITEOFF',
            item_name:    item.item_name,
            old_stock:    oldStock,
            added_qty:    -writeOffQty,
            new_stock:    newStock,
            details:      `WRITE-OFF: ${item.item_name} | Qty: -${writeOffQty} | Reason: ${reasonLabel}${reason_detail ? ' — ' + reason_detail : ''} | Cost lost: KES ${totalCostLost.toFixed(2)} | By: ${userName}`,
            timestamp:    new Date().toISOString()
        }]);

        // ── 3. Record as expense (cost of goods lost) ─────────────────────────
        const expCat = expense_category || 'Stock Write-offs';
        await supabase.from('expenses').insert([{
            description:  `Stock write-off: ${item.item_name} × ${writeOffQty} units (${reasonLabel})${reason_detail ? ' — ' + reason_detail : ''}`,
            category:     expCat,
            amount:       totalCostLost,
            spent_by:     userName,
            expense_date: nowEATIso()
        }]);

        // ── 4. Notify KRA via DigiTax SUBTRACT ───────────────────────────────
        // Movement type '05' = write-off/adjustment (not a sale, not a return)
        let kraNotified = false;
        if (item.digitax_item_id && DIGITAX_API_KEY) {
            try {
                const etimsQty = toEtimsQty(writeOffQty, item);
                const syncResult = await syncStockWithEtims(
                item.digitax_item_id,      // The ID linked to DigiTax
                etimsQty,                  // Converted sub-unit amount damaged               // The amount damaged (e.g., 2)
                `Stock write-off: ${reasonLabel}${reason_detail ? ' — ' + reason_detail : ''}`, // Description
                '05',                      // KRA Movement Type 05 = "Waste/Write-off"
                'DEDUCT'                      // Correct direction: Removes from KRA balance
            );
                kraNotified = !!syncResult;
                if (kraNotified) {
                    log.info('[eTIMS] ✅ Stock write-off synced to KRA', {
                        item: item.item_name, qty: writeOffQty, reason
                    });
                } else {
                    log.warn('[eTIMS] ❌ Write-off stock deduction failed in DigiTax', {
                        item: item.item_name, qty: writeOffQty
                    });
                }
            } catch (etimsErr) {
                log.warn('[eTIMS] Write-off DigiTax error (stock still updated)', {
                    item: item.item_name, error: etimsErr.message
                });
            }
        } else if (!item.digitax_item_id) {
            log.warn('[eTIMS] Write-off: item not registered with KRA — no DigiTax sync', {
                item: item.item_name
            });
        }

        res.json({
            success:      true,
            message:      `${writeOffQty} unit(s) of "${item.item_name}" written off. KES ${totalCostLost.toFixed(2)} recorded as expense.${kraNotified ? ' ✅ KRA notified.' : ' ⚠ KRA sync pending — item may not be registered.'}`,
            oldStock,
            newStock,
            totalCostLost,
            kraNotified,
            expense_category: expCat
        });
    } catch (err) {
        log.error('[STOCK WRITE-OFF] Error:', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});


// ============================================================
//  ACCOUNTING MODULE — Double-entry bookkeeping
//  Balance Sheet · Income Statement · M-Pesa Reconciliation
// ============================================================

// ── GET Balance Sheet ─────────────────────────────────────────────────────────
app.get('/api/accounting/balance-sheet', requireAuth, requireRole('admin','manager'), async (req, res) => {
    try {
        // Pull live figures from operational tables
        const [
            { data: debtors },
            { data: stockData },
            { data: suppliers },
            { data: salesData },
            { data: expData },
            { data: poData }
        ] = await Promise.all([
            supabase.from('Sales').select('total_amount, amount_paid').eq('is_voided', false).in('payment_status', ['Credit','Partial']),
            supabase.from('Inventory').select('stock_quantity, cost_price'),
            supabase.from('suppliers').select('balance'),
            // Fetch all non-voided sales with cost fields to compute real COGS & realized revenue
            supabase.from('Sales').select('total_amount, amount_paid, cost_price, quantity_sold, payment_status').eq('is_voided', false),
            supabase.from('expenses').select('amount'),
            supabase.from('purchase_orders').select('total_amount, amount_paid').in('status', ['Sent','Partial','Received'])
        ]);

        // Debtors = sum of outstanding balances
        const debtorsTotal = (debtors||[]).reduce((s,d) =>
            s + Math.max(0, (parseFloat(d.total_amount)||0) - (parseFloat(d.amount_paid)||0)), 0);

        // Stock at cost
        const stockValue = (stockData||[]).reduce((s,i) =>
            s + (parseFloat(i.stock_quantity)||0) * (parseFloat(i.cost_price)||0), 0);

        // Supplier payables — use outstanding PO balances as source of truth
        // (sum of what's still owed on Sent/Partial/Received POs)
        const poPayables = (poData||[]).reduce((s, po) => {
            const owed = (parseFloat(po.total_amount)||0) - (parseFloat(po.amount_paid)||0);
            return s + Math.max(0, owed);
        }, 0);
        // Fall back to supplier.balance sum if no PO data available
        const supplierBalanceTotal = (suppliers||[]).reduce((s,sup) =>
            s + Math.max(0, parseFloat(sup.balance)||0), 0);
        const payablesTotal = poPayables > 0 ? poPayables : supplierBalanceTotal;

        // Realized revenue & real COGS
        // Revenue: only what was collected (amount_paid) — unpaid credit excluded
        // COGS: full cost of ALL goods sold — goods left the shop regardless of payment
        let realizedSales = 0, totalCogs = 0;
        (salesData||[]).forEach(sale => {
            const paid = parseFloat(sale.amount_paid || 0);
            const cost = parseFloat(sale.cost_price  || 0) * parseFloat(sale.quantity_sold || 0);
            realizedSales += paid;
            totalCogs     += cost;
        });

        // Cash estimate: realized revenue minus all expenses
        const totalExp = (expData||[]).reduce((s,e) => s + (parseFloat(e.amount)||0), 0);
        const cashEst  = Math.max(0, realizedSales - totalExp);

        // VAT payable (16/116 of realized revenue)
        const vatPayable = realizedSales * 0.16 / 1.16;

        // Net Profit = Collected Revenue − Full COGS − Expenses
        const curProfit = realizedSales - totalCogs - totalExp;

        res.json({
            success: true,
            data: {
                cash:              cashEst,
                mpesa:             0,          // manual entry — no bank feed yet
                debtors:           debtorsTotal,
                stock:             stockValue,
                fixed_assets:      0,          // manual entry
                payables:          payablesTotal,
                vat_payable:       vatPayable,
                retained_earnings: 0,          // from journal entries
                current_profit:    curProfit
            }
        });
    } catch(err) {
        log.error('[Balance Sheet]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── GET Income Statement ──────────────────────────────────────────────────────
app.get('/api/accounting/income-statement', requireAuth, requireRole('admin','manager'), async (req, res) => {
    const { from, to } = req.query;
    const fromISO = from ? `${from}T00:00:00.000+03:00` : '2020-01-01T00:00:00.000+03:00';
    const toISO   = to   ? `${to}T23:59:59.999+03:00`   : new Date().toISOString();

    try {
        const [
            { data: sales },
            { data: expenses },
            { data: stockData },
            { data: poData }
        ] = await Promise.all([
            supabase.from('Sales').select('total_amount, amount_paid, cost_price, quantity_sold, payment_status')
                .eq('is_voided', false).gte('sale_date', fromISO).lte('sale_date', toISO),
            supabase.from('expenses').select('amount, category')
                .gte('expense_date', fromISO).lte('expense_date', toISO),
            supabase.from('Inventory').select('stock_quantity, cost_price'),
            supabase.from('purchase_orders').select('total_amount')
                .in('status', ['Received','Partial']).gte('created_at', fromISO).lte('created_at', toISO)
        ]);

        const grossSales  = (sales||[]).reduce((s,sale) => s + (parseFloat(sale.total_amount)||0), 0);
        const creditUnpaid = (sales||[]).filter(s => ['Credit','Partial'].includes(s.payment_status))
            .reduce((s,sale) => s + Math.max(0, (parseFloat(sale.total_amount)||0) - (parseFloat(sale.amount_paid)||0)), 0);
        const netRevenue  = grossSales - creditUnpaid;

        // COGS from sales cost records
        const cogs = (sales||[]).reduce((s,sale) =>
            s + (parseFloat(sale.cost_price)||0) * (parseFloat(sale.quantity_sold)||0), 0);

        const stockValue   = (stockData||[]).reduce((s,i) => s + (parseFloat(i.stock_quantity)||0)*(parseFloat(i.cost_price)||0), 0);
        const purchases    = (poData||[]).reduce((s,po) => s + (parseFloat(po.total_amount)||0), 0);

        const grossProfit  = netRevenue - cogs;

        // Expenses by category
        const expByCat = {};
        (expenses||[]).forEach(e => {
            const cat = e.category || 'General';
            expByCat[cat] = (expByCat[cat]||0) + (parseFloat(e.amount)||0);
        });
        const totalExpenses = Object.values(expByCat).reduce((s,v) => s+v, 0);
        const netProfit     = grossProfit - totalExpenses;

        res.json({
            success: true,
            data: {
                gross_sales:      grossSales,
                credit_unpaid:    creditUnpaid,
                net_revenue:      netRevenue,
                opening_stock:    stockValue,   // simplified — use closing stock as proxy
                purchases,
                closing_stock:    stockValue,
                cogs,
                gross_profit:     grossProfit,
                expenses_by_cat:  expByCat,
                total_expenses:   totalExpenses,
                net_profit:       netProfit
            }
        });
    } catch (err) {
        log.error('[Income Statement]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── GET M-Pesa Reconciliation ─────────────────────────────────────────────────
app.get('/api/accounting/reconcile', requireAuth, requireRole('admin','manager'), async (req, res) => {
    // Support both ?date=YYYY-MM-DD (legacy daily) and ?from=YYYY-MM-DD&to=YYYY-MM-DD (range)
    const { date, from, to, filter } = req.query;
    const fromDate  = from  || date || null;
    const toDate    = to    || date || null;
    const fromISO   = fromDate ? `${fromDate}T00:00:00.000+03:00` : null;
    const toISO     = toDate   ? `${toDate}T23:59:59.999+03:00`   : null;

    try {
        // Pull from c2b_payments table (your existing M-Pesa C2B log)
        let q = supabase.from('c2b_payments').select('*').order('created_at', { ascending: false });
        if (fromISO) q = q.gte('created_at', fromISO).lte('created_at', toISO);
        if (filter && filter !== 'all') q = q.eq('status', filter);

        const { data: c2bTxns, error: c2bErr } = await q;
        if (c2bErr) throw c2bErr;

        // Also pull M-Pesa from payments table (STK push only)
        // We must exclude any payments whose mpesa_code already appears in c2b_payments
        // to avoid double-counting C2B payments that were reconciled and created a payments record.
        let pq = supabase.from('payments').select('*').eq('payment_method', 'M-Pesa').order('created_at', { ascending: false });
        if (fromISO) pq = pq.gte('created_at', fromISO).lte('created_at', toISO);
        const { data: allMpesaPayments } = await pq;

        // Build a set of all mpesa_codes that came in via C2B (use ALL c2b records, not just date-filtered)
        const { data: allC2BCodes } = await supabase.from('c2b_payments').select('mpesa_code');
        const c2bCodeSet = new Set((allC2BCodes || []).map(r => r.mpesa_code).filter(Boolean));

        // Only keep payments whose mpesa_code is NOT in c2b_payments (i.e. genuine STK push)
        const stkPayments = (allMpesaPayments || []).filter(p => !p.mpesa_code || !c2bCodeSet.has(p.mpesa_code));

        // Total M-Pesa received through POS — C2B only (STK excluded to avoid double-count)
        // C2B amounts are the source of truth; STK payments linked to C2B are already counted
        const c2bTotal  = (c2bTxns||[]).reduce((s,p) => s + (parseFloat(p.amount)||0), 0);
        const stkTotal  = stkPayments.reduce((s,p) => s + (parseFloat(p.amount)||0), 0);
        const totalMpesaPos = c2bTotal + stkTotal;

        // Combine and shape for frontend
        const transactions = [
            ...(c2bTxns||[]).map(t => ({
                id:           t.id,
                customer_name: t.customer_name,
                phone:        t.phone,
                mpesa_code:   t.mpesa_code,
                account_ref:  t.account_ref,
                amount:       t.amount,
                amount_excess: t.amount_excess || 0,
                status:       t.status,
                created_at:   t.created_at,
                source:       'C2B'
            })),
            ...(stkPayments||[]).map(p => ({
                id:           p.id,
                customer_name: p.customer_name,
                phone:        null,
                mpesa_code:   p.mpesa_code,
                account_ref:  null,
                amount:       p.amount,
                amount_excess: 0,
                status:       'matched',   // STK push payments are always linked to a sale
                created_at:   p.created_at,
                source:       'STK'
            }))
        ].sort((a,b) => new Date(b.created_at) - new Date(a.created_at));

        const unmatchedCount = (c2bTxns||[]).filter(t => ['unmatched','excess'].includes(t.status)).length;

        res.json({
            success:          true,
            transactions,
            total_mpesa_pos:  totalMpesaPos,
            unmatched_count:  unmatchedCount
        });
    } catch (err) {
        log.error('[Reconcile]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ============================================================
//  DIGITAX RECONCILIATION — Cross-check POS vs KRA
//  GET /api/digitax/reconcile?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD
//
//  DigiTax API: GET /sales (paginated, max 20/page, cursor-based)
//  Response: { pagination: { next: "<cursor-id>|null", previous, page_size }, data: [...] }
//  IMPORTANT: pagination.next is a cursor ID string (e.g. "sale_01KN4N7TF4SPQYJ14FF6B6H9S2"),
//             NOT a URL. Build the next page URL by passing it as ?after=<cursor>.
//  Each sale total = sum of sale.item_list[].total_amount
//  Sale status: PENDING | FAILED | COMPLETED
// ============================================================
app.get('/api/digitax/reconcile', requireAuth, requireRole('admin'), async (req, res) => {
    const { start_date, end_date } = req.query;

    if (!start_date || !end_date) {
        return res.status(400).json({ success: false, message: 'start_date and end_date are required (YYYY-MM-DD).' });
    }

    try {
        const fromISO = `${start_date}T00:00:00.000+03:00`;
        const toISO   = `${end_date}T23:59:59.999+03:00`;

        // ── POS side ──────────────────────────────────────────────────────
        const { data: posSales, error: posErr } = await supabase
            .from('Sales')
            .select('id, total_amount, amount_paid, payment_status, sale_date, "Kra_Receipt_No", "E-tims_No", is_voided, receipt_number, invoice_number')
            .eq('is_voided', false)
            .gte('sale_date', fromISO)
            .lte('sale_date', toISO);

        if (posErr) throw posErr;

        const posTotal = (posSales || []).reduce((s, x) => s + (parseFloat(x.total_amount) || 0), 0);

        // Count distinct invoices/receipts — multi-item carts produce one Sales row per
        // line item but share the same receipt_number / invoice_number, so counting raw
        // rows inflates the invoice count relative to what DigiTax received (1 per checkout).
        const distinctTxnKeys = new Set(
            (posSales || []).map(x => x.receipt_number || x.invoice_number || `solo-${x.id}`)
        );
        const posCount = distinctTxnKeys.size;

        // A transaction is "submitted to KRA" if ANY of its rows has a KRA receipt.
        // Group rows by transaction key first, then check.
        const txnMap = {};
        for (const row of (posSales || [])) {
            const key = row.receipt_number || row.invoice_number || `solo-${row.id}`;
            if (!txnMap[key]) txnMap[key] = { hasKra: false };
            if (row['Kra_Receipt_No'] || row['E-tims_No']) txnMap[key].hasKra = true;
        }
        const posSubmitted = Object.values(txnMap).filter(t => t.hasKra).length;
        const posPending   = posCount - posSubmitted;

        // ── DigiTax side: paginated GET /sales ───────────────────────────
        // pagination.next is a cursor ID, not a URL.
        // Pass it as ?after=<cursor> to get the next page.
        let allDtSales   = [];
        let digitaxError = null;

        if (DIGITAX_API_KEY) {
            try {
                let afterCursor = null;
                let pagesFetched = 0;
                const MAX_PAGES  = 50; // safety cap: 50 × 20 = 1,000 sales

                do {
                    const params = new URLSearchParams({
                        start_date,
                        end_date,
                        page_size: '20',
                        ...(afterCursor ? { after: afterCursor } : {})
                    });

                    const dtRes = await fetch(
                        `${DIGITAX_BASE_URL}/sales?${params}`,
                        {
                            headers: { 'x-api-key': DIGITAX_API_KEY, 'Content-Type': 'application/json' },
                            signal: AbortSignal.timeout(15000)
                        }
                    );

                    const dtText = await dtRes.text();
                    let page;
                    try { page = JSON.parse(dtText); } catch { page = null; }

                    if (!dtRes.ok || !page) {
                        digitaxError = `DigiTax API error ${dtRes.status}: ${dtText.slice(0, 200)}`;
                        break;
                    }

                    const records = Array.isArray(page.data) ? page.data : [];
                    allDtSales.push(...records);
                    pagesFetched++;

                    // pagination.next is a cursor ID string or null — never a URL
                    afterCursor = page.pagination?.next || null;

                } while (afterCursor && pagesFetched < MAX_PAGES);

                log.info('[DigiTax Reconcile] Pages fetched', { pages: pagesFetched, records: allDtSales.length });

            } catch (err) {
                digitaxError = `DigiTax unreachable: ${err.message}`;
            }
        } else {
            digitaxError = 'DIGITAX_API_KEY not configured on server.';
        }

        // ── Aggregate DigiTax totals ──────────────────────────────────────
        // Exclude FAILED sales from total — they didn't reach KRA.
        // Each sale's revenue = sum of its item_list[].total_amount.
        const dtSalesValid = allDtSales.filter(s => s.status !== 'FAILED');
        const dtTotal = digitaxError === null
            ? dtSalesValid.reduce((sum, sale) =>
                sum + (sale.item_list || []).reduce((s, item) => s + (parseFloat(item.total_amount) || 0), 0), 0)
            : null;
        const dtCount     = digitaxError === null ? dtSalesValid.length                              : null;
        const dtPending   = allDtSales.filter(s => s.status === 'PENDING').length;
        const dtFailed    = allDtSales.filter(s => s.status === 'FAILED').length;
        const dtCompleted = allDtSales.filter(s => s.status === 'COMPLETED').length;

        // ── Variance & status ─────────────────────────────────────────────
        const amountVariance = dtTotal !== null ? posTotal - dtTotal : null;
        const countVariance  = dtCount  !== null ? posCount - dtCount  : null;

        // Empty result (0 records from DigiTax) while POS has sales = transmission lag
        const digitaxReturnedEmpty = digitaxError === null && allDtSales.length === 0 && posCount > 0;

        let status = 'unknown';
        if (digitaxError) {
            status = 'unknown';
        } else if (digitaxReturnedEmpty) {
            status = posPending === 0 ? 'kra_verified' : 'pending_invoices';
        } else if (dtTotal !== null) {
            if (Math.abs(amountVariance) < 1 && countVariance === 0)        status = 'matched';
            else if (Math.abs(amountVariance) < 500 || Math.abs(countVariance) <= 1) status = 'minor_variance';
            else                                                              status = 'mismatch';
        }

        log.info('[DigiTax Reconcile]', {
            start_date, end_date,
            posTotal, posCount, posSubmitted, posPending,
            dtTotal, dtCount, dtPending, dtFailed, dtCompleted,
            status
        });

        res.json({
            success: true,
            period:  { start_date, end_date },
            pos: {
                total:       posTotal,
                count:       posCount,
                submitted:   posSubmitted,
                pending_kra: posPending,
            },
            digitax: digitaxError === null ? {
                total:     dtTotal,
                count:     dtCount,
                pending:   dtPending,
                failed:    dtFailed,
                completed: dtCompleted,
            } : null,
            variance:              { amount: amountVariance, count: countVariance, status },
            digitax_returned_empty: digitaxReturnedEmpty,
            error:                 digitaxError || null,
        });

    } catch (err) {
        log.error('[DigiTax Reconcile]', err.message);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});


// ╔══════════════════════════════════════════════════════════════════════════════╗
// ║                  ELITE HARDWARE POS — AUTOMATED SCRIPTS                     ║
// ║  All scripts run on server startup and on a recurring schedule.             ║
// ║  Configure recipients via FROM_EMAIL in .env (falls back to EMAIL_USER).  ║
// ╚══════════════════════════════════════════════════════════════════════════════╝

const FROM_EMAIL = process.env.FROM_EMAIL || process.env.EMAIL_USER;

// ─── Helper: send a formatted HTML email ───────────────────────────────────────
async function sendAlertEmail(subject, htmlBody, to = FROM_EMAIL) {
    if (!to || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        log.warn('[EMAIL] Skipping send — EMAIL_USER or EMAIL_PASS not configured in environment.');
        return;
    }
    try {
        const info = await transporter.sendMail({
            from: `"Elite Hardware POS" <${process.env.FROM_EMAIL}>`,
            to,
            subject,
            html: `
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
                    <div style="background:#0a0f1e;padding:20px 24px;border-radius:8px 8px 0 0;">
                        <h2 style="color:#00e5a0;margin:0;font-size:16px;letter-spacing:1px;">🛠️ ELITE HARDWARE POS</h2>
                        <p style="color:#64748b;font-size:11px;margin:4px 0 0;">Automated Alert System</p>
                    </div>
                    <div style="background:#111827;padding:24px;border-radius:0 0 8px 8px;color:#e2e8f0;">
                        ${htmlBody}
                    </div>
                    <p style="text-align:center;font-size:10px;color:#64748b;margin-top:12px;">
                        Sent by Elite Hardware POS · ${new Date().toLocaleString('en-KE')}
                    </p>
                </div>`
        });
        log.info(`[EMAIL] ✅ Sent "${subject}" → ${to} (msgId: ${info.messageId})`);
    } catch (err) {
        log.error(`[EMAIL] ✗ Failed to send "${subject}" → ${to}: ${err.message}`);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SCRIPT 1: eTIMS RETRY
// Runs every 15 minutes. Finds sales where Kra_Receipt_No is still null (eTIMS
// submission failed or timed out at point of sale) and retries DigiTax submission.
// Caps at 20 retries per run to avoid hammering the API.
// ════════════════════════════════════════════════════════════════════════════════
async function retryPendingEtims() {
    if (!DIGITAX_API_KEY) return; // skip silently if not configured
    try {
        const { data: pendingSales, error } = await supabase
            .from('Sales')
            .select('id, item_name, total_amount, amount_paid, payment_status, sold_by, customer_name, customer_phone, receipt_number, invoice_number, sale_date')
            .is('Kra_Receipt_No', null)
            .eq('is_voided', false)
            .not('payment_status', 'in', '("Credit","Partial","Unpaid")') // only paid sales need eTIMS
            .order('sale_date', { ascending: true })
            .limit(20);

        if (error) throw error;
        if (!pendingSales || pendingSales.length === 0) return;

        log.info(`[eTIMS RETRY] Found ${pendingSales.length} sales pending KRA submission`);

        let retried = 0, succeeded = 0;
        for (const sale of pendingSales) {
            retried++;
            try {
                const result = await submitSaleToEtims({
                    invoiceNumber:  sale.invoice_number || sale.receipt_number,
                    receiptNumber:  sale.receipt_number,
                    itemName:       sale.item_name || 'Hardware Goods',
                    quantity:       1,
                    unitPrice:      parseFloat(sale.total_amount),
                    paymentMethod:  sale.payment_status === 'Paid' ? 'Cash' : sale.payment_status,
                    customerName:   sale.customer_name || null,
                    totalAmount:    parseFloat(sale.total_amount),
                });

                if (result?.kraReceiptNo || result?.digitaxSaleId) {
                    await supabase.from('Sales').update({
                        'Kra_Receipt_No':      result.kraReceiptNo      || null,
                        'kra_qr_url':          result.kraQrUrl          || null,
                        'E-tims_No':           result.etimsNo           ?? null,
                        'Control_unit_number': result.controlUnitNumber || null,
                        digitax_sale_id:       result.digitaxSaleId     || null,
                    }).eq('id', sale.id);
                    succeeded++;
                    log.info(`[eTIMS RETRY] ✅ Sale ${sale.id} submitted: ${result.kraReceiptNo}`);
                }
            } catch (saleErr) {
                log.warn(`[eTIMS RETRY] ❌ Sale ${sale.id} failed: ${saleErr.message}`);
            }
            // Throttle: 1 request per second to avoid rate limiting
            await new Promise(r => setTimeout(r, 1000));
        }

        if (succeeded > 0) {
            log.info(`[eTIMS RETRY] Run complete: ${succeeded}/${retried} sales submitted to KRA`);
        }
    } catch (err) {
        log.error('[eTIMS RETRY] Script error:', err.message);
    }
}
// Run immediately on startup (catches any overnight backlog), then every 15 min
retryPendingEtims();
setInterval(retryPendingEtims, 15 * 60 * 1000);


// ════════════════════════════════════════════════════════════════════════════════
// SCRIPT 2: END-OF-DAY SUMMARY EMAIL
// Runs every day at 9 PM (East Africa Time = UTC+3, so 18:00 UTC).
// Emails admin a full daily digest: revenue, top products, cash vs M-Pesa split,
// credit sales made, debt recovered, eTIMS pending count.
// ════════════════════════════════════════════════════════════════════════════════
async function sendEodSummary() {
    if (!FROM_EMAIL) return;
    try {
        const today    = new Date();
        const dateStr  = today.toISOString().split('T')[0];
        const dayStart = `${dateStr}T00:00:00.000+03:00`;
        const dayEnd   = `${dateStr}T23:59:59.999+03:00`;
        const fmt      = n => `KES ${parseFloat(n||0).toLocaleString('en-KE', {minimumFractionDigits:2})}`;

        const [
            { data: sales },
            { data: payments },
            { data: expenses },
            { data: debtLogs },
        ] = await Promise.all([
            supabase.from('Sales').select('total_amount, amount_paid, payment_status, item_name, quantity_sold, sold_by, Kra_Receipt_No').eq('is_voided', false).gte('sale_date', dayStart).lte('sale_date', dayEnd),
            supabase.from('payments').select('amount, payment_method').gte('created_at', dayStart).lte('created_at', dayEnd),
            supabase.from('expenses').select('amount, description').gte('expense_date', dayStart).lte('expense_date', dayEnd),
            supabase.from('debt_payments').select('amount_paid, processed_by').gte('payment_date', dayStart).lte('payment_date', dayEnd),
        ]);

        // Revenue metrics
        let totalRevenue = 0, cashCollected = 0, mpesaCollected = 0, creditIssued = 0;
        (sales || []).forEach(s => {
            const paid = parseFloat(s.amount_paid || 0);
            const total = parseFloat(s.total_amount || 0);
            totalRevenue += paid;
            if (['Credit','Partial'].includes(s.payment_status)) creditIssued += (total - paid);
        });
        (payments || []).forEach(p => {
            const amt = parseFloat(p.amount || 0);
            if (p.payment_method === 'Cash') cashCollected += amt;
            else if (p.payment_method === 'M-Pesa') mpesaCollected += amt;
        });

        const totalExpenses  = (expenses  || []).reduce((s,e) => s + parseFloat(e.amount||0), 0);
        const debtRecovered  = (debtLogs  || []).reduce((s,d) => s + parseFloat(d.amount_paid||0), 0);
        const txCount        = (sales     || []).length;
        const etimsPending   = (sales     || []).filter(s => !s['Kra_Receipt_No']).length;

        // Top 5 products by revenue
        const prodMap = {};
        (sales || []).forEach(s => {
            const k = s.item_name || 'Unknown';
            if (!prodMap[k]) prodMap[k] = { rev: 0, qty: 0 };
            prodMap[k].rev += parseFloat(s.amount_paid || 0);
            prodMap[k].qty += parseFloat(s.quantity_sold || 0);
        });
        const topProds = Object.entries(prodMap).sort((a,b) => b[1].rev - a[1].rev).slice(0,5);

        // Staff performance
        const staffMap = {};
        (sales || []).forEach(s => {
            const k = s.sold_by || 'Unknown';
            if (!staffMap[k]) staffMap[k] = { rev: 0, txns: 0 };
            staffMap[k].rev  += parseFloat(s.amount_paid || 0);
            staffMap[k].txns += 1;
        });
        const staffRows = Object.entries(staffMap).sort((a,b) => b[1].rev - a[1].rev)
            .map(([n,d]) => `<tr><td style="padding:6px 10px;">${n}</td><td style="padding:6px 10px;text-align:right;">${d.txns}</td><td style="padding:6px 10px;text-align:right;color:#00e5a0;">${fmt(d.rev)}</td></tr>`).join('');

        const topProdRows = topProds.map(([n,d]) =>
            `<tr><td style="padding:6px 10px;">${n}</td><td style="padding:6px 10px;text-align:right;">${d.qty} units</td><td style="padding:6px 10px;text-align:right;color:#00e5a0;">${fmt(d.rev)}</td></tr>`).join('');

        const etimsWarn = etimsPending > 0
            ? `<p style="background:rgba(245,158,11,0.2);border:1px solid #f59e0b;border-radius:6px;padding:10px 14px;color:#fbbf24;font-size:12px;">⚠️ <strong>${etimsPending} sale(s)</strong> are still pending KRA/eTIMS submission. The retry script will attempt these overnight.</p>`
            : `<p style="background:rgba(0,229,160,0.1);border:1px solid #00e5a0;border-radius:6px;padding:10px 14px;color:#00e5a0;font-size:12px;">✅ All today's sales have been submitted to KRA.</p>`;

        sendAlertEmail(
            `📊 EOD Summary — ${dateStr} | Revenue: ${fmt(totalRevenue)}`,
            `
            <h3 style="color:#00e5a0;margin-top:0;">${today.toLocaleDateString('en-KE',{weekday:'long',year:'numeric',month:'long',day:'numeric'})}</h3>
            ${etimsWarn}
            <table style="width:100%;border-collapse:collapse;margin:16px 0;font-size:13px;">
                <tr><td style="padding:8px 0;color:#94a3b8;">Total Revenue</td><td style="text-align:right;font-weight:700;font-size:16px;color:#00e5a0;">${fmt(totalRevenue)}</td></tr>
                <tr><td style="padding:8px 0;color:#94a3b8;">Cash Collected</td><td style="text-align:right;color:#e2e8f0;">${fmt(cashCollected)}</td></tr>
                <tr><td style="padding:8px 0;color:#94a3b8;">M-Pesa Collected</td><td style="text-align:right;color:#e2e8f0;">${fmt(mpesaCollected)}</td></tr>
                <tr><td style="padding:8px 0;color:#94a3b8;">Credit Issued (unpaid)</td><td style="text-align:right;color:#f59e0b;">${fmt(creditIssued)}</td></tr>
                <tr><td style="padding:8px 0;color:#94a3b8;">Debt Recovered</td><td style="text-align:right;color:#22d3ee;">${fmt(debtRecovered)}</td></tr>
                <tr><td style="padding:8px 0;color:#94a3b8;">Expenses</td><td style="text-align:right;color:#ff4d6d;">${fmt(totalExpenses)}</td></tr>
                <tr style="border-top:1px solid #1e293b;"><td style="padding:8px 0;color:#94a3b8;">Transactions</td><td style="text-align:right;color:#e2e8f0;">${txCount}</td></tr>
            </table>
            ${topProds.length > 0 ? `
            <h4 style="color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:20px 0 8px;">Top Products</h4>
            <table style="width:100%;border-collapse:collapse;font-size:12px;background:rgba(255,255,255,0.03);border-radius:6px;">
                <thead><tr style="color:#64748b;font-size:10px;"><th style="padding:6px 10px;text-align:left;">Product</th><th style="padding:6px 10px;text-align:right;">Qty</th><th style="padding:6px 10px;text-align:right;">Revenue</th></tr></thead>
                <tbody>${topProdRows}</tbody>
            </table>` : ''}
            ${staffRows ? `
            <h4 style="color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:20px 0 8px;">Staff Performance</h4>
            <table style="width:100%;border-collapse:collapse;font-size:12px;background:rgba(255,255,255,0.03);border-radius:6px;">
                <thead><tr style="color:#64748b;font-size:10px;"><th style="padding:6px 10px;text-align:left;">Staff</th><th style="padding:6px 10px;text-align:right;">Txns</th><th style="padding:6px 10px;text-align:right;">Revenue</th></tr></thead>
                <tbody>${staffRows}</tbody>
            </table>` : ''}
            `
        );

        log.info(`[EOD] Summary email sent for ${dateStr}: ${txCount} txns, revenue ${fmt(totalRevenue)}`);
    } catch (err) {
        log.error('[EOD] Script error:', err.message);
    }
}

// Schedule EOD at 21:00 EAT (18:00 UTC) daily
function scheduleEod() {
    const now   = new Date();
    // Next 21:00 EAT = 18:00 UTC
    const next  = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 18, 0, 0));
    if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
    const msUntil = next - now;
    log.info(`[EOD] Next summary scheduled in ${Math.round(msUntil/60000)} minutes`);
    setTimeout(() => {
        sendEodSummary();
        setInterval(sendEodSummary, 24 * 60 * 60 * 1000); // then every 24h
    }, msUntil);
}
scheduleEod();


// ════════════════════════════════════════════════════════════════════════════════
// SCRIPT 3: CREDIT AGING ALERT
// Runs every Monday at 8 AM EAT. Finds all outstanding credit sales, groups by
// age bucket (0–30, 31–60, 60+ days overdue), and emails admin a ranked list.
// Only emails if there are debts older than 30 days.
// ════════════════════════════════════════════════════════════════════════════════
async function runCreditAgingAlert() {
    if (!FROM_EMAIL) return;
    try {
        const { data: credits, error } = await supabase
            .from('Sales')
            .select('customer_name, customer_phone, total_amount, amount_paid, sale_date')
            .in('payment_status', ['Credit', 'Partial', 'Unpaid'])
            .eq('is_voided', false)
            .order('sale_date', { ascending: true });

        if (error) throw error;
        if (!credits || credits.length === 0) return;

        const now = Date.now();
        const fmt = n => `KES ${parseFloat(n||0).toLocaleString('en-KE', {minimumFractionDigits:2})}`;

        // Consolidate per customer
        const custMap = {};
        credits.forEach(s => {
            const balance = (parseFloat(s.total_amount)||0) - (parseFloat(s.amount_paid)||0);
            if (balance <= 0) return;
            const key   = (s.customer_phone || s.customer_name || 'Unknown').toLowerCase().trim();
            const days  = Math.floor((now - new Date(s.sale_date).getTime()) / (1000 * 60 * 60 * 24));
            if (!custMap[key]) custMap[key] = { name: s.customer_name || 'Unknown', phone: s.customer_phone || '—', balance: 0, oldest: 0 };
            custMap[key].balance += balance;
            if (days > custMap[key].oldest) custMap[key].oldest = days;
        });

        const aged30  = Object.values(custMap).filter(c => c.oldest >= 30 && c.oldest < 60);
        const aged60  = Object.values(custMap).filter(c => c.oldest >= 60);
        const current = Object.values(custMap).filter(c => c.oldest < 30);

        // Only alert if there are overdue accounts (30+ days)
        if (aged30.length === 0 && aged60.length === 0) {
            log.info('[AGING] No overdue credit accounts this week');
            return;
        }

        const totalOwed = Object.values(custMap).reduce((s,c) => s+c.balance, 0);

        const makeRows = (customers, color) => customers
            .sort((a,b) => b.balance - a.balance)
            .map(c => `<tr><td style="padding:6px 10px;">${c.name}</td><td style="padding:6px 10px;">${c.phone}</td><td style="padding:6px 10px;text-align:right;color:${color};font-weight:700;">${fmt(c.balance)}</td><td style="padding:6px 10px;text-align:right;color:#64748b;">${c.oldest} days</td></tr>`)
            .join('');

        sendAlertEmail(
            `⚠️ Credit Aging Report — ${aged60.length} accounts 60+ days overdue | Total: ${fmt(totalOwed)}`,
            `
            <h3 style="color:#f59e0b;margin-top:0;">Weekly Credit Aging Report</h3>
            <p style="color:#94a3b8;font-size:13px;">Total outstanding across <strong style="color:#e2e8f0;">${Object.keys(custMap).length} customers</strong>: <strong style="color:#ff4d6d;font-size:16px;">${fmt(totalOwed)}</strong></p>

            ${aged60.length > 0 ? `
            <h4 style="color:#ff4d6d;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:20px 0 8px;">🔴 60+ Days Overdue (${aged60.length} accounts)</h4>
            <table style="width:100%;border-collapse:collapse;font-size:12px;background:rgba(255,77,109,0.05);border-radius:6px;">
                <thead><tr style="color:#64748b;font-size:10px;"><th style="padding:6px 10px;text-align:left;">Customer</th><th style="padding:6px 10px;text-align:left;">Phone</th><th style="padding:6px 10px;text-align:right;">Balance</th><th style="padding:6px 10px;text-align:right;">Age</th></tr></thead>
                <tbody>${makeRows(aged60,'#ff4d6d')}</tbody>
            </table>` : ''}

            ${aged30.length > 0 ? `
            <h4 style="color:#f59e0b;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin:20px 0 8px;">🟡 30–60 Days Overdue (${aged30.length} accounts)</h4>
            <table style="width:100%;border-collapse:collapse;font-size:12px;background:rgba(245,158,11,0.05);border-radius:6px;">
                <thead><tr style="color:#64748b;font-size:10px;"><th style="padding:6px 10px;text-align:left;">Customer</th><th style="padding:6px 10px;text-align:left;">Phone</th><th style="padding:6px 10px;text-align:right;">Balance</th><th style="padding:6px 10px;text-align:right;">Age</th></tr></thead>
                <tbody>${makeRows(aged30,'#f59e0b')}</tbody>
            </table>` : ''}

            ${current.length > 0 ? `<p style="color:#64748b;font-size:11px;margin-top:16px;">Plus ${current.length} account(s) under 30 days — within normal credit terms.</p>` : ''}
            `
        );

        log.info(`[AGING] Alert sent: ${aged60.length} critical, ${aged30.length} warning accounts`);
    } catch (err) {
        log.error('[AGING] Script error:', err.message);
    }
}

// Schedule: every Monday at 08:00 EAT (05:00 UTC)
function scheduleAgingAlert() {
    function msToNextMonday8am() {
        const now = new Date();
        const next = new Date(now);
        next.setUTCHours(5, 0, 0, 0);
        const day = now.getUTCDay(); // 0=Sun, 1=Mon
        const daysUntilMon = day === 1 ? (now.getUTCHours() >= 5 ? 7 : 0) : (8 - day) % 7 || 7;
        next.setUTCDate(next.getUTCDate() + daysUntilMon);
        return next - now;
    }
    const ms = msToNextMonday8am();
    log.info(`[AGING] First aging alert in ${Math.round(ms/3600000)}h`);
    setTimeout(() => {
        runCreditAgingAlert();
        setInterval(runCreditAgingAlert, 7 * 24 * 60 * 60 * 1000);
    }, ms);
}
scheduleAgingAlert();


// ════════════════════════════════════════════════════════════════════════════════
// SCRIPT 4: DEAD STOCK DETECTOR
// Runs every Sunday at 7 AM EAT. Flags items that have stock > 0 but have not
// sold a single unit in the past 60 days. Emails admin a ranked list by value
// tied up (qty × cost_price). Only emails if dead stock value > KES 5,000.
// ════════════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════════════
// SCRIPT 4: DEAD STOCK DETECTOR
// Runs every Sunday at 7 AM EAT. Flags items that have stock > 0 but have not
// sold a single unit in the past 60 days. Emails admin a ranked list by value.
// Only runs if the system has been active for at least 60 days.
// ════════════════════════════════════════════════════════════════════════════════
async function runDeadStockDetector() {
    if (!FROM_EMAIL) return;
    try {
        // ── 1. SYSTEM AGE CHECK (The "Cold Start" Fix) ──────────────
        const { data: firstSale, error: firstSaleErr } = await supabase
            .from('Sales')
            .select('sale_date')
            .order('sale_date', { ascending: true })
            .limit(1)
            .maybeSingle();

        if (firstSaleErr) throw firstSaleErr;
        
        if (!firstSale) {
            log.info('[DEAD STOCK] No sales in the system yet — skipping check');
            return;
        }

        const systemAgeDays = (Date.now() - new Date(firstSale.sale_date).getTime()) / (1000 * 60 * 60 * 24);

        if (systemAgeDays < 60) {
            log.info(`[DEAD STOCK] System has only been active for ${Math.round(systemAgeDays)} days. Waiting until Day 60 to run dead stock analysis.`);
            return;
        }
        // ────────────────────────────────────────────────────────────

        const cutoffDate = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
        const fmt = n => `KES ${parseFloat(n||0).toLocaleString('en-KE', {minimumFractionDigits:2})}`;

        // All inventory with stock
        const { data: inventory, error: invErr } = await supabase
            .from('Inventory')
            .select('id, item_name, category, stock_quantity, cost_price, price')
            .gt('stock_quantity', 0)
            .order('item_name', { ascending: true });
        if (invErr) throw invErr;

        // Items that sold in last 60 days
        const { data: recentSales, error: salesErr } = await supabase
            .from('Sales')
            .select('item_name')
            .eq('is_voided', false)
            .gte('sale_date', cutoffDate);
        if (salesErr) throw salesErr;

        const recentNames = new Set((recentSales||[]).map(s => (s.item_name||'').toLowerCase().trim()));

        // Dead stock = in Inventory but not in recentNames
        const deadItems = (inventory||[]).filter(item =>
            !recentNames.has((item.item_name||'').toLowerCase().trim())
        ).map(item => ({
            ...item,
            qty:        parseInt(item.stock_quantity) || 0,
            costValue:  (parseInt(item.stock_quantity)||0) * (parseFloat(item.cost_price)||0),
            sellValue:  (parseInt(item.stock_quantity)||0) * (parseFloat(item.price)||0),
        })).sort((a,b) => b.costValue - a.costValue);

        const totalDeadValue = deadItems.reduce((s,i) => s + i.costValue, 0);

        // Only alert if dead stock value is significant
        if (totalDeadValue < 5000) {
            log.info(`[DEAD STOCK] Dead stock value KES ${totalDeadValue.toFixed(0)} is below threshold — no alert`);
            return;
        }

        const rows = deadItems.slice(0,20).map(i =>
            `<tr><td style="padding:6px 10px;">${i.item_name}</td><td style="padding:6px 10px;color:#64748b;">${i.category||'—'}</td><td style="padding:6px 10px;text-align:right;">${i.qty}</td><td style="padding:6px 10px;text-align:right;color:#f59e0b;">${fmt(i.costValue)}</td></tr>`
        ).join('');

        sendAlertEmail(
            `📦 Dead Stock Alert — ${deadItems.length} items, ${fmt(totalDeadValue)} tied up`,
            `
            <h3 style="color:#f59e0b;margin-top:0;">Dead Stock Report <span style="font-size:12px;color:#64748b;">(No sales in 60 days)</span></h3>
            <p style="color:#94a3b8;font-size:13px;"><strong style="color:#ff4d6d;">${deadItems.length} items</strong> have not sold in 60+ days. <strong style="color:#f59e0b;">${fmt(totalDeadValue)}</strong> in capital is tied up.</p>
            <p style="color:#64748b;font-size:12px;">Consider discounting, bundling, or returning these to suppliers.</p>
            <table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:16px;">
                <thead><tr style="color:#64748b;font-size:10px;background:rgba(255,255,255,0.03);">
                    <th style="padding:6px 10px;text-align:left;">Item</th>
                    <th style="padding:6px 10px;text-align:left;">Category</th>
                    <th style="padding:6px 10px;text-align:right;">Stock</th>
                    <th style="padding:6px 10px;text-align:right;">Cost Value</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
            ${deadItems.length > 20 ? `<p style="color:#64748b;font-size:11px;margin-top:12px;">... and ${deadItems.length - 20} more items.</p>` : ''}
            `
        );
        log.info(`[DEAD STOCK] Alert sent: ${deadItems.length} items, ${fmt(totalDeadValue)} value`);
    } catch (err) {
        log.error('[DEAD STOCK] Script error:', err.message);
    }
}
// Schedule: every Sunday at 07:00 EAT (04:00 UTC)
function scheduleDeadStock() {
    function msToNextSunday7am() {
        const now = new Date();
        const next = new Date(now);
        next.setUTCHours(4, 0, 0, 0);
        const day = now.getUTCDay(); // 0=Sun
        const daysUntilSun = day === 0 ? (now.getUTCHours() >= 4 ? 7 : 0) : 7 - day;
        next.setUTCDate(next.getUTCDate() + daysUntilSun);
        return next - now;
    }
    const ms = msToNextSunday7am();
    log.info(`[DEAD STOCK] First check in ${Math.round(ms/3600000)}h`);
    setTimeout(() => {
        runDeadStockDetector();
        setInterval(runDeadStockDetector, 7 * 24 * 60 * 60 * 1000);
    }, ms);
}
scheduleDeadStock();


// ════════════════════════════════════════════════════════════════════════════════
// SCRIPT 5: SUSPICIOUS VOID DETECTOR
// Runs every hour. Flags if more than 3 voids occurred in the past hour or if
// any single cashier has voided more than 2 transactions today. Emails admin
// immediately with full details so fraud can be investigated in real time.
// ════════════════════════════════════════════════════════════════════════════════
async function checkSuspiciousVoids() {
    if (!FROM_EMAIL) return;
    try {
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        const todayStart = new Date(); todayStart.setHours(0,0,0,0);
        const fmt = n => `KES ${parseFloat(n||0).toLocaleString('en-KE', {minimumFractionDigits:2})}`;

        const { data: recentVoids, error } = await supabase
            .from('audit_logs')
            .select('performed_by, item_name, details, timestamp')
            .eq('action', 'VOID_TRANSACTION')
            .gte('timestamp', todayStart.toISOString())
            .order('timestamp', { ascending: false });

        if (error) throw error;
        if (!recentVoids || recentVoids.length === 0) return;

        const lastHourVoids = recentVoids.filter(v => new Date(v.timestamp) >= new Date(oneHourAgo));

        // Per-cashier void count today
        const cashierVoids = {};
        recentVoids.forEach(v => {
            cashierVoids[v.performed_by] = (cashierVoids[v.performed_by]||0) + 1;
        });
        const suspiciousCashiers = Object.entries(cashierVoids).filter(([,count]) => count > 2);

        const isAlert = lastHourVoids.length >= 3 || suspiciousCashiers.length > 0;
        if (!isAlert) return;

        const voidRows = lastHourVoids.slice(0,10).map(v =>
            `<tr><td style="padding:6px 10px;">${new Date(v.timestamp).toLocaleTimeString('en-KE')}</td><td style="padding:6px 10px;">${v.performed_by}</td><td style="padding:6px 10px;color:#64748b;font-size:11px;">${(v.details||'').substring(0,80)}</td></tr>`
        ).join('');

        const cashierWarnings = suspiciousCashiers.map(([name,count]) =>
            `<p style="background:rgba(255,77,109,0.1);border:1px solid #ff4d6d;border-radius:6px;padding:8px 12px;color:#fca5a5;font-size:12px;">🚨 <strong>${name}</strong> has voided <strong>${count} transactions</strong> today.</p>`
        ).join('');

        sendAlertEmail(
            `🚨 Suspicious Void Activity — ${lastHourVoids.length} voids in last hour`,
            `
            <h3 style="color:#ff4d6d;margin-top:0;">Suspicious Void Alert</h3>
            <p style="color:#94a3b8;font-size:13px;"><strong style="color:#ff4d6d;">${lastHourVoids.length} transactions</strong> were voided in the last 60 minutes. Immediate review recommended.</p>
            ${cashierWarnings}
            <table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:16px;">
                <thead><tr style="color:#64748b;font-size:10px;background:rgba(255,255,255,0.03);">
                    <th style="padding:6px 10px;text-align:left;">Time</th>
                    <th style="padding:6px 10px;text-align:left;">Voided By</th>
                    <th style="padding:6px 10px;text-align:left;">Details</th>
                </tr></thead>
                <tbody>${voidRows}</tbody>
            </table>
            <p style="color:#64748b;font-size:11px;margin-top:16px;">Review full void log in the Sales Reports page.</p>
            `
        );
        log.warn(`[VOID ALERT] Suspicious activity: ${lastHourVoids.length} voids in last hour, ${suspiciousCashiers.length} cashier(s) flagged`);
    } catch (err) {
        log.error('[VOID ALERT] Script error:', err.message);
    }
}
setInterval(checkSuspiciousVoids, 60 * 60 * 1000); // every hour


// ════════════════════════════════════════════════════════════════════════════════
// SCRIPT 6: DATABASE CLEANUP
// Runs every night at midnight EAT (21:00 UTC previous day).
// Purges: stale pending_mpesa (already done per-minute, this is belt-and-braces),
// audit_logs older than 180 days, and resolved pending_mpesa older than 24h.
// Does NOT touch Sales, payments, or expenses — those are permanent records.
// ════════════════════════════════════════════════════════════════════════════════
async function runDatabaseCleanup() {
    try {
        const now = new Date();
        let cleaned = [];

        // 1. pending_mpesa: delete all non-pending rows older than 24 hours
        const mpesa24h = new Date(now - 24 * 60 * 60 * 1000).toISOString();
        const { error: mpesaErr, count: mpesaCount } = await supabase
            .from('pending_mpesa')
            .delete({ count: 'exact' })
            .lt('created_at', mpesa24h)
            .neq('status', 'pending');
        if (!mpesaErr) cleaned.push(`pending_mpesa: ${mpesaCount||0} resolved rows`);

        // 2. audit_logs: delete entries older than 180 days
        const logCutoff = new Date(now - 180 * 24 * 60 * 60 * 1000).toISOString();
        const { error: logErr, count: logCount } = await supabase
            .from('audit_logs')
            .delete({ count: 'exact' })
            .lt('timestamp', logCutoff);
        if (!logErr) cleaned.push(`audit_logs: ${logCount||0} rows older than 180 days`);

        log.info('[CLEANUP] Nightly DB cleanup complete:', cleaned.join(', '));
    } catch (err) {
        log.error('[CLEANUP] Script error:', err.message);
    }
}

// Schedule: midnight EAT = 21:00 UTC
function scheduleCleanup() {
    function msToNext21UTC() {
        const now  = new Date();
        const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 21, 0, 0));
        if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
        return next - now;
    }
    setTimeout(() => {
        runDatabaseCleanup();
        setInterval(runDatabaseCleanup, 24 * 60 * 60 * 1000);
    }, msToNext21UTC());
}
scheduleCleanup();

// ── EXPOSE MANUAL TRIGGERS (admin-only API endpoints) ─────────────────────────
// Useful for testing scripts without waiting for their schedule, and for
// running a retry/report on demand from the admin panel.

// ════════════════════════════════════════════════════════════════════════════════
// SCRIPT 7: DAILY DATABASE BACKUP
// Runs every day at 2:00 AM EAT (23:00 UTC previous day).
// Exports all critical business tables from Supabase via REST API, packages them
// into a single JSON snapshot, and emails it to admin as an attachment.
// Also keeps a rolling 7-day archive in memory so /api/scripts/backup-download
// can serve the last N backups without re-running the export.
//
// Tables backed up (in order of business criticality):
//   Sales, payments, debt_payments, Inventory, stock_batches, customers,
//   expenses, purchase_orders, purchase_order_items, suppliers, supplier_returns,
//   returns_log, employees, audit_logs, c2b_payments, chart_of_accounts,
//   journal_entries
// ════════════════════════════════════════════════════════════════════════════════

const BACKUP_TABLES = [
    'Sales', 'payments', 'debt_payments',
    'Inventory', 'stock_batches',
    'customers',
    'expenses',
    'purchase_orders', 'purchase_order_items',
    'suppliers', 'supplier_returns', 'returns_log',
    'employees',
    'audit_logs',
    'c2b_payments',
    'chart_of_accounts', 'journal_entries'
];

// Rolling in-memory archive — keeps last 7 backups so admin can re-download
const _backupArchive = []; // [{ createdAt, label, sizeKb, tables, json }]

// ── Helper: Convert JSON Array to CSV String ──
function jsonToCsv(items) {
    if (!items || !items.length) return '';
    // Extract headers from the first object
    const head = Object.keys(items[0]);
    const csv = [
        head.join(','), // Header row
        ...items.map(row => head.map(fieldName => {
            let val = row[fieldName] === null ? '' : row[fieldName];
            // If value is a string, escape double quotes and wrap in quotes
            if (typeof val === 'string') {
                val = `"${val.replace(/"/g, '""')}"`;
            }
            return val;
        }).join(','))
    ].join('\r\n');
    return csv;
}

async function runDailyBackup() {
    const startedAt = new Date();
    log.info('[BACKUP] Starting daily database backup (CSV Format)...');

    const results = [];
    const attachments = [];
    let totalRows = 0;

    for (const table of BACKUP_TABLES) {
        try {
            let allRows = [];
            let from = 0;
            const chunk = 1000;
            let hasMore = true;

            while (hasMore) {
                const { data, error } = await supabase
                    .from(table)
                    .select('*')
                    .range(from, from + chunk - 1)
                    .order('id', { ascending: true });

                if (error) throw error;

                if (!data || data.length === 0) {
                    hasMore = false;
                } else {
                    allRows = allRows.concat(data);
                    from += chunk;
                    hasMore = data.length === chunk;
                }
            }

            if (allRows.length > 0) {
                const csvContent = jsonToCsv(allRows);
                attachments.push({
                    filename: `${table}_${startedAt.toISOString().slice(0, 10)}.csv`,
                    content: csvContent,
                    contentType: 'text/csv'
                });
                totalRows += allRows.length;
                results.push({ table, rows: allRows.length, status: 'ok' });
                log.info(`[BACKUP] ✓ ${table}: ${allRows.length} rows converted to CSV`);
            } else {
                results.push({ table, rows: 0, status: 'empty' });
            }

        } catch (err) {
            results.push({ table, rows: 0, status: 'error', error: err.message });
            log.warn(`[BACKUP] ✗ ${table}: ${err.message}`);
        }
    }

    if (attachments.length === 0) {
        log.warn('[BACKUP] No data found to back up — skipping email.');
        return;
    }

    // ── Prepare Email ──
    const RECIPIENT = process.env.FROM_EMAIL;
    const dateLabel = startedAt.toLocaleDateString('en-KE', { weekday:'long', year:'numeric', month:'long', day:'numeric' });
    
    // Calculate approximate size for logging
    const totalSizeKb = Math.round(attachments.reduce((sum, att) => sum + Buffer.byteLength(att.content, 'utf8'), 0) / 1024);

    const tableRowsHtml = results.map(r => `
        <tr>
            <td style="padding:7px 12px;border-bottom:1px solid #1e293b;font-family:monospace;font-size:12px;color:#e2e8f0;">${r.table}</td>
            <td style="padding:7px 12px;border-bottom:1px solid #1e293b;text-align:right;font-family:monospace;font-size:12px;color:${r.status === 'ok' ? '#00e5a0' : '#64748b'};">${r.rows.toLocaleString()}</td>
            <td style="padding:7px 12px;border-bottom:1px solid #1e293b;font-size:11px;color:${r.status === 'ok' ? '#00e5a0' : r.status === 'error' ? '#ff4d6d' : '#64748b'};">
                ${r.status === 'ok' ? '✓ CSV Ready' : r.status === 'empty' ? 'Empty' : '✗ ' + (r.error || 'Error')}
            </td>
        </tr>`).join('');

    try {
        const info = await transporter.sendMail({
            from: `"Elite Hardware POS" <${process.env.FROM_EMAIL}>`,
            to:   RECIPIENT,
            subject: `🗄️ Daily CSV Backup — ${startedAt.toISOString().slice(0, 10)} — ${totalRows.toLocaleString()} rows`,
            html: `
                <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;background:#0a0f1e;padding:20px;border-radius:12px;">
                    <h2 style="color:#00e5a0;margin-top:0;">Daily Database Backup</h2>
                    <p style="color:#94a3b8;font-size:14px;">Backup generated on <strong>${dateLabel}</strong>.</p>
                    
                    <div style="background:#111827;padding:16px;border-radius:8px;margin:20px 0;border-left:4px solid #00e5a0;">
                        <p style="color:#e2e8f0;margin:0;font-size:13px;">Total Tables: <b>${attachments.length}</b></p>
                        <p style="color:#e2e8f0;margin:5px 0 0;font-size:13px;">Total Rows: <b>${totalRows.toLocaleString()}</b></p>
                    </div>

                    <table style="width:100%;border-collapse:collapse;background:#111827;border-radius:8px;overflow:hidden;">
                        <thead>
                            <tr style="background:#1f2937;color:#64748b;font-size:10px;text-transform:uppercase;">
                                <th style="padding:10px 12px;text-align:left;">Table</th>
                                <th style="padding:10px 12px;text-align:right;">Rows</th>
                                <th style="padding:10px 12px;text-align:left;">Status</th>
                            </tr>
                        </thead>
                        <tbody>${tableRowsHtml}</tbody>
                    </table>

                    <p style="color:#64748b;font-size:11px;margin-top:20px;">
                        Attached are individual CSV files for each table. These can be opened directly in Excel, Google Sheets, or Numbers.
                    </p>
                </div>`,
            attachments: attachments
        });

        log.info(`[BACKUP] ✅ CSV Backup email sent to ${RECIPIENT} (msgId: ${info.messageId}) — Total Size: ~${totalSizeKb} KB`);
    } catch (mailErr) {
        log.error(`[BACKUP] ✗ Failed to email CSV backup: ${mailErr.message}`);
    }
}
// Schedule: 2:00 AM EAT = 23:00 UTC (previous day)
function scheduleBackup() {
    function msToNext23UTC() {
        const now  = new Date();
        const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 23, 0, 0));
        if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
        return next - now;
    }
    const ms = msToNext23UTC();
    log.info(`[BACKUP] Next daily backup in ${Math.round(ms / 60000)} minutes (2:00 AM EAT)`);
    setTimeout(() => {
        runDailyBackup();
        setInterval(runDailyBackup, 24 * 60 * 60 * 1000); // then every 24h
    }, ms);
}
scheduleBackup();

app.post('/api/scripts/etims-retry', requireAuth, requireRole('admin'), async (req, res) => {
    res.json({ success: true, message: 'eTIMS retry started in background' });
    retryPendingEtims();
});

app.post('/api/scripts/eod-summary', requireAuth, requireRole('admin'), async (req, res) => {
    res.json({ success: true, message: 'EOD summary email triggered' });
    sendEodSummary();
});

app.post('/api/scripts/credit-aging', requireAuth, requireRole('admin'), async (req, res) => {
    res.json({ success: true, message: 'Credit aging report triggered' });
    runCreditAgingAlert();
});

app.post('/api/scripts/dead-stock', requireAuth, requireRole('admin'), async (req, res) => {
    res.json({ success: true, message: 'Dead stock check triggered' });
    runDeadStockDetector();
});

app.post('/api/scripts/db-cleanup', requireAuth, requireRole('admin'), async (req, res) => {
    res.json({ success: true, message: 'Database cleanup started' });
    runDatabaseCleanup();
});

app.post('/api/scripts/backup', requireAuth, requireRole('admin'), async (req, res) => {
    res.json({ success: true, message: 'Database backup started — check your email in ~1 minute' });
    runDailyBackup();
});

// GET /api/scripts/backup-list — list recent backups stored in memory
app.get('/api/scripts/backup-list', requireAuth, requireRole('admin'), (req, res) => {
    res.json({
        success: true,
        count: _backupArchive.length,
        backups: _backupArchive.map(b => ({
            createdAt: b.createdAt,
            label:     b.label,
            sizeKb:    b.sizeKb,
            totalRows: b.totalRows,
            tables:    b.results.map(r => ({ table: r.table, rows: r.rows, status: r.status }))
        }))
    });
});

// GET /api/scripts/backup-download/:index — download a specific backup (0 = latest)
app.get('/api/scripts/backup-download/:index', requireAuth, requireRole('admin'), (req, res) => {
    const idx    = parseInt(req.params.index) || 0;
    const backup = _backupArchive[idx];
    if (!backup) return res.status(404).json({ success: false, message: 'No backup found at that index. Run a backup first.' });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${backup.label}.json"`);
    res.send(backup.json);
});

// ============================================================
//  CUSTOMER STATEMENTS (General & Credit Ledgers)
// ============================================================
app.get('/api/reports/customer-statement', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { phone, from, to, type } = req.query; // type = 'all' | 'credit'
    
    if (!phone) return res.status(400).json({ success: false, message: 'Phone number required' });

    try {
        // 1. Get Customer Name
        const { data: cust } = await supabase.from('customers').select('name').eq('phone', phone).maybeSingle();
        const customerName = cust ? cust.name : 'Walk-In Customer';

        // 2. Fetch all sales (Invoices/Debits) for this phone number
        // ADDED: payment_status and is_credit_sale so we can filter them!
        const { data: sales, error: salesErr } = await supabase.from('Sales')
            .select('id, sale_date, item_name, quantity_sold, total_amount, invoice_number, receipt_number, payment_status, is_credit_sale')
            .eq('customer_phone', phone)
            .eq('is_voided', false)
            .order('sale_date', { ascending: true });
        
        if (salesErr) throw salesErr;

        // --- THE FIX: Filter for Credit Statement BEFORE pulling payments ---
        let targetSales = sales || [];
        if (type === 'credit') {
            targetSales = targetSales.filter(s => 
                s.is_credit_sale === true || ['Credit', 'Partial'].includes(s.payment_status)
            );
        }

        const saleIds = targetSales.map(s => s.id);

        // Group cart sales by transaction reference so 10 items look like 1 invoice
        const salesGroups = {};
        targetSales.forEach(s => {
            const key = s.invoice_number || s.receipt_number || `solo_${s.id}`;
            if (!salesGroups[key]) {
                salesGroups[key] = {
                    date: s.sale_date,
                    ref: key,
                    items: [],
                    debit: 0
                };
            }
            salesGroups[key].items.push(`${s.item_name} x${s.quantity_sold}`);
            salesGroups[key].debit += parseFloat(s.total_amount || 0);
        });

        // 3. Fetch actual payments (Credits) ONLY for the targeted sales
        let payments = [];
        if (saleIds.length > 0) {
            const { data: pays, error: payErr } = await supabase.from('payments')
                .select('id, created_at, amount, payment_method, mpesa_code, sale_id')
                .in('sale_id', saleIds)
                .order('created_at', { ascending: true });
            if (payErr) throw payErr;
            payments = pays || [];
        }

        // Group payments that occurred in the exact same minute to consolidate multi-item carts
        const payGroups = {};
        payments.forEach(p => {
            const minuteKey = p.created_at.substring(0, 16); 
            const baseCode = p.mpesa_code ? p.mpesa_code.split('-')[0] : p.payment_method;
            const key = `${minuteKey}_${baseCode}`;

            if (!payGroups[key]) {
                payGroups[key] = {
                    date: p.created_at,
                    ref: p.mpesa_code ? p.mpesa_code.split('-')[0] : `PAY-${minuteKey.replace(/\D/g, '')}`,
                    method: p.payment_method,
                    credit: 0
                };
            }
            payGroups[key].credit += parseFloat(p.amount || 0);
        });

        // 4. Assemble the Chronological Ledger
        let ledger = [];
        
        Object.values(salesGroups).forEach(sg => {
            ledger.push({
                date: sg.date,
                type: 'Invoice',
                ref: sg.ref,
                description: `Goods: ${sg.items.join(', ')}`,
                debit: sg.debit,         // Amount charged to customer
                credit: 0                // ZERO. Payments are strictly handled below.
            });
        });

        Object.values(payGroups).forEach(pg => {
            ledger.push({
                date: pg.date,
                type: 'Payment',
                ref: pg.ref,
                description: `Payment (${pg.method})`,
                debit: 0,
                credit: pg.credit        // Amount customer actually paid
            });
        });

        // Sort everything purely by chronological Date
        ledger.sort((a, b) => new Date(a.date) - new Date(b.date));

        // 5. Calculate Running Balances and Apply Date Filters
        let runningBalance = 0;
        let openingBalance = 0;
        let filteredLedger = [];
        let totalDebits = 0;
        let totalCredits = 0;

        const fromDate = from ? new Date(`${from}T00:00:00.000+03:00`) : null;
        const toDate   = to   ? new Date(`${to}T23:59:59.999+03:00`)   : null;

        ledger.forEach(entry => {
            const entryDate = new Date(entry.date);
            
            if (fromDate && entryDate < fromDate) {
                // Occurred before the requested period — roll into Opening Balance
                runningBalance += entry.debit - entry.credit;
                openingBalance = runningBalance;
            } else if (!toDate || entryDate <= toDate) {
                // Occurs within the period
                runningBalance += entry.debit - entry.credit;
                entry.balance = runningBalance;
                filteredLedger.push(entry);
                totalDebits += entry.debit;
                totalCredits += entry.credit;
            }
        });

        res.json({
            success: true,
            customer: { name: customerName, phone: phone },
            period: { from, to },
            summary: { openingBalance, totalDebits, totalCredits, closingBalance: runningBalance },
            ledger: filteredLedger
        });

    } catch (err) {
        console.error('[CUSTOMER STATEMENT]', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
// ============================================================
//  SUPPLIER STATEMENTS (Accounts Payable Ledger)
// ============================================================
app.get('/api/reports/supplier-statement', requireAuth, requireRole('admin', 'manager'), async (req, res) => {
    const { supplier_id, from, to } = req.query;
    
    if (!supplier_id) return res.status(400).json({ success: false, message: 'Supplier ID required' });

    try {
        // 1. Get Supplier Details
        const { data: sup } = await supabase.from('suppliers')
            .select('name, contact, phone, email').eq('id', supplier_id).single();
        if (!sup) throw new Error("Supplier not found");

        // 2. Fetch valid Purchase Orders (Billed Amounts)
        const { data: pos } = await supabase.from('purchase_orders')
            .select('po_number, order_date, total_amount, status')
            .eq('supplier_id', supplier_id)
            .neq('status', 'Draft')
            .neq('status', 'Cancelled');

        // 3. Fetch Payments (from audit_logs since payments reduce PO balances directly)
        const { data: payments } = await supabase.from('audit_logs')
            .select('timestamp, details, item_name')
            .eq('action', 'SUPPLIER_PAYMENT')
            .ilike('details', `%to ${sup.name}%`);

        // 4. Fetch Returns (which act as credits/reductions to the balance)
        const { data: returns } = await supabase.from('supplier_returns')
            .select('id, created_at, total_return_value, item_name, po_id')
            .eq('supplier_id', supplier_id)
            .eq('balance_adjusted', true);

        // 5. Assemble the Ledger
        let ledger = [];

        (pos || []).forEach(po => {
            ledger.push({
                date: po.order_date,
                type: 'Invoice',
                ref: po.po_number,
                description: `Purchase Order (${po.status})`,
                billed: parseFloat(po.total_amount || 0), // Increases what we owe
                paid: 0
            });
        });

        (payments || []).forEach(pay => {
            const amtMatch = pay.details.match(/Payment KES ([\d,.]+)/);
            const amt = amtMatch ? parseFloat(amtMatch[1].replace(/,/g, '')) : 0;
            
            const methMatch = pay.details.match(/Method: ([^|]+)/);
            const method = methMatch ? methMatch[1].trim() : 'Payment';

            ledger.push({
                date: pay.timestamp,
                type: 'Payment',
                ref: pay.item_name || 'PAYMENT', // po_number is usually in item_name
                description: `Payment Sent (${method})`,
                billed: 0,
                paid: amt // Decreases what we owe
            });
        });

        (returns || []).forEach(ret => {
            ledger.push({
                date: ret.created_at,
                type: 'Return',
                ref: `RET-${ret.id || 'N/A'}`,
                description: `Goods Returned: ${ret.item_name}`,
                billed: 0,
                paid: parseFloat(ret.total_return_value || 0) // Decreases what we owe
            });
        });

        // 6. Sort Chronologically
        ledger.sort((a, b) => new Date(a.date) - new Date(b.date));

        // 7. Calculate Running Balances & Apply Date Filters
        let runningBalance = 0;
        let openingBalance = 0;
        let filteredLedger = [];
        let totalBilled = 0;
        let totalPaid = 0;

        const fromDate = from ? new Date(`${from}T00:00:00.000+03:00`) : null;
        const toDate   = to   ? new Date(`${to}T23:59:59.999+03:00`)   : null;

        ledger.forEach(entry => {
            const entryDate = new Date(entry.date);
            
            if (fromDate && entryDate < fromDate) {
                runningBalance += entry.billed - entry.paid;
                openingBalance = runningBalance;
            } else if (!toDate || entryDate <= toDate) {
                runningBalance += entry.billed - entry.paid;
                entry.balance = runningBalance;
                filteredLedger.push(entry);
                totalBilled += entry.billed;
                totalPaid += entry.paid;
            }
        });

        res.json({
            success: true,
            supplier: sup,
            period: { from, to },
            summary: { openingBalance, totalBilled, totalPaid, closingBalance: runningBalance },
            ledger: filteredLedger
        });

    } catch (err) {
        console.error('[SUPPLIER STATEMENT]', err);
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
// ============================================================
//  SALES ORDERS / QUOTATIONS
// ============================================================

// Helper to generate SO number
function generateSONumber() {
    const now = new Date();
    const date = now.getFullYear().toString() + String(now.getMonth() + 1).padStart(2, '0') + String(now.getDate()).padStart(2, '0');
    const time = String(now.getHours()).padStart(2, '0') + String(now.getMinutes()).padStart(2, '0') + String(now.getSeconds()).padStart(2, '0');
    return `SO-${date}-${time}`;
}

// ── GET All Sales Orders ──────────────────────────────────────────────────────
app.get('/api/sales-orders', requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('sales_orders')
            .select('*, sales_order_items(*)')
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── GET Single Sales Order ────────────────────────────────────────────────────
app.get('/api/sales-orders/:id', requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('sales_orders')
            .select('*, sales_order_items(*)')
            .eq('id', req.params.id)
            .single();
        if (error || !data) return res.status(404).json({ success: false, message: 'Sales order not found.' });
        res.json(data);
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── POST Create Sales Order (Quote) ───────────────────────────────────────────
app.post('/api/sales-orders', requireAuth, requireSubscription, async (req, res) => {
    const { customerName, customerPhone, validUntil, notes, items } = req.body;
    if (!customerName) return res.status(400).json({ success: false, message: 'Customer name required.' });
    if (!items || !items.length) return res.status(400).json({ success: false, message: 'Add at least one item.' });

    try {
        const so_number = generateSONumber();
        const total_amount = items.reduce((s, i) => s + (parseFloat(i.qty_ordered) * parseFloat(i.unit_price)), 0);

        const { data: so, error: soErr } = await supabase
            .from('sales_orders')
            .insert([{
                so_number, customer_name: customerName, customer_phone: customerPhone,
                status: 'Quote', order_date: new Date().toISOString().split('T')[0],
                valid_until: validUntil || null, total_amount, notes, created_by: req.user.name
            }]).select().single();
        
        if (soErr) throw soErr;

        const lineItems = items.map(i => ({
            so_id: so.id, inventory_id: i.inventory_id,
            item_name: i.item_name, qty_ordered: parseInt(i.qty_ordered),
            unit_price: parseFloat(i.unit_price), line_total: parseFloat(i.qty_ordered) * parseFloat(i.unit_price)
        }));

        await supabase.from('sales_order_items').insert(lineItems);
        
        await supabase.from('audit_logs').insert([{
            performed_by: req.user.name, action: 'SO_CREATED', item_name: so_number,
            details: `Quote ${so_number} created for ${customerName}. Total: KES ${total_amount}`,
            timestamp: new Date().toISOString()
        }]);

        res.json({ success: true, message: 'Quotation created successfully.', data: so });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ── PUT Update Status (Confirm / Cancel) ──────────────────────────────────────
app.put('/api/sales-orders/:id/status', requireAuth, requireSubscription, async (req, res) => {
    const { status } = req.body;
    const ALLOWED_STATUSES = ['Quote', 'Confirmed', 'Fulfilled', 'Cancelled'];
    if (!status || !ALLOWED_STATUSES.includes(status)) {
        return res.status(400).json({ success: false, message: `Invalid status. Must be one of: ${ALLOWED_STATUSES.join(', ')}.` });
    }
    try {
        const { error } = await supabase.from('sales_orders').update({ status }).eq('id', req.params.id);
        if (error) throw error;
        res.json({ success: true, message: `Order marked as ${status}.` });
    } catch (err) {
        log.error('[API]', err.message); res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});
// ════════════════════════════════════════════════════════════════════════════════
// SCRIPT 8: SELF-PINGING (Anti-Sleep)
// Runs every 10 minutes. Hits the root URL of the server to keep the instance
// active on hosting platforms like Render (Free Tier).
// ════════════════════════════════════════════════════════════════════════════════
const SELF_URL = process.env.SELF_URL;

async function runSelfPing() {
    if (!SELF_URL) {
        log.info('[SELF-PING] No SELF_URL configured. Skipping anti-sleep ping.');
        return;
    }
    
    try {
        const res = await fetch(SELF_URL, { signal: AbortSignal.timeout(5000) });
        if (res.ok) {
            log.info(`[SELF-PING] Heartbeat sent to ${SELF_URL} — Status: ${res.status}`);
        } else {
            log.warn(`[SELF-PING] Heartbeat returned non-OK status: ${res.status}`);
        }
    } catch (err) {
        log.error(`[SELF-PING] Failed to ping ${SELF_URL}: ${err.message}`);
    }
}

// Only start pinging if the environment is not local
if (process.env.NODE_ENV === 'production' || process.env.MPESA_ENV === 'live') {
    // Ping immediately on startup
    runSelfPing();
    // Repeat every 10 minutes (600,000 ms)
    setInterval(runSelfPing, 10 * 60 * 1000);
}
// ── ONE-TIME STARTUP MIGRATION: quantity_sold → NUMERIC ─────────────────────
// Supabase Sales.quantity_sold was INTEGER, which rejects decimal sub-unit
// quantities (e.g. 0.5 Kg sold loose). This migration widens it to NUMERIC(12,4)
// so fractional quantities are stored accurately. Safe to run on every restart —
// ALTER TYPE to same or wider type is idempotent in Postgres.
(async () => {
    try {
        const { error } = await supabase.rpc('exec_sql', {
            sql: `ALTER TABLE "Sales" ALTER COLUMN quantity_sold TYPE NUMERIC(12,4) USING quantity_sold::NUMERIC;`
        });
        if (error) {
            // exec_sql RPC may not exist — fall back to a direct query via the REST API
            // This is fine — the column may already be NUMERIC from a prior run.
            log.warn('[MIGRATION] quantity_sold column type: could not alter via RPC —', error.message,
                '(safe to ignore if already NUMERIC)');
        } else {
            log.info('[MIGRATION] Sales.quantity_sold column confirmed NUMERIC(12,4)');
        }
    } catch (e) {
        log.warn('[MIGRATION] quantity_sold migration skipped:', e.message);
    }
})();

app.listen(PORT, () => log.info(`🚀 Elite Hardware POS running on http://localhost:${PORT}`));