// ═══════════════════════════════════════════════════════════════════════════════
//  AI ASSISTANT — Elite Hardware POS
//
//  Mount from server.js (just above app.listen):
//      require('./ai-assistant')({ app, express, supabase, requireAuth, requireRole, log });
//
//  Env vars:
//      ANTHROPIC_API_KEY   required for: Ask, Restock summary, Flags summary, Delivery-note photo
//      AI_MODEL            optional, default claude-sonnet-5-5
//      AI_DAILY_LIMIT      optional, max AI calls per day for the whole shop (default 300)
//      BUSINESS_NAME       optional, used in debt-reminder messages (default "Elite Hardware")
//
//  Endpoints (all admin + manager only):
//      GET  /api/ai/status
//      POST /api/ai/ask                  { question, history? }
//      GET  /api/ai/restock              ?cover_days=21&summary=1
//      POST /api/ai/debt-reminders       { min_days?, limit? }
//      POST /api/ai/parse-delivery-note  raw image bytes (Content-Type: image/jpeg|png|webp)
//      GET  /api/ai/flags                ?days=30&summary=1
//      POST /api/ai/match-payment        { c2bId }          (rule based, no AI call)
//
//  Safety: the AI only ever receives read-only tools. Nothing here writes to the database;
//  stock / purchase orders are changed by the existing routes after a person confirms.
//  Customer phone numbers are masked before they are sent to the model.
// ═══════════════════════════════════════════════════════════════════════════════
'use strict';

module.exports = function mountAI({ app, express, supabase, requireAuth, requireRole, log }) {
    const AI_KEY   = process.env.ANTHROPIC_API_KEY || '';
    const AI_MODEL = process.env.AI_MODEL || 'claude-sonnet-5-5';
    const DAILY_LIMIT = parseInt(process.env.AI_DAILY_LIMIT || '300', 10);
    const BUSINESS = process.env.BUSINESS_NAME || 'Elite Hardware';
    const CREDIT = ['Credit', 'Partial', 'credit', 'partial', 'Unpaid'];
    const guard = [requireAuth, requireRole('admin', 'manager')];

    // ── helpers ────────────────────────────────────────────────────────────────
    const r2 = n => Math.round((parseFloat(n) || 0) * 100) / 100;
    const num = n => parseFloat(n) || 0;
    const eatDate = (d = new Date()) => new Date(d.getTime() + 3 * 3600 * 1000).toISOString().split('T')[0];
    const dayStart = d => `${d}T00:00:00.000+03:00`;
    const dayEnd = d => `${d}T23:59:59.999+03:00`;
    const isDate = d => /^\d{4}-\d{2}-\d{2}$/.test(String(d || ''));
    const addDays = (d, n) => eatDate(new Date(new Date(dayStart(d)).getTime() + n * 86400000));
    const daysBetween = (iso) => Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86400000));
    const maskPhone = p => { const s = String(p || '').replace(/\D/g, ''); return s ? `***${s.slice(-3)}` : ''; };
    const last9 = p => String(p || '').replace(/\D/g, '').slice(-9);
    const waPhone = p => { let s = String(p || '').replace(/\D/g, ''); if (s.startsWith('0')) s = '254' + s.slice(1); return s.length >= 11 ? s : ''; };
    const fail = (res, err, tag, msg = 'An internal server error occurred.') => {
        log.error(`[AI ${tag}]`, err.message); res.status(500).json({ success: false, message: msg });
    };

    async function fetchAll(build, pageSize = 1000, maxPages = 60) {
        let rows = [];
        for (let p = 0; p < maxPages; p++) {
            const { data, error } = await build().range(p * pageSize, (p + 1) * pageSize - 1);
            if (error) throw error;
            rows = rows.concat(data || []);
            if (!data || data.length < pageSize) break;
        }
        return rows;
    }

    // ── daily budget + Claude call ─────────────────────────────────────────────
    const usage = { day: eatDate(), calls: 0 };
    function takeBudget() {
        const today = eatDate();
        if (usage.day !== today) { usage.day = today; usage.calls = 0; }
        if (usage.calls >= DAILY_LIMIT) { const e = new Error('Daily AI limit reached.'); e.code = 'LIMIT'; throw e; }
        usage.calls++;
    }
    function needKey() {
        if (!AI_KEY) { const e = new Error('AI is not configured.'); e.code = 'NOKEY'; throw e; }
    }
    function aiError(res, err, tag) {
        if (err.code === 'NOKEY') return res.status(503).json({ success: false, message: 'AI is not switched on yet. Add ANTHROPIC_API_KEY to the server environment.' });
        if (err.code === 'LIMIT') return res.status(429).json({ success: false, message: `Daily AI limit (${DAILY_LIMIT} requests) reached. It resets at midnight.` });
        return fail(res, err, tag, 'The AI service could not answer right now. Please try again.');
    }
    async function claude({ system, messages, tools, max_tokens = 1200 }) {
        needKey(); takeBudget();
        const body = { model: AI_MODEL, max_tokens, system, messages };
        if (tools && tools.length) body.tools = tools;
        const r = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: { 'x-api-key': AI_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(60000)
        });
        const text = await r.text();
        let data; try { data = JSON.parse(text); } catch { throw new Error('Non-JSON from Anthropic: ' + text.slice(0, 200)); }
        if (!r.ok) throw new Error(`Anthropic ${r.status}: ${data?.error?.message || text.slice(0, 200)}`);
        return data;
    }
    const textOf = d => (d.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
    function parseJson(s) {
        const m = String(s).match(/[\[{][\s\S]*[\]}]/);
        if (!m) throw new Error('No JSON in model output');
        return JSON.parse(m[0]);
    }

    // ═══════════════════════════ shared data loaders ═══════════════════════════
    async function loadSales(from, to, extra = '') {
        return fetchAll(() => supabase.from('Sales')
            .select('id,item_name,quantity_sold,unit_price,total_amount,amount_paid,cost_price,customer_name,customer_phone,sold_by,sale_date,payment_status,price_tier,is_voided,voided_by,void_reason')
            .gte('sale_date', dayStart(from)).lte('sale_date', dayEnd(to)).order('id'));
    }

    async function loadDebtors() {
        const rows = await fetchAll(() => supabase.from('Sales')
            .select('id,item_name,total_amount,amount_paid,customer_name,customer_phone,sale_date,invoice_number,receipt_number')
            .eq('is_voided', false).in('payment_status', CREDIT).order('id'));
        const groups = {};
        for (const s of rows) {
            const bal = num(s.total_amount) - num(s.amount_paid);
            if (bal <= 0.01) continue;
            const phone = String(s.customer_phone || '').trim();
            const hasPhone = phone && !/no phone/i.test(phone);
            const key = hasPhone ? 'p' + last9(phone) : 'n' + String(s.customer_name || 'Unknown').trim().toLowerCase();
            const g = groups[key] || (groups[key] = { key, name: s.customer_name || 'Unknown', phone: hasPhone ? phone : '', owed: 0, invoices: 0, oldest: s.sale_date, sale_ids: [] });
            g.owed += bal; g.invoices++; g.sale_ids.push(s.id);
            if (new Date(s.sale_date) < new Date(g.oldest)) g.oldest = s.sale_date;
        }
        return Object.values(groups).map(g => ({ ...g, owed: r2(g.owed), age_days: daysBetween(g.oldest) }))
            .sort((a, b) => b.owed - a.owed);
    }

    // ═══════════════════════ 1. ASK YOUR DATA (tool use) ═══════════════════════
    const TOOLS = [
        { name: 'get_debtors', description: 'Customers who owe money: amount owed, number of unpaid invoices, age in days of the oldest unpaid invoice. Sorted by amount owed.',
          input_schema: { type: 'object', properties: { limit: { type: 'integer', description: 'max rows, default 15' } } } },
        { name: 'get_sales_summary', description: 'Sales totals between two dates (inclusive, YYYY-MM-DD, East Africa Time): count, gross sales, cash received, credit unpaid, cost of goods, profit. Optionally grouped by day, item or cashier (top 20).',
          input_schema: { type: 'object', required: ['from', 'to'], properties: { from: { type: 'string' }, to: { type: 'string' }, group_by: { type: 'string', enum: ['none', 'day', 'item', 'cashier'] } } } },
        { name: 'top_products', description: 'Best selling products between two dates ranked by revenue, quantity or profit.',
          input_schema: { type: 'object', required: ['from', 'to'], properties: { from: { type: 'string' }, to: { type: 'string' }, by: { type: 'string', enum: ['revenue', 'quantity', 'profit'] }, limit: { type: 'integer' } } } },
        { name: 'profit_by_day', description: 'Per-day cash received, cost of goods, expenses and net profit between two dates. Use it to find which day was weak.',
          input_schema: { type: 'object', required: ['from', 'to'], properties: { from: { type: 'string' }, to: { type: 'string' } } } },
        { name: 'get_day_detail', description: 'Explain one day: its top items by profit, big credit sales, expenses and voids. Use to answer "why was profit low on <date>".',
          input_schema: { type: 'object', required: ['date'], properties: { date: { type: 'string' } } } },
        { name: 'get_stock', description: 'Current stock. low_only=true returns items running low relative to how fast they sell.',
          input_schema: { type: 'object', properties: { low_only: { type: 'boolean' }, limit: { type: 'integer' } } } },
        { name: 'get_expenses', description: 'Expenses between two dates grouped by category, plus the 10 biggest.',
          input_schema: { type: 'object', required: ['from', 'to'], properties: { from: { type: 'string' }, to: { type: 'string' } } } }
    ];

    const top = (obj, key, n = 20) => Object.entries(obj).map(([k, v]) => ({ name: k, ...v }))
        .sort((a, b) => b[key] - a[key]).slice(0, n).map(o => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, typeof v === 'number' ? r2(v) : v])));

    async function runTool(name, input) {
        input = input || {};
        const need = (...ks) => { for (const k of ks) if (!isDate(input[k])) throw new Error(`${k} must be YYYY-MM-DD`); };
        switch (name) {
            case 'get_debtors': {
                const d = await loadDebtors();
                return { total_owed: r2(d.reduce((s, x) => s + x.owed, 0)), debtor_count: d.length,
                    debtors: d.slice(0, Math.min(parseInt(input.limit) || 15, 40)).map(x => ({ name: x.name, phone: maskPhone(x.phone), owed: x.owed, unpaid_invoices: x.invoices, oldest_unpaid_days: x.age_days })) };
            }
            case 'get_sales_summary': {
                need('from', 'to');
                const rows = (await loadSales(input.from, input.to)).filter(s => !s.is_voided);
                const tot = { sales_count: rows.length, gross_sales: 0, cash_received: 0, credit_unpaid: 0, cost_of_goods: 0 };
                const groups = {};
                for (const s of rows) {
                    const t = num(s.total_amount), p = num(s.amount_paid), c = num(s.cost_price);
                    tot.gross_sales += t; tot.cash_received += p; tot.credit_unpaid += Math.max(0, t - p); tot.cost_of_goods += c;
                    const gb = input.group_by;
                    if (gb && gb !== 'none') {
                        const k = gb === 'day' ? eatDate(new Date(s.sale_date)) : gb === 'item' ? s.item_name : (s.sold_by || 'unknown');
                        const g = groups[k] || (groups[k] = { sales: 0, received: 0, profit: 0, count: 0 });
                        g.sales += t; g.received += p; g.profit += p - c; g.count++;
                    }
                }
                const out = Object.fromEntries(Object.entries(tot).map(([k, v]) => [k, k === 'sales_count' ? v : r2(v)]));
                out.profit_before_expenses = r2(tot.cash_received - tot.cost_of_goods);
                if (input.group_by && input.group_by !== 'none') out.groups = input.group_by === 'day'
                    ? Object.entries(groups).sort().map(([k, v]) => ({ name: k, sales: r2(v.sales), received: r2(v.received), profit: r2(v.profit), count: v.count }))
                    : top(groups, 'sales');
                return out;
            }
            case 'top_products': {
                need('from', 'to');
                const rows = (await loadSales(input.from, input.to)).filter(s => !s.is_voided);
                const g = {};
                for (const s of rows) {
                    const x = g[s.item_name] || (g[s.item_name] = { revenue: 0, quantity: 0, profit: 0 });
                    x.revenue += num(s.total_amount); x.quantity += num(s.quantity_sold); x.profit += num(s.total_amount) - num(s.cost_price);
                }
                return { ranked_by: input.by || 'revenue', products: top(g, input.by || 'revenue', Math.min(parseInt(input.limit) || 10, 30)) };
            }
            case 'profit_by_day': {
                need('from', 'to');
                const [rows, exps] = await Promise.all([
                    loadSales(input.from, input.to),
                    fetchAll(() => supabase.from('expenses').select('id,amount,expense_date').gte('expense_date', dayStart(input.from)).lte('expense_date', dayEnd(input.to)).order('id'))
                ]);
                const days = {};
                const d = k => days[k] || (days[k] = { received: 0, cost: 0, expenses: 0, sales: 0 });
                for (const s of rows) { if (s.is_voided) continue; const x = d(eatDate(new Date(s.sale_date))); x.received += num(s.amount_paid); x.cost += num(s.cost_price); x.sales += num(s.total_amount); }
                for (const e of exps) d(eatDate(new Date(e.expense_date))).expenses += num(e.amount);
                return { days: Object.entries(days).sort().map(([k, v]) => ({ date: k, weekday: new Date(dayStart(k)).toLocaleDateString('en-US', { weekday: 'long', timeZone: 'Africa/Nairobi' }), gross_sales: r2(v.sales), cash_received: r2(v.received), cost_of_goods: r2(v.cost), expenses: r2(v.expenses), net_profit: r2(v.received - v.cost - v.expenses) })) };
            }
            case 'get_day_detail': {
                need('date');
                const [rows, exps] = await Promise.all([
                    loadSales(input.date, input.date),
                    fetchAll(() => supabase.from('expenses').select('id,amount,category,description').gte('expense_date', dayStart(input.date)).lte('expense_date', dayEnd(input.date)).order('id'))
                ]);
                const live = rows.filter(s => !s.is_voided), voids = rows.filter(s => s.is_voided);
                const items = {};
                for (const s of live) { const x = items[s.item_name] || (items[s.item_name] = { profit: 0, revenue: 0 }); x.profit += num(s.amount_paid) - num(s.cost_price); x.revenue += num(s.total_amount); }
                return {
                    date: input.date, sales_count: live.length, gross_sales: r2(live.reduce((s, x) => s + num(x.total_amount), 0)),
                    cash_received: r2(live.reduce((s, x) => s + num(x.amount_paid), 0)), cost_of_goods: r2(live.reduce((s, x) => s + num(x.cost_price), 0)),
                    credit_sales: live.filter(s => num(s.amount_paid) < num(s.total_amount) - 0.01).slice(0, 8).map(s => ({ customer: s.customer_name, item: s.item_name, total: r2(s.total_amount), paid: r2(s.amount_paid) })),
                    weakest_items: top(items, 'profit', 200).sort((a, b) => a.profit - b.profit).slice(0, 5),
                    best_items: top(items, 'profit', 5),
                    expenses: exps.map(e => ({ category: e.category, description: e.description, amount: r2(e.amount) })).slice(0, 15),
                    total_expenses: r2(exps.reduce((s, e) => s + num(e.amount), 0)),
                    voided_sales: voids.map(s => ({ item: s.item_name, total: r2(s.total_amount), by: s.voided_by, reason: s.void_reason })).slice(0, 10)
                };
            }
            case 'get_stock': {
                const items = await fetchAll(() => supabase.from('Inventory').select('id,item_name,stock_quantity,unit,price,cost_price').order('id'));
                let list = items.map(i => ({ id: i.id, name: i.item_name, stock: num(i.stock_quantity), unit: i.unit, cost: num(i.cost_price) }));
                if (input.low_only) {
                    const rs = await restockList(21);
                    return { items: rs.filter(x => x.days_left <= 14).slice(0, Math.min(parseInt(input.limit) || 15, 40)).map(x => ({ name: x.item_name, stock: x.stock, sells_per_day: x.daily_rate, days_left: x.days_left })) };
                }
                return { item_count: list.length, stock_value_at_cost: r2(list.reduce((s, i) => s + Math.max(0, i.stock) * i.cost, 0)),
                    items: list.sort((a, b) => a.stock - b.stock).slice(0, Math.min(parseInt(input.limit) || 15, 40)).map(({ name, stock, unit }) => ({ name, stock, unit })) };
            }
            case 'get_expenses': {
                need('from', 'to');
                const exps = await fetchAll(() => supabase.from('expenses').select('id,amount,category,description,expense_date').gte('expense_date', dayStart(input.from)).lte('expense_date', dayEnd(input.to)).order('id'));
                const cat = {};
                for (const e of exps) cat[e.category || 'Other'] = (cat[e.category || 'Other'] || 0) + num(e.amount);
                return { total: r2(exps.reduce((s, e) => s + num(e.amount), 0)), by_category: Object.entries(cat).map(([k, v]) => ({ category: k, amount: r2(v) })).sort((a, b) => b.amount - a.amount),
                    biggest: exps.sort((a, b) => num(b.amount) - num(a.amount)).slice(0, 10).map(e => ({ date: eatDate(new Date(e.expense_date)), category: e.category, description: e.description, amount: r2(e.amount) })) };
            }
            default: throw new Error('Unknown tool ' + name);
        }
    }

    app.get('/api/ai/status', ...guard, (req, res) => {
        res.json({ success: true, configured: !!AI_KEY, model: AI_MODEL, calls_today: usage.day === eatDate() ? usage.calls : 0, daily_limit: DAILY_LIMIT });
    });

    app.post('/api/ai/ask', ...guard, async (req, res) => {
        try {
            const question = String(req.body?.question || '').trim().slice(0, 600);
            if (!question) return res.status(400).json({ success: false, message: 'Type a question first.' });
            const history = Array.isArray(req.body?.history) ? req.body.history.slice(-6)
                .filter(m => m && ['user', 'assistant'].includes(m.role) && typeof m.content === 'string')
                .map(m => ({ role: m.role, content: m.content.slice(0, 2000) })) : [];
            const system = `You are the business assistant for ${BUSINESS}, a hardware store in Kenya. Answer the owner's question using ONLY the tools provided. Never guess numbers; if the data does not answer the question, say so.
Today is ${eatDate()} (East Africa Time). Weeks start on Monday. All money is Kenya shillings; write it like "KES 12,500".
Rules: "cash received" is revenue; unpaid credit is not revenue until paid. Profit = cash received − cost of goods − expenses.
Be concise and plain: lead with the answer, then 2-4 short supporting points. Do not reveal customer phone numbers. You cannot change anything in the system.`;
            const messages = [...history, { role: 'user', content: question }];
            const used = [];
            for (let i = 0; i < 6; i++) {
                const resp = await claude({ system, messages, tools: TOOLS, max_tokens: 1200 });
                if (resp.stop_reason !== 'tool_use') return res.json({ success: true, answer: textOf(resp) || 'I could not find an answer.', tools_used: used });
                messages.push({ role: 'assistant', content: resp.content });
                const results = [];
                for (const b of resp.content.filter(c => c.type === 'tool_use')) {
                    used.push(b.name);
                    let out, isErr = false;
                    try { out = await runTool(b.name, b.input); } catch (e) { out = { error: e.message }; isErr = true; }
                    results.push({ type: 'tool_result', tool_use_id: b.id, content: JSON.stringify(out).slice(0, 12000), ...(isErr ? { is_error: true } : {}) });
                }
                messages.push({ role: 'user', content: results });
            }
            res.json({ success: true, answer: 'That question needs too many steps — try asking it in smaller parts.', tools_used: used });
        } catch (err) { aiError(res, err, 'ASK'); }
    });

    // ═══════════════════════════ 2. RESTOCK SUGGESTIONS ════════════════════════
    async function restockList(coverDays = 21) {
        const to = eatDate(), from = addDays(to, -29);
        const [sales, inv] = await Promise.all([
            loadSales(from, to),
            fetchAll(() => supabase.from('Inventory').select('id,item_name,stock_quantity,unit,cost_price,price').order('id'))
        ]);
        const sold = {};
        for (const s of sales) if (!s.is_voided) sold[s.item_name] = (sold[s.item_name] || 0) + num(s.quantity_sold);
        const out = [];
        for (const i of inv) {
            const units = sold[i.item_name] || 0; if (units <= 0) continue;
            const rate = units / 30, stock = Math.max(0, num(i.stock_quantity));
            const daysLeft = rate > 0 ? stock / rate : 999;
            const suggested = Math.max(0, Math.ceil(rate * coverDays - stock));
            out.push({ inventory_id: i.id, item_name: i.item_name, unit: i.unit || '', stock: r2(stock), sold_30d: r2(units), daily_rate: r2(rate),
                days_left: r2(daysLeft), suggested_qty: suggested, unit_cost: num(i.cost_price), est_cost: r2(suggested * num(i.cost_price)),
                urgency: daysLeft <= 3 ? 'critical' : daysLeft <= 7 ? 'high' : daysLeft <= 14 ? 'medium' : 'ok' });
        }
        return out.sort((a, b) => a.days_left - b.days_left);
    }

    app.get('/api/ai/restock', ...guard, async (req, res) => {
        try {
            const cover = Math.min(Math.max(parseInt(req.query.cover_days) || 21, 7), 90);
            const list = (await restockList(cover)).filter(x => x.urgency !== 'ok' && x.suggested_qty > 0);
            let summary = null;
            if (req.query.summary === '1' && list.length && AI_KEY) {
                try {
                    const d = await claude({ max_tokens: 400, system: `You help the owner of ${BUSINESS}, a hardware store. Write a 3-4 sentence plain summary of what to reorder first and why. Mention the 3 most urgent items by name with days left. KES for money. No headings.`,
                        messages: [{ role: 'user', content: JSON.stringify({ cover_days: cover, items: list.slice(0, 25).map(x => ({ item: x.item_name, stock: x.stock, per_day: x.daily_rate, days_left: x.days_left, suggest: x.suggested_qty, est_cost: x.est_cost })) }) }] });
                    summary = textOf(d);
                } catch (e) { log.warn('[AI RESTOCK] summary skipped: ' + e.message); }
            }
            res.json({ success: true, cover_days: cover, count: list.length, total_est_cost: r2(list.reduce((s, x) => s + x.est_cost, 0)), summary, items: list.slice(0, 80) });
        } catch (err) { fail(res, err, 'RESTOCK'); }
    });

    // ═══════════════════════════ 3. DEBT REMINDERS ═════════════════════════════
    const money = n => 'KES ' + Math.round(n).toLocaleString('en-KE');
    const templateReminder = d => {
        const first = String(d.name).trim().split(/\s+/)[0] || 'Customer';
        const when = d.age_days >= 30 ? `which has been outstanding for ${d.age_days} days` : d.age_days > 0 ? `from ${d.age_days} day${d.age_days === 1 ? '' : 's'} ago` : 'from today';
        return `Hello ${first}, this is ${BUSINESS}. A friendly reminder that you have an outstanding balance of ${money(d.owed)} ${when}. You can pay by M-Pesa or at the shop. Thank you for your business!`;
    };

    app.post('/api/ai/debt-reminders', ...guard, async (req, res) => {
        try {
            const minDays = Math.max(0, parseInt(req.body?.min_days) || 0);
            const limit = Math.min(Math.max(parseInt(req.body?.limit) || 15, 1), 25);
            const debtors = (await loadDebtors()).filter(d => d.age_days >= minDays).slice(0, limit);
            const out = debtors.map((d, i) => ({ id: i, name: d.name, phone: d.phone, owed: d.owed, age_days: d.age_days, invoices: d.invoices, message: templateReminder(d), wa_phone: waPhone(d.phone), ai: false }));
            if (out.length && AI_KEY) {
                try {
                    const d = await claude({ max_tokens: 2500, system: `You write short WhatsApp debt reminders for ${BUSINESS}, a hardware store in Kenya. For each debtor write ONE message (max 45 words), polite and warm, in simple English. Use the customer's first name, the exact amount as "KES 1,234" and how long it has been outstanding. Tone: friendly for under 30 days, firmer but respectful for 30-60 days, clear and serious (still respectful, no threats) over 60 days. Mention they can pay by M-Pesa or at the shop. No emojis other than at most one. Return ONLY a JSON array: [{"id":0,"message":"..."}]`,
                        messages: [{ role: 'user', content: JSON.stringify(out.map(o => ({ id: o.id, name: o.name, owed: o.owed, days_outstanding: o.age_days, unpaid_invoices: o.invoices }))) }] });
                    const arr = parseJson(textOf(d));
                    for (const m of arr) { const o = out[m.id]; if (o && typeof m.message === 'string' && m.message.length > 10) { o.message = m.message.trim(); o.ai = true; } }
                } catch (e) { log.warn('[AI REMINDERS] using templates: ' + e.message); }
            }
            res.json({ success: true, count: out.length, ai_used: out.some(o => o.ai),
                reminders: out.map(o => ({ ...o, wa_link: o.wa_phone ? `https://wa.me/${o.wa_phone}?text=${encodeURIComponent(o.message)}` : null, phone: o.phone })) });
        } catch (err) { aiError(res, err, 'REMINDERS'); }
    });

    // ═══════════════════════════ 4. DELIVERY NOTE → STOCK ══════════════════════
    const STOP = new Set(['the', 'and', 'of', 'for', 'pcs', 'pc', 'piece', 'pieces', 'no', 'x', 'mm', 'cm', 'inch', 'in']);
    const toks = s => String(s || '').toLowerCase().replace(/(\d)\s+([a-z])/g, '$1$2').replace(/[^a-z0-9.\s]/g, ' ').split(/\s+/).filter(t => t && !STOP.has(t));
    function similarity(a, b) {
        const A = toks(a), B = toks(b); if (!A.length || !B.length) return 0;
        const sa = new Set(A), sb = new Set(B); let inter = 0;
        for (const t of sa) if (sb.has(t)) inter++;
        let score = inter / (sa.size + sb.size - inter);
        if (inter >= 2) score = Math.max(score, 0.8 * inter / Math.min(sa.size, sb.size));   // short catalogue name inside a longer printed one
        const na = A.join(' '), nb = B.join(' ');
        if (na === nb) score = 1; else if (na.includes(nb) || nb.includes(na)) score = Math.max(score, 0.75);
        return score;
    }

    app.post('/api/ai/parse-delivery-note', ...guard,
        express.raw({ type: ['image/jpeg', 'image/png', 'image/webp'], limit: '8mb' }),
        async (req, res) => {
            try {
                if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ success: false, message: 'Send the photo as an image (JPEG, PNG or WebP).' });
                const mediaType = String(req.headers['content-type'] || '').split(';')[0];
                const d = await claude({ max_tokens: 3000,
                    system: 'You read photos of supplier delivery notes and invoices for a hardware store. Extract the line items exactly as printed. Return ONLY JSON: {"supplier":string|null,"delivery_number":string|null,"date":"YYYY-MM-DD"|null,"items":[{"name":string,"qty":number,"unit_cost":number|null}]}. unit_cost is the price per single unit EXCLUDING any line total; if only a line total is shown, divide by qty. Use null when something is unreadable — never guess. Ignore totals, VAT and discount lines.',
                    messages: [{ role: 'user', content: [
                        { type: 'image', source: { type: 'base64', media_type: mediaType, data: req.body.toString('base64') } },
                        { type: 'text', text: 'Extract this delivery note.' }] }] });
                const parsed = parseJson(textOf(d));
                const inv = await fetchAll(() => supabase.from('Inventory').select('id,item_name,stock_quantity,price,cost_price,unit').order('id'));
                const items = (Array.isArray(parsed.items) ? parsed.items : []).slice(0, 80).map(it => {
                    const cands = inv.map(i => ({ id: i.id, item_name: i.item_name, price: num(i.price), cost_price: num(i.cost_price), stock: num(i.stock_quantity), unit: i.unit, score: r2(similarity(it.name, i.item_name)) }))
                        .filter(c => c.score >= 0.25).sort((a, b) => b.score - a.score).slice(0, 4);
                    return { raw_name: String(it.name || '').slice(0, 120), qty: num(it.qty), unit_cost: it.unit_cost == null ? null : num(it.unit_cost),
                        match: cands[0] && cands[0].score >= 0.5 ? cands[0] : null, candidates: cands };
                });
                res.json({ success: true, supplier: parsed.supplier || null, delivery_number: parsed.delivery_number || null, date: parsed.date || null, items });
            } catch (err) { aiError(res, err, 'DELIVERY'); }
        });

    // ═══════════════════════════ 5. FRAUD / ERROR FLAGS ════════════════════════
    app.get('/api/ai/flags', ...guard, async (req, res) => {
        try {
            const days = Math.min(Math.max(parseInt(req.query.days) || 30, 7), 180);
            const to = eatDate(), from = addDays(to, -(days - 1));
            const [sales, inv, audit] = await Promise.all([
                loadSales(from, to),
                fetchAll(() => supabase.from('Inventory').select('id,item_name,price,cost_price').order('id')),
                supabase.from('audit_logs').select('performed_by,action,item_name,details,timestamp').gte('timestamp', dayStart(from)).order('timestamp', { ascending: false }).limit(400)
            ]);
            const flags = [];
            const live = sales.filter(s => !s.is_voided), voided = sales.filter(s => s.is_voided);
            const priceOf = Object.fromEntries(inv.map(i => [i.item_name, num(i.price)]));

            // a) voids per cashier
            const perCashier = {};
            for (const s of sales) { const c = perCashier[s.sold_by || 'unknown'] || (perCashier[s.sold_by || 'unknown'] = { sales: 0, voids: 0, void_value: 0 }); c.sales++; if (s.is_voided) { c.voids++; c.void_value += num(s.total_amount); } }
            const overallRate = sales.length ? voided.length / sales.length : 0;
            for (const [name, c] of Object.entries(perCashier)) {
                if (c.voids >= 3 && c.voids / c.sales > Math.max(overallRate * 2, 0.05))
                    flags.push({ type: 'voids', severity: 'high', who: name, title: `${name} voided ${c.voids} of ${c.sales} sales (${Math.round(100 * c.voids / c.sales)}%)`, detail: `Voided value KES ${Math.round(c.void_value).toLocaleString()}. Shop-wide void rate is ${Math.round(overallRate * 1000) / 10}%.` });
            }
            // b) sold below cost
            for (const s of live) {
                const total = num(s.total_amount), cost = num(s.cost_price);
                if (cost > 0 && total < cost * 0.98)
                    flags.push({ type: 'below_cost', severity: 'high', who: s.sold_by, title: `${s.item_name} sold below cost`, detail: `${eatDate(new Date(s.sale_date))}: sold for KES ${Math.round(total).toLocaleString()}, cost KES ${Math.round(cost).toLocaleString()} (loss KES ${Math.round(cost - total).toLocaleString()}).`, sale_id: s.id });
            }
            // c) big discounts vs list price (tier prices are allowed to be lower)
            for (const s of live) {
                const list = priceOf[s.item_name];
                if (!list || s.price_tier) continue;
                if (num(s.unit_price) > 0 && num(s.unit_price) < list * 0.85 && num(s.cost_price) < num(s.total_amount) * 0.999)
                    flags.push({ type: 'discount', severity: 'medium', who: s.sold_by, title: `${s.item_name} sold ${Math.round(100 * (1 - num(s.unit_price) / list))}% under list price`, detail: `${eatDate(new Date(s.sale_date))}: KES ${r2(s.unit_price)} each vs current price KES ${r2(list)}.`, sale_id: s.id });
            }
            // d) unusually large sale lines
            const totals = live.map(s => num(s.total_amount));
            if (totals.length >= 30) {
                const mean = totals.reduce((a, b) => a + b, 0) / totals.length;
                const sd = Math.sqrt(totals.reduce((a, b) => a + (b - mean) ** 2, 0) / totals.length);
                for (const s of live.filter(s => num(s.total_amount) > mean + 4 * sd).slice(0, 5))
                    flags.push({ type: 'outlier', severity: 'low', who: s.sold_by, title: `Unusually large sale: ${s.item_name}`, detail: `KES ${Math.round(num(s.total_amount)).toLocaleString()} on ${eatDate(new Date(s.sale_date))} (typical line is about KES ${Math.round(mean).toLocaleString()}).`, sale_id: s.id });
            }
            // e) night-time sales
            const night = {};
            for (const s of live) { const h = new Date(new Date(s.sale_date).getTime() + 3 * 3600000).getUTCHours(); if (h >= 22 || h < 5) night[s.sold_by || 'unknown'] = (night[s.sold_by || 'unknown'] || 0) + 1; }
            for (const [name, n] of Object.entries(night)) if (n >= 3)
                flags.push({ type: 'after_hours', severity: 'medium', who: name, title: `${name} recorded ${n} sales between 10pm and 5am`, detail: 'Check the shop was actually open.' });
            // f) price / cost edits
            for (const a of (audit.data || []).filter(a => /EDIT|PRICE|UPDATE/i.test(a.action || '')).slice(0, 12))
                flags.push({ type: 'price_edit', severity: 'low', who: a.performed_by, title: `${a.action}: ${a.item_name || ''}`.trim(), detail: String(a.details || '').slice(0, 200) });

            const order = { high: 0, medium: 1, low: 2 };
            flags.sort((a, b) => order[a.severity] - order[b.severity]);
            let summary = null;
            if (req.query.summary === '1' && flags.length && AI_KEY) {
                try {
                    const d = await claude({ max_tokens: 450, system: `You review shop-floor red flags for the owner of ${BUSINESS}. In 3-5 sentences say which findings matter most, which are probably innocent (e.g. clearance, tier pricing, a single typo), and what to check first. Be fair: these are signals, not proof. Name staff only as given in the data.`,
                        messages: [{ role: 'user', content: JSON.stringify({ window_days: days, flags: flags.slice(0, 30) }) }] });
                    summary = textOf(d);
                } catch (e) { log.warn('[AI FLAGS] summary skipped: ' + e.message); }
            }
            res.json({ success: true, window_days: days, sales_checked: sales.length, count: flags.length, summary, flags: flags.slice(0, 60) });
        } catch (err) { fail(res, err, 'FLAGS'); }
    });

    // ═══════════════════════════ 6. MATCH UNMATCHED M-PESA ═════════════════════
    app.post('/api/ai/match-payment', ...guard, async (req, res) => {
        try {
            const id = req.body?.c2bId;
            if (!id) return res.status(400).json({ success: false, message: 'Missing payment id.' });
            const { data: pay } = await supabase.from('c2b_payments').select('*').eq('id', id).maybeSingle();
            if (!pay) return res.status(404).json({ success: false, message: 'Payment not found.' });
            const amount = num(pay.amount_excess > 0 ? pay.amount_excess : pay.amount);
            const debtors = await loadDebtors();
            const payTokens = new Set([...toks(pay.customer_name), ...toks(pay.account_ref)]);
            const scored = debtors.map(d => {
                let score = 0; const why = [];
                if (pay.phone && d.phone && last9(pay.phone) === last9(d.phone)) { score += 60; why.push('same phone number'); }
                const nameScore = Math.max(similarity(pay.customer_name, d.name), similarity(pay.account_ref, d.name));
                const dTok = new Set(toks(d.name)); let shared = 0; for (const t of dTok) if (payTokens.has(t)) shared++;
                if (nameScore >= 0.5 || shared >= 1) { score += Math.round(10 + 25 * Math.max(nameScore, shared / Math.max(dTok.size, 1))); why.push('name looks similar'); }
                if (Math.abs(amount - d.owed) < 1) { score += 20; why.push('amount equals the full balance'); }
                else if (amount < d.owed) { score += 5; why.push('amount is less than what they owe'); }
                else { score -= 5; why.push('amount is more than they owe'); }
                return { name: d.name, phone: d.phone, owed: d.owed, age_days: d.age_days, invoices: d.invoices, score, reasons: why };
            }).filter(c => c.score >= 25).sort((a, b) => b.score - a.score).slice(0, 3)
              .map(c => ({ ...c, confidence: c.score >= 70 ? 'high' : c.score >= 45 ? 'medium' : 'low' }));
            res.json({ success: true, amount, candidates: scored });
        } catch (err) { fail(res, err, 'MATCH'); }
    });

    log.info(`[AI] Assistant routes mounted — AI ${AI_KEY ? 'ENABLED (' + AI_MODEL + ')' : 'OFF (set ANTHROPIC_API_KEY)'}`);
};
