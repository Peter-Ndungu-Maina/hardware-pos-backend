const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 5001;

// 1. CLOUD CREDENTIALS
const supabaseUrl = 'https://sjivzccjmoqyisjsgwhj.supabase.co';
const supabaseKey = 'sb_publishable_lIikLnKzTtJdltCNJVaszw_FGkgnERa'; 
const supabase = createClient(supabaseUrl, supabaseKey);

// 2. EMAIL CONFIGURATION
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'karayapeter2@gmail.com', 
        pass: 'adypkfdyhyfmynzj'    
    }
});

app.use(cors());
app.use(express.json());

// Static File Serving
const frontendPath = path.join(__dirname, '..', 'frontend');
const pagesPath = path.join(__dirname, '..', 'frontend', 'src', 'pages');
app.use(express.static(frontendPath));
app.use('/pages', express.static(pagesPath));

// --- 3. LOGIN ROUTE ---
app.post('/api/login', async (req, res) => {
    const employeeId = req.body.employeeId?.trim();
    const pin = req.body.pin?.trim();
    try {
        const { data: user, error } = await supabase
            .from('employees')
            .select('*')
            .eq('emp_id', employeeId)
            .eq('pin', pin)
            .single();

        if (user) {
            res.json({ success: true, message: `Welcome ${user.name}`, role: user.role, name: user.name });
        } else {
            res.status(401).json({ success: false, message: 'Invalid ID or PIN' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: "Login server error" });
    }
});

// --- 4. INVENTORY ROUTES ---
// --- 4. INVENTORY ROUTES ---
// --- 1. UPDATED FETCH ROUTE ---
app.get('/api/inventory', async (req, res) => {
    const { role, search, category, page } = req.query; 
    
    // 1. Define columns and include the batch join
    // We join stock_batches to get the actual data for the frontend popup
    let columns = '*, stock_batches(*)'; 
    if (role?.toLowerCase() !== 'admin') {
        columns = 'id, item_name, category, price, stock_quantity, unit, stock_batches(*)'; 
    }

    let query = supabase.from('Inventory').select(columns, { count: 'exact' });

    if (search) query = query.ilike('item_name', `%${search}%`);
    if (category && category !== 'All') query = query.eq('category', category);

    try {
        let items = [];
        let totalCount = 0;
        const itemsPerPage = 15;

        // 2. Fetch Data (with Pagination if requested)
        if (page) {
            const start = (parseInt(page) - 1) * itemsPerPage;
            const end = start + itemsPerPage - 1;

            const { data, count, error } = await query
                .order('item_name', { ascending: true })
                .range(start, end);

            if (error) throw error;
            items = data;
            totalCount = count;
        } else {
            const { data, error } = await query.order('item_name', { ascending: true });
            if (error) throw error;
            items = data;
        }

        // 3. Process data for the frontend
        // We add 'active_batches' count but KEEP the 'stock_batches' array for the details popup
        const enrichedItems = items.map(item => {
            const activeBatches = item.stock_batches ? item.stock_batches.filter(b => b.remaining_qty > 0) : [];
            return {
                ...item,
                active_batches: activeBatches.length,
                // We rename it to batch_details to match what your inventory.html expects
                batch_details: activeBatches 
            };
        });

        if (page) {
            return res.json({ 
                items: enrichedItems, 
                totalCount: totalCount,
                totalPages: Math.ceil(totalCount / itemsPerPage)
            });
        } 

        res.json(enrichedItems);
    } catch (err) {
        console.error("Inventory Fetch Error:", err.message);
        res.status(500).json({ error: err.message });
    }
});
// --- 2. UPDATED REGISTER NEW PRODUCT ROUTE ---
app.post('/api/inventory', async (req, res) => {
    const { itemName, category, unit, costPrice, sellingPrice, stockQty, role, deliveryNote, userName } = req.body;

    // 1. Authorization Check
    if (role?.toLowerCase() !== 'admin' && role?.toLowerCase() !== 'manager') {
        return res.status(403).json({ success: false, message: "Unauthorized." });
    }

    try {
        // --- DUPLICATE DN CHECK ---
        const { data: existingBatch } = await supabase
            .from('stock_batches')
            .select('delivery_number')
            .eq('delivery_number', deliveryNote?.trim().toUpperCase())
            .maybeSingle();

        if (existingBatch) {
            return res.status(400).json({ 
                success: false, 
                message: `Delivery Note ${deliveryNote} has already been used. Please use a unique DN.` 
            });
        }

        // 2. Insert the main product record
        const { data: newItem, error: invError } = await supabase
            .from('Inventory')
            .insert([{ 
                item_name: itemName, 
                category, 
                unit, 
                cost_price: parseFloat(costPrice), 
                price: parseFloat(sellingPrice), 
                stock_quantity: parseInt(stockQty) 
            }])
            .select()
            .single();

        if (invError) throw invError;

        // 3. Create the initial FIFO layer WITH stock_at_entry = 0
        // Inside app.post('/api/inventory', ...) 
// Update the step 3 insert:
const { error: batchError } = await supabase
    .from('stock_batches')
    .insert([{
        inventory_id: newItem.id,
        batch_qty: parseInt(stockQty),
        remaining_qty: parseInt(stockQty), 
        unit_cost: parseFloat(costPrice),
        delivery_number: deliveryNote?.trim().toUpperCase() || 'INITIAL-STOCK',
        stock_at_entry: 0,
        performed_by: userName || 'Admin' // <-- ADD THIS LINE
    }]);

        if (batchError) {
            // Rollback: Delete the inventory item if the batch fails
            await supabase.from('Inventory').delete().eq('id', newItem.id);
            throw batchError;
        }

        // 4. Detailed Audit Log (Supports the "Jump" Visualization)
        await supabase.from('audit_logs').insert([{
            performed_by: userName || 'Admin',
            action: 'INITIAL_STOCK',
            dn_number: deliveryNote || 'N/A',
            item_name: itemName,             // Useful for quick filtering
            old_stock: 0,                    // Snapshot Start
            added_qty: parseInt(stockQty),   // Change Amount
            new_stock: parseInt(stockQty),   // Snapshot End
            details: `Registered ${itemName}. Jump from 0 to ${stockQty}`,
            timestamp: new Date().toISOString()
        }]);

        res.json({ success: true, message: "Product and initial batch registered successfully!" });
    } catch (err) {
        console.error("Registration Error:", err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});
app.post('/api/inventory/restock-fifo', async (req, res) => {
    const { inventory_id, batch_qty, unit_cost, new_selling_price, delivery_number, userName } = req.body;

    try {
        // 1. Get current "Snapshot" (Old Stock)
        const { data: item, error: fetchErr } = await supabase
            .from('Inventory')
            .select('item_name, stock_quantity')
            .eq('id', inventory_id)
            .single();

        if (fetchErr) throw fetchErr;

        const oldStock = parseInt(item.stock_quantity) || 0;
        const added = parseInt(batch_qty);
        const newTotal = oldStock + added;

        // 2. Update Inventory Total & Selling Price
        const { error: invErr } = await supabase
            .from('Inventory')
            .update({ 
                stock_quantity: newTotal, 
                cost_price: parseFloat(unit_cost),
                price: parseFloat(new_selling_price)
            })
            .eq('id', inventory_id);

        if (invErr) throw invErr;

        // 3. Create the FIFO layer in stock_batches with stock_at_entry
        const { error: batchErr } = await supabase
            .from('stock_batches')
            .insert([{
                inventory_id,
                batch_qty: added,
                remaining_qty: added,
                unit_cost: parseFloat(unit_cost),
                delivery_number: String(delivery_number),
                stock_at_entry: oldStock // Capture current state here
            }]);

        if (batchErr) throw batchErr;

        // 4. Log to Audit
        await supabase.from('audit_logs').insert([{
            performed_by: userName || 'Admin',
            action: 'RESTOCK_FIFO',
            dn_number: String(delivery_number),
            item_name: item.item_name,
            old_stock: oldStock,
            added_qty: added,
            new_stock: newTotal,
            details: `Restocked ${item.item_name}. Jump from ${oldStock} to ${newTotal}`,
            timestamp: new Date().toISOString()
        }]);

        res.json({ success: true, message: "Restock successful!" });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
// --- UPDATE INVENTORY ITEM (Full Edit) ---
app.put('/api/inventory/:id', async (req, res) => {
    const { id } = req.params;
    const { item_name, category, price, cost_price, stock_quantity, unit, role, userName } = req.body;

    if (role?.toLowerCase() !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized. Admins only." });
    }

    try {
        // 1. Fetch current stock BEFORE updating (The Snapshot)
        const { data: oldItem } = await supabase
            .from('Inventory')
            .select('stock_quantity')
            .eq('id', id)
            .single();

        const oldStock = parseInt(oldItem?.stock_quantity || 0);

        // 2. Update the main Inventory table
        const { error: invError } = await supabase
            .from('Inventory')
            .update({ 
                item_name, 
                category, 
                price: parseFloat(price), 
                cost_price: parseFloat(cost_price), 
                stock_quantity: parseInt(stock_quantity), 
                unit 
            })
            .eq('id', id);

        if (invError) throw invError;

        // 3. Synchronize Batches
        // Delete old batches for this item
        await supabase.from('stock_batches').delete().eq('inventory_id', id);

        // Create new master batch with snapshot data
        const { error: batchError } = await supabase
            .from('stock_batches')
            .insert([{
                inventory_id: id,
                batch_qty: parseInt(stock_quantity),
                remaining_qty: parseInt(stock_quantity),
                unit_cost: parseFloat(cost_price),
                delivery_number: 'MANUAL-EDIT',
                stock_at_entry: oldStock, // Store the snapshot for the audit jump
                performed_by: userName || 'Admin' // Ensure the user is logged
            }]);

        if (batchError) throw batchError;

        // 4. Log the Admin override to general audit_logs
        await supabase.from('audit_logs').insert([{
            performed_by: userName || 'Admin',
            action: 'MANUAL_INVENTORY_EDIT',
            item_name: item_name,
            old_stock: oldStock,
            new_stock: parseInt(stock_quantity),
            details: `Admin manual reset of ${item_name}. Jump from ${oldStock} to ${stock_quantity}`,
            timestamp: new Date().toISOString()
        }]);

        res.json({ success: true, message: "Item and Batches synchronized!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});
// New route for standalone price updates
app.patch('/api/inventory/update-price/:id', async (req, res) => {
    const { id } = req.params;
    const { newPrice, userName } = req.body;

    try {
        // 1. Get current item name and old price for the log
        const { data: item } = await supabase
            .from('Inventory')
            .select('item_name, price')
            .eq('id', id)
            .single();

        // 2. Update only the selling price
        const { error } = await supabase
            .from('Inventory')
            .update({ price: parseFloat(newPrice) })
            .eq('id', id);

        if (error) throw error;

        // 3. Log the change so you can track why margins dropped
        await supabase.from('audit_logs').insert([{
            performed_by: userName || 'Admin',
            action: 'PRICE_MARKDOWN',
            details: `Price for ${item.item_name} adjusted from ${item.price} to ${newPrice} (Market Competition)`,
            timestamp: new Date().toISOString()
        }]);

        res.json({ success: true, message: "Selling price updated!" });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
app.get('/api/inventory/audit-logs', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('stock_batches')
            .select(`
                *,
                Inventory ( item_name )
            `) // Fetches all columns including performed_by and stock_at_entry
            .order('created_at', { ascending: false });

        if (error) throw error;

        // Send raw data directly. 
        // The frontend will handle (old_stock + batch_qty) calculation.
        res.json(data);
    } catch (err) {
        console.error("Audit Logs Error:", err.message);
        res.status(500).json({ error: err.message });
    }
});
// // --- 5. DASHBOARD SUMMARY (UPDATED PERMISSIONS) ---
// --- 5. DASHBOARD SUMMARY (UPDATED WITH EXPENSES & NET PROFIT) ---
app.get('/api/reports/daily-summary', async (req, res) => {
    try {
        const { processedBy, role } = req.query; 
        const isAdmin = role?.toLowerCase() === 'admin';
        const isManager = role?.toLowerCase() === 'manager';

        // 1. Fetch Sales
        let salesQuery = supabase
            .from('Sales')
            .select('total_amount, cost_price, quantity_sold, amount_paid, sold_by, payment_status');

        if (processedBy && role?.toLowerCase() === 'cashier') {
            salesQuery = salesQuery.eq('sold_by', processedBy);
        }

        const { data: allSales, error: salesError } = await salesQuery;
        if (salesError) throw salesError;

        // 2. Fetch Expenses
        const { data: allExpenses, error: expError } = await supabase.from('expenses').select('amount');
        if (expError) throw expError;

        // 3. Initialize Accumulators
        let realizedSales = 0;      // Cash/Mpesa actually received
        let realizedCostOfGoods = 0; // Cost of items that were actually paid for
        let totalOwed = 0;          // Total debt pending
        let totalExpenses = 0;

        // 4. Realized Accounting Calculation
        allSales?.forEach(s => {
            const totalVal = parseFloat(s.total_amount || 0);
            const paid = parseFloat(s.amount_paid || 0);
            const unitCost = parseFloat(s.cost_price || 0);
            const qty = parseInt(s.quantity_sold || 0);
            
            // Calculate total cost for this specific sale
            const totalCost = unitCost * qty;

            // TRACK DEBT
            const debt = totalVal - paid;
            if (debt > 0) totalOwed += debt;

            // REALIZED CALCULATION:
            // If it's a Credit sale with 0 paid, Profit contributed is 0.
            // If it's a partial payment, we only count the 'paid' part as revenue.
            realizedSales += paid;

            // We only deduct the cost of goods for the portion that was paid.
            // If fully paid: deduct full cost. If credit (0 paid): deduct 0 cost.
            if (paid >= totalVal && totalVal > 0) {
                realizedCostOfGoods += totalCost;
            } else if (paid > 0 && totalVal > 0) {
                // Partial payment cost logic (Pro-rata)
                const percentPaid = paid / totalVal;
                realizedCostOfGoods += (totalCost * percentPaid);
            }
        });

        // 5. Calculate Total Expenses
        allExpenses?.forEach(e => {
            totalExpenses += parseFloat(e.amount || 0);
        });

        // 6. Final Calculation
        // Profit = Actual Cash Received - Cost of that specific stock - Expenses
        const realizedGrossProfit = realizedSales - realizedCostOfGoods;
        const netProfit = realizedGrossProfit - totalExpenses;

        res.json({ 
            totalSales: realizedSales, // This will now show 300 instead of 33,000
            totalExpenses,
            netProfit: (isAdmin || isManager) ? netProfit : null, 
            totalOwed // This will show the 32,700
        });

    } catch (err) {
        console.error("Summary Error:", err);
        res.status(500).json({ error: err.message });
    }
});
// --- 6. DETAILED SALES REPORT (WITH NET PROFIT CALCULATION) ---
// --- 6. DETAILED SALES REPORT (CASH-BASED NET PROFIT) ---
app.get('/api/reports/sales', async (req, res) => {
    const { role, date, month, year, method } = req.query;
    
    // Authorization: Only Admin and Manager can view reports
    const authorized = ['admin', 'manager'];
    if (!authorized.includes(role?.toLowerCase())) {
        return res.status(403).json({ success: false, message: "Unauthorized access." });
    }

    try {
        // We select everything from Sales, including the cost_price snapshot we saved during the sale
        let query = supabase
            .from('Sales')
            .select('*, payments(mpesa_code, amount, payment_method)')
            .order('sale_date', { ascending: false });

        // Apply Filters
        if (date && date !== "") {
            query = query.gte('sale_date', `${date}T00:00:00Z`).lte('sale_date', `${date}T23:59:59Z`);
        } else if (month && year) {
            const startDate = `${year}-${month.padStart(2, '0')}-01T00:00:00Z`;
            const lastDay = new Date(year, month, 0).getDate();
            const endDate = `${year}-${month.padStart(2, '0')}-${lastDay}T23:59:59Z`;
            query = query.gte('sale_date', startDate).lte('sale_date', endDate);
        }

        if (method && method !== "") {
            if (method === 'Credit') {
                query = query.in('payment_status', ['Credit', 'Partial']);
            } else {
                query = query.eq('payment_status', method);
            }
        }

        const { data, error } = await query;
        if (error) throw error;

        // --- PROFIT CALCULATION LOGIC ---
        const reportsWithCalculations = data.map(sale => {
            const totalRevenue = parseFloat(sale.total_amount || 0);
            const amountPaid = parseFloat(sale.amount_paid || 0);
            const quantity = parseInt(sale.quantity_sold || 0);
            const unitCost = parseFloat(sale.cost_price || 0);
            
            // 1. Calculate Total Potential Profit (If fully paid)
            const totalCostOfGoods = unitCost * quantity;
            const totalPotentialProfit = totalRevenue - totalCostOfGoods;

            // 2. Calculate Realized Profit (Based on cash in hand)
            // If they paid 0 (Credit), realized profit is 0.
            // If they paid 100% (Cash/Mpesa), realized profit is 100%.
            const paymentRatio = totalRevenue > 0 ? (amountPaid / totalRevenue) : 0;
            const realizedProfit = totalPotentialProfit * paymentRatio;

            return {
                ...sale,
                // We send 'profit' to the frontend so the existing table works
                profit: Math.max(0, realizedProfit), 
                total_cost: totalCostOfGoods,
                remaining_balance: totalRevenue - amountPaid
            };
        });

        res.json(reportsWithCalculations);
    } catch (err) {
        console.error("Report Generation Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});
// --- 7. PAYMENTS REPORT (FIXED FILTERS) ---
app.get('/api/reports/payments', async (req, res) => {
    try {
        const { date, month, year, method } = req.query;
        
        let query = supabase
            .from('payments')
            .select(`*, Sales ( customer_name, item_name )`)
            .order('created_at', { ascending: false });

        // 1. Filter by Specific Date (Highest Priority)
        if (date && date !== "") {
            query = query
                .gte('created_at', `${date}T00:00:00Z`)
                .lte('created_at', `${date}T23:59:59Z`);
        } 
        // 2. Filter by Month/Year (Only if date is empty)
        else if (month && year) {
            const startDate = `${year}-${month.padStart(2, '0')}-01T00:00:00Z`;
            const lastDay = new Date(year, month, 0).getDate();
            const endDate = `${year}-${month.padStart(2, '0')}-${lastDay}T23:59:59Z`;
            query = query.gte('created_at', startDate).lte('created_at', endDate);
        }

        // 3. Filter by Method
        if (method && method !== "") {
            query = query.eq('payment_method', method);
        }

        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// --- 9. DEBTORS ROUTE (FILTERED BY USER) ---
app.get('/api/reports/debtors', async (req, res) => {
    try {
        const { processedBy, role } = req.query;

        let query = supabase
            .from('Sales')
            .select('id, customer_name, item_name, total_amount, amount_paid, sale_date, sold_by')
            .neq('payment_status', 'Paid') 
            .order('sale_date', { ascending: false });

        // CASHIER: Only see their own sales/debts
        // MANAGER/ADMIN: See everything
        if (role?.toLowerCase() === 'cashier' && processedBy) {
            query = query.eq('sold_by', processedBy);
        }

        const { data, error } = await query;
        if (error) throw error;

        const actualDebtors = data.filter(d => (parseFloat(d.total_amount) - parseFloat(d.amount_paid)) > 0);
        res.json(actualDebtors);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- DEBT STATUS REPORT (Consolidated) ---
app.get('/api/reports/debt-status', async (req, res) => {
    try {
        const { date } = req.query; // Capture the date from the frontend request
        
        let query = supabase
            .from('Sales')
            .select('customer_name, customer_phone, total_amount, amount_paid, payment_status, sale_date')
            .in('payment_status', ['Credit', 'Partial', 'credit', 'partial', 'Unpaid']);

        // Filter by date if provided
        if (date) {
            query = query
                .gte('sale_date', `${date}T00:00:00.000Z`)
                .lte('sale_date', `${date}T23:59:59.999Z`);
        }

        const { data: debtSales, error } = await query;

        if (error) throw error;

        const consolidated = debtSales.reduce((acc, sale) => {
            const name = (sale.customer_name || 'Walking Customer').trim();
            const phone = (sale.customer_phone || 'No Phone').trim();
            const key = `${name}-${phone}`.toLowerCase();
            
            const total = parseFloat(sale.total_amount) || 0;
            const paid = parseFloat(sale.amount_paid) || 0;
            const balance = total - paid;

            if (balance > 0.1) { 
                if (!acc[key]) {
                    acc[key] = { name, phone, total_debt: 0 };
                }
                acc[key].total_debt += balance;
            }
            return acc;
        }, {});

        res.json(Object.values(consolidated));
    } catch (err) {
        console.error("Debt Status Error:", err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});
// --- UPDATED: PAYMENTS REPORT (JOINED WITH CUSTOMER DATA) ---
// --- 12. UPDATED: GENERAL PAYMENTS REPORT (WITH JOIN) ---
app.get('/api/reports/payments', async (req, res) => {
    try {
        const { date, month, year, method } = req.query;
        
        // This 'select' pulls payment info AND related Sale/Customer info in one go
        let query = supabase
            .from('payments')
            .select(`
                *,
                Sales (
                    customer_name,
                    customer_phone,
                    item_name
                )
            `)
            .order('created_at', { ascending: false });

        if (date && date !== "") {
            query = query.gte('created_at', `${date}T00:00:00Z`).lte('created_at', `${date}T23:59:59Z`);
        } else if (month && year) {
            const startDate = `${year}-${month.padStart(2, '0')}-01T00:00:00Z`;
            const lastDay = new Date(year, month, 0).getDate();
            const endDate = `${year}-${month.padStart(2, '0')}-${lastDay}T23:59:59Z`;
            query = query.gte('created_at', startDate).lte('created_at', endDate);
        }

        if (method && method !== "") {
            query = query.eq('payment_method', method);
        }

        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (err) {
        console.error("Payment Report Error:", err);
        res.status(500).json({ error: err.message });
    }
});

//
// --- 10. TRANSACTIONAL SALE ROUTE (UPDATED FOR CUSTOMER LINKING & DEBT) ---
app.post('/api/sell', async (req, res) => {
    let { 
        itemId, quantity, price, itemName, soldBy, 
        paymentMethod, mpesaId, mpesaCode, customerName, amountPaid 
    } = req.body;
    
    let linkedPhone = (mpesaId && mpesaId.trim() !== "") ? mpesaId.trim() : null;

    if ((paymentMethod === 'M-Pesa' || paymentMethod === 'Credit') && !linkedPhone) {
        return res.status(400).json({ success: false, message: "Phone number is required for this transaction." });
    }

    if (paymentMethod === 'M-Pesa' && (!mpesaCode || mpesaCode.trim() === "")) {
        return res.status(400).json({ success: false, message: "M-Pesa Code is required." });
    }

    try {
        // 1. Fetch current inventory details
        const { data: item, error: fetchError } = await supabase
            .from('Inventory')
            .select('stock_quantity, item_name')
            .eq('id', itemId)
            .single();

        if (fetchError || !item) throw new Error(`Item not found.`);
        if (item.stock_quantity < quantity) throw new Error(`Insufficient stock. Available: ${item.stock_quantity}`);

        // --- 2. NEW FIFO BATCH DRAIN LOGIC ---
        // Fetch batches for this item, oldest first
        const { data: batches, error: batchErr } = await supabase
            .from('stock_batches')
            .select('*')
            .eq('inventory_id', itemId)
            .gt('remaining_qty', 0)
            .order('created_at', { ascending: true });

        if (batchErr) throw batchErr;

        let remainingToDrain = quantity;
        let totalCostForThisSale = 0;

       // ... inside your FIFO for loop in /api/sell ...
for (const batch of batches) {
    if (remainingToDrain <= 0) break;

    const sellFromThisBatch = Math.min(batch.remaining_qty, remainingToDrain);
    const newBatchQty = batch.remaining_qty - sellFromThisBatch;
    
    totalCostForThisSale += (sellFromThisBatch * parseFloat(batch.unit_cost || 0));

    // Update the batch
    await supabase
        .from('stock_batches')
        .update({ remaining_qty: newBatchQty })
        .eq('id', batch.id);

    // --- NEW: BATCH DEPLETION ALERT ---
    if (newBatchQty === 0) {
        const nextBatch = batches[batches.indexOf(batch) + 1];
        
        const batchMailOptions = {
            from: 'karayapeter@gmail.com',
            to: 'karayapeter2@gmail.com',
            subject: `📦 BATCH FINISHED: ${itemName}`,
            text: `The inventory layer for "${itemName}" bought at KES ${batch.unit_cost} is now DEPLETED.\n\n` +
                  `Current Sale: Used ${sellFromThisBatch} units to finish this batch.\n` +
                  `Next Available Batch Cost: ${nextBatch ? 'KES ' + nextBatch.unit_cost : 'NO STOCK REMAINING!'}\n\n` +
                  `Action: Please check if your current selling price (KES ${price}) still covers your margins for the next batch.`
        };

        transporter.sendMail(batchMailOptions, (error) => {
            if (error) console.error("Batch Alert Email Failed:", error);
        });
    }

    remainingToDrain -= sellFromThisBatch;
}
        const totalAmount = quantity * price;
        const paidNow = parseFloat(amountPaid) || 0;
        const avgUnitCostAtSale = totalCostForThisSale / quantity;
        const totalProfitOnSale = totalAmount - totalCostForThisSale;

        // 3. CUSTOMER HANDLING
        if (linkedPhone) {
            const { data: existingCust } = await supabase
                .from('customers')
                .select('name, total_debt')
                .eq('phone', linkedPhone)
                .single();

            if (!existingCust) {
                await supabase.from('customers').insert({ 
                    phone: linkedPhone, 
                    name: customerName || 'New Customer' 
                });
            }

            if (paymentMethod === 'Credit') {
                const debtAmount = totalAmount - paidNow;
                const newTotalDebt = (parseFloat(existingCust?.total_debt || 0)) + debtAmount;
                await supabase.from('customers').update({ total_debt: newTotalDebt }).eq('phone', linkedPhone);
            }
        }

        // 4. RECORD THE SALE WITH CALCULATED BATCH PROFIT
        const { data: saleData, error: insertError } = await supabase
            .from('Sales')
            .insert([{
                item_name: itemName, 
                quantity_sold: quantity, 
                unit_price: price, 
                total_amount: totalAmount,
                amount_paid: paidNow, 
                cost_price: avgUnitCostAtSale, // Saved from batch calculation
                profit: totalProfitOnSale,      // Saved from batch calculation
                payment_status: paidNow >= totalAmount ? 'Paid' : (paidNow > 0 ? 'Partial' : 'Credit'), 
                customer_name: customerName || 'Walk-in',
                customer_phone: linkedPhone, 
                sold_by: soldBy, 
                sale_date: new Date().toISOString()
            }])
            .select();

        if (insertError) throw insertError;

        // 5. RECORD PAYMENT AUDIT
        if (paidNow > 0) {
            await supabase.from('payments').insert([{
                sale_id: saleData[0].id,
                amount: paidNow,
                payment_method: paymentMethod || 'Cash',
                mpesa_code: mpesaCode || null, 
                received_by: soldBy,
                created_at: new Date().toISOString()
            }]);
        }

        // 6. UPDATE MAIN INVENTORY TOTAL
        const newStockLevel = item.stock_quantity - quantity;
        await supabase.from('Inventory').update({ stock_quantity: newStockLevel }).eq('id', itemId);

        // --- STOCK ALERT LOGIC ---
        if (newStockLevel <= 10) { 
            // ... (keep your existing transporter.sendMail logic here)
        }

        res.json({ success: true, message: `Sale recorded. Batches updated. Stock: ${newStockLevel}` });

    } catch (err) {
        console.error("Sale Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});
// --- 11. CLEAR DEBT ROUTE (SYNCHRONIZED WITH DB) ---
// --- 11. CLEAR DEBT ROUTE (SYNCHRONIZED WITH CUSTOMER TABLE) ---
app.post('/api/clear-debt', async (req, res) => {
    const { saleId, paymentAmount, paymentMethod, mpesaId, processedBy } = req.body;

    if (!saleId || !paymentAmount) {
        return res.status(400).json({ success: false, message: "Missing Sale ID or Amount" });
    }

    try {
        // 1. Fetch the sale and link to customer_phone
        const { data: sale, error: getErr } = await supabase
            .from('Sales')
            .select('*, customer_phone')
            .eq('id', saleId)
            .single();
        
        if (getErr || !sale) throw new Error("Sale record not found.");

        const amountToPay = parseFloat(paymentAmount);
        const currentPaid = parseFloat(sale.amount_paid || 0);
        const totalAmount = parseFloat(sale.total_amount);
        const updatedTotalPaid = currentPaid + amountToPay;
        let newStatus = updatedTotalPaid >= totalAmount ? 'Paid' : 'Partial';

        // 2. Update the main Sales record
        const { error: updateErr } = await supabase
            .from('Sales')
            .update({ 
                amount_paid: updatedTotalPaid, 
                payment_status: newStatus 
            })
            .eq('id', saleId);

        if (updateErr) throw updateErr;

        // 3. NEW: Update the central Customer Debt balance
        if (sale.customer_phone) {
            const { data: customer } = await supabase
                .from('customers')
                .select('total_debt')
                .eq('phone', sale.customer_phone)
                .single();

            // Safely subtract the payment from the cumulative debt
            const currentDebt = parseFloat(customer?.total_debt || 0);
            const newCentralDebt = Math.max(0, currentDebt - amountToPay);

            await supabase
                .from('customers')
                .update({ total_debt: newCentralDebt })
                .eq('phone', sale.customer_phone);
        }

        // 4. Register in 'payments' table (Global Audit)
        await supabase.from('payments').insert([{
            sale_id: saleId,
            amount: amountToPay, 
            payment_method: paymentMethod,
            mpesa_code: mpesaId || null,
            received_by: processedBy,
            customer_name: sale.customer_name,
            created_at: new Date().toISOString()
        }]);

        // 5. Register in 'debt_payments' table
        await supabase.from('debt_payments').insert([{
            sale_id: saleId,
            amount_paid: amountToPay, 
            payment_method: paymentMethod,
            mpesa_id: mpesaId || null,
            processed_by: processedBy,
            customer_name: sale.customer_name,
            customer_phone: sale.customer_phone,
            payment_date: new Date().toISOString()
        }]);

        res.json({ 
            success: true, 
            message: `Success! KES ${amountToPay} recorded and customer balance updated.` 
        });

    } catch (err) {
        console.error("Critical Payment Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});
// INVENTORY MANAGEMENT (STOCK UPDATE) with Audit Logging
app.patch('/api/inventory/:id', async (req, res) => {
    const { id } = req.params;
    // 1. Capture the DN from the body
    const { added_quantity, role, userName, delivery_note_ref } = req.body; 
    
    const authorizedRoles = ['admin', 'manager'];
    if (!authorizedRoles.includes(role?.toLowerCase())) {
        return res.status(403).json({ success: false, message: "Unauthorized." });
    }
    
    try {
        const { data: item, error: fetchError } = await supabase
            .from('Inventory')
            .select('item_name, stock_quantity')
            .eq('id', id)
            .single();

        if (fetchError || !item) throw new Error("Item not found");

        const currentStock = parseInt(item.stock_quantity) || 0;
        const addQty = parseInt(added_quantity) || 0;
        const newTotal = currentStock + addQty;

        // Update Stock
        const { error: updateError } = await supabase
            .from('Inventory')
            .update({ stock_quantity: newTotal })
            .eq('id', id);

        if (updateError) throw updateError;

        // 2. Audit Log - Mapping to your 'delivery_number' column
        await supabase.from('audit_logs').insert([{
            performed_by: userName || 'Unknown Staff',
            action: 'RESTOCK',
            dn_number: String(delivery_note_ref), // Saved as string
            details: `Added ${addQty} units to ${item.item_name}. New total: ${newTotal}`,
            timestamp: new Date().toISOString()
        }]);

        res.json({ success: true, message: `Added ${addQty}. Total: ${newTotal}` });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
// DELETE ITEM ROUTE with Audit Logging
app.delete('/api/inventory/:id', async (req, res) => {
    const { id } = req.params;
    const { role, userName } = req.query; // Capture userName from frontend

    const authorizedRoles = ['admin'];
    if (!authorizedRoles.includes(role?.toLowerCase())) {
        return res.status(403).json({ success: false, message: "Unauthorized." });
    }

    try {
        // 1. Get item details before deleting to log the name
        const { data: item } = await supabase
            .from('Inventory')
            .select('item_name')
            .eq('id', id)
            .single();

        // 2. Perform the deletion
        const { error } = await supabase.from('Inventory').delete().eq('id', id);
        if (error) throw error;

        // 3. LOG THE ACTION to audit_logs
        await supabase.from('audit_logs').insert([{
            performed_by: userName || 'Unknown Staff',
            action: 'DELETE',
            details: `Permanently removed item: ${item?.item_name || 'Unknown'} (ID: ${id})`,
            timestamp: new Date().toISOString()
        }]);

        res.json({ success: true, message: "Item deleted and logged." });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
// --- 13. ADD EMPLOYEE ROUTE (NEW) ---
app.post('/api/employees', async (req, res) => {
    const { name, employeeId, pin, role, requesterRole } = req.body;

    if (requesterRole?.toLowerCase() !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized: Admin only." });
    }

    try {
        const { data, error } = await supabase
            .from('employees')
            .insert([{ 
                name, 
                emp_id: employeeId.toUpperCase(), 
                pin, 
                role 
            }]);

        if (error) throw error;
        res.json({ success: true, message: "Staff created!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "ID already exists or Database error." });
    }
});
// --- 14. DEBT REPAYMENT AUDIT LOGS ---
// --- 14. UPDATED: DEBT REPAYMENT AUDIT LOGS ---
app.get('/api/reports/debt-logs', async (req, res) => {
    const { date } = req.query;
    try {
        // We select all from debt_payments. 
        // Note: Your /api/clear-debt route now inserts customer_name here automatically.
        let query = supabase
            .from('debt_payments')
            .select('*') 
            .order('payment_date', { ascending: false });

        if (date && date !== "") {
            query = query
                .gte('payment_date', `${date}T00:00:00.000Z`)
                .lte('payment_date', `${date}T23:59:59.999Z`);
        }

        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (err) {
        console.error("Debt Log Error:", err);
        res.status(500).json({ error: err.message });
    }
});

// --- 15 NEW: CUSTOMER LOOKUP FOR AUTO-FILL ---
app.get('/api/customers/:phone', async (req, res) => {
    const { phone } = req.params;
    try {
        const { data, error } = await supabase
            .from('customers')
            .select('name, total_debt')
            .eq('phone', phone)
            .single();

        if (error) return res.status(404).json({ message: "Not found" });
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// --- 16. EXPENSES ROUTES ---

// Record a new expense
// --- EXPENSES ROUTE ---
app.post('/api/expenses', async (req, res) => {
    const { description, category, amount, spentBy } = req.body;
    try {
        const { data, error } = await supabase
            .from('expenses') // Ensure this is lowercase 'e'
            .insert([{ 
                description, 
                category, 
                amount: parseFloat(amount), 
                spent_by: spentBy 
            }]);

        if (error) throw error;
        res.json({ success: true, message: "Expense recorded!" });
    } catch (err) {
        console.error("Expense Save Error:", err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});
// Get expenses for reports (with optional date filtering)
app.get('/api/reports/expenses', async (req, res) => {
    const { date, month, year } = req.query;
    try {
        let query = supabase.from('expenses').select('*').order('expense_date', { ascending: false });
        
        if (date) {
            query = query.gte('expense_date', `${date}T00:00:00Z`).lte('expense_date', `${date}T23:59:59Z`);
        } else if (month && year) {
            const startDate = `${year}-${month.padStart(2, '0')}-01T00:00:00Z`;
            const lastDay = new Date(year, month, 0).getDate();
            const endDate = `${year}-${month.padStart(2, '0')}-${lastDay}T23:59:59Z`;
            query = query.gte('expense_date', startDate).lte('expense_date', endDate);
        }

        const { data, error } = await query;
        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// 17--- PROFIT & LOSS REPORT ROUTE ---
app.get('/api/reports/profit-loss', async (req, res) => {
    const { month, year } = req.query;
    const mm = month.toString().padStart(2, '0');
    const lastDay = new Date(year, month, 0).getDate(); 

    const startISO = `${year}-${mm}-01T00:00:00.000Z`;
    const endISO = `${year}-${mm}-${lastDay}T23:59:59.999Z`;

    try {
        const { data: sales, error: sErr } = await supabase
            .from('Sales')
            .select('*')
            .gte('sale_date', startISO)
            .lte('sale_date', endISO);

        if (sErr) throw sErr;

        let totalSales = 0, totalCogs = 0, unpaidDebts = 0;

        sales.forEach(s => {
            const amt = parseFloat(s.total_amount) || 0;
            const qty = parseInt(s.quantity_sold) || 0;
            
            // FIFO Logic: Since your POS sells the old batch first, 
            // the cost_price recorded here is the exact cost of that specific batch.
            const unitCost = parseFloat(s.cost_price) || 0; 
            const transactionCogs = unitCost * qty;

            const status = (s.payment_status || '').toLowerCase().trim();

            if (status === 'credit' || status === 'unpaid') {
                unpaidDebts += amt;
                // For a standard P&L, we still count the sale and the cost 
                // to see the performance, even if the money hasn't arrived yet.
                totalSales += amt;
                totalCogs += transactionCogs;
            } else {
                totalSales += amt;
                totalCogs += transactionCogs;
            }
        });

        // 2. Fetch Expenses for the same period
        const { data: expenses } = await supabase
            .from('expenses')
            .select('amount')
            .gte('expense_date', startISO)
            .lte('expense_date', endISO);

        const totalExpenses = (expenses || []).reduce((sum, e) => sum + (parseFloat(e.amount) || 0), 0);
        
        // 3. Final Calculations
        const grossProfit = totalSales - totalCogs;
        const netProfit = grossProfit - totalExpenses;

        res.json({
            totalSales,      // Cash + Credit
            unpaidDebts,     // Just the credit portion
            totalCogs,       // Total purchase cost of items sold
            grossProfit,     // Profit before expenses
            totalExpenses,   // Operating costs
            netProfit        // Final take-home profit
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));



