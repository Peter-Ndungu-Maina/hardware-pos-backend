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
        user: 'your-email@gmail.com', 
        pass: 'your-app-password'    
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
app.get('/api/inventory', async (req, res) => {
    const { role } = req.query;
    
    // If cashier, DO NOT send cost_price to frontend
    let columns = '*';
    if (role?.toLowerCase() !== 'admin') {
        columns = 'id, item_name, category, price, stock_quantity, unit'; 
    }

    const { data, error } = await supabase.from('Inventory').select(columns).order('item_name');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});
/// --- 4. INVENTORY ROUTES ---
app.get('/api/inventory', async (req, res) => {
    const { role } = req.query;
    let columns = '*';
    if (role?.toLowerCase() !== 'admin') {
        columns = 'id, item_name, category, price, stock_quantity, unit'; 
    }
    const { data, error } = await supabase.from('Inventory').select(columns).order('item_name');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// NEW: REGISTER NEW PRODUCT ROUTE
app.post('/api/inventory', async (req, res) => {
    const { itemName, category, unit, costPrice, sellingPrice, stockQty, role } = req.body;

    if (role?.toLowerCase() !== 'admin' && role?.toLowerCase() !== 'manager') {
        return res.status(403).json({ success: false, message: "Unauthorized." });
    }

    try {
        const { error } = await supabase
            .from('Inventory')
            .insert([{ 
                item_name: itemName, 
                category, 
                unit, 
                cost_price: parseFloat(costPrice), 
                price: parseFloat(sellingPrice), 
                stock_quantity: parseInt(stockQty) 
            }]);

        if (error) throw error;
        res.json({ success: true, message: "Product registered!" });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// --- UPDATE INVENTORY ITEM (Full Edit) ---
// UPDATE INVENTORY ITEM (FIXED: ADMIN ONLY)
app.put('/api/inventory/:id', async (req, res) => {
    const { id } = req.params;
    const { item_name, category, price, cost_price, stock_quantity, unit, role } = req.body;

    // CHANGE: Ensure 'manager' cannot access this
    if (role?.toLowerCase() !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized. Admins only." });
    }

    try {
        const { error } = await supabase
            .from('Inventory')
            .update({ item_name, category, price, cost_price, stock_quantity, unit })
            .eq('id', id);

        if (error) throw error;
        res.json({ success: true, message: "Item updated!" });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
// // --- 5. DASHBOARD SUMMARY (UPDATED PERMISSIONS) ---
app.get('/api/reports/daily-summary', async (req, res) => {
    try {
        const { processedBy, role } = req.query; 
        
        const now = new Date();
        const offset = now.getTimezoneOffset() * 60000; 
        const localISOTime = (new Date(now - offset)).toISOString().split('T')[0];

        let salesQuery = supabase
            .from('Sales')
            .select('total_amount, profit')
            .filter('sale_date', 'gte', `${localISOTime}T00:00:00`)
            .filter('sale_date', 'lte', `${localISOTime}T23:59:59`);

        if (processedBy && role?.toLowerCase() === 'cashier') {
            salesQuery = salesQuery.eq('sold_by', processedBy);
        }

        const { data: todaySales, error: salesError } = await salesQuery;
        if (salesError) throw salesError;

        let totalSales = 0, totalProfit = 0, totalOwed = 0;

        todaySales?.forEach(s => {
            totalSales += parseFloat(s.total_amount || 0);
            // Only calculate profit if the requester is an Admin
            if (role?.toLowerCase() === 'admin') {
                totalProfit += parseFloat(s.profit || 0);
            }
        });

        // Get Unpaid Debt
        let debtQuery = supabase.from('Sales').select('total_amount, amount_paid').neq('payment_status', 'Paid');
        if (processedBy && role?.toLowerCase() === 'cashier') {
            debtQuery = debtQuery.eq('sold_by', processedBy);
        }

        const { data: allDebt, error: debtError } = await debtQuery;
        if (debtError) throw debtError;

        allDebt?.forEach(s => {
            const owed = parseFloat(s.total_amount || 0) - parseFloat(s.amount_paid || 0);
            if (owed > 0) totalOwed += owed;
        });

        // If not admin, totalProfit returns null (frontend handles this as "Locked")
        res.json({ 
            totalSales, 
            totalProfit: role?.toLowerCase() === 'admin' ? totalProfit : null, 
            totalOwed 
        });
    } catch (err) {
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
// --- GET PENDING DEBTS (STATUS REPORT) ---
// --- GET PENDING DEBTS (ROLE-BASED STATUS REPORT) ---
// --- GET PENDING DEBTS (FIXED DATE FILTER) ---
app.get('/api/reports/debt-status', async (req, res) => {
    const { role, date } = req.query; 
    const authorized = ['admin', 'manager'];

    if (!role || !authorized.includes(role.toLowerCase())) {
        return res.status(403).json({ success: false, message: "Unauthorized." });
    }

    try {
        let query = supabase
            .from('Sales')
            .select('*')
            .or('payment_status.eq.Credit,payment_status.eq.Partial');

        // FIXED: Filter using a range to catch today's transactions regardless of time
        if (date && date !== "") {
            query = query
                .gte('sale_date', `${date}T00:00:00.000Z`)
                .lte('sale_date', `${date}T23:59:59.999Z`);
        }

        const { data, error } = await query.order('sale_date', { ascending: false });

        if (error) throw error;
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/// --- 10. TRANSACTIONAL SALE ROUTE (UPDATED FOR STOCK ALERTS & COST SNAPSHOT) ---
app.post('/api/sell', async (req, res) => {
    let { itemId, quantity, price, itemName, soldBy, paymentMethod, mpesaId, mpesaCode, customerName, amountPaid } = req.body;
    
    if (paymentMethod === 'M-Pesa' && (!mpesaCode || mpesaCode.trim() === "")) {
        return res.status(400).json({ success: false, message: "M-Pesa Code is required." });
    }

    try {
        // 1. Fetch current details from Inventory
        const { data: item, error: fetchError } = await supabase
            .from('Inventory')
            .select('stock_quantity, cost_price, item_name')
            .eq('id', itemId)
            .single();

        if (fetchError || !item) throw new Error(`Item not found.`);
        
        const totalAmount = quantity * price;
        const paidNow = parseFloat(amountPaid) || 0;
        
        // --- COST PRICE SNAPSHOT LOGIC ---
        const unitCost = parseFloat(item.cost_price || 0);
        const totalCostOfSale = unitCost * quantity;
        const totalProfitOnSale = totalAmount - totalCostOfSale;

        // 2. RECORD SALE (Added cost_price column here)
        const { data: saleData, error: insertError } = await supabase
            .from('Sales')
            .insert([{
                item_name: itemName, 
                quantity_sold: quantity, 
                unit_price: price, 
                total_amount: totalAmount,
                amount_paid: paidNow, 
                cost_price: unitCost,      // <--- THIS SAVES THE COST PERMANENTLY
                profit: totalProfitOnSale, // Optional: stores pre-calculated total profit
                payment_status: paidNow >= totalAmount ? 'Paid' : (paidNow > 0 ? 'Partial' : 'Credit'), 
                customer_name: customerName,
                customer_phone: mpesaId, 
                sold_by: soldBy, 
                sale_date: new Date().toISOString()
            }])
            .select();

        if (insertError) throw insertError;

        // 3. RECORD PAYMENT
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

        // 4. Update Stock & TRIGGER ALERT
        const newStockLevel = item.stock_quantity - quantity;
        await supabase.from('Inventory').update({ stock_quantity: newStockLevel }).eq('id', itemId);

        // --- STOCK ALERT LOGIC ---
        if (newStockLevel <= 10) { // Threshold: 5 units
            const mailOptions = {
                from: 'your-email@gmail.com',
                to: 'karayapeter2@gmail.com', // Change to your actual admin email
                subject: `⚠️ LOW STOCK ALERT: ${item.item_name}`,
                text: `The stock for "${item.item_name}" is critically low.\nRemaining: ${newStockLevel} units.\nPlease restock soon.`
            };
            
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) console.error("Email Alert Failed:", error);
                else console.log("Stock Alert Sent:", info.response);
            });
        }

        res.json({ success: true, message: `Sale recorded. Stock: ${newStockLevel}` });
    } catch (err) {
        console.error("Sale Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});
// --- 11. CLEAR DEBT ROUTE (SYNCHRONIZED WITH DB) ---
app.post('/api/clear-debt', async (req, res) => {
    const { saleId, paymentAmount, paymentMethod, mpesaId, processedBy } = req.body;

    if (!saleId || !paymentAmount) {
        return res.status(400).json({ success: false, message: "Missing Sale ID or Amount" });
    }

    try {
        // 1. Fetch existing sale to calculate balance
        const { data: sale, error: getErr } = await supabase
            .from('Sales')
            .select('*')
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

        // 3. Register in 'payments' table (Global Audit)
        // Uses column name: 'amount'
        const { error: payErr } = await supabase.from('payments').insert([{
            sale_id: saleId,
            amount: amountToPay, 
            payment_method: paymentMethod,
            mpesa_code: mpesaId || null,
            received_by: processedBy,
            customer_name: sale.customer_name,
            created_at: new Date().toISOString()
        }]);

        if (payErr) throw payErr;

        // 4. Register in 'debt_payments' table
const { error: debtErr } = await supabase.from('debt_payments').insert([{
    sale_id: saleId,
    amount_paid: amountToPay, 
    payment_method: paymentMethod,
    mpesa_id: mpesaId || null,
    processed_by: processedBy,
    customer_name: sale.customer_name, // Add this line
    payment_date: new Date().toISOString()
}]);

        if (debtErr) throw debtErr;

        res.json({ 
            success: true, 
            message: `Success! KES ${amountToPay} recorded in both ledgers.` 
        });

    } catch (err) {
        console.error("Critical Payment Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});
// INVENTORY MANAGEMENT (STOCK UPDATE) with Audit Logging
app.patch('/api/inventory/:id', async (req, res) => {
    const { id } = req.params;
    const { added_quantity, role, userName } = req.body; 
    
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

        const { error: updateError } = await supabase
            .from('Inventory')
            .update({ stock_quantity: newTotal })
            .eq('id', id);

        if (updateError) throw updateError;

        // LOG THE ACTION
        await supabase.from('audit_logs').insert([{
            performed_by: userName || 'Unknown Staff',
            action: 'RESTOCK',
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
app.get('/api/reports/debt-logs', async (req, res) => {
    const { date } = req.query;
    try {
        let query = supabase
            .from('debt_payments')
            .select('*')
            .order('payment_date', { ascending: false });

        if (date && date !== "") {
            // Filter for the specific day selected in the frontend
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
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));



