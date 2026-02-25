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
// --- 4b. UPDATE INVENTORY ITEM (Full Edit) ---
app.put('/api/inventory/:id', async (req, res) => {
    const { id } = req.params;
    const { item_name, category, price, cost_price, stock_quantity, unit, role } = req.body;

    if (role?.toLowerCase() !== 'admin') {
        return res.status(403).json({ success: false, message: "Unauthorized. Admin only." });
    }

    try {
        const { error } = await supabase
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

        if (error) throw error;
        res.json({ success: true, message: "Item updated successfully!" });
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

// --- 6. DETAILED SALES REPORT (FIXED FOR MANAGER ACCESS) ---
app.get('/api/reports/sales', async (req, res) => {
    const { role, date, month, year, method } = req.query;
    
    // ALLOW BOTH ADMIN AND MANAGER HERE
    const authorized = ['admin', 'manager'];
    if (!authorized.includes(role?.toLowerCase())) {
        return res.status(403).json({ success: false, message: "Unauthorized access." });
    }

    try {
        let query = supabase
            .from('Sales')
            .select('*, payments(mpesa_code, amount, payment_method)')
            .order('sale_date', { ascending: false });

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
        res.json(data);
    } catch (err) {
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
// --- 10. TRANSACTIONAL SALE ROUTE (UPDATED FOR STOCK ALERTS) ---
app.post('/api/sell', async (req, res) => {
    let { itemId, quantity, price, itemName, soldBy, paymentMethod, mpesaId, customerName, amountPaid } = req.body;
    
    try {
        // 1. Fetch current stock and cost price
        const { data: item, error: fetchError } = await supabase
            .from('Inventory')
            .select('stock_quantity, cost_price')
            .eq('id', itemId)
            .single();

        if (fetchError || !item) throw new Error(`Item not found.`);
        
        // Check if there is enough stock before proceeding
        if (item.stock_quantity < quantity) {
            return res.status(400).json({ success: false, message: "Insufficient stock!" });
        }

        const newStockQuantity = item.stock_quantity - quantity;
        const totalAmount = quantity * price;
        const paidNow = parseFloat(amountPaid) || 0;
        const totalCost = parseFloat(item.cost_price) * quantity;
        
        // Calculate profit based on what was actually paid
        const profitMargin = totalAmount > 0 ? ((totalAmount - totalCost) / totalAmount) : 0;
        const earnedProfit = Math.max(0, paidNow * profitMargin);

        let status = '';
        if (paidNow <= 0) {
            status = 'Credit';
        } else if (paidNow < totalAmount) {
            status = 'Partial';
        } else {
            status = paymentMethod || 'Cash'; 
        }

        // 2. Update Inventory Stock
        const { error: stockErr } = await supabase
            .from('Inventory')
            .update({ stock_quantity: newStockQuantity })
            .eq('id', itemId);

        if (stockErr) throw stockErr;
        
        // 3. Record the Sale
        const { data: saleData, error: insertError } = await supabase
            .from('Sales')
            .insert([{
                item_name: itemName, 
                quantity_sold: quantity, 
                unit_price: price, 
                total_amount: totalAmount,
                amount_paid: paidNow, 
                payment_status: status, 
                customer_name: customerName || "Walking Customer",
                profit: earnedProfit, 
                sold_by: soldBy, 
                sale_date: new Date().toISOString()
            }])
            .select();

        if (insertError) throw insertError;
        const newSaleId = saleData[0].id;

        // 4. Record the Payment record (if any money was paid)
        if (paidNow > 0) {
            await supabase.from('payments').insert([{
                sale_id: newSaleId,
                amount: paidNow,
                payment_method: paymentMethod || 'Cash',
                mpesa_code: mpesaId || null,
                received_by: soldBy,
                created_at: new Date().toISOString()
            }]);
        }

        // 5. SUCCESS RESPONSE: Include the new stock level for frontend alerts
        res.json({ 
            success: true, 
            message: `Sale recorded as ${status}!`,
            newStock: newStockQuantity // <--- This is used by the frontend to trigger alerts
        });

    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// --- 11. CLEAR DEBT ROUTE (COMPLETED) ---
app.post('/api/payments/clear-debt', async (req, res) => {
    const { saleId, paymentAmount, paymentMethod, mpesaId, processedBy, role } = req.body;
    
    // 1. Authorization Check (Allow Admin and Manager)
    const authorized = ['admin', 'manager'];
    if (!authorized.includes(role?.toLowerCase())) {
        return res.status(403).json({ success: false, message: "Unauthorized. Managers/Admins only." });
    }

    try {
        // 2. Fetch the current sale record
        const { data: sale, error: getErr } = await supabase
            .from('Sales')
            .select('*')
            .eq('id', saleId)
            .single();
        
        if (getErr || !sale) throw new Error("Sale record not found.");

        const totalAmount = parseFloat(sale.total_amount);
        const alreadyPaid = parseFloat(sale.amount_paid || 0);
        const newPayment = parseFloat(paymentAmount || 0);
        const updatedTotalPaid = alreadyPaid + newPayment;

        if (alreadyPaid >= totalAmount) {
            return res.status(400).json({ success: false, message: "This debt has already been cleared." });
        }

        // 3. Calculate New Profit
        // We calculate profit proportionally based on the new payment
        const { data: item } = await supabase.from('Inventory').select('cost_price').eq('item_name', sale.item_name).single();
        const costPrice = item ? parseFloat(item.cost_price) : 0;
        const totalCost = costPrice * sale.quantity_sold;
        
        const profitMargin = totalAmount > 0 ? ((totalAmount - totalCost) / totalAmount) : 0;
        const additionalProfit = newPayment * profitMargin;
        const updatedProfit = (parseFloat(sale.profit || 0)) + additionalProfit;

        // 4. Determine New Status
        let newStatus = updatedTotalPaid >= totalAmount ? 'Paid' : 'Partial';

        // 5. Update the Sales Table
        const { error: updateErr } = await supabase
            .from('Sales')
            .update({ 
                amount_paid: updatedTotalPaid, 
                payment_status: newStatus,
                profit: updatedProfit 
            })
            .eq('id', saleId);

        if (updateErr) throw updateErr;

        // 6. Record the payment in the Payments Audit table
        await supabase.from('payments').insert([{
            sale_id: saleId,
            amount: newPayment,
            payment_method: paymentMethod || 'Cash',
            mpesa_code: mpesaId || null,
            received_by: processedBy,
            created_at: new Date().toISOString()
        }]);

        // 7. SEND SUCCESS RESPONSE (Crucial to stop frontend "Processing" hang)
        res.json({ 
            success: true, 
            message: `Payment of Ksh ${newPayment} recorded. Status: ${newStatus}` 
        });

    } catch (err) {
        console.error("Debt Clearing Error:", err);
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

    const authorizedRoles = ['admin', 'manager'];
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

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));



