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
    const { data, error } = await supabase.from('Inventory').select('*').order('item_name');
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

// --- 5. DASHBOARD SUMMARY ---
app.get('/api/reports/daily-summary', async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];

        const { data: todaySales, error: salesError } = await supabase
            .from('Sales')
            .select('total_amount, profit')
            .gte('sale_date', `${today}T00:00:00Z`);

        if (salesError) throw salesError;

        const { data: allUnpaidSales, error: debtError } = await supabase
            .from('Sales')
            .select('total_amount, amount_paid')
            .neq('payment_status', 'Paid'); 

        if (debtError) throw debtError;

        let totalSales = 0;
        let totalProfit = 0;
        let totalOwed = 0;

        todaySales.forEach(sale => {
            totalSales += parseFloat(sale.total_amount || 0);
            totalProfit += parseFloat(sale.profit || 0);
        });

        allUnpaidSales.forEach(sale => {
            const balance = parseFloat(sale.total_amount || 0) - parseFloat(sale.amount_paid || 0);
            if (balance > 0) { 
                totalOwed += balance; 
            }
        });

        res.json({ totalSales, totalProfit, totalOwed });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- 6. DETAILED SALES REPORT ---
app.get('/api/reports/sales', async (req, res) => {
    const { role, date, month, year, method } = req.query;
    if (role?.toLowerCase() !== 'admin') return res.status(403).json({ success: false, message: "Unauthorized." });

    try {
        let query = supabase
            .from('Sales')
          .select('*, payments(mpesa_code, amount, payment_method)')
            .order('sale_date', { ascending: false });

        if (date) {
            query = query.gte('sale_date', `${date}T00:00:00Z`).lte('sale_date', `${date}T23:59:59Z`);
        } 
        else if (month && year) {
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

// --- 7. PAYMENTS REPORT ---
// --- 7. PAYMENTS REPORT ---
app.get('/api/reports/payments', async (req, res) => {
    try {
        const { date, month, year, method } = req.query;
        
        let query = supabase
            .from('payments')
            .select(`*, Sales ( customer_name, item_name )`)
            .order('created_at', { ascending: false });

        // 1. Filter by Specific Date
        if (date) {
            query = query
                .gte('created_at', `${date}T00:00:00Z`)
                .lte('created_at', `${date}T23:59:59Z`);
        } 
        // 2. Filter by Month and Year
        else if (month && year) {
            const startDate = `${year}-${month.padStart(2, '0')}-01T00:00:00Z`;
            const lastDay = new Date(year, month, 0).getDate();
            const endDate = `${year}-${month.padStart(2, '0')}-${lastDay}T23:59:59Z`;
            query = query.gte('created_at', startDate).lte('created_at', endDate);
        }

        // 3. Filter by Payment Method
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

// --- 8. LOW STOCK ROUTE ---
app.get('/api/reports/low-stock', async (req, res) => {
    const { data, error } = await supabase.from('Inventory').select('*').lte('stock_quantity', 10);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// --- 9. DEBTORS ROUTE ---
app.get('/api/reports/debtors', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('Sales')
            .select('id, customer_name, item_name, total_amount, amount_paid, sale_date')
            .neq('payment_status', 'Paid') 
            .order('sale_date', { ascending: false });

        if (error) throw error;
        const actualDebtors = data.filter(d => (parseFloat(d.total_amount) - parseFloat(d.amount_paid)) > 0);
        res.json(actualDebtors);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- 10. TRANSACTIONAL SALE ROUTE ---
app.post('/api/sell', async (req, res) => {
    let { itemId, quantity, price, itemName, soldBy, paymentMethod, mpesaId, customerName, amountPaid } = req.body;
    
    try {
        const { data: item, error: fetchError } = await supabase.from('Inventory').select('stock_quantity, cost_price').eq('id', itemId).single();
        if (fetchError || !item) throw new Error(`Item not found.`);
        if (item.stock_quantity < quantity) return res.status(400).json({ success: false, message: "Insufficient stock!" });

        const totalAmount = quantity * price;
        const paidNow = parseFloat(amountPaid) || 0;
        const totalCost = parseFloat(item.cost_price) * quantity;
        
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

        const { error: stockErr } = await supabase
            .from('Inventory')
            .update({ stock_quantity: item.stock_quantity - quantity })
            .eq('id', itemId);
        if (stockErr) throw stockErr;
        
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

        res.json({ success: true, message: `Sale recorded as ${status}!` });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// --- 11. CLEAR DEBT ROUTE ---
app.post('/api/payments/clear-debt', async (req, res) => {
    const { saleId, paymentAmount, paymentMethod, mpesaId, processedBy } = req.body;
    
    try {
        const { data: sale, error: getErr } = await supabase.from('Sales').select('*').eq('id', saleId).single();
        if (getErr || !sale) throw new Error("Sale record not found.");

        const { data: item } = await supabase.from('Inventory').select('cost_price').eq('item_name', sale.item_name).single();
        
        const amountToPayNow = parseFloat(paymentAmount);
        const totalAmount = parseFloat(sale.total_amount);
        const qtySold = parseFloat(sale.quantity_sold);
        const unitCost = item ? parseFloat(item.cost_price) : 0;

        const totalPotentialProfit = (parseFloat(sale.unit_price) - unitCost) * qtySold;
        const profitFromThisPayment = (amountToPayNow / totalAmount) * totalPotentialProfit;

        const updatedPaid = (parseFloat(sale.amount_paid) || 0) + amountToPayNow;
        const newTotalProfit = (parseFloat(sale.profit) || 0) + profitFromThisPayment;

        const { error: updateErr } = await supabase.from('Sales').update({ 
            amount_paid: updatedPaid, 
            payment_status: updatedPaid >= totalAmount ? paymentMethod : 'Partial', 
            profit: newTotalProfit, 
            sale_date: new Date().toISOString()
        }).eq('id', saleId);

        if (updateErr) throw updateErr;

        await supabase.from('payments').insert([{
            sale_id: saleId,
            amount: amountToPayNow,
            payment_method: paymentMethod, 
            mpesa_code: mpesaId || null,
            received_by: processedBy,
            created_at: new Date().toISOString()
        }]);

        res.json({ success: true, message: `Payment received. Profit updated.` });
        
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// --- 12. INVENTORY MANAGEMENT (STOCK UPDATE) ---

// THIS IS THE UPDATED ROUTE TO HANDLE THE QUICK RESTOCK
app.patch('/api/inventory/:id', async (req, res) => {
    const { id } = req.params;
    const { stock_quantity, role } = req.body; // Changed from newQuantity to stock_quantity
    
    if (role?.toLowerCase() !== 'admin') {
        return res.status(403).json({ success: false, message: "Admin only." });
    }
    
    try {
        const { data, error } = await supabase
            .from('Inventory')
            .update({ stock_quantity: parseInt(stock_quantity) })
            .eq('id', id)
            .select();

        if (error) throw error;
        res.json({ success: true, message: "Stock updated successfully!", data });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete('/api/inventory/:id', async (req, res) => {
    const { id } = req.params;
    const { role } = req.query;
    if (role?.toLowerCase() !== 'admin') return res.status(403).json({ success: false, message: "Unauthorized." });
    
    const { error } = await supabase.from('Inventory').delete().eq('id', id);
    if (error) return res.status(500).json({ success: false, message: error.message });
    res.json({ success: true });
});

app.post('/api/inventory', async (req, res) => {
    const { item_name, category, price, cost_price, stock_quantity, unit, role } = req.body;
    if (role?.toLowerCase() !== 'admin') return res.status(403).json({ success: false, message: "Unauthorized." });

    try {
        const { data, error } = await supabase.from('Inventory').insert([{ 
            item_name, category: category || "General", price: parseFloat(price) || 0, 
            cost_price: parseFloat(cost_price) || 0, stock_quantity: parseInt(stock_quantity) || 0, unit: unit || "pcs"
        }]).select();
        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
