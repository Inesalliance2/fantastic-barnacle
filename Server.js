const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ─── TiDB Connection Pool ───────────────────────────────────────────────
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'gateway01.ap-southeast-1.prod.aws.tidbcloud.com',
    port: process.env.DB_PORT || 4000,
    user: process.env.DB_USER || '3DUterCnd1nKr4m.root',
    password: process.env.DB_PASSWORD || '80TYOm0dXEkH2Ow9',
    database: process.env.DB_NAME || 'BetterBasket',
    ssl: { rejectUnauthorized: true },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test connection
pool.query('SELECT 1', (err) => {
    if (err) {
        console.error('DB connection failed:', err);
    } else {
        console.log('Connected to TiDB via pool!');
    }
});

// ─── TEST ENDPOINT ───────────────────────────────────────────────
app.get('/hello', (req, res) => {
    res.json({ message: 'Better Basket API is running!' });
});

// ─── REGISTER CONSUMER ───────────────────────────────────────────
app.post('/api/register/consumer', async (req, res) => {
    const { firstName, lastName, email, phone, password } = req.body;
    if (!firstName || !lastName || !email || !phone || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const insertUser = `
            INSERT INTO user (userType, firstName, lastName, email, phone, passwordHash) 
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        pool.query(insertUser, ['consumer', firstName, lastName, email, phone, passwordHash], (err, userResult) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email already registered' });
                console.error('Error inserting user:', err);
                return res.status(500).json({ error: 'Failed to create user' });
            }
            const newUserID = userResult.insertId;
            pool.query(`INSERT INTO consumer (userID) VALUES (?)`, [newUserID], (err) => {
                if (err) return res.status(500).json({ error: 'Failed to create consumer profile' });
                res.status(201).json({ message: 'Consumer registered successfully', userID: newUserID });
            });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ─── REGISTER MANAGER ────────────────────────────────────────────
app.post('/api/register/manager', async (req, res) => {
    const { firstName, lastName, email, phone, password, managerCode, branchCode } = req.body;
    if (!firstName || !lastName || !email || !phone || !password || !managerCode || !branchCode) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const insertUser = `
            INSERT INTO user (userType, firstName, lastName, email, phone, passwordHash) 
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        pool.query(insertUser, ['manager', firstName, lastName, email, phone, passwordHash], (err, userResult) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email already registered' });
                return res.status(500).json({ error: 'Failed to create user' });
            }
            const newUserID = userResult.insertId;
            pool.query(`INSERT INTO manager (userID, managerCode, branchCode) VALUES (?, ?, ?)`,
                [newUserID, managerCode, branchCode], (err) => {
                    if (err) return res.status(500).json({ error: 'Failed to create manager profile' });
                    res.status(201).json({ message: 'Manager registered successfully', userID: newUserID });
                });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ─── LOGIN ───────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    pool.query(`SELECT * FROM user WHERE email = ?`, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (results.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

        const user = results[0];
        const passwordMatch = await bcrypt.compare(password, user.passwordHash);
        if (!passwordMatch) return res.status(401).json({ error: 'Invalid email or password' });

        res.status(200).json({
            message: 'Login successful',
            userID: user.userID,
            userType: user.userType,
            firstName: user.firstName,
            lastName: user.lastName
        });
    });
});

// ─── GET USER PROFILE ────────────────────────────────────────────
app.get('/api/user/:userID', (req, res) => {
    pool.query(`SELECT userID, userType, firstName, lastName, email, phone FROM user WHERE userID = ?`,
        [req.params.userID], (err, results) => {
            if (err) return res.status(500).json({ error: 'Server error' });
            if (results.length === 0) return res.status(404).json({ error: 'User not found' });
            res.status(200).json(results[0]);
        });
});

// ─── UPDATE USER PROFILE ─────────────────────────────────────────
app.put('/api/user/:userID', async (req, res) => {
    const { firstName, lastName, email, phone, password } = req.body;
    if (!firstName || !lastName || !email || !phone) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        let query, params;
        if (password) {
            const passwordHash = await bcrypt.hash(password, 10);
            query = `UPDATE user SET firstName=?, lastName=?, email=?, phone=?, passwordHash=? WHERE userID=?`;
            params = [firstName, lastName, email, phone, passwordHash, req.params.userID];
        } else {
            query = `UPDATE user SET firstName=?, lastName=?, email=?, phone=? WHERE userID=?`;
            params = [firstName, lastName, email, phone, req.params.userID];
        }
        pool.query(query, params, (err, result) => {
            if (err) return res.status(500).json({ error: 'Failed to update user' });
            if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
            res.status(200).json({ message: 'Profile updated successfully' });
        });
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// ─── GET ALL CATEGORIES ───────────────────────────────────────────
app.get('/api/categories', (req, res) => {
    pool.query(`SELECT categoryID, categoryName FROM productcategory ORDER BY categoryName`, (err, results) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch categories' });
        res.status(200).json(results);
    });
});

// … (all other product/store routes updated the same way with pool.query)

// ─── START SERVER ─────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Better Basket API running on port ${PORT}`);
});
