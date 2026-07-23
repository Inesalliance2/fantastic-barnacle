const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// TiDB connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'gateway01.ap-southeast-1.prod.aws.tidbcloud.com',
    port: process.env.DB_PORT || 4000,
    user: process.env.DB_USER || '3DUterCnd1nKr4m.root',
    password: process.env.DB_PASSWORD || '80TYOm0dXEkH2Ow9',
    database: process.env.DB_NAME || 'BetterBasket',
    ssl: { rejectUnauthorized: true }
});

db.connect((err) => {
    if (err) {
        console.error('DB connection failed:', err);
        return;
    }
    console.log('Connected to TiDB!');
});

db.on('error', (err) => {
    console.error('Database error:', err.message);
});

// ─── TEST ENDPOINT ───────────────────────────────────────────────
app.get('/hello', (req, res) => {
    res.json({ message: 'Better Basket API is running!' });
});

// ─── REGISTER CONSUMER ───────────────────────────────────────────
app.post('/api/register/consumer', async (req, res) => {
    let body = req.body;

    if (typeof body === 'string') {
        try {
            body = JSON.parse(body);
        } catch (err) {
            console.error('Consumer registration JSON parse failed:', err.message);
            return res.status(400).json({ error: 'Invalid JSON payload' });
        }
    }

    if (!body || typeof body !== 'object') {
        body = {};
    }

    const { firstName, lastName, email, phone, password } = body;
    const missingFields = [];

    if (!firstName) missingFields.push('firstName');
    if (!lastName) missingFields.push('lastName');
    if (!email) missingFields.push('email');
    if (!phone) missingFields.push('phone');
    if (!password) missingFields.push('password');

    if (missingFields.length > 0) {
        return res.status(400).json({ error: 'Missing required fields', missingFields });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);

        const insertUser = `
            INSERT INTO user (userType, firstName, lastName, email, phone, passwordHash) 
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        db.query(insertUser, ['consumer', firstName, lastName, email, phone, passwordHash], (err, userResult) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ error: 'Email already registered' });
                }
                console.error('Error inserting user:', err);
                return res.status(500).json({ error: 'Failed to create user' });
            }

            const newUserID = userResult.insertId;

            const insertConsumer = `INSERT INTO consumer (userID) VALUES (?)`;
            db.query(insertConsumer, [newUserID], (err) => {
                if (err) {
                    console.error('Error inserting consumer:', err);
                    return res.status(500).json({ error: 'Failed to create consumer profile' });
                }

                res.status(201).json({
                    message: 'Consumer registered successfully',
                    userID: newUserID
                });
            });
        });

    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ─── REGISTER MANAGER ────────────────────────────────────────────
app.post('/api/register/manager', async (req, res) => {
    console.log('MANAGER ROUTE HIT from', __filename);
    let body = req.body;

    if (typeof body === 'string') {
        try {
            body = JSON.parse(body);
        } catch (err) {
            console.error('Manager registration JSON parse failed:', err.message);
            return res.status(400).json({ error: 'Invalid JSON payload' });
        }
    }

    if (!body || typeof body !== 'object') {
        body = {};
    }

    console.log('Manager registration body:', body);
    console.log('Manager registration content-type:', req.headers['content-type']);

    const { firstName, lastName, email, phone, password, managerCode, branchCode } = body;
    const missingFields = [];

    if (!firstName) missingFields.push('firstName');
    if (!lastName) missingFields.push('lastName');
    if (!email) missingFields.push('email');
    if (!phone) missingFields.push('phone');
    if (!password) missingFields.push('password');
    if (!managerCode) missingFields.push('managerCode');
    if (!branchCode) missingFields.push('branchCode');

    if (missingFields.length > 0) {
        return res.status(400).json({ error: 'manager-validation-v2', missingFields });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);

        const insertUser = `
            INSERT INTO user (userType, firstName, lastName, email, phone, passwordHash) 
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        db.query(insertUser, ['manager', firstName, lastName, email, phone, passwordHash], (err, userResult) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ error: 'Email already registered' });
                }
                console.error('Error inserting user:', err);
                return res.status(500).json({ error: 'Failed to create user' });
            }

            const newUserID = userResult.insertId;

            const insertManager = `
                INSERT INTO manager (userID, managerCode, branchCode) 
                VALUES (?, ?, ?)
            `;
            db.query(insertManager, [newUserID, managerCode, branchCode], (err) => {
                if (err) {
                    console.error('Error inserting manager:', err);
                    return res.status(500).json({ error: 'Failed to create manager profile' });
                }

                res.status(201).json({
                    message: 'Manager registered successfully',
                    userID: newUserID
                });
            });
        });

    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ─── LOGIN ───────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const findUser = `SELECT * FROM user WHERE email = ?`;
        db.query(findUser, [email], async (err, results) => {
            if (err) {
                console.error('Error finding user:', err);
                return res.status(500).json({ error: 'Server error' });
            }

            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const user = results[0];

            const passwordMatch = await bcrypt.compare(password, user.passwordHash);
            if (!passwordMatch) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            res.status(200).json({
                message: 'Login successful',
                userID: user.userID,
                userType: user.userType,
                firstName: user.firstName,
                lastName: user.lastName
            });
        });

    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ─── GET USER PROFILE ────────────────────────────────────────────
app.get('/api/user/:userID', (req, res) => {
    const { userID } = req.params;

    const query = `
        SELECT userID, userType, firstName, lastName, email, phone 
        FROM user WHERE userID = ?
    `;
    db.query(query, [userID], (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ error: 'Server error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json(results[0]);
    });
});

// ─── UPDATE USER PROFILE ─────────────────────────────────────────
app.put('/api/user/:userID', async (req, res) => {
    const { userID } = req.params;
    const { firstName, lastName, email, phone, password } = req.body;

    if (!firstName || !lastName || !email || !phone) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        let query;
        let params;

        if (password) {
            const passwordHash = await bcrypt.hash(password, 10);
            query = `
                UPDATE user 
                SET firstName = ?, lastName = ?, email = ?, phone = ?, passwordHash = ?
                WHERE userID = ?
            `;
            params = [firstName, lastName, email, phone, passwordHash, userID];
        } else {
            query = `
                UPDATE user 
                SET firstName = ?, lastName = ?, email = ?, phone = ?
                WHERE userID = ?
            `;
            params = [firstName, lastName, email, phone, userID];
        }

        db.query(query, params, (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ error: 'Email already in use' });
                }
                console.error('Error updating user:', err);
                return res.status(500).json({ error: 'Failed to update user' });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            res.status(200).json({ message: 'Profile updated successfully' });
        });

    } catch (err) {
        console.error('Server error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ─── GET ALL CATEGORIES ───────────────────────────────────────────
app.get('/api/categories', (req, res) => {
    const query = `SELECT categoryID, categoryName FROM productcategory ORDER BY categoryName`;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching categories:', err);
            return res.status(500).json({ error: 'Failed to fetch categories' });
        }
        res.status(200).json(results);
    });
});

// ─── ADD PRODUCT ─────────────────────────────────────────────────
app.post('/api/product', (req, res) => {
    const { productName, brand, typicalUnit, categoryID, price, storeID } = req.body;

    if (!productName || !categoryID || !price || !storeID) {
        return res.status(400).json({ error: 'productName, categoryID, price and storeID are required' });
    }

    // Step 1: Insert into product
    const insertProduct = `
        INSERT INTO product (productName, brand, typicalUnit, categoryID) 
        VALUES (?, ?, ?, ?)
    `;
    db.query(insertProduct, [productName, brand || null, typicalUnit || null, categoryID], (err, productResult) => {
        if (err) {
            console.error('Error inserting product:', err);
            return res.status(500).json({ error: 'Failed to add product' });
        }

        const newProductID = productResult.insertId;

        // Step 2: Insert into storeproduct
        const insertStoreProduct = `
            INSERT INTO storeproduct (productID, storeID, available) 
            VALUES (?, ?, TRUE)
        `;
        db.query(insertStoreProduct, [newProductID, storeID], (err, storeProductResult) => {
            if (err) {
                console.error('Error inserting store product:', err);
                return res.status(500).json({ error: 'Failed to link product to store' });
            }

            const newStoreProductID = storeProductResult.insertId;

            // Step 3: Insert into pricehistory
            const insertPrice = `
                INSERT INTO pricehistory (storeProductID, price, recordedDate) 
                VALUES (?, ?, CURDATE())
            `;
            db.query(insertPrice, [newStoreProductID, price], (err) => {
                if (err) {
                    console.error('Error inserting price:', err);
                    return res.status(500).json({ error: 'Failed to record price' });
                }

                res.status(201).json({
                    message: 'Product added successfully',
                    productID: newProductID,
                    storeProductID: newStoreProductID
                });
            });
        });
    });
});

// ─── GET PRODUCTS FOR STORE ───────────────────────────────────────
app.get('/api/store/:storeID/products', (req, res) => {
    const { storeID } = req.params;
    console.log('Fetching products for store:', storeID);

    const query = `
        SELECT 
            sp.storeProductID,
            p.productID,
            p.productName,
            p.brand,
            p.typicalUnit,
            p.categoryID,
            pc.categoryName,
            ph.price,
            sp.available
        FROM storeproduct sp
        JOIN product p ON sp.productID = p.productID
        LEFT JOIN productcategory pc ON p.categoryID = pc.categoryID
        LEFT JOIN (
            SELECT ph1.storeProductID, ph1.price
            FROM pricehistory ph1
            INNER JOIN (
                SELECT storeProductID, MAX(recordedDate) AS latestRecordedDate
                FROM pricehistory
                GROUP BY storeProductID
            ) ph2
            ON ph1.storeProductID = ph2.storeProductID
            AND ph1.recordedDate = ph2.latestRecordedDate
        ) ph ON sp.storeProductID = ph.storeProductID
        WHERE sp.storeID = ?
        ORDER BY p.productName
    `;

    db.query(query, [storeID], (err, results) => {
        if (err) {
            console.error('Error fetching products:', err);
            console.error('Query:', query);
            return res.status(500).json({ error: 'Failed to fetch products', detail: err.message });
        }

        console.log('Products fetched:', results.length);
        res.status(200).json(results);
    });
});

// ─── UPDATE PRODUCT PRICE ─────────────────────────────────────────
app.post('/api/product/:storeProductID/price', (req, res) => {
    const { storeProductID } = req.params;
    const { price } = req.body;

    if (!price || price <= 0) {
        return res.status(400).json({ error: 'Valid price is required' });
    }

    const insertPrice = `
        INSERT INTO pricehistory (storeProductID, price, recordedDate) 
        VALUES (?, ?, CURDATE())
    `;
    db.query(insertPrice, [storeProductID, price], (err) => {
        if (err) {
            console.error('Error updating price:', err);
            return res.status(500).json({ error: 'Failed to update price' });
        }

        res.status(200).json({ message: 'Price updated successfully' });
    });
});

// ─── UPDATE PRODUCT AVAILABILITY ──────────────────────────────────
app.put('/api/product/:storeProductID/availability', (req, res) => {
    const { storeProductID } = req.params;
    const { available } = req.body;

    if (available === undefined) {
        return res.status(400).json({ error: 'Available field is required' });
    }

    const query = `UPDATE storeproduct SET available = ? WHERE storeProductID = ?`;
    db.query(query, [available, storeProductID], (err) => {
        if (err) {
            console.error('Error updating availability:', err);
            return res.status(500).json({ error: 'Failed to update availability' });
        }

        res.status(200).json({ message: 'Availability updated successfully' });
    });
});

// ─── DELETE PRODUCT ───────────────────────────────────────────────
app.delete('/api/product/:storeProductID', (req, res) => {
    const { storeProductID } = req.params;

    const query = `DELETE FROM storeproduct WHERE storeProductID = ?`;
    db.query(query, [storeProductID], (err, result) => {
        if (err) {
            console.error('Error deleting product:', err);
            return res.status(500).json({ error: 'Failed to delete product' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        res.status(200).json({ message: 'Product deleted successfully' });
    });
});

// ─── GET STORE INFO ───────────────────────────────────────────────
app.get('/api/store/:storeID', (req, res) => {
    const { storeID } = req.params;

    const query = `
        SELECT storeID, storeName, storeChain, location, latitude, longitude, openingHours 
        FROM store WHERE storeID = ?
    `;
    db.query(query, [storeID], (err, results) => {
        if (err) {
            console.error('Error fetching store:', err);
            return res.status(500).json({ error: 'Server error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Store not found' });
        }

        res.status(200).json(results[0]);
    });
});

// ─── UPDATE STORE INFO ────────────────────────────────────────────
app.put('/api/store/:storeID', (req, res) => {
    const { storeID } = req.params;
    const { storeName, storeChain, location, openingHours } = req.body;

    if (!storeName) {
        return res.status(400).json({ error: 'Store name is required' });
    }

    const query = `
        UPDATE store 
        SET storeName = ?, storeChain = ?, location = ?, openingHours = ?
        WHERE storeID = ?
    `;
    db.query(query, [storeName, storeChain || null, location || null, openingHours || null, storeID], (err, result) => {
        if (err) {
            console.error('Error updating store:', err);
            return res.status(500).json({ error: 'Failed to update store' });
        }

        res.status(200).json({ message: 'Store information updated successfully' });
    });
});

// ─── START SERVER ─────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Better Basket API running on port ${PORT}`);
});;