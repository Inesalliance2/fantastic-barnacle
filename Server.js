const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: true }
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        process.exit(1);
    }
    console.log('Connected to TiDB!');
});

// JWT middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Health check
app.get('/hello', (req, res) => {
    res.json({ message: 'Better Basket API is running' });
});

// Register consumer
app.post('/api/register/consumer', async (req, res) => {
    const { firstName, lastName, email, phone, password } = req.body;

    if (!firstName || !lastName || !email || !phone || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);

        db.query(
            'INSERT INTO user (userType, firstName, lastName, email, phone, passwordHash) VALUES (?, ?, ?, ?, ?, ?)',
            ['consumer', firstName, lastName, email, phone, passwordHash],
            (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(409).json({ error: 'Email already registered' });
                    }
                    return res.status(500).json({ error: 'Registration failed' });
                }

                const userID = result.insertId;

                db.query(
                    'INSERT INTO consumer (userID) VALUES (?)',
                    [userID],
                    (err2) => {
                        if (err2) {
                            return res.status(500).json({ error: 'Failed to create consumer profile' });
                        }
                        res.status(201).json({ message: 'Consumer registered successfully', userID });
                    }
                );
            }
        );
    } catch (err) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Register manager
app.post('/api/register/manager', async (req, res) => {
    const { firstName, lastName, email, phone, password, managerCode, branchCode } = req.body;

    if (!firstName || !lastName || !email || !phone || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);

        db.query(
            'INSERT INTO user (userType, firstName, lastName, email, phone, passwordHash) VALUES (?, ?, ?, ?, ?, ?)',
            ['manager', firstName, lastName, email, phone, passwordHash],
            (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(409).json({ error: 'Email already registered' });
                    }
                    return res.status(500).json({ error: 'Registration failed' });
                }

                const userID = result.insertId;

                db.query(
                    'INSERT INTO manager (userID, managerCode, branchCode) VALUES (?, ?, ?)',
                    [userID, managerCode || '', branchCode || ''],
                    (err2) => {
                        if (err2) {
                            return res.status(500).json({ error: 'Failed to create manager profile' });
                        }
                        res.status(201).json({ message: 'Manager registered successfully', userID });
                    }
                );
            }
        );
    } catch (err) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const loginQuery = `
        SELECT u.*, m.branchCode 
        FROM user u 
        LEFT JOIN manager m ON u.userID = m.userID 
        WHERE u.email = ?
    `;

    db.query(loginQuery, [email], async (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Login failed' });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = results[0];
        const passwordMatch = await bcrypt.compare(password, user.passwordHash);

        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { userID: user.userID, userType: user.userType },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({
            message: 'Login successful',
            userID: user.userID,
            userType: user.userType,
            firstName: user.firstName,
            lastName: user.lastName,
            storeID: user.branchCode ? parseInt(user.branchCode) : 0,
            token
        });
    });
});

// Get user profile
app.get('/api/user/:userID', authenticateToken, (req, res) => {
    const { userID } = req.params;

    db.query('SELECT userID, userType, firstName, lastName, email, phone FROM user WHERE userID = ?', [userID], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch user' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json(results[0]);
    });
});

// Update user profile
app.put('/api/user/:userID', authenticateToken, async (req, res) => {
    const { userID } = req.params;
    const { firstName, lastName, email, phone, password } = req.body;

    if (!firstName || !lastName || !email || !phone) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists
    db.query('SELECT * FROM user WHERE userID = ?', [userID], async (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Update failed' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check for duplicate email (excluding current user)
        db.query('SELECT userID FROM user WHERE email = ? AND userID != ?', [email, userID], async (err2, duplicates) => {
            if (err2) {
                return res.status(500).json({ error: 'Update failed' });
            }

            if (duplicates.length > 0) {
                return res.status(409).json({ error: 'Email already in use' });
            }

            let query = 'UPDATE user SET firstName = ?, lastName = ?, email = ?, phone = ?';
            let params = [firstName, lastName, email, phone];

            if (password) {
                const passwordHash = await bcrypt.hash(password, 10);
                query += ', passwordHash = ?';
                params.push(passwordHash);
            }

            query += ' WHERE userID = ?';
            params.push(userID);

            db.query(query, params, (err3) => {
                if (err3) {
                    return res.status(500).json({ error: 'Update failed' });
                }
                res.status(200).json({ message: 'Profile updated successfully' });
            });
        });
    });
});

// Get all product categories
app.get('/api/categories', authenticateToken, (req, res) => {
    db.query('SELECT categoryID, categoryName FROM productcategory ORDER BY categoryName', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch categories' });
        }
        res.status(200).json(results);
    });
});

// Add a new product
app.post('/api/product', authenticateToken, (req, res) => {
    const { productName, brand, typicalUnit, categoryID, price, storeID } = req.body;

    if (!productName || !categoryID || !price || !storeID) {
        return res.status(400).json({ error: 'productName, categoryID, price and storeID are required' });
    }

    db.query(
        'INSERT INTO product (productName, brand, typicalUnit, categoryID) VALUES (?, ?, ?, ?)',
        [productName, brand || '', typicalUnit || '', categoryID],
        (err, productResult) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to add product' });
            }

            const productID = productResult.insertId;

            db.query(
                'INSERT INTO storeproduct (productID, storeID, available) VALUES (?, ?, TRUE)',
                [productID, storeID],
                (err2, spResult) => {
                    if (err2) {
                        return res.status(500).json({ error: 'Failed to add product' });
                    }

                    const storeProductID = spResult.insertId;

                    db.query(
                        'INSERT INTO pricehistory (storeProductID, price, recordedDate) VALUES (?, ?, CURDATE())',
                        [storeProductID, price],
                        (err3) => {
                            if (err3) {
                                return res.status(500).json({ error: 'Failed to add product' });
                            }

                            res.status(201).json({
                                message: 'Product added successfully',
                                productID,
                                storeProductID
                            });
                        }
                    );
                }
            );
        }
    );
});

// Get products for a store
app.get('/api/store/:storeID/products', authenticateToken, (req, res) => {
    const { storeID } = req.params;

    const query = `
        SELECT sp.storeProductID, p.productID, p.productName, p.brand, p.typicalUnit,
               pc.categoryName, ph.price, sp.available
        FROM storeproduct sp
        JOIN product p ON sp.productID = p.productID
        LEFT JOIN productcategory pc ON p.categoryID = pc.categoryID
        LEFT JOIN pricehistory ph ON sp.storeProductID = ph.storeProductID
            AND ph.recordedDate = (
                SELECT MAX(ph2.recordedDate) FROM pricehistory ph2
                WHERE ph2.storeProductID = sp.storeProductID
            )
        WHERE sp.storeID = ?
        ORDER BY p.productName
    `;

    db.query(query, [storeID], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch products' });
        }
        res.status(200).json(results);
    });
});

// Update product price (append-only)
app.post('/api/product/:storeProductID/price', authenticateToken, (req, res) => {
    const { storeProductID } = req.params;
    const { price } = req.body;

    if (!price || price <= 0) {
        return res.status(400).json({ error: 'Valid price is required' });
    }

    db.query(
        'INSERT INTO pricehistory (storeProductID, price, recordedDate) VALUES (?, ?, CURDATE())',
        [storeProductID, price],
        (err) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to update price' });
            }
            res.status(200).json({ message: 'Price updated successfully' });
        }
    );
});

// Toggle product availability
app.put('/api/product/:storeProductID/availability', authenticateToken, (req, res) => {
    const { storeProductID } = req.params;
    const { available } = req.body;

    if (available === undefined || available === null) {
        return res.status(400).json({ error: 'Available field is required' });
    }

    db.query(
        'UPDATE storeproduct SET available = ? WHERE storeProductID = ?',
        [available, storeProductID],
        (err) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to update availability' });
            }
            res.status(200).json({ message: 'Availability updated successfully' });
        }
    );
});

// Delete a product from a store
app.delete('/api/product/:storeProductID', authenticateToken, (req, res) => {
    const { storeProductID } = req.params;

    // Delete price history first (FK constraint)
    db.query('DELETE FROM pricehistory WHERE storeProductID = ?', [storeProductID], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to delete product' });
        }

        db.query('DELETE FROM storeproduct WHERE storeProductID = ?', [storeProductID], (err2, result) => {
            if (err2) {
                return res.status(500).json({ error: 'Failed to delete product' });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Product not found' });
            }

            res.status(200).json({ message: 'Product deleted successfully' });
        });
    });
});

// Get all stores
app.get('/api/stores', authenticateToken, (req, res) => {
    db.query('SELECT storeID, storeName, storeChain, location, latitude, longitude, openingHours FROM store ORDER BY storeName', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch stores' });
        }
        res.status(200).json(results);
    });
});

// Get store information
app.get('/api/store/:storeID', authenticateToken, (req, res) => {
    const { storeID } = req.params;

    db.query('SELECT * FROM store WHERE storeID = ?', [storeID], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch store' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Store not found' });
        }

        res.status(200).json(results[0]);
    });
});

// Update store information
app.put('/api/store/:storeID', authenticateToken, (req, res) => {
    const { storeID } = req.params;
    const { storeName, storeChain, location, openingHours } = req.body;

    if (!storeName) {
        return res.status(400).json({ error: 'Store name is required' });
    }

    db.query(
        'UPDATE store SET storeName = ?, storeChain = ?, location = ?, openingHours = ? WHERE storeID = ?',
        [storeName, storeChain || '', location || '', openingHours || '', storeID],
        (err) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to update store' });
            }
            res.status(200).json({ message: 'Store information updated successfully' });
        }
    );
});

// Get discounts for a store
app.get('/api/store/:storeID/discounts', authenticateToken, (req, res) => {
    const { storeID } = req.params;

    const query = `
        SELECT d.discountID, d.storeProductID, d.discountPercent, d.startDate, d.endDate,
               p.productName, sp.available
        FROM discountoffer d
        JOIN storeproduct sp ON d.storeProductID = sp.storeProductID
        JOIN product p ON sp.productID = p.productID
        WHERE sp.storeID = ?
        ORDER BY d.endDate DESC
    `;

    db.query(query, [storeID], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch discounts' });
        }
        res.status(200).json(results);
    });
});

// Add a new discount
app.post('/api/discount', authenticateToken, (req, res) => {
    const { storeProductID, discountPercent, startDate, endDate } = req.body;

    if (!storeProductID || !discountPercent || !startDate || !endDate) {
        return res.status(400).json({ error: 'All discount fields are required' });
    }

    db.query(
        'INSERT INTO discountoffer (storeProductID, discountPercent, startDate, endDate) VALUES (?, ?, ?, ?)',
        [storeProductID, discountPercent, startDate, endDate],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to add discount' });
            }
            res.status(201).json({ message: 'Discount added successfully', discountID: result.insertId });
        }
    );
});

// Update a discount
app.put('/api/discount/:discountID', authenticateToken, (req, res) => {
    const { discountID } = req.params;
    const { discountPercent, startDate, endDate } = req.body;

    if (!discountPercent || !startDate || !endDate) {
        return res.status(400).json({ error: 'All discount fields are required' });
    }

    db.query(
        'UPDATE discountoffer SET discountPercent = ?, startDate = ?, endDate = ? WHERE discountID = ?',
        [discountPercent, startDate, endDate, discountID],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to update discount' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Discount not found' });
            }
            res.status(200).json({ message: 'Discount updated successfully' });
        }
    );
});

// Delete a discount
app.delete('/api/discount/:discountID', authenticateToken, (req, res) => {
    const { discountID } = req.params;

    db.query('DELETE FROM discountoffer WHERE discountID = ?', [discountID], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to delete discount' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Discount not found' });
        }
        res.status(200).json({ message: 'Discount deleted successfully' });
    });
});

// Set or update manager's store association (D1600)
app.put('/api/manager/:userID/store', authenticateToken, (req, res) => {
    const { userID } = req.params;
    const { branchCode } = req.body;

    if (!branchCode) {
        return res.status(400).json({ error: 'Branch code is required' });
    }

    // Verify the branchCode matches an existing store
    db.query('SELECT storeID, storeName, location FROM store WHERE storeID = ?', [branchCode], (err, stores) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to look up store' });
        }

        if (stores.length === 0) {
            return res.status(404).json({ error: 'Store not found. Please enter a valid branch code.' });
        }

        const store = stores[0];

        // Update the manager's branchCode
        db.query('UPDATE manager SET branchCode = ? WHERE userID = ?', [branchCode, userID], (err2, result) => {
            if (err2) {
                return res.status(500).json({ error: 'Failed to update store association' });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Manager not found' });
            }

            res.status(200).json({
                message: 'Store association updated successfully',
                storeID: store.storeID,
                storeName: store.storeName,
                location: store.location
            });
        });
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Better Basket API running on port ${PORT}`);
});
