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
<<<<<<< HEAD
=======
// ===== DISCOUNT ROUTES (B800) =====

// Get all discounts for a store (with product name join)
app.get('/api/discounts/store/:storeID', authenticateToken, (req, res) => {
    const { storeID } = req.params;
    const query = `
        SELECT d.discountID, d.storeProductID, d.discountPercent,
               d.startDate, d.endDate, p.productName
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

// Create a new discount
app.post('/api/discounts', authenticateToken, (req, res) => {
    const { storeProductID, discountPercent, startDate, endDate } = req.body;
    if (!storeProductID || !discountPercent || !endDate) {
        return res.status(400).json({ error: 'storeProductID, discountPercent, and endDate are required' });
    }
    const effectiveStartDate = startDate || new Date().toISOString().slice(0, 10);
    db.query(
        'INSERT INTO discountoffer (storeProductID, discountPercent, startDate, endDate) VALUES (?, ?, ?, ?)',
        [storeProductID, discountPercent, effectiveStartDate, endDate],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to create discount' });
            }
            res.status(201).json({ message: 'Discount created successfully', discountID: result.insertId });
        }
    );
});
// Update an existing discount
app.put('/api/discounts/:discountID', authenticateToken, (req, res) => {
    const { discountID } = req.params;
    const { discountPercent, startDate, endDate } = req.body;

    if (!discountPercent || !endDate) {
        return res.status(400).json({ error: 'discountPercent and endDate are required' });
    }

    const effectiveStartDate = startDate || new Date().toISOString().slice(0, 10);

    db.query(
        'UPDATE discountoffer SET discountPercent = ?, startDate = ?, endDate = ? WHERE discountID = ?',
        [discountPercent, effectiveStartDate, endDate, discountID],
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

// ===== C-Series: Fuel Settings (C100/C200/C300) =====

// Get consumer fuel settings
app.get('/api/consumer/:userID/fuel', authenticateToken, (req, res) => {
    const { userID } = req.params;

    db.query(
        'SELECT fuelPricePerLitre, consumptionLitresPer100km, fuelRegion, fuelManualOverride FROM consumer WHERE userID = ?',
        [userID],
        (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch fuel settings' });
            }

            if (results.length === 0) {
                return res.status(404).json({ error: 'No fuel settings found' });
            }

            const row = results[0];
            res.status(200).json({
                userID: parseInt(userID),
                fuelPricePerLitre: row.fuelPricePerLitre || 0,
                consumptionLitresPer100km: row.consumptionLitresPer100km || 0,
                region: row.fuelRegion || 'inland',
                manualOverride: row.fuelManualOverride ? true : false
            });
        }
    );
});

// Update consumer fuel settings
app.put('/api/consumer/:userID/fuel', authenticateToken, (req, res) => {
    const { userID } = req.params;
    const { fuelPricePerLitre, consumptionLitresPer100km, region, manualOverride } = req.body;

    if (!fuelPricePerLitre || fuelPricePerLitre <= 0) {
        return res.status(400).json({ error: 'Fuel price must be greater than 0' });
    }

    if (!consumptionLitresPer100km || consumptionLitresPer100km < 3.0 || consumptionLitresPer100km > 25.0) {
        return res.status(400).json({ error: 'Consumption must be between 3.0 and 25.0 L/100km' });
    }

    db.query(
        'UPDATE consumer SET fuelPricePerLitre = ?, consumptionLitresPer100km = ?, fuelRegion = ?, fuelManualOverride = ? WHERE userID = ?',
        [fuelPricePerLitre, consumptionLitresPer100km, region || 'inland', manualOverride ? 1 : 0, userID],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to update fuel settings' });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Consumer not found' });
            }

            res.status(200).json({ message: 'Fuel settings updated successfully' });
        }
    );
});

// ===== C-Series: Consumer Preferences (C400/C500/C600) =====

// Get consumer preferences
app.get('/api/consumer/:userID/preferences', authenticateToken, (req, res) => {
    const { userID } = req.params;

    db.query('SELECT maxTravelDistanceKm FROM consumer WHERE userID = ?', [userID], (err, consumerResults) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch preferences' });
        }

        if (consumerResults.length === 0) {
            return res.status(404).json({ error: 'Consumer not found' });
        }

        const maxTravelDistanceKm = consumerResults[0].maxTravelDistanceKm || 10;

        const storeQuery = `
            SELECT p.preferenceValue, up.consumerID
            FROM preference p
            LEFT JOIN userPreference up ON p.preferenceID = up.preferenceID AND up.consumerID = ?
            WHERE p.preferenceType = 'store'
        `;

        db.query(storeQuery, [userID], (err2, storeResults) => {
            if (err2) {
                return res.status(500).json({ error: 'Failed to fetch preferences' });
            }

            const preferredStores = [];
            const excludedStores = [];

            for (const row of storeResults) {
                if (row.consumerID) {
                    preferredStores.push(row.preferenceValue);
                } else {
                    excludedStores.push(row.preferenceValue);
                }
            }

            const dietaryQuery = `
                SELECT p.preferenceValue, up.consumerID
                FROM preference p
                LEFT JOIN userPreference up ON p.preferenceID = up.preferenceID AND up.consumerID = ?
                WHERE p.preferenceType = 'dietary'
            `;

            db.query(dietaryQuery, [userID], (err3, dietaryResults) => {
                if (err3) {
                    return res.status(200).json({ maxTravelDistanceKm, preferredStores, excludedStores, dietaryFilters: {} });
                }

                const dietaryFilters = {};
                for (const row of dietaryResults) {
                    dietaryFilters[row.preferenceValue] = row.consumerID ? true : false;
                }

                res.status(200).json({ maxTravelDistanceKm, preferredStores, excludedStores, dietaryFilters });
            });
        });
    });
});

// Update consumer preferences
app.put('/api/consumer/:userID/preferences', authenticateToken, (req, res) => {
    const { userID } = req.params;
    const { maxTravelDistanceKm, preferredStores, dietaryFilters } = req.body;

    if (maxTravelDistanceKm !== undefined && maxTravelDistanceKm <= 0) {
        return res.status(400).json({ error: 'Distance must be greater than 0' });
    }

    const distanceUpdate = maxTravelDistanceKm !== undefined
        ? new Promise((resolve, reject) => {
            db.query('UPDATE consumer SET maxTravelDistanceKm = ? WHERE userID = ?', [maxTravelDistanceKm, userID], (err) => {
                if (err) reject(err); else resolve();
            });
        })
        : Promise.resolve();

    distanceUpdate.then(() => {
        if (preferredStores && Array.isArray(preferredStores)) {
            db.query(
                `DELETE FROM userPreference WHERE consumerID = ? AND preferenceID IN (SELECT preferenceID FROM preference WHERE preferenceType = 'store')`,
                [userID],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to update store preferences' });
                    }

                    if (preferredStores.length === 0) {
                        return updateDietaryAndRespond();
                    }

                    const placeholders = preferredStores.map(() => '?').join(',');
                    const insertQuery = `
                        INSERT INTO userPreference (consumerID, preferenceID)
                        SELECT ?, preferenceID FROM preference
                        WHERE preferenceType = 'store' AND preferenceValue IN (${placeholders})
                    `;

                    db.query(insertQuery, [userID, ...preferredStores], (err2) => {
                        if (err2) {
                            return res.status(500).json({ error: 'Failed to update store preferences' });
                        }
                        updateDietaryAndRespond();
                    });
                }
            );
        } else {
            updateDietaryAndRespond();
        }
    }).catch(() => {
        return res.status(500).json({ error: 'Failed to update preferences' });
    });

    function updateDietaryAndRespond() {
        if (dietaryFilters && typeof dietaryFilters === 'object') {
            db.query(
                `DELETE FROM userPreference WHERE consumerID = ? AND preferenceID IN (SELECT preferenceID FROM preference WHERE preferenceType = 'dietary')`,
                [userID],
                (err) => {
                    if (err) {
                        return res.status(200).json({ message: 'Preferences updated (dietary sync failed)' });
                    }

                    const activeFilters = Object.entries(dietaryFilters).filter(([_, v]) => v).map(([k]) => k);

                    if (activeFilters.length === 0) {
                        return res.status(200).json({ message: 'Preferences updated successfully' });
                    }

                    const placeholders = activeFilters.map(() => '?').join(',');
                    const insertQuery = `
                        INSERT INTO userPreference (consumerID, preferenceID)
                        SELECT ?, preferenceID FROM preference
                        WHERE preferenceType = 'dietary' AND preferenceValue IN (${placeholders})
                    `;

                    db.query(insertQuery, [userID, ...activeFilters], (err2) => {
                        res.status(200).json({ message: 'Preferences updated successfully' });
                    });
                }
            );
        } else {
            res.status(200).json({ message: 'Preferences updated successfully' });
        }
    }
});

// Stores within radius (C500)
app.get('/api/stores/nearby', authenticateToken, (req, res) => {
    const { lat, lng, radiusKm } = req.query;

    if (!lat || !lng || !radiusKm) {
        return res.status(400).json({ error: 'lat, lng, and radiusKm are required' });
    }

    const query = `
        SELECT storeID, storeName, storeChain,
            (6371 * acos(cos(radians(?)) * cos(radians(latitude)) *
            cos(radians(longitude) - radians(?)) + sin(radians(?)) * sin(radians(latitude)))) AS distanceKm
        FROM store
        HAVING distanceKm <= ?
        ORDER BY distanceKm
    `;

    db.query(query, [parseFloat(lat), parseFloat(lng), parseFloat(lat), parseFloat(radiusKm)], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch nearby stores' });
        }

        res.status(200).json({
            count: results.length,
            stores: results.map(r => ({
                storeID: r.storeID,
                storeName: r.storeName,
                distanceKm: Math.round(r.distanceKm * 10) / 10
            }))
        });
    });
});

// ===== C-Series: Product Search & Price History (C700/C800/C900) =====

// Product search
app.get('/api/product/search', authenticateToken, (req, res) => {
    const { q } = req.query;

    if (!q || q.trim().length === 0) {
        return res.status(400).json({ error: 'Search query is required' });
    }

    const query = `
        SELECT p.productID, p.productName, p.brand, pc.categoryName
        FROM product p
        LEFT JOIN productcategory pc ON p.categoryID = pc.categoryID
        WHERE p.productName LIKE CONCAT('%', ?, '%')
        ORDER BY p.productName
        LIMIT 20
    `;

    db.query(query, [q.trim()], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Search failed' });
        }
        res.status(200).json(results);
    });
});

// Multi-store price history for a product (C700/C900)
app.get('/api/product/:productID/pricehistory', authenticateToken, (req, res) => {
    const { productID } = req.params;
    const days = parseInt(req.query.days) || 90;

    const historyQuery = `
        SELECT ph.recordedDate AS date, ph.price, s.storeID, s.storeName, s.storeChain,
               sp.storeProductID
        FROM pricehistory ph
        JOIN storeproduct sp ON ph.storeProductID = sp.storeProductID
        JOIN store s ON sp.storeID = s.storeID
        WHERE sp.productID = ? AND ph.recordedDate >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
        ORDER BY s.storeID, ph.recordedDate
    `;

    const discountQuery = `
        SELECT d.specialPrice, d.startDate, d.endDate, s.storeName, sp.storeProductID
        FROM discountoffer d
        JOIN storeproduct sp ON d.storeProductID = sp.storeProductID
        JOIN store s ON sp.storeID = s.storeID
        WHERE sp.productID = ? AND d.endDate >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
    `;

    db.query('SELECT productName FROM product WHERE productID = ?', [productID], (err, productResults) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch price history' });
        }

        if (productResults.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const productName = productResults[0].productName;

        db.query(historyQuery, [productID, days], (err2, historyResults) => {
            if (err2) {
                return res.status(500).json({ error: 'Failed to fetch price history' });
            }

            const storesMap = {};
            for (const row of historyResults) {
                if (!storesMap[row.storeID]) {
                    storesMap[row.storeID] = {
                        storeID: row.storeID,
                        storeProductID: row.storeProductID,
                        storeName: row.storeName,
                        storeChain: row.storeChain,
                        history: []
                    };
                }
                storesMap[row.storeID].history.push({
                    date: row.date ? row.date.toISOString().split('T')[0] : null,
                    price: row.price
                });
            }

            const stores = Object.values(storesMap);

            db.query(discountQuery, [productID, days], (err3, discountResults) => {
                if (err3) {
                    return res.status(200).json({ productID: parseInt(productID), productName, stores, discounts: [] });
                }

                const discounts = discountResults.map(d => ({
                    storeProductID: d.storeProductID,
                    storeName: d.storeName,
                    specialPrice: d.specialPrice,
                    startDate: d.startDate ? d.startDate.toISOString().split('T')[0] : null,
                    endDate: d.endDate ? d.endDate.toISOString().split('T')[0] : null
                }));

                res.status(200).json({ productID: parseInt(productID), productName, stores, discounts });
            });
        });
    });
});

// Single store product price history (C800)
app.get('/api/storeproduct/:storeProductID/pricehistory', authenticateToken, (req, res) => {
    const { storeProductID } = req.params;
    const { startDate, endDate } = req.query;

    const infoQuery = `
        SELECT sp.storeProductID, p.productName, s.storeName
        FROM storeproduct sp
        JOIN product p ON sp.productID = p.productID
        JOIN store s ON sp.storeID = s.storeID
        WHERE sp.storeProductID = ?
    `;

    db.query(infoQuery, [storeProductID], (err, infoResults) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch price history' });
        }

        if (infoResults.length === 0) {
            return res.status(404).json({ error: 'Store product not found' });
        }

        const info = infoResults[0];

        let historyQuery = `
            SELECT priceHistoryID, price, recordedDate
            FROM pricehistory
            WHERE storeProductID = ?
        `;
        const params = [storeProductID];

        if (startDate) {
            historyQuery += ' AND recordedDate >= ?';
            params.push(startDate);
        }

        if (endDate) {
            historyQuery += ' AND recordedDate <= ?';
            params.push(endDate);
        }

        historyQuery += ' ORDER BY recordedDate ASC';

        db.query(historyQuery, params, (err2, historyResults) => {
            if (err2) {
                return res.status(500).json({ error: 'Failed to fetch price history' });
            }

            const history = historyResults.map(row => ({
                priceHistoryID: row.priceHistoryID,
                price: row.price,
                recordedDate: row.recordedDate ? row.recordedDate.toISOString().split('T')[0] : null
            }));

            res.status(200).json({
                storeProductID: parseInt(storeProductID),
                productName: info.productName,
                storeName: info.storeName,
                history
            });
        });
    });
});

// ============================================================
// A-SERIES: Shopping List CRUD Endpoints (A200-A1000)
// ============================================================

// A200 — Get active shopping list for a consumer
app.get('/api/user/:userID/shopping-list', authenticateToken, (req, res) => {
    const { userID } = req.params;

    db.query('SELECT * FROM shoppinglist WHERE consumerID = ? AND status = ?', [userID, 'active'], (err, lists) => {
        if (err) {
            console.log('GET LIST error:', err.message);
            return res.status(500).json({ error: 'Failed to fetch shopping list' });
        }

        if (lists.length === 0) {
            return res.status(200).json({ listID: null, status: null, items: [] });
        }

        const list = lists[0];

        const itemQuery = `
            SELECT sli.productID, p.productName, p.brand, p.typicalUnit,
                   pc.categoryName, sli.quantity,
                   MIN(ph.price) AS lowestPrice
            FROM shoppinglistitem sli
            JOIN product p ON sli.productID = p.productID
            LEFT JOIN productcategory pc ON p.categoryID = pc.categoryID
            LEFT JOIN storeproduct sp ON p.productID = sp.productID AND sp.available = TRUE
            LEFT JOIN pricehistory ph ON sp.storeProductID = ph.storeProductID
            WHERE sli.listID = ?
            GROUP BY sli.productID, p.productName, p.brand, p.typicalUnit, pc.categoryName, sli.quantity
        `;

        db.query(itemQuery, [list.listID], (err2, items) => {
            if (err2) {
                console.log('GET LIST ITEMS error:', err2.message);
                return res.status(500).json({ error: 'Failed to fetch list items' });
            }

            const itemCount = items.reduce((sum, item) => sum + item.quantity, 0);
            const categories = [...new Set(items.map(i => i.categoryName).filter(Boolean))];
            const baselineSubtotal = items.reduce((sum, item) => sum + (item.lowestPrice || 0) * item.quantity, 0);

            res.status(200).json({
                listID: list.listID,
                listName: list.listName,
                status: list.status,
                createdDate: list.createdDate,
                lastModifiedDate: list.lastModifiedDate,
                itemCount,
                categoryCount: categories.length,
                baselineSubtotal: Math.round(baselineSubtotal * 100) / 100,
                items
            });
        });
    });
});

// A200 — Create new shopping list
app.post('/api/user/:userID/shopping-list', authenticateToken, (req, res) => {
    const { userID } = req.params;
    const { listName } = req.body;

    db.query('SELECT listID FROM shoppinglist WHERE consumerID = ? AND status = ?', [userID, 'active'], (err, existing) => {
        if (err) {
            console.log('CREATE LIST check error:', err.message);
            return res.status(500).json({ error: 'Failed to create list' });
        }

        if (existing.length > 0) {
            return res.status(409).json({ error: 'Active shopping list already exists', listID: existing[0].listID });
        }

        db.query('INSERT INTO shoppinglist (consumerID, listName, status) VALUES (?, ?, ?)', [userID, listName || 'My Shopping List', 'active'], (err2, result) => {
            if (err2) {
                console.log('CREATE LIST insert error:', err2.message);
                return res.status(500).json({ error: 'Failed to create list' });
            }
            res.status(201).json({ message: 'Shopping list created', listID: result.insertId });
        });
    });
});

// A300 — Add item to shopping list
app.post('/api/shopping-list/:listID/items', authenticateToken, (req, res) => {
    const { listID } = req.params;
    const { productID, quantity, userID } = req.body;

    if (!productID || !quantity || quantity < 1 || quantity > 99) {
        return res.status(400).json({ error: 'Valid productID and quantity (1-99) are required' });
    }

    db.query('SELECT quantity FROM shoppinglistitem WHERE listID = ? AND productID = ?', [listID, productID], (err, existing) => {
        if (err) {
            console.log('ADD ITEM check error:', err.message);
            return res.status(500).json({ error: 'Failed to add item' });
        }

        if (existing.length > 0) {
            const newQty = Math.min(existing[0].quantity + quantity, 99);
            db.query('UPDATE shoppinglistitem SET quantity = ? WHERE listID = ? AND productID = ?', [newQty, listID, productID], (err2) => {
                if (err2) {
                    return res.status(500).json({ error: 'Failed to update item quantity' });
                }
                res.status(200).json({ message: 'Item already on list — quantity updated', productID, quantity: newQty, isDuplicate: true });
            });
        } else {
            const consumerID = userID || req.user.userID;
            db.query('INSERT INTO shoppinglistitem (listID, userID, productID, quantity) VALUES (?, ?, ?, ?)', [listID, consumerID, productID, quantity], (err2) => {
                if (err2) {
                    console.log('ADD ITEM insert error:', err2.message);
                    return res.status(500).json({ error: 'Failed to add item' });
                }
                res.status(201).json({ message: 'Item added to list', productID, quantity, isDuplicate: false });
            });
        }
    });
});

// A500 — Update item quantity
app.put('/api/shopping-list/:listID/items/:productID', authenticateToken, (req, res) => {
    const { listID, productID } = req.params;
    const { quantity } = req.body;

    if (!quantity || quantity < 1 || quantity > 99) {
        return res.status(400).json({ error: 'Quantity must be between 1 and 99' });
    }

    db.query('UPDATE shoppinglistitem SET quantity = ? WHERE listID = ? AND productID = ?', [quantity, listID, productID], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to update quantity' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Item not found on list' });
        }
        res.status(200).json({ message: 'Quantity updated', productID: parseInt(productID), quantity });
    });
});

// A400 — Remove item from list
app.delete('/api/shopping-list/:listID/items/:productID', authenticateToken, (req, res) => {
    const { listID, productID } = req.params;

    db.query('DELETE FROM shoppinglistitem WHERE listID = ? AND productID = ?', [listID, productID], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to remove item' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Item not found on list' });
        }
        res.status(200).json({ message: 'Item removed from list', productID: parseInt(productID) });
    });
});

// A700 — Archive shopping list
app.put('/api/shopping-list/:listID/archive', authenticateToken, (req, res) => {
    const { listID } = req.params;

    db.query('SELECT * FROM shoppinglist WHERE listID = ? AND status = ?', [listID, 'active'], (err, lists) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to archive list' });
        }
        if (lists.length === 0) {
            return res.status(404).json({ error: 'Active list not found' });
        }

        const snapshotQuery = `
            UPDATE shoppinglistitem sli
            SET sli.priceAtArchive = (
                SELECT MIN(ph.price) FROM storeproduct sp
                JOIN pricehistory ph ON sp.storeProductID = ph.storeProductID
                    AND ph.recordedDate = (SELECT MAX(ph2.recordedDate) FROM pricehistory ph2 WHERE ph2.storeProductID = sp.storeProductID)
                WHERE sp.productID = sli.productID AND sp.available = TRUE
            )
            WHERE sli.listID = ?
        `;

        db.query(snapshotQuery, [listID], () => {
            db.query('UPDATE shoppinglist SET status = ?, archivedDate = NOW() WHERE listID = ?', ['archived', listID], (err3) => {
                if (err3) {
                    return res.status(500).json({ error: 'Failed to archive list' });
                }
                res.status(200).json({ message: 'List archived successfully', listID: parseInt(listID), archivedDate: new Date().toISOString() });
            });
        });
    });
});

// A800 — Get archived shopping lists
app.get('/api/user/:userID/shopping-lists/archived', authenticateToken, (req, res) => {
    const { userID } = req.params;
    const { sort, order, days } = req.query;

    let query = `
        SELECT sl.listID, sl.listName, sl.createdDate, sl.archivedDate,
               COUNT(sli.productID) AS itemCount,
               COALESCE(SUM(sli.priceAtArchive * sli.quantity), 0) AS totalCost
        FROM shoppinglist sl
        LEFT JOIN shoppinglistitem sli ON sl.listID = sli.listID
        WHERE sl.consumerID = ? AND sl.status = 'archived'
    `;
    let params = [userID];

    if (days && days !== 'all') {
        query += ` AND sl.archivedDate >= DATE_SUB(NOW(), INTERVAL ? DAY)`;
        params.push(parseInt(days));
    }

    query += ` GROUP BY sl.listID`;

    if (sort === 'cost') {
        query += ` ORDER BY totalCost ${order === 'asc' ? 'ASC' : 'DESC'}`;
    } else {
        query += ` ORDER BY sl.archivedDate ${order === 'asc' ? 'ASC' : 'DESC'}`;
    }

    db.query(query, params, (err, results) => {
        if (err) {
            console.log('ARCHIVED LISTS error:', err.message);
            return res.status(500).json({ error: 'Failed to fetch archived lists' });
        }
        res.status(200).json(results);
    });
});

// A800/A900 — Get list details
app.get('/api/shopping-list/:listID/details', authenticateToken, (req, res) => {
    const { listID } = req.params;

    db.query('SELECT * FROM shoppinglist WHERE listID = ?', [listID], (err, lists) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch list' });
        }
        if (lists.length === 0) {
            return res.status(404).json({ error: 'List not found' });
        }

        const list = lists[0];

        db.query(`
            SELECT sli.productID, p.productName, p.brand, p.typicalUnit,
                   pc.categoryName, sli.quantity, sli.priceAtArchive,
                   MIN(store_latest.price) AS lowestPrice
            FROM shoppinglistitem sli
            JOIN product p ON sli.productID = p.productID
            LEFT JOIN productcategory pc ON p.categoryID = pc.categoryID
            LEFT JOIN (
                SELECT sp.productID, sp.storeID, MAX(latest.price) AS price
                FROM storeproduct sp
                JOIN (
                    SELECT ph.storeProductID, ph.price, ph.recordedDate
                    FROM pricehistory ph
                    INNER JOIN (
                        SELECT storeProductID, MAX(recordedDate) AS maxDate
                        FROM pricehistory
                        GROUP BY storeProductID
                    ) latest_dates
                    ON ph.storeProductID = latest_dates.storeProductID
                    AND ph.recordedDate = latest_dates.maxDate
                ) latest ON sp.storeProductID = latest.storeProductID
                WHERE sp.available = TRUE
                GROUP BY sp.productID, sp.storeID
            ) store_latest ON store_latest.productID = sli.productID
            WHERE sli.listID = ?
            GROUP BY sli.productID, p.productName, p.brand, p.typicalUnit, pc.categoryName, sli.quantity, sli.priceAtArchive
        `, [listID], (err2, items) => {
            if (err2) {
                return res.status(500).json({ error: 'Failed to fetch list items' });
            }

            res.status(200).json({
                listID: list.listID,
                listName: list.listName,
                status: list.status,
                createdDate: list.createdDate,
                archivedDate: list.archivedDate,
                items
            });
        });
    });
});
// A900 — Copy archived list to active
app.post('/api/shopping-list/:listID/copy', authenticateToken, (req, res) => {
    const { listID } = req.params;
    const { mode } = req.body;
    const userID = req.user.userID;

    if (!mode) {
        return res.status(400).json({ error: 'mode is required (replace or merge)' });
    }

    db.query('SELECT * FROM shoppinglist WHERE listID = ? AND status = ?', [listID, 'archived'], (err, source) => {
        if (err || source.length === 0) {
            return res.status(404).json({ error: 'Archived list not found' });
        }

        db.query('SELECT productID, quantity FROM shoppinglistitem WHERE listID = ?', [listID], (err2, items) => {
            if (err2) {
                return res.status(500).json({ error: 'Failed to read archived list items' });
            }

            const processItems = (newListID) => {
                let copiedItems = 0;
                let unavailableItems = [];
                let processed = 0;

                if (items.length === 0) {
                    return res.status(201).json({ message: 'List copied (empty)', newListID, copiedItems: 0, unavailableItems: [] });
                }

                items.forEach((item) => {
                    db.query('SELECT storeProductID FROM storeproduct WHERE productID = ? AND available = TRUE LIMIT 1', [item.productID], (err3, available) => {
                        processed++;

                        if (available && available.length > 0) {
                            db.query('INSERT INTO shoppinglistitem (listID, userID, productID, quantity) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)',
                                [newListID, userID, item.productID, item.quantity]);
                            copiedItems++;
                        } else {
                            db.query('SELECT productName FROM product WHERE productID = ?', [item.productID], (err4, prod) => {
                                unavailableItems.push({
                                    productID: item.productID,
                                    productName: prod && prod[0] ? prod[0].productName : 'Unknown',
                                    reason: 'No longer available at any store'
                                });
                            });
                        }

                        if (processed === items.length) {
                            setTimeout(() => {
                                res.status(201).json({ message: 'List copied to active', newListID, copiedItems, unavailableItems });
                            }, 150);
                        }
                    });
                });
            };

            if (mode === 'replace') {
                db.query('SELECT listID FROM shoppinglist WHERE consumerID = ? AND status = ?', [userID, 'active'], (err3, existing) => {
                    if (existing && existing.length > 0) {
                        db.query('DELETE FROM shoppinglistitem WHERE listID = ?', [existing[0].listID], () => {
                            db.query('DELETE FROM shoppinglist WHERE listID = ?', [existing[0].listID], () => {
                                db.query('INSERT INTO shoppinglist (consumerID, listName, status) VALUES (?, ?, ?)', [userID, 'Copied List', 'active'], (err4, result) => {
                                    if (err4) return res.status(500).json({ error: 'Failed to create new list' });
                                    processItems(result.insertId);
                                });
                            });
                        });
                    } else {
                        db.query('INSERT INTO shoppinglist (consumerID, listName, status) VALUES (?, ?, ?)', [userID, 'Copied List', 'active'], (err4, result) => {
                            if (err4) return res.status(500).json({ error: 'Failed to create new list' });
                            processItems(result.insertId);
                        });
                    }
                });
            } else if (mode === 'merge') {
                db.query('SELECT listID FROM shoppinglist WHERE consumerID = ? AND status = ?', [userID, 'active'], (err3, existing) => {
                    if (existing && existing.length > 0) {
                        processItems(existing[0].listID);
                    } else {
                        db.query('INSERT INTO shoppinglist (consumerID, listName, status) VALUES (?, ?, ?)', [userID, 'Merged List', 'active'], (err4, result) => {
                            if (err4) return res.status(500).json({ error: 'Failed to create new list' });
                            processItems(result.insertId);
                        });
                    }
                });
            } else {
                return res.status(400).json({ error: 'mode must be "replace" or "merge"' });
            }
        });
    });
});

// A1000 — Store summary with list matching
app.get('/api/store/:storeID/summary', authenticateToken, (req, res) => {
    const { storeID } = req.params;
    const { userID } = req.query;

    db.query('SELECT * FROM store WHERE storeID = ?', [storeID], (err, stores) => {
        if (err || stores.length === 0) {
            return res.status(404).json({ error: 'Store not found' });
        }

        const store = stores[0];

        db.query('SELECT COUNT(*) AS productCount FROM storeproduct WHERE storeID = ? AND available = TRUE', [storeID], (err2, countResult) => {
            const productCount = countResult && countResult[0] ? countResult[0].productCount : 0;

            if (userID) {
                db.query(
                    `SELECT COUNT(DISTINCT sli.productID) AS matchingItems
                     FROM shoppinglist sl
                     JOIN shoppinglistitem sli ON sl.listID = sli.listID
                     JOIN storeproduct sp ON sli.productID = sp.productID AND sp.storeID = ? AND sp.available = TRUE
                     WHERE sl.consumerID = ? AND sl.status = 'active'`,
                    [storeID, userID],
                    (err3, matchResult) => {
                        const matchingListItems = matchResult && matchResult[0] ? matchResult[0].matchingItems : 0;
                        res.status(200).json({ ...store, productCount, matchingListItems, distanceKm: null });
                    }
                );
            } else {
                res.status(200).json({ ...store, productCount, matchingListItems: 0, distanceKm: null });
            }
        });
    });
});
>>>>>>> c0afcecf5d8df7f6c33020e85299ad21c2d0ca98

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Better Basket API running on port ${PORT}`);
});
