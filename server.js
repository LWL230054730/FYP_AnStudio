const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken'); // 新增 JWT

const app = express();
const port = process.env.PORT || 3000;

// JWT secret key
const JWT_SECRET = 'your-secret-key'; // 實際使用時應該放喺環境變數

// 設置 MySQL 連接
const db = mysql.createConnection({
    host: 'fyp.ch2yo0q2w1xc.ap-southeast-2.rds.amazonaws.com',
    user: 'admin',
    password: 'Iveisrubbish',
    database: 'fyp'
});

// 連接到數據庫
db.connect(err => {
    if (err) {
        console.error('Database connection failed: ' + err.stack);
        return;
    }
    console.log('Connected to database.');
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 後端 CORS 設定
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Content-Type', 'application/json');
    
    // Handle preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).json({});
    }
    next();
});

// 檢查請求中的 token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Authentication token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// 註冊 API
app.post('/api/register', async (req, res) => {
    try {
        const { userName, firstName, lastName, email, phone, userPw } = req.body;

        // 檢查必填字段
        if (!userName || !firstName || !lastName || !email || !phone || !userPw) {
            return res.status(400).json({ message: 'All fields are required.' });
        }

        // 檢查用戶名是否已存在
        const checkUser = 'SELECT * FROM user WHERE userName = ?';
        db.query(checkUser, [userName], async (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ message: 'Database error occurred.' });
            }

            if (results.length > 0) {
                return res.status(409).json({ message: 'Username already exists.' });
            }

            // 對密碼進行加密
            const hashedPassword = await bcrypt.hash(userPw, 10);

            // 插入新用戶
            const insertUser = 'INSERT INTO user (userName, firstName, lastName, email, phone, userPw) VALUES (?, ?, ?, ?, ?, ?)';
            db.query(insertUser, [userName, firstName, lastName, email, phone, hashedPassword], (error, results) => {
                if (error) {
                    console.error('Database error:', error);
                    return res.status(500).json({ message: 'Registration failed.' });
                }

                // 生成 JWT token
                const token = jwt.sign(
                    { userId: results.insertId, userName: userName },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                res.status(201).json({
                    message: 'Registration successful',
                    token: token,
                    user: {
                        userName: userName,
                        firstName: firstName
                    }
                });
            });
        });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 登入 API
app.post('/api/login', async (req, res) => {
    try {
        console.log('Login request received:', req.body);
        const { userName, userPw } = req.body;

        const query = 'SELECT * FROM user WHERE userName = ?';
        db.query(query, [userName], async (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ message: 'Database error occurred.' });
            }

            console.log('Database results:', results);

            if (results.length === 0) {
                console.log('User not found');
                return res.status(401).json({ message: 'Invalid credentials.' });
            }

            const user = results[0];
            const validPassword = await bcrypt.compare(userPw, user.userPw);
            
            console.log('Password comparison:', {
                provided: userPw,
                stored: user.userPw,
                isValid: validPassword
            });

            if (!validPassword) {
                return res.status(401).json({ message: 'Invalid credentials.' });
            }

            // 生成 JWT token
            const token = jwt.sign(
                { userId: user.id, userName: user.userName },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.status(200).json({
                message: 'Login successful',
                token: token,
                user: {
                    userName: user.userName,
                    firstName: user.firstName
                }
            });
        });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 獲取用戶資料 API (需要認證)
app.get('/api/user/profile', authenticateToken, (req, res) => {
    const query = 'SELECT userName, firstName, lastName, email, phone FROM user WHERE userName = ?';
    db.query(query, [req.user.userName], (error, results) => {
        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({ message: 'Database error occurred.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({ user: results[0] });
    });
});

// 更新用戶資料 API (需要認證)
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { firstName, lastName, email, phone } = req.body;

        // 更新用戶資料
        const query = 'UPDATE user SET firstName = ?, lastName = ?, email = ?, phone = ? WHERE userName = ?';
        db.query(query, [firstName, lastName, email, phone, req.user.userName], (error, results) => {
            if (error) {
                console.error('Database error:', error);
                return res.status(500).json({ message: 'Update failed.' });
            }

            res.status(200).json({ 
                message: 'Profile updated successfully',
                user: {
                    userName: req.user.userName,
                    firstName,
                    lastName,
                    email,
                    phone
                }
            });
        });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ message: 'Server error occurred.' });
    }
});

// 錯誤處理中間件
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// 啟動服務器
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

// 優雅關閉程序
process.on('SIGTERM', () => {
    db.end();
    process.exit(0);
});