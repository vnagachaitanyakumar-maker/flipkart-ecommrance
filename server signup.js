require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Middleware
app.use(cors());
app.use(express.json());

// ==================== CLOUDINARY CONFIG ====================
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'estore_products',
        allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
        transformation: [{ width: 800, height: 800, crop: 'limit' }]
    }
});
const upload = multer({ storage: storage });

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/estore';

mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.log('❌ MongoDB Error:', err));

// ==================== MYSQL CONNECTION ====================
const mysqlConfig = {
    host: process.env.MYSQL_HOST || 'localhost',
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database: process.env.MYSQL_DATABASE || 'estore',
    waitForConnections: true,
    connectionLimit: 10
};

let mysqlPool;

async function initializeMySQL() {
    try {
        mysqlPool = mysql.createPool(mysqlConfig);
        
        // Create MySQL tables
        await mysqlPool.execute(`
            CREATE TABLE IF NOT EXISTS users_mysql (
                id INT AUTO_INCREMENT PRIMARY KEY,
                mongodb_id VARCHAR(255),
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                phone VARCHAR(20),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await mysqlPool.execute(`
            CREATE TABLE IF NOT EXISTS products_mysql (
                id INT AUTO_INCREMENT PRIMARY KEY,
                mongodb_id VARCHAR(255),
                name VARCHAR(255) NOT NULL,
                price DECIMAL(10,2) NOT NULL,
                category VARCHAR(100) NOT NULL,
                image VARCHAR(500),
                stock INT DEFAULT 10,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await mysqlPool.execute(`
            CREATE TABLE IF NOT EXISTS orders_mysql (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                total DECIMAL(10,2) NOT NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        console.log('✅ MySQL Connected & Tables Created');
    } catch (err) {
        console.error('❌ MySQL Error:', err);
    }
}

initializeMySQL();

// ==================== MONGODB SCHEMAS ====================
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    category: { type: String, required: true },
    image: { type: String, required: true },
    stock: { type: Number, default: 10 },
    createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', productSchema);

const cartSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [{
        productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
        quantity: { type: Number, required: true, default: 1 },
        addedAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
});
const Cart = mongoose.model('Cart', cartSchema);

// ==================== JWT MIDDLEWARE ====================
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// ==================== AUTH APIs (Dual Storage) ====================
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        
        // Check MongoDB
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'Email already registered' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Save to MongoDB
        const user = new User({ name, email, password: hashedPassword, phone });
        await user.save();
        
        // Save to MySQL (dual storage)
        await mysqlPool.execute(
            'INSERT INTO users_mysql (mongodb_id, name, email, password, phone) VALUES (?, ?, ?, ?, ?)',
            [user._id.toString(), name, email, hashedPassword, phone]
        );
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
        
        res.status(201).json({
            message: 'User created in both databases',
            token,
            user: { id: user._id, name, email, phone }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Check MongoDB
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ message: 'Invalid credentials' });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({
            message: 'Login successful',
            token,
            user: { id: user._id, name: user.name, email: user.email, phone: user.phone }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== PRODUCT APIs (Dual Storage) ====================
app.post('/api/products', verifyToken, upload.single('image'), async (req, res) => {
    try {
        const { name, price, category, stock } = req.body;
        const image = req.file ? req.file.path : '';
        
        // Save to MongoDB
        const product = new Product({ name, price, category, image, stock });
        await product.save();
        
        // Save to MySQL (dual storage)
        await mysqlPool.execute(
            'INSERT INTO products_mysql (mongodb_id, name, price, category, image, stock) VALUES (?, ?, ?, ?, ?, ?)',
            [product._id.toString(), name, price, category, image, stock]
        );
        
        res.status(201).json({
            message: 'Product created in both databases',
            product
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/products/category/:category', async (req, res) => {
    try {
        const products = await Product.find({ category: req.params.category }).sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== CART APIs (MongoDB) ====================
app.get('/api/cart', verifyToken, async (req, res) => {
    try {
        const cart = await Cart.findOne({ userId: req.userId }).populate('items.productId');
        if (!cart) return res.json({ items: [], total: 0 });
        
        const total = cart.items.reduce((sum, item) => sum + (item.productId?.price * item.quantity), 0);
        res.json({ items: cart.items, total });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/cart/add', verifyToken, async (req, res) => {
    try {
        const { productId, quantity } = req.body;
        let cart = await Cart.findOne({ userId: req.userId });
        if (!cart) cart = new Cart({ userId: req.userId, items: [] });
        
        const existingItem = cart.items.find(item => item.productId.toString() === productId);
        if (existingItem) {
            existingItem.quantity += quantity || 1;
        } else {
            cart.items.push({ productId, quantity: quantity || 1 });
        }
        
        await cart.save();
        res.json({ message: 'Item added to cart' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== ORDER APIs (MySQL) ====================
app.post('/api/orders', verifyToken, async (req, res) => {
    try {
        const { total } = req.body;
        
        // Save order to MySQL
        const [result] = await mysqlPool.execute(
            'INSERT INTO orders_mysql (user_id, total, status) VALUES (?, ?, ?)',
            [req.userId, total, 'Pending']
        );
        
        res.status(201).json({
            message: 'Order created in MySQL',
            orderId: result.insertId
        });
    } catch (error) {
        console.error('Order error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/orders', verifyToken, async (req, res) => {
    try {
        const [orders] = await mysqlPool.execute(
            'SELECT * FROM orders_mysql WHERE user_id = ? ORDER BY created_at DESC',
            [req.userId]
        );
        res.json(orders);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
    console.log('========================================');
    console.log('☁️  DUAL DATABASE SERVER RUNNING');
    console.log(`📡 URL: http://localhost:${PORT}`);
    console.log('🗄️  Databases Connected:');
    console.log('   ✅ MongoDB (Users, Products, Cart)');
    console.log('   ✅ MySQL (Users, Products, Orders)');
    console.log('   ✅ Cloudinary (Image Storage)');
    console.log('========================================');
});