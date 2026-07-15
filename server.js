require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Middleware
app.use(cors());
app.use(express.json());

// Serve static HTML files
app.use(express.static(path.join(__dirname)));

// Connect to MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/estore';
mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.log('❌ MongoDB Error:', err));

// ==================== SCHEMAS ====================

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
    subcategory: { type: String },
    brand: { type: String },
    image: { type: String, required: true },
    description: { type: String },
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

// ==================== AUTH APIs ====================

// Signup
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword, phone });
        await user.save();
        
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
        
        res.status(201).json({
            message: 'User created',
            token,
            user: { id: user._id, name, email, phone }
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
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
        res.status(500).json({ message: 'Server error' });
    }
});

// Get User Profile
app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== PRODUCT APIs ====================

// Search products (MUST be before /:category to avoid route conflict)
app.get('/api/search', async (req, res) => {
    try {
        const { q } = req.query;
        const products = await Product.find({
            $or: [
                { name: { $regex: q, $options: 'i' } },
                { description: { $regex: q, $options: 'i' } },
                { category: { $regex: q, $options: 'i' } }
            ]
        }).sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Get featured products (MUST be before /:category)
app.get('/api/products/featured', async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: -1 }).limit(8);
        res.json(products);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Get all products
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Get products by category (named route)
app.get('/api/products/category/:category', async (req, res) => {
    try {
        const products = await Product.find({ category: req.params.category }).sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Get products by category (param route - for frontend calls like /api/products/fashion)
app.get('/api/products/:category', async (req, res) => {
    try {
        const products = await Product.find({ category: req.params.category }).sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== CART APIs ====================

app.get('/api/cart', verifyToken, async (req, res) => {
    try {
        const cart = await Cart.findOne({ userId: req.userId }).populate('items.productId');
        if (!cart) return res.json({ items: [], total: 0 });
        
        const total = cart.items.reduce((sum, item) => {
            return sum + (item.productId.price * item.quantity);
        }, 0);
        
        res.json({ items: cart.items, total });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/cart/add', verifyToken, async (req, res) => {
    try {
        const { productId, quantity } = req.body;
        const userId = req.userId;
        
        let cart = await Cart.findOne({ userId });
        if (!cart) cart = new Cart({ userId, items: [] });
        
        const existingItem = cart.items.find(item => 
            item.productId.toString() === productId
        );
        
        if (existingItem) {
            existingItem.quantity += quantity || 1;
        } else {
            cart.items.push({ productId, quantity: quantity || 1 });
        }
        
        await cart.save();
        const cartCount = cart.items.reduce((total, item) => total + item.quantity, 0);
        
        res.json({ message: 'Item added to cart', cartCount });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/cart/count', verifyToken, async (req, res) => {
    try {
        const cart = await Cart.findOne({ userId: req.userId });
        const count = cart ? cart.items.reduce((total, item) => total + item.quantity, 0) : 0;
        res.json({ count });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/cart/update', verifyToken, async (req, res) => {
    try {
        const { itemId, quantity } = req.body;
        const userId = req.userId;
        
        const cart = await Cart.findOne({ userId });
        if (!cart) return res.status(404).json({ message: 'Cart not found' });
        
        const item = cart.items.id(itemId);
        if (!item) return res.status(404).json({ message: 'Item not found' });
        
        if (quantity <= 0) {
            item.remove();
        } else {
            item.quantity = quantity;
        }
        
        await cart.save();
        res.json({ message: 'Cart updated' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/cart/remove/:itemId', verifyToken, async (req, res) => {
    try {
        const { itemId } = req.params;
        const userId = req.userId;
        
        const cart = await Cart.findOne({ userId });
        if (!cart) return res.status(404).json({ message: 'Cart not found' });
        
        cart.items = cart.items.filter(item => item._id.toString() !== itemId);
        await cart.save();
        
        res.json({ message: 'Item removed' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log('========================================');
    console.log('✅ Server Running on http://localhost:' + PORT);
    console.log('========================================');
});
