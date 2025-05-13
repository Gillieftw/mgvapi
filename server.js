require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key';

// Dummy user data (replace with a database in production)
const users = [
  {
    id: 1,
    username: 'testuser',
    password: '$2b$12$5O4zwmm4qKf4KJfRgFn/1OL95XqnfLB7QTc93QiAKBYRVGuqT9r/W', // Hashed password for "password123"
    role: 'tester'
  },
  {
    id: 2,
    username: 'testadmin',
    password: '$2b$12$5O4zwmm4qKf4KJfRgFn/1OL95XqnfLB7QTc93QiAKBYRVGuqT9r/W', // Hashed password for "password123"
    role: 'admin'
  }
];

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
  res.json({
    token,
    username: user.username,
    role: user.role
  });
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token is missing' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}!`, user: req.user });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Auth API running at http://localhost:${PORT}`);
});

