const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const users = [
    { username: 'user', password: 'user', role: 'user' },
    { username: 'admin', password: 'admin', role: 'admin' }
];


  const validRoles = ['user', 'admin'];

  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).send('User not found');
    }
    if (user.password === password) {
        const token = jwt.sign(
            { username: user.username, role: user.role }, 
            process.env.JWT_SECRET,
            { expiresIn: '10m' }
        );
        res.json({ token });
    } else {
        res.status(401).send('Invalid credentials');
    }
});

app.post('/token', (req, res) => {
    const { role } = req.body;

    if (!validRoles.includes(role)) {
        return res.status(400).send('Invalid role');
    }

    const token = jwt.sign(
        { role: role },
        process.env.JWT_SECRET,
        { expiresIn: '10m' } 
    );

    res.json({ token });
});


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function authenticateAdmin(req, res, next) {
    authenticateToken(req, res, () => {
        if (req.user.role !== 'admin') {
            return res.sendStatus(403);
        }
        next();
    });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});