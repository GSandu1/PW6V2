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
            { expiresIn: '1m' }
        );
        res.json({ token });
    } else {
        res.status(401).send('Invalid credentials');
    }
});

app.get('/protected', authenticateToken, (req, res) => {
    res.send(`Hello, ${req.user.username}`);
});

app.post('/token', (req, res) => {
    const { role } = req.body;

    if (!validRoles.includes(role)) {
        return res.status(400).send('Invalid role');
    }

    const token = jwt.sign(
        { role: role },
        process.env.JWT_SECRET,
        { expiresIn: '1m' } 
    );

    res.json({ token });
});

app.get('/data', authenticateToken, (req, res) => {
    if (req.user.role === 'admin') {
        res.send('You can read/write data.');
    } else if (req.user.role === 'user') {
        res.send('You can read data.');
    } else {
        res.status(403).send('Access Denied');
    }
});


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).send('Your token is expired');
            }
            return res.sendStatus(403); 
        }
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


require('./swagger.js')(app);

/**
 * @openapi
 * /token:
 *   post:
 *     tags:
 *       - Token
 *     summary: Generate a JWT based on role
 *     description: This endpoint generates a new JWT for a given role, which should be either 'user' or 'admin'.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *                 description: The role for which to generate the token. Must be 'user' or 'admin'.
 *                 enum:
 *                   - user
 *                   - admin
 *     responses:
 *       200:
 *         description: Successfully generated JWT
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: The newly generated JWT.
 *       400:
 *         description: Invalid role provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Error message indicating the role is invalid.
 *       401:
 *         description: Authentication required
 *       403:
 *         description: Authorization failure, role not permitted to generate token
 */

/**
 * @openapi
 * /login:
 *   post:
 *     tags:
 *       - Users
 *     summary: Logs in a user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: A JWT token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       401:
 *         description: Invalid credentials
 */

/**
 * @openapi
 * /data:
 *   get:
 *     tags:
 *       - Data
 *     summary: Access user-specific data
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Data view permission based on user role
 *       403:
 *         description: Access denied
 */

/**
 * @openapi
 * /protected:
 *   get:
 *     tags:
 *       - Test
 *     summary: Protected route that requires authentication
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Greeting to the user
 *       401:
 *         description: Authentication required or token is expired
 *       403:
 *         description: Access denied – authorization failure
 */