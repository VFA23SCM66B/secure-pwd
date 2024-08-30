import 'dotenv/config';
import express from 'express';
import { Sequelize } from 'sequelize';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { expressjwt } from 'express-jwt';
import crypto from 'crypto';
import configOptions from './config/config.js';
import nodemailer from 'nodemailer';
import rateLimit from 'express-rate-limit';
import initializeModels from './models/index.js';

const db = await initializeModels();
const { User, UserPassword, SharedPassword } = db;
const app = express();
const environment = process.env.NODE_ENV || 'production';
const config = configOptions[environment];
const sequelize = new Sequelize(config);

// Database connection
sequelize.authenticate()
    .then(() => console.log('Database connection successful'))
    .catch((err) => console.error('Database connection failed:', err));

app.use(bodyParser.json());
const port = process.env.PORT || 3000;

// Default route
app.get('/', (req, res) => {
    res.json({ message: 'Welcome to the application' });
});

// JWT middleware
app.use(
    expressjwt({
        secret: process.env.JWT_SECRET,
        algorithms: ['HS256'],
    }).unless({ path: ['/login', '/signup', '/'] })
);

// Signup API
app.post('/signup', async (req, res) => {
    const { name, email, encryption_key, password } = req.body;

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(409).json({ error: 'Email is already registered.' });
        }

        // Hash the password and encryption key
        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedEncryptionKey = await bcrypt.hash(encryption_key, 10);

        // Create and save the new user
        const newUser = await User.create({
            name,
            email,
            password: hashedPassword,
            encryption_key: hashedEncryptionKey,
        });

        // Respond with success message and user data
        return res.status(201).json({
            message: 'User successfully registered.',
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                createdAt: newUser.createdAt,
                updatedAt: newUser.updatedAt,
            },
        });
    } catch (error) {
        console.error('Error during user registration:', error);
        return res.status(500).json({
            error: 'An error occurred while registering the user. Please try again later.',
        });
    }
});

// Login API
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if the user exists
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(404).json({ error: 'User not found. Please sign up.' });
        }

        // Compare the provided password with the stored hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid password. Please try again.' });
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                id: user.id,
                name: user.name,
                email: user.email,
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        // Respond with the token and a success message
        return res.status(200).json({
            message: `Hi ${user.name}, you have successfully logged in.`,
            sysMessage: `Welcome back, ${user.name}!`,
            name:user.name,
            token: token,
        });
    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).json({
            error: 'An error occurred during login. Please try again later.',
        });
    }
});
// label, url, username/email, password, password_encryption_key, jwt_token
// Password Save API
app.post('/passwords/save', async (req, res) => {
    const { url, username, password, encryption_key, label } = req.body;
    try {
        // Validate required fields
        if (!url || !username || !password || !encryption_key || !label) {
            return res.status(400).json({
                error: 'All fields (url, username, password, encryption_key, label) are required.',
            });
        }

        // Extract user ID from JWT token (assuming the user is authenticated)
        const token = req.headers.authorization.split(' ')[1];
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decodedToken.id;

        // Get the user record based on user ID
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Validate the encryption key
        const isEncryptionKeyValid = await bcrypt.compare(encryption_key, user.encryption_key);
        if (!isEncryptionKeyValid) {
            return res.status(401).json({ error: 'Invalid encryption key.' });
        }

        // Encrypt the username and password with the provided encryption key using AES-256-GCM
        const encryptedUsername = encryptData(username, encryption_key);
        const encryptedPassword = encryptData(password, encryption_key);

        // Save the encrypted credentials and other details in the database
        const savedPassword = await UserPassword.create({
            userId,
            url,
            username: encryptedUsername,
            password: encryptedPassword,
            label,
        });

        return res.status(201).json({
            message: 'Password saved successfully.',
            savedPassword,
        });
    } catch (error) {
        console.error('Error saving password:', error);
        return res.status(500).json({
            error: 'An error occurred while saving the password. Please try again later.',
        });
    }
});
// Middleware to check for JWT token
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authorization token is missing.' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token.' });
        req.user = user; // Attach user to request
        next();
    });
};
// Password List API
app.get('/passwords/list', authenticateToken, async (req, res) => {
    const { encryption_key } = req.body;

    if (!encryption_key) {
        return res.status(400).json({ error: 'Encryption key is required.' });
    }

    try {
        const userId = req.user.id;

        // Retrieve the user record based on user ID
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Validate the provided encryption key
        const isEncryptionKeyValid = await bcrypt.compare(encryption_key, user.encryption_key);
        if (!isEncryptionKeyValid) {
            return res.status(400).json({ error: 'Incorrect encryption key.' });
        }

        // Retrieve password records for the authenticated user
        const userPasswords = await UserPassword.findAll({
            where: { userId },
        });

        // Process and decrypt passwords
        const passwordsArr = await Promise.all(userPasswords.map(async (record) => {
            let decryptedUsername, decryptedPassword;

                // Decrypt with the new key
                decryptedUsername = decryptData(record.username, encryption_key);
                decryptedPassword = decryptData(record.password, encryption_key);
            

            // // Check expiry date
            // const isExpired = record.expiry_date && new Date() > new Date(record.expiry_date);

            return {
                id:record.id,
                url: record.url,
                username: decryptedUsername,
                password: decryptedPassword,
                label: record.label,
            };
        }));

        return res.status(200).json({
            message: 'Passwords retrieved successfully.',
            passwords: passwordsArr,
        });
    } catch (error) {
        console.error('Error retrieving passwords:', error);
        return res.status(500).json({
            error: 'An error occurred while retrieving the passwords. Please try again later.',
        });
    }
});
// Rate limit for sharing passwords
const sharePasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 5 requests per windowMs
    message: 'Too many password share requests from this IP, please try again later.',
});
app.post('/passwords/share-password', authenticateToken, sharePasswordLimiter, async (req, res) => {
    const { password_id, encryption_key, email, expiry_date } = req.body;

    if (!password_id || !encryption_key || !email || !expiry_date) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const userId = req.user.id;

        // Fetch the password record
        const passwordRecord = await UserPassword.findOne({
            where: { id: password_id, userId },
        });
        
        if (!passwordRecord) {
            return res.status(400).json({ error: 'Incorrect password_id.' });
        }
        
        // if (passwordRecord.expiry_date && new Date() > new Date(passwordRecord.expiry_date)) {
        //     return res.status(400).json({ error: 'This password has already expired and cannot be shared.' });
        // }
        // Verify encryption key
        const user = await User.findByPk(userId);
        const isEncryptionKeyValid = await bcrypt.compare(encryption_key, user.encryption_key);
        if (!isEncryptionKeyValid) {
            return res.status(400).json({ error: 'Incorrect encryption key.' });
        }

        // Find recipient user
        const recipientUser = await User.findOne({ where: { email } });
        if (!recipientUser) {
            return res.status(404).json({ error: 'Recipient user not found.' });
        }
        // // Check if the recipient is the original owner or the one who shared the password
        // if (passwordRecord.userId === recipientUser.id || passwordRecord.sharedByUserId === recipientUser.id) {
        //     return res.status(400).json({ error: 'You cannot share the password back to yourself.' });
        // }

        const existingSharedPassword = await SharedPassword.findOne({
            where: {
                ownerUserId: recipientUser.id,
                sharedByUserId: userId,
                source_password_id: password_id,
            },
        });
        // if (passwordRecord.expiry_date && new Date() > new Date(passwordRecord.expiry_date)) {
        //     return res.status(400).json({ error: 'This password has already expired and cannot be shared.' });
        // }
        //const isExpired = existingSharedPassword.expiry_date && new Date() > new Date(existingSharedPassword.expiry_date);
        if (existingSharedPassword) {
            const isExpired = existingSharedPassword.expiry_date && new Date() > new Date(existingSharedPassword.expiry_date);
            if(!isExpired){
                return res.status(200).json({ message: 'This password has already been shared with the recipient.' });
            }
            
        }

        // Decrypt password for sharing
        const decryptedUsername = decryptData(passwordRecord.username, encryption_key);
        const decryptedPassword = decryptData(passwordRecord.password, encryption_key);

        // Encrypt password for recipient
        const encryptedUsername = encryptData(decryptedUsername, recipientUser.encryption_key);
        const encryptedPassword = encryptData(decryptedPassword, recipientUser.encryption_key);

        // Save shared password record
        const sharedPassword = await SharedPassword.create({
            ownerUserId: recipientUser.id,
            label: passwordRecord.label,
            url: passwordRecord.url,
            username: encryptedUsername,
            password: encryptedPassword,
            sharedByUserId: userId,
            weak_encryption: true,
            source_password_id: password_id,
            expiry_date: expiry_date ? new Date(expiry_date) : null,
        });

        return res.status(200).json({ message: 'Password shared successfully.' });
    } catch (error) {
        console.error('Error sharing password:', error);
        return res.status(500).json({
            error: 'An error occurred while sharing the password. Please try again later.',
        });
    }
});
app.get('/shared-passwords/list', authenticateToken, async (req, res) => {
    const { encryption_key } = req.body;

    if (!encryption_key) {
        return res.status(400).json({ error: 'Encryption key is required.' });
    }

    try {
        const userId = req.user.id;

        // Retrieve the user record based on user ID
        const user = await User.findByPk(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Validate the provided encryption key
        const isEncryptionKeyValid = await bcrypt.compare(encryption_key, user.encryption_key);
        if (!isEncryptionKeyValid) {
            return res.status(400).json({ error: 'Incorrect encryption key.' });
        }

        // Retrieve shared password records where the user is the owner
        const sharedPasswords = await SharedPassword.findAll({
            where: { ownerUserId: userId },
        });

        // Process and decrypt shared passwords
        const sharedPasswordsArr = sharedPasswords.map(record => {
            // Decrypt with the provided encryption key
            const decryptedUsername = decryptData(record.username, user.encryption_key);
            const decryptedPassword = decryptData(record.password, user.encryption_key);

            // Check expiry date
            const isExpired = record.expiry_date && new Date() > new Date(record.expiry_date);
            console.log(isExpired);
            return {
                id: record.id,
                url: record.url,
                username: decryptedUsername,
                password: decryptedPassword,
                label: record.label,
                isExpired,
            };
        });

        return res.status(200).json({
            message: 'Shared passwords retrieved successfully.',
            sharedPasswords: sharedPasswordsArr,
        });
    } catch (error) {
        console.error('Error retrieving shared passwords:', error);
        return res.status(500).json({
            error: 'An error occurred while retrieving shared passwords. Please try again later.',
        });
    }
});


// Helper function to encrypt data using AES-256-GCM
const encryptData = (text, encryptionKey) => {
    const iv = crypto.randomBytes(12); // Initialization vector
    const cipher = crypto.createCipheriv('aes-256-gcm', crypto.createHash('sha256').update(encryptionKey).digest(), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
};

// Helper function to decrypt data using AES-256-GCM
const decryptData = (encryptedData, encryptionKey) => {
    const [iv, authTag, encrypted] = encryptedData.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', crypto.createHash('sha256').update(encryptionKey).digest(), Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};
// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});