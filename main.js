import 'dotenv/config';
import express from 'express';
import { Sequelize } from 'sequelize';
import * as bodyParser from "body-parser";
import * as jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import {expressjwt} from "express-jwt";
import crypto from "crypto";
import * as models from "./models/index.js";
const env = process.env.NODE_ENV || 'production';
import configuration from './config/config.js'
const config = configuration[env]

const sequelize = new Sequelize(config);

sequelize.authenticate().then(() => console.log("connected")).catch((e) => console.error(e));

const app = express();
app.use(bodyParser.default.json());
const port = process.env.PORT || 3000;

app.get('/', (req, res, next) => {
    res.json({message: "Welcome"})
});

app.use(
    expressjwt({
        secret: process.env.JWT_SECRET,
        algorithms: ["HS256"],
    }).unless({ path: ["/login", "/signup", '/'] })
);

app.post('/signup', async (req, res, next) => {
    const { email, password, encryption_key, name } = req.body;
    const modelsObj = await models.default;
    try {
        const emailExists = await modelsObj.User.findOne({attributes: ['id'], where: { email } });
        if (emailExists) {
            res.status(400);
            return res.json({message: "This email already exists", "sys_message": "email_exists"});
        }
        console.log( (await hashStr(password)).length);
        const result = await modelsObj.User.create({
            email, password: await hashStr(password), encryption_key: await hashStr(encryption_key), name
        });
        res.json({message: "Signup is successful"});
    } catch (e) {
        res.status(403);
        res.json({ message: e.message })
    }
});

app.post('/login', async (req, res, next) => {
    const { email, password } = req.body;
    const modelsObj = await models.default;
    try {
        const userRecord = await modelsObj.User.findOne({
            attributes: ['password', 'name', 'id'], where: { email }
        });
        if (!userRecord) {
            res.status(403);
            return res.json({message: "Invalid email or password", "sys_message": "invalid_email_password"});
        }
        const matched = await bcrypt.compare(password, userRecord.password);
        if (matched) {
            const token = jwt.default.sign({user_id: userRecord.id}, process.env.JWT_SECRET,
                {algorithm: "HS256", expiresIn: "1h"}
            );
            res.json({
                messages: "Login is successful", "sys_message": "login_success", token, name: userRecord.name
            });
            return;
        }
        res.status(403);
        res.json({message: "Invalid email or password", "sys_message": "login_failed"});
    } catch (e) {
        res.status(403);
        res.json({ message: e.message })
    }
});

// label, url, username/email, password, password_encryption_key, jwt_token

app.post('/passwords/save', async (req, res, next) => {
    const { url, username, password, encryption_key, label } = req.body;
    const userId = req.auth.user_id;
    const modelsObj = await models.default;
    const userRecord = await modelsObj.User.findOne({
        attributes: ['encryption_key'], where: { id: userId }
    });
    if (!userRecord) {
        res.status(403);
        return res.json({message: 'Unable to find the account'});
    }
    const matched = await bcrypt.compare(encryption_key, userRecord.encryption_key);
    if (!matched) {
        res.status(400);
        return res.json({message: 'Incorrect encryption key'});
    }
    if (!(username && password && url)) {
        res.status(400);
        return res.json({message: 'Missing parameters'});
    }
    const encryptedUsername = encrypt(username, encryption_key);
    const encryptedPassword = encrypt(password, encryption_key);
    const result = await modelsObj.UserPassword.create({
        ownerUserId: userId, password: encryptedPassword, username: encryptedUsername, url, label
    });
    // users_passwords id, owner_user_id, url, username, password, shared_by_user_id, created_at, updated_at
    res.status(200);
    res.json({message: 'Password is saved'});
});

app.post('/passwords/list', async (req, res, next) => {
    const userId = req.auth.user_id;
    const encryptionKey = req.body.encryption_key;
    const modelsObj = await models.default;
    let passwords = await modelsObj.UserPassword.findAll({
        attributes: ['id', 'url', 'username', 'password', 'label', 'weak_encryption'], where: { ownerUserId: userId }
    });
    const userRecord = await modelsObj.User.findOne({
        attributes: ['encryption_key'], where: { id: userId }
    });
    const matched = await bcrypt.compare(encryptionKey, userRecord.encryption_key);
    if (!matched) {
        res.status(400);
        return res.json({message: 'Incorrect encryption key'});
    }
    const passwordsArr = [];
    for (let i = 0; i < passwords.length; i++) {
        const element = passwords[i];
        if (element.weak_encryption) {
            const decryptedPassword = decrypt(element.password, userRecord.encryption_key);// decrypted with encryption key hash
            const decryptedUserName = decrypt(element.username, userRecord.encryption_key);
            element.password = encrypt(decryptedPassword, encryptionKey);// re-encrypted with actual encryption key
            element.username = encrypt(decryptedUserName, encryptionKey);
            element.weak_encryption = false;
            await element.save();// save
        }
        element.password = decrypt(element.password, encryptionKey);
        element.username = decrypt(element.username, encryptionKey);
        passwordsArr.push(element);
    }
    res.status(200);
    res.json({message: 'Success', data: passwordsArr});
});

app.post('/passwords/share-password', async (req, res, next) => {
    try {
        const {password_id, encryption_key, email} = req.body;
        const userId = req.auth.user_id;
        const modelsObj = await models.default;
        const passwordRow = await modelsObj.UserPassword.findOne({
            attributes: ['label', 'url', 'username', 'password'], where: { id: password_id, ownerUserId: userId}
        });
        if (!passwordRow) {
            res.status(400);
            return res.json({message: 'Incorrect password_id'});
        }
        const userRecord = await modelsObj.User.findOne({
            attributes: ['encryption_key'], where: { id: userId }
        });
        const matched = await bcrypt.compare(encryption_key, userRecord.encryption_key);
        if (!matched) {
            res.status(400);
            return res.json({message: 'Incorrect encryption key'});
        }
        const shareUserObj = await modelsObj.User.findOne({attributes: ['id', 'encryption_key'], where: { email } });
        if (!shareUserObj) {
            res.status(400);
            return res.json({message: 'User with whom you want to share password does not exist'});
        }
        const existingSharedPassword = await modelsObj.UserPassword.findOne({
            attributes: ['id'], where: { source_password_id: password_id, ownerUserId: shareUserObj.id}
        });
        if (existingSharedPassword) {
            res.status(400);
            return res.json({message: `This password is already shared with the user`});
        }
        const decryptedUserName = decrypt(passwordRow.username, encryption_key);
        const encryptedSharedUserName = encrypt(decryptedUserName, shareUserObj.encryption_key);// encrypting with hash of share user encryption key
        const decryptedPassword = decrypt(passwordRow.password, encryption_key);
        const encryptedSharedPassword = encrypt(decryptedPassword, shareUserObj.encryption_key);
        const newPassword = {
            ownerUserId: shareUserObj.id,
            label: passwordRow.label,
            url: passwordRow.url,
            username: encryptedSharedUserName,
            password: encryptedSharedPassword,
            sharedByUserId: userId,
            weak_encryption: true,
            source_password_id: password_id
        };
        await modelsObj.UserPassword.create(newPassword);
        return res.json({message: 'Password shared successfully'});
    } catch (e) {
        console.error(e);
        res.status(500);
        // todo log error in logging library.
        return res.json({message: 'An error occurred.'})
    }
});

//  jwt({ secret: process.env.JWT_SECRET, algorithms: ["HS256"]})
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

async function hashStr(str) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(str, salt);
}

function encrypt(unenrypted_string, key) {
    const algorithm = 'aes-256-ctr';
    const iv = crypto.randomBytes(16);
    const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32)
    const cipher = crypto.createCipheriv(algorithm, encKey, iv);
    let crypted = cipher.update(unenrypted_string,'utf-8',"base64") + cipher.final("base64");
    return `${crypted}-${iv.toString('base64')}`;
}

function decrypt(encStr, key) {
    const algorithm = 'aes-256-ctr';
    const encArr = encStr.split('-');
    const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
    const decipher = crypto.createDecipheriv(algorithm, encKey, Buffer.from(encArr[1], 'base64'));
    let decrypted = decipher.update(encArr[0], 'base64', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}