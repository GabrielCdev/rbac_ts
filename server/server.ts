import express, { NextFunction, Request, Response } from "express";
import mongoose from 'mongoose';
const jwt = require('jsonwebtoken');
const path = require('path');
const User = require('./models/userModel');
const routes = require('./routes/route');

require('dotenv').config({
    path: path.join(__dirname, '../.env')
});

const app = express();
const PORT = process.env.PORT || 3000;

mongoose.connect('mongodb://localhost:27017/rbac_ts').then(() => {
    console.log('Conectado ao banco de dados com sucesso!');
});

app.use(express.urlencoded({ extended: true }));

app.use(async (req: Request, res: Response, next: NextFunction) => {
    if (req.headers['x-access-token']) {
        const accessToken = req.headers['x-access-token'];
        const { userId, exp } = await jwt.verify(accessToken, process.env.JWT_SECRET);

        if (exp < Date.now().valueOf() / 1000) {
            return res.status(401).json({
                error: 'Token JWT expirado, faça o login novamente!'
            });
        }

        res.locals.loggedInUser = await User.findById(userId);

        next();
    } else {
        next();
    }
});

app.use('/', routes);

app.listen(PORT, () => {
    console.log('Server is listening on Port: ', PORT);
});