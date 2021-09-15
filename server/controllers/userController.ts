const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
import { Request, Response, NextFunction } from 'express';
import { roles } from '../roles';

async function hashPassword(password: String) {
    return await bcrypt.hash(password, 10)
}

async function validatePassword(plainPassword: String, hashedPassword: String) {
    return await bcrypt.compare(plainPassword, hashedPassword);
}

export async function signup(req: Request, res: Response, next: NextFunction) {
    try {
        const { login, password, role } = req.body;
        const hashedPassword = await hashPassword(password);
        const newUser = new User({ login, password: hashedPassword, role: role || 'operador' });
        const accessToken = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, {
            expiresIn: '1d'
        });

        newUser.accessToken = accessToken;

        await newUser.save();

        res.json({
            data: newUser,
            accessToken
        })
    } catch (error) {
        next(error);
    }
}

export async function login(req: Request, res: Response, next: NextFunction) {
    try {
        const { login, password } = req.body;
        const user = await User.findOne({ login });
        if (!user) return next(new Error('Nome de usuário incorreto!'));

        const validPassword = await validatePassword(password, user.password);
        if (!validPassword) return next(new Error('Senha incorreta!'));

        const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
            expiresIn: '1d'
        });

        await User.findByIdAndUpdate(user._id, { accessToken })

        res.status(200).json({
            data: { login: user.login, role: user.role },
            accessToken
        })
    } catch (error) {
        next(error);
    }
}

export async function getUsers(req: Request, res: Response, next: NextFunction) {
    const users = await User.find({});

    res.status(200).json({
        data: users
    });
}

export async function getUser(req: Request, res: Response, next: NextFunction) {
    try {
        const userId = req.params.userId;
        const user = await User.findById(userId);

        if (!user) return next(new Error('Usuário inexistente!'));

        res.status(200).json({
            data: user
        });
    } catch (error) {
        next(error);
    }
}

export async function updateUser(req: Request, res: Response, next: NextFunction) {
    try {
        const update = req.body;
        const userId = req.params.userId;

        await User.findByIdAndUpdate(userId, update);

        const user = await User.findById(userId);

        res.status(200).json({
            data: user,
            message: 'O usuário foi atualizado!'
        });
    } catch (error) {
        next(error);
    }
}

export async function deleteUser(req: Request, res: Response, next: NextFunction) {
    try {
        const userId = req.params.userId;

        await User.findByIdAndDelete(userId);

        res.status(200).json({
            data: null,
            message: 'O usuário foi deletado'
        });
    } catch (error) {
        next(error);
    }
}

export function grantAccess(action: any, resource: any) {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            const permission = roles.can(req.user.role)[action](resource);

            if (!permission.granted) {
                return res.status(401).json({
                    error: 'Você não tem permissão para esta ação!'
                });
            }
            next();
        } catch (error) {
            next(error);
        }
    }
}

export async function allowIfLoggedIn(req: Request, res: Response, next: NextFunction) {
    try {
        const user = res.locals.loggedInUser

        if (!user)
            return res.status(401).json({
                error: 'Você precisa estar logado para acessar!'
            });

        req.user = user;
        next();
    } catch (error) {
        next(error);
    }
}
