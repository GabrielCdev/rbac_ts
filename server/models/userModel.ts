import mongoose from "mongoose";

const { Schema } = mongoose;

const UserSchema = new Schema({
    login: {
        type: String,
        required: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        default: 'operador',
        enum: ['operador', 'supervisor', 'admin']
    },
    accessToken: {
        type: String
    }
});

export const User = mongoose.model('user', UserSchema);
