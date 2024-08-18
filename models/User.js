const mongoose = require('mongoose');
const { Schema } = mongoose;

const userSchema = new Schema({
    name: { type: String, required: true },
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    category: { type: String, required: true },
    otp: String,
    otpExpires: Date,
    inviteCode: String,
    verified: { type: Boolean, default: false },
    inviteCodes: { type: Number, default: 0 },
    chatRoomId: { type: mongoose.Schema.Types.ObjectId, ref: 'ChatRoom' },
    blocked: {
        type: Boolean,
        default: false
    }
});

const ChatRoomSchema = new mongoose.Schema({
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], 
    inviteCode: { type: String, unique: true, required: true }
});


const messageSchema = new mongoose.Schema({
    content: { type: String, required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    inviteCode: { type: String, required: true },
    userName: {type: String, required: true},
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const ChatRoom = mongoose.model('ChatRoom', ChatRoomSchema);
const Message = mongoose.model('Message', messageSchema);

module.exports = { User, ChatRoom, Message };
