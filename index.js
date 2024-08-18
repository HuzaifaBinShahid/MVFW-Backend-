const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const userRoutes = require('./routes/userRoutes');
const { User, ChatRoom, Message } = require('./models/User');

const app = express();
const http = require('http');
const server = http.createServer(app);
const socketIo = require('socket.io')(server, {
    cors: {
        origin: 'https://www.mvfw.social/',
        methods: ['GET', 'POST'],
        credentials: true
    }
});

// Middleware
app.use(bodyParser.json());
app.use(cors({
    origin: 'https://www.mvfw.social/',
    methods: ['GET', 'POST'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const sessionSecret = crypto.randomBytes(64).toString('hex');

app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,
        httpOnly: true
    }
}));

socketIo.on('connection', (socket) => {
    console.log('New client connected');
    console.log(socket.id);

    socket.on('joinRoom', async (inviteCode) => {
        console.log('Received inviteCode:', inviteCode);
        if (inviteCode) {
          const room = await ChatRoom.findOne({ inviteCode });
          if (room) {
            socket.join(inviteCode);
            console.log(`User joined room: ${inviteCode}`);
            // Load previous messages and send to the user
            const messages = await Message.find({ inviteCode }).populate('sender');
            console.log(messages,'messages')
            socket.emit('previousMessages', messages);
          } else {
            socket.emit('error', 'Chat room not found');
          }
        } else {
          socket.emit('error', 'Invalid invite code');
        }
    });

    // Handle sending a message
    socket.on('sendMessage', async (data) => {
        const { inviteCode, content, userId, userName } = data;
        console.log(content,'content')
        try {
            // Save the message to the database
            const newMessage = new Message({ inviteCode, userName, content, sender: userId });
            await newMessage.save();

            // Emit the message to the chat room
            socketIo.to(inviteCode).emit('receiveMessage', newMessage);
        } catch (error) {
            console.error('Error saving message:', error);
        }
    });

    // Handle disconnect
    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});


// Routes
app.use('/api/users', userRoutes);

app.use(express.static(path.join(__dirname, 'html-template')));

app.get('/', (req, res) => {
    res.redirect('/signup.html');
});

app.get('/api/users/all', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Error fetching users' });
    }
});

app.post('/api/users/verify/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        user.verified = true;
        await user.save();
        res.json({ message: 'User verified' });
    } catch (error) {
        console.error('Error verifying user:', error);
        res.status(500).json({ message: 'Error verifying user' });
    }
});

app.post('/api/users/create-and-send-invite/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const inviteCode = generateInviteCode();
        user.inviteCodes = inviteCode;
        await user.save();
        res.json({ message: 'Invite email sent successfully', inviteCode });
    } catch (error) {
        console.error('Error creating and sending invite:', error);
        res.status(500).json({ message: 'Error creating and sending invite' });
    }
});

app.post('/verify-invite-code', async (req, res) => {
    try {
        const { inviteCode } = req.body;
        console.log('Received invite code:', inviteCode);

        const user = await User.findOne({ inviteCodes: inviteCode });

        if (!user) {
            console.error('Invalid invite code:', inviteCode);
            return res.status(400).json({ success: false, message: 'Invalid invite code' });
        }

        console.log('Valid invite code:', inviteCode, 'User ID:', user._id);
        res.json({ success: true, chatRoomId: user._id });
    } catch (error) {
        console.error('Error verifying invite code:', error);
        res.status(500).json({ success: false, message: 'Error verifying invite code' });
    }
});


mongoose.connect(process.env.MONGO_URI, {
}).then(() => {
    console.log('Connected to MongoDB');
    server.listen(5000, () => {
        console.log('Server is running on port 5000');
    });
}).catch(err => console.log(err));

function generateInviteCode() {
    return Math.random().toString(36).substr(2, 9);
}
