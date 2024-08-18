const express = require('express');
const router = express.Router();
const { User, ChatRoom, Message } = require('../models/User');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { createAuthorizationToken, verifyToken, isAdmin } = require('../middleware/authMiddleware');



// Register Route
router.post('/signup', async (req, res) => {
    const { name, username, email, password, category } = req.body;
    try {
        // Check if username already exists
        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Check if email already exists
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ error: 'Email already in use' });
        }

        // Check if category is 'admin' and if there's already an admin user
        if (category === 'admin') {
            const existingAdmin = await User.findOne({ category: 'admin' });
            if (existingAdmin) {
                return res.status(400).json({ error: 'Admin already exists' });
            }
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = new User({
            name,
            username,
            email,
            password: hashedPassword,
            category
        });

        // Save user to database
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// Route to check if username exists
router.get('/username/:username', async (req, res) => {
    const username = req.params.username;
    try {
        const user = await User.findOne({ username });
        if (user) {
            res.json({ exists: true });
        } else {
            res.json({ exists: false });
        }
    } catch (error) {
        console.error('Error checking username:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to check if email exists and send OTP
router.get('/email/:email', async (req, res) => {
    const email = req.params.email;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'Email does not exist' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Save OTP in user's record or in a separate OTP collection if needed
        user.otp = otp;
        await user.save();

        // Send OTP to user's email
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            secure: true,
            port: 465,
            auth: {
                user: "shuzaifa222@gmail.com",
                pass: "dodmgdjhwwxdffej",
            },
        });

        const mailOptions = {
            from: "shuzaifa222@gmail.com",
            to: email,
            subject: "Your OTP Code",
            text: `Your OTP code is ${otp}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending OTP email:', error);
                return res.status(500).json({ error: 'Failed to send OTP. Please try again later.' });
            } else {
                console.log('OTP email sent:', info.response);
                return res.status(200).json({ message: 'OTP sent successfully' });
            }
        });
    } catch (error) {
        console.error('Error checking email:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Route to check if admin user exists
router.get('/admin', async (req, res) => {
    try {
        const adminUser = await User.findOne({ category: 'admin' });
        if (adminUser) {
            res.json({ exists: true });
        } else {
            res.json({ exists: false });
        }
    } catch (error) {
        console.error('Error checking admin user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Login Route
router.post('/login', async (req, res) => {
    const { email, password, category } = req.body;

    try {
        // Find the user by email and category
        const user = await User.findOne({ email, category });

        if (!user) {
            return res.status(400).json({ error: 'Invalid email, password, or category.' });
        }

        // Check the password
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid email, password, or category.' });
        }

        // Check if user is blocked
        if (user.blocked) {
            return res.status(403).json({ error: 'User blocked' });
        }

        const token = createAuthorizationToken(user);

        // Successful login
        res.status(200).json({ message: 'Login successful!', user, token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});



// Route to get user data based on session
router.get('/profile', verifyToken, async (req, res) => {
    try {
        const userId = req.query.userId;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// Logout route
router.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Failed to log out' });
        }
        res.status(200).json({ message: 'Logged out successfully' });
    });
});;

// Get all users
router.get('/all', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});


// Route to verify admin password
router.post('/verify-password', async (req, res) => {
    const { password } = req.body;

    try {
        // Find user with category 'admin'
        const adminUser = await User.findOne({
            category: 'admin'
        });

        if (adminUser) {
            // Compare hashed password
            const passwordMatch = await bcrypt.compare(password, adminUser.password);

            if (passwordMatch) {
                res.status(200).json({ success: true });
            } else {
                res.status(401).json({ error: 'Incorrect password' });
            }
        } else {
            res.status(404).json({ error: 'Admin not found' });
        }
    } catch (err) {
        console.error('Error verifying admin password:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});



// Verify user endpoint
router.post('/verify/:id', verifyToken, isAdmin, async (req, res) => {
    const userId = req.params.id;

    try {
        const updatedUser = await User.findByIdAndUpdate(userId, { verified: true }, { new: true });
        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ message: 'User verified successfully', user: updatedUser });
    } catch (error) {
        console.error('Error verifying user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Fetch all users with their invite codes
router.get('/all', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users', error });
    }
});

// Block/unblock user route
router.post('/block/:userId', async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).send({ message: 'User not found' });

        user.blocked = !user.blocked; // Toggle blocked status
        await user.save(); // Save updated user status to the database

        res.json({ success: true, message: `User ${user.blocked ? 'blocked' : 'unblocked'}` });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});


// Fetch all blocked users
router.get('/blocked', async (req, res) => {
    try {
        const blockedUsers = await User.find({ blocked: true });
        res.json(blockedUsers);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// Fetch users with invite codes count
router.get('/with-invite-codes', async (req, res) => {
    try {
        const usersWithInviteCodes = await User.find({}, 'name username email category inviteCodes');
        res.json(usersWithInviteCodes);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users with invite codes', error });
    }
});


// Route to create a chat room and send invite
router.post('/create-and-send-invite/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        // Generate invite code
        const inviteCode = uuidv4();

        // Update user's record with invite code
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Save invite code to user's record
        user.inviteCode = inviteCode;
        user.inviteCodes = (user.inviteCodes || 0) + 1; // Increment inviteCodes
        await user.save();

        console.log("invite code is: ", inviteCode);

        // Function to send invite email
        const sendInviteEmail = async (email, inviteCode) => {
            try {
                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: "shuzaifa222@gmail.com",
                        pass: "dodmgdjhwwxdffej"
                    },
                });

                const mailOptions = {
                    from: "shuzaifa222@gmail.com",
                    to: email,
                    subject: 'Invitation to Chat Room',
                    text: `You have been invited to a chat room. Use this invite code to join: ${inviteCode}`,
                };

                const info = await transporter.sendMail(mailOptions);
                console.log('Invite email sent:', info.response);
                return true;
            } catch (error) {
                console.error('Error sending invite email:', error);
                return false;
            }
        };

        // Send invite email
        const emailSent = await sendInviteEmail(user.email, inviteCode);
        if (emailSent) {
            //Chat room creating the same time,
            console.log(user,'user')
            const chatRoom = new ChatRoom({
                participants: [user._id], // Add the user to the chat room participants
                inviteCode: inviteCode
            });
            await chatRoom.save();
            res.status(200).json({ message: 'Invite created and sent successfully', inviteCode });
        } else {
            res.status(500).json({ error: 'Failed to send invite email' });
        }
    } catch (error) {
        console.error('Error creating and sending invite:', error);
        res.status(500).json({ error: 'Failed to create and send invite' });
    }
});

router.delete('/end-chat/:inviteCode', async (req, res) => {
    const { inviteCode } = req.params;

    try {
        // Remove inviteCode from users
        await User.updateMany({ inviteCode }, { $unset: { inviteCode: "" } });

        // Delete chat room
        await ChatRoom.deleteOne({ inviteCode });

        // Delete all messages
        await Message.deleteMany({ inviteCode });

        res.status(200).json({ message: 'Chat room ended successfully', ok: true });
    } catch (error) {
        console.error(error,'error');
        res.status(500).json({ error: 'An error occurred while ending the chat room' });
    }
});




// Route to create a chat room and send invite
router.post('/create-chat-room/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Create a chat room
        const chatRoom = new ChatRoom({
            participants: [user._id], // Add the user to the chat room participants
            inviteCode: user.inviteCode
        });
        await chatRoom.save();

        // Save chat room ID to user's record
        user.chatRoomId = chatRoom._id;
        await user.save();

        console.log('Chat room created with ID:', chatRoom._id);

        res.status(200).json({ message: 'Chat room created successfully', chatRoomId: chatRoom._id });
    } catch (error) {
        console.error('Error creating chat room:', error);
        res.status(500).json({ error: 'Failed to create chat room' });
    }
});


// Fetch messages for a specific chat room
router.get('/:chatRoomId/messages', async (req, res) => {
    const { chatRoomId } = req.params;

    try {
        const messages = await Message.find({ chatRoom: chatRoomId })
            .populate('sender', 'name'); // Populate sender details if needed

        res.json(messages);
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: 'Error fetching messages' });
    }
});


router.post('/join-room', async (req, res) => {
    console.log("Received join-room request");
    const { userId, inviteCode } = req.body;

    console.log('Request received with data:', req.body);

    if (!userId || !inviteCode) {
        console.log('User ID or invite code is missing');
        return res.status(400).json({ error: 'User ID and invite code are required' });
    }

    try {
        // Find the user by userId
        const user = await User.findById(userId);
        if (!user) {
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Log the invite codes for debugging
        console.log('Stored invite code:', user.inviteCode);
        console.log('Received invite code:', inviteCode);
        console.log('Stored invite code type:', typeof user.inviteCode);
        console.log('Received invite code type:', typeof inviteCode);

        // Normalize invite codes for comparison
        const storedInviteCode = user.inviteCode ? user.inviteCode.trim().toLowerCase() : '';
        const receivedInviteCode = inviteCode.trim().toLowerCase();

        // Check if the invite code matches the user's inviteCode
        if (storedInviteCode !== receivedInviteCode) {
            console.log('Invite code does not match');
            return res.status(400).json({ error: 'Invalid invite code. Please try again.' });
        }

        // Find the chat room associated with the invite code
        const chatRoom = await ChatRoom.findOne({ inviteCode: storedInviteCode });
        if (!chatRoom) {
            console.log('Chat room not found');
            return res.status(404).json({ error: 'Chat room not found' });
        }

        // Add the user to the chat room
        chatRoom.participants.push(user._id);
        await chatRoom.save();

        console.log('User added to chat room:', chatRoom);

        // Return success response with chat room details
        res.status(200).json({ message: 'Joined chat room successfully', chatRoom });
    } catch (error) {
        console.error('Error joining chat room:', error);
        res.status(500).json({ error: 'Server error' });
    }
});



// Route to fetch user ID
router.get('/get-user-id', verifyToken, async (req, res) => {
    // Retrieve user ID based on authentication (e.g., JWT)
    const userId = req.user.id;
    console.log("user ID is: ", userId);
    if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    res.status(200).json({ userId });
});

// Route to check invite code
router.post('/check-invite-code', verifyToken, async (req, res) => {
    const { userId, inviteCode } = req.body;

    try {
        // Find user by ID and check invite code
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.inviteCode !== inviteCode) {
            return res.status(400).json({ error: 'Invalid invite code' });
        }

        res.status(200).json({ message: 'Invite code is valid', inviteCode });
    } catch (error) {
        console.error('Error checking invite code:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to create a chat room
router.post('/create-chat-room', async (req, res) => {
    try {
        const { adminId, userId } = req.body; // Assuming adminId and userId are sent in the request body

        // Create a new chat room
        const chatRoom = new ChatRoom({
            participants: [adminId, userId],
            // Add other initial properties as needed
        });

        // Save the chat room to the database
        await chatRoom.save();

        // Respond with the chat room ID
        res.json({ chatRoomId: chatRoom._id });
    } catch (error) {
        console.error('Error creating chat room:', error);
        res.status(500).json({ error: 'Failed to create chat room' });
    }
});








module.exports = router;
