
const { User } = require('../models/User');
const jwt = require("jsonwebtoken");
const createAuthorizationToken = (user) => jwt.sign({
    exp: Math.floor(Date.now() / 1000) + 7200,
    data: { email: user.email, id: user._id }
}, process.env.JWT_SECRET);


const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: "Auth Token Missing", ok: false });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.data; // Store decoded user information in request object
        next();
    } catch (err) {
        console.error(err);
        return res.status(403).json({ message: "Unauthorized", ok: false });
    }
};


const isAdmin = (req, res, next) => {
    const userId = req.user.id; // Assuming userId is available in the decoded token data
    console.log("userId is :", userId);
    // Fetch user from database and check if admin
    User.findById(userId)
        .then(user => {
            if (!user || user.category !== 'admin') {
                return res.status(403).json({ error: 'Unauthorized access' });
            }
            next(); // Continue to the next middleware or route handler
        })
        .catch(error => {
            console.error('Error verifying admin:', error);
            res.status(500).json({ error: 'Internal server error' });
        });
};

module.exports = ({
    verifyToken,
    createAuthorizationToken,
    isAdmin
})