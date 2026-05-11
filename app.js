// Load the global include() helper before anything else
require('./utils.js');

// Load environment variables from .env
require('dotenv').config();

const express = require('express');
const session    = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const mongoSanitizer = require('mongo-sanitizer').default;

const saltRounds = 12;
const app = express();

const PORT = process.env.PORT || 3000;
const expireTime = 24 * 60 * 60 * 1000; // 1 day in milliseconds

/* ── Secrets (from .env) ──────────────────────────────────────────────────── */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// Database connection
// Uses the global include() from utils.js to load databaseConnection.js
const { database } = include('databaseConnection');
const userCollection = database.db(mongodb_user_database).collection('users');

// middleware

// Use EJS as the templating engine; views live in /views by default
app.set('view engine', 'ejs');

// Parse URL-encoded POST bodies (form fields → req.body)
app.use(express.urlencoded({ extended: false }));

// Parse JSON bodies
app.use(express.json());

// Sanitize all incoming requests to prevent NoSQL injection
// Replaces dangerous MongoDB operators ($, .) with underscores
app.use(mongoSanitizer({ replaceWith: '_' }));

// Session store in MongoDB so sessions survive server restarts
const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
    crypto: { secret: mongodb_session_secret }
});

app.use(session({
    secret:            node_session_secret,
    store:             mongoStore,
    saveUninitialized: false,   // don't save empty sessions
    resave:            true     // keep session alive on each request
}));

// Serve static files (images, CSS, JS) from /public
app.use(express.static(__dirname + '/public'));

/* ── Authorization middleware ─────────────────────────────────────────────── */

// Middleware: redirect to /login if the user has no valid session
function sessionValidation(req, res, next) {
    if (req.session.authenticated) {
        next(); // session is valid — proceed to the route
    } else {
        res.redirect('/login');
    }
}

// Middleware: show 403 if the user is logged in but NOT an admin
function adminAuthorization(req, res, next) {
    if (req.session.user_type !== 'admin') {
        res.status(403);
        res.render('403');
        return; // stop here — do not call next()
    }
    next();
}

/* ── Routes ───────────────────────────────────────────────────────────────── */

// Home page — shows sign-up/login links for guests; greeting for logged-in users
app.get('/', (req, res) => {
    res.render('index', {
        authenticated: req.session.authenticated || false,
        name:          req.session.name || ''
    });
});

// Sign up form
app.get('/signup', (req, res) => {
    res.render('signup', { error: null });
});

// Handle sign-up submission
app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    // Joi validates that all fields are present and safe strings
    const schema = Joi.object({
        name:     Joi.string().max(50).required(),
        email:    Joi.string().email().max(100).required(),
        password: Joi.string().max(50).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        return res.render('signup', { error: validationResult.error.details[0].message });
    }

    // Hash the password — never store plaintext passwords
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert the new user; all new users start as 'user' type
    await userCollection.insertOne({
        name,
        email,
        password: hashedPassword,
        user_type: 'user'
    });
    console.log('Inserted user');

    // Create session right away so the user is logged in after signing up
    req.session.authenticated = true;
    req.session.name          = name;
    req.session.email         = email;
    req.session.user_type     = 'user';
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

// Login form
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// Handle login submission
app.post('/loginSubmit', async (req, res) => {
    const { email, password } = req.body;

    // Validate email and password with Joi to prevent NoSQL injection
    const schema = Joi.object({
        email:    Joi.string().email().max(100).required(),
        password: Joi.string().max(50).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        return res.render('login', { error: 'Invalid email or password.' });
    }

    // Look up the user by email; project only the fields we need
    const result = await userCollection
        .find({ email })
        .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
        .toArray();

    // Guard against a null/empty result before checking length
        if (!result || result.length != 1) {
            console.log('User not found');
            return res.render('login', { error: 'Invalid email/password combination.' });
        }

    console.log(result);

    if (result.length != 1) {
        console.log('User not found');
        return res.render('login', { error: 'Invalid email/password combination.' });
    }

    const user = result[0];

    // bcrypt.compare checks the plain password against the stored hash
    if (await bcrypt.compare(password, user.password)) {
        console.log('Correct password');
        req.session.authenticated = true;
        req.session.name          = user.name;
        req.session.email         = user.email;
        req.session.user_type     = user.user_type;
        req.session.cookie.maxAge = expireTime;
        return res.redirect('/members');
    }

    console.log('Incorrect password');
    return res.render('login', { error: 'Invalid email/password combination.' });
});

// Members page — the assignment specifies redirect to / (not /login) when not logged in
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }
    res.render('members', { name: req.session.name });
});

// Logout — destroy the session cookie and redirect home
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Admin page — requires both a valid session AND admin user_type
app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    // Fetch all users from the database to display the user list
    const users = await userCollection
        .find({})
        .project({ name: 1, email: 1, user_type: 1, _id: 0 })
        .toArray();

    res.render('admin', { users });
});

// Promote a user to admin — updates user_type field in MongoDB
app.post('/promoteUser', sessionValidation, adminAuthorization, async (req, res) => {
    // Validate the email coming from the hidden form field
    const schema = Joi.string().email().max(100).required();
    const validationResult = schema.validate(req.body.email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        return res.redirect('/admin');
    }

    // $set updates only user_type; all other fields remain unchanged
    await userCollection.updateOne(
        { email: req.body.email },
        { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
});

// Demote an admin back to a regular user
app.post('/demoteUser', sessionValidation, adminAuthorization, async (req, res) => {
    const schema = Joi.string().email().max(100).required();
    const validationResult = schema.validate(req.body.email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        return res.redirect('/admin');
    }

    await userCollection.updateOne(
        { email: req.body.email },
        { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
});

// 404 catch-all — must always be the LAST route
app.use((req, res) => {
    res.status(404);
    res.render('404');
});

/* ── Start server ─────────────────────────────────────────────────────────── */
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
