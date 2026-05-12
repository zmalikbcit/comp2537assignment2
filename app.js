require('dotenv').config();

const express    = require('express');
const session    = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt     = require('bcrypt');
const Joi        = require('joi');

const { database } = require('./databaseConnection');

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 12;

// Session expiry: 1 hour
const expireTime = 1 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host             = process.env.MONGODB_HOST;
const mongodb_user             = process.env.MONGODB_USER;
const mongodb_password         = process.env.MONGODB_PASSWORD;
const mongodb_user_database    = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret   = process.env.MONGODB_SESSION_SECRET;
const node_session_secret      = process.env.NODE_SESSION_SECRET;
/* END secret section */

const userCollection = database.db(mongodb_user_database).collection('users');

// middleware
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
    dbName: mongodb_user_database,

});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.use(express.static(__dirname + '/public'));

// authorization middleware

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render('403');
        return;
    }
    next();
}

// Routes

app.get('/', (req, res) => {
    res.render('index', {
        authenticated: req.session.authenticated || false,
        name: req.session.name || ''
    });
});

app.get('/signup', (req, res) => {
    res.render('signup', { error: null });
});

app.post('/signupSubmit', async (req, res) => {
    var name     = req.body.name;
    var email    = req.body.email;
    var password = req.body.password;

    if (!name) {
        res.render('signup', { error: 'Name is required.' });
        return;
    }
    if (!email) {
        res.render('signup', { error: 'Email is required.' });
        return;
    }
    if (!password) {
        res.render('signup', { error: 'Password is required.' });
        return;
    }

    const schema = Joi.object({
        name:     Joi.string().max(50).required(),
        email:    Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('signup', { error: 'Invalid input.' });
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name:      name,
        email:     email,
        password:  hashedPassword,
        user_type: 'user'
    });
    console.log('Inserted user');

    req.session.authenticated = true;
    req.session.name          = name;
    req.session.email         = email;
    req.session.user_type     = 'user';
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/loginSubmit', async (req, res) => {
    var email    = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email:    Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('login', { error: 'Invalid email or password.' });
        return;
    }

    var result = await userCollection
        .find({ email: email })
        .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
        .toArray();

    if (result.length != 1) {
        console.log('User not found');
        res.render('login', { error: 'Invalid email/password combination.' });
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name          = result[0].name;
        req.session.email         = result[0].email;
        req.session.user_type     = result[0].user_type;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
        return;
    }

    console.log('Incorrect password');
    res.render('login', { error: 'Invalid email/password combination.' });
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }
    res.render('members', { name: req.session.name });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    var users = await userCollection
        .find({})
        .project({ name: 1, email: 1, user_type: 1, _id: 0 })
        .toArray();

    res.render('admin', { users: users });
});

app.post('/promoteUser', sessionValidation, adminAuthorization, async (req, res) => {
    const schema = Joi.string().email().required();
    const validationResult = schema.validate(req.body.email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/admin');
        return;
    }

    await userCollection.updateOne(
        { email: req.body.email },
        { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
});

app.post('/demoteUser', sessionValidation, adminAuthorization, async (req, res) => {
    const schema = Joi.string().email().required();
    const validationResult = schema.validate(req.body.email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/admin');
        return;
    }

    await userCollection.updateOne(
        { email: req.body.email },
        { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
});

// 404 catch-all — must be the LAST route
app.get('*', (req, res) => {
    res.status(404);
    res.render('404');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});