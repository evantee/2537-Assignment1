require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { MongoStore } = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse URL-encoded bodies (form data)
app.use(express.urlencoded({ extended: false }));

// Serve static files from the 'public' directory
app.use(express.static('public'));

// MongoDB Connection String Construction
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;

const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true&w=majority`;

// Session Configuration
const expireTime = 1 * 60 * 60 * 1000; // 1 hour in milliseconds

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        mongoUrl: mongoUrl,
        crypto: {
            secret: process.env.MONGODB_SESSION_SECRET
        },
        dbName: mongodb_database
    }),
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: expireTime }
}));

// Database Connection Setup
let userCollection;
async function connectDB() {
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const db = client.db(mongodb_database);
    userCollection = db.collection('users');
    console.log("Connected to MongoDB");
}
connectDB().catch(console.error);

// Routes

// 1. Home Page
app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.send(`
            <h1>Hello, ${req.session.name}!</h1>
            <a href="/members"><button>Go to Members Area</button></a><br><br>
            <a href="/logout"><button>Logout</button></a>
        `);
    } else {
        res.send(`
            <h1>Welcome!</h1>
            <a href="/signup"><button>Sign up</button></a><br><br>
            <a href="/login"><button>Log in</button></a>
        `);
    }
});

// 2. Sign Up Page
app.get('/signup', (req, res) => {
    res.send(`
        <h2>create user</h2>
        <form action="/signup" method="POST">
            <input name="name" type="text" placeholder="name"><br>
            <input name="email" type="email" placeholder="email"><br>
            <input name="password" type="password" placeholder="password"><br>
            <button type="submit">Submit</button>
        </form>
    `);
});

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    // Joi Validation to prevent NoSQL injection
    const schema = Joi.object({
        name: Joi.string().max(50).required().messages({
            'string.empty': 'Name is required.'
        }),
        email: Joi.string().email().required().messages({
            'string.empty': 'Please provide an email address.'
        }),
        password: Joi.string().max(50).required().messages({
            'string.empty': 'Password is required.'
        })
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        return res.send(`
            <p>${validationResult.error.details[0].message}</p>
            <a href="/signup">Try again</a>
        `);
    }

    // Hash password and store in DB
    const hashedPassword = await bcrypt.hash(password, 12);
    
    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword
    });

    // Create session
    req.session.authenticated = true;
    req.session.name = name;
    res.redirect('/members');
});

// 3. Log In Page
app.get('/login', (req, res) => {
    res.send(`
        <h2>log in</h2>
        <form action="/login" method="POST">
            <input name="email" type="email" placeholder="email"><br>
            <input name="password" type="password" placeholder="password"><br>
            <button type="submit">Submit</button>
        </form>
    `);
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Joi Validation
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        return res.send(`
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
    }

    const user = await userCollection.findOne({ email: email });

    if (!user) {
        return res.send(`
            <p>User and password not found.</p>
            <a href="/login">Try again</a>
        `);
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (passwordMatch) {
        req.session.authenticated = true;
        req.session.name = user.name;
        res.redirect('/members');
    } else {
        res.send(`
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
    }
});

// 4. Members Only Page
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect('/');
    }

    const randomImageNumber = Math.floor(Math.random() * 3) + 1;
    const imagePath = `/${randomImageNumber}.png`; 
    // Assumes 1.png, 2.png, 3.png are in /public folder

    res.send(`
        <h1>Hello, ${req.session.name}.</h1>
        <img src="${imagePath}" alt="Random Image" style="max-width: 300px;"><br><br>
        <a href="/logout"><button>Sign out</button></a>
    `);
});

// 5. Log Out
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// 6. 404 Page (Catch-all)
app.get(/(.*)/, (req, res) => {
    res.status(404);
    res.send(`
        <h1>Page not found - 404</h1>
    `);
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});