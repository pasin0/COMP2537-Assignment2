// Load env. variables
require('dotenv').config();

// Required Modules
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const { MongoClient } = require('mongodb');
const Joi = require('joi');
const fs = require('fs');
const path = require('path');

// Express setup
const app = express();
const port = process.env.PORT || 3000;

//EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


// Middleware to parse POST form data
app.use(express.urlencoded({ extended: false }));

// Middleware for Admin checking
function isAdmin(req) {
  return req.session.authenticated && req.session.user_type === "admin";
}

function adminOnly(req, res, next) {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }

  if (req.session.user_type !== "admin") {
    res.status(403).render("unauthorized");
    return;
  }

  next();
}

// Session setup
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    dbName: 'authdb',
    crypto: { secret: process.env.MONGODB_SESSION_SECRET }
  }),
  cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// Accesses the public folder for images
app.use(express.static('public'));

// Handles GET requests to sign up and returns sign up form HTML page
app.get('/signup', (req, res) => {
  res.render('signup', { emailTaken: false });
});

// Handles POST request when a user submits the signup form
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body; // Get form data from POST body

  // Validate the input using Joi schema
  const schema = Joi.object({
    name: Joi.string().max(30).required(), // name must be a string
    email: Joi.string().email().required(), // must be a valid email
    password: Joi.string().min(6).required() // password must be a least 6 chars
  });

  const validation = schema.validate({ name, email, password });
  if (validation.error) {
    // If validation fails show error and link to go back
    return res.send(`<p>Error: ${validation.error.message}</p><a href="/signup">Go back</a>`);
  }

  // Hash the password using bcrypt
  const hashedPassword = await bcrypt.hash(password, 12); // 12 salt rounds

  // Check if email already exists
  const existingUser = await userCollection.findOne({ email });
  if (existingUser) {
    return res.render('signup', { emailTaken: true });
  }

  // Insert new user into the database
  await userCollection.insertOne({
    name,
    email,
    password: hashedPassword,
    user_type: "user" // default user
  });

  // Store user session data
  req.session.authenticated = true;
  req.session.name = name;
  req.session.user_type = "user";
  req.session.email = email;

  // Redirect to members-only area
  res.redirect('/members');
});

app.get('/members', (req, res) => {
  // If the user is not logged in, redirect to home page
  if (!req.session.authenticated) {
    return res.redirect('/');
  }

  // Get the name from the session
  const name = req.session.name || "Guest";

  // Create an array of image filenames
  const images = ['froggy.jpeg', 'monkey.jpeg', 'strawberry.jpeg'];

  res.render("members", { name, images });
});


// Logs out the user
app.get('/logout', (req, res) => {
  const sid = req.session.id;

  req.session.destroy(async (err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("Error logging out.");
    }

    console.log(`Session ${sid} destroyed`);
    res.render("logout");
  });
});

// Login form
app.get('/login', (req, res) => {
  res.render("login");
});

// Admin route
app.get("/admin", adminOnly, async (req, res) => {
  const users = await userCollection.find().toArray();
  res.render("admin", { users });
});

// Promote/Demote routes
app.get("/promote/:email", adminOnly, async (req, res) => {
  const { email } = req.params;
  if (req.session.email === email) {
    req.session.user_type = "admin";
  }
  await userCollection.updateOne({ email }, { $set: { user_type: "admin" } });
  res.redirect("/admin");
});

app.get("/demote/:email", adminOnly, async (req, res) => {
  const { email } = req.params;
  if (req.session.email === email) {
    req.session.user_type = "user";
  }
  await userCollection.updateOne({ email }, { $set: { user_type: "user" } });
  res.redirect("/admin");
});

// Handle form submission
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const validation = schema.validate({ email, password });

  if (validation.error) {
    return res.render('error', {
      message: `Login error: ${validation.error.message}`,
      redirectURL: "/login"
    });
  }

  // Find user by email
  const user = await userCollection.findOne({ email });

  if (!user) {
    return res.render('error', {
      message: "No account found with that email.",
      redirectURL: "/login"
    });
  }

  // Check password with bcrypt
  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.render('error', {
      message: "Incorrect password.",
      redirectURL: "/login"
    });
  }

  // Store login state in session
  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.user_type = user.user_type;
  req.session.email = user.email;

  res.redirect('/');
});

// MongoDB setup
const client = new MongoClient(process.env.MONGODB_URI);
let userCollection;

client.connect()
  .then(() => {
    console.log("Connected to MongoDB");
    const db = client.db("authdb");
    userCollection = db.collection("users");

    // Start server only after sucessful DB connection
    app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
    });
  })
  .catch(err => console.error("MongoDB connection error"));

// TEMP: Root route
app.get("/", (req, res) => {
  const name = req.session.name || null;
  const user_type = req.session.user_type || null;
  res.render("index", { name, user_type });
});

// Error 404 page
app.use((req, res) => {
  res.status(404).render("404");
});
