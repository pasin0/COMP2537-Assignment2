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

//Middleware to parse POST form data
app.use(express.urlencoded({ extended: false }));

// Session setup
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    crypto: { secret: process.env.MONGODB_SESSION_SECRET }
  }),
  cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// Accesses the public folder for images
app.use(express.static('public'));

// Handles GET requests to sign up and returns sign up form HTML page
app.get('/signup', (req, res) => {
  const filePath = path.join(__dirname, 'views', 'signup.html'); // Build the absolute path to signup.html
  res.sendFile(filePath);
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
  const existingUser = await userCollection.findOne({ email: email });
  if (existingUser) {
    return res.send(`<p>Email already in use.</p><a href="/signup">Try again</a>`);
  }

  // Insert new user into the database
  await userCollection.insertOne({
    name,
    email,
    password: hashedPassword
  });

  // Store user session data
  req.session.authenticated = true;
  req.session.name = name;

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

  // Pick a random image from the array
  const randomIndex = Math.floor(Math.random() * images.length);
  const selectedImage = images[randomIndex];

  // Return the HTML response
  res.send(`
    <h1>Welcome, ${name}!</h1>
    <p>Here’s a random image for you <3:</p>
    <img src="/${selectedImage}" alt="Random Image" style="max-width: 300px;">
    <br><br>
    <a href="/logout">Logout</a>
  `);
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
    setTimeout(() => {
      res.send("<h2>You are logged out. <a href='/'>Home</a></h2>");
    }, 300); 
  });
});

// Login form
app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form action="/login" method="POST">
      <label>Email:</label><br>
      <input type="email" name="email" required><br><br>
      <label>Password:</label><br>
      <input type="password" name="password" required><br><br>
      <button type="submit">Login</button>
    </form>
  `);
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
    return res.send(`<p>Login error: ${validation.error.message}</p><a href="/login">Go back</a>`);
  }

  // Find user by email
  const user = await userCollection.findOne({ email });

  if (!user) {
    return res.send(`<p>No account found with that email.</p><a href="/login">Try again</a>`);
  }

  // Check password with bcrypt
  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.send(`<p>Incorrect password.</p><a href="/login">Try again</a>`);
  }

  // Store login state in session
  req.session.authenticated = true;
  req.session.name = user.name;

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
  if (!req.session.authenticated) {
    return res.send(`
      <h1>Welcome</h1>
      <a href="/signup">Sign up</a><br>
      <a href="/login">Log in</a>
    `);
  } else {
    const name = req.session.name || "Guest";
    return res.send(`
      <h1>Hello, ${name}!</h1>
      <a href="/members">Go to Members Area</a><br>
      <a href="/logout">Logout</a>
    `);
  }
});

app.use((req, res) => {
  res.status(404).send(`
  <!DOCTYPE html>
    <html>
    <head><title>404</title></head>
    <body>
      <h1>404 – Page Not Found</h1>
      <a href="/">Go Home</a>
    </body>
    </html>`);
});
