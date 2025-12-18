const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
  secret: "kirimnomorSecret",
  resave: false,
  saveUninitialized: true
}));

// Database
const db = new sqlite3.Database('./db.sqlite');

// Create table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)`);

// Routes
app.get("/", (req, res) => {
  res.render("home");
});

// Signup
app.get("/signup", (req, res) => {
  res.render("signup");
});
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashed], (err) => {
    if (err) {
      return res.send("Username sudah digunakan!");
    }
    res.redirect("/login");
  });
});

// Login
app.get("/login", (req, res) => {
  res.render("login");
});
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (!user) return res.send("Username tidak ditemukan");
    
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.user = user;
      res.redirect("/dashboard");
    } else {
      res.send("Password salah!");
    }
  });
});

// Dashboard (protected)
app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  res.render("dashboard", { username: req.session.user.username });
});

app.listen(3000, () => {
  console.log("Server berjalan di http://localhost:3000");
});
