const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/db");

// Register User
exports.registerUser = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into database
    const [user] = await db.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to register user" });
  }
};

// Login User
exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const [users] = await db.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (users.length === 0) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const user = users[0];

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Generate token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
};

// Get Users (admin protected)
exports.getUsers = async (req, res) => {
  try {
    const [users] = await db.query(
      "SELECT id, name, email, created_at, last_login_at, status FROM users"
    );
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve users" });
  }
};
