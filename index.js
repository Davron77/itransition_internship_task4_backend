// index.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const { admin, db } = require("./firebase");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// Secret key for JWT
const JWT_SECRET = "your_jwt_secret_key"; // Change this to a secure secret

// Middleware
app.use(cors({ methods: "GET,HEAD,PUT,PATCH,POST,DELETE", credentials: true }));
app.use(bodyParser.json());

// Middleware to verify the JWT token
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Get token from header

  if (!token) return res.sendStatus(401); // No token provided

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token
    req.user = user; // Save user info for later use
    next(); // Proceed to the next middleware or route
  });
};

// Registration endpoint
app.post("/register", async (req, res) => {
  const { email, password, username } = req.body;

  try {
    // Check if the email is already registered
    const userDoc = await db.collection("users").doc(email).get();

    if (userDoc.exists) {
      return res.status(400).json({ message: "Email already registered!" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store user data in Firestore
    await db.collection("users").doc(email).set({
      email,
      name: username,
      password: hashedPassword,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
      status: "active",
    });

    // Generate a JWT token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1h" });

    res
      .status(201)
      .json({ message: "User registered successfully!", token, email });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const userDoc = await db.collection("users").doc(email).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found!" });
    }

    const userData = userDoc.data();

    // Check if the user is active
    if (userData.status === "blocked") {
      return res.status(403).json({ error: "User is blocked!" });
    }

    const isPasswordValid = await bcrypt.compare(password, userData.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid password!" });
    }

    // Generate a JWT token
    const token = jwt.sign({ email: userData.email }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ message: "Login successful!", token, email });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Logout endpoint
app.post("/logout", authenticateToken, (req, res) => {
  const token = req.token; // Assuming you store the token in the request
  blacklistedTokens.add(token); // Add token to blacklist
  res.json({ message: "Logged out successfully." });
});

// Block user endpoint
app.post("/block-users", authenticateToken, async (req, res) => {
  const { userIds } = req.body; // Array of user IDs or emails to block

  try {
    const batch = db.batch();

    userIds.forEach((userId) => {
      const userRef = db.collection("users").doc(userId);
      batch.update(userRef, { status: "blocked" });
    });

    await batch.commit();
    res.json({ message: "Users have been successfully blocked!" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Unblock user endpoint
app.post("/unblock-users", authenticateToken, async (req, res) => {
  const { userIds } = req.body; // Array of user IDs or emails to unblock

  try {
    const batch = db.batch();

    userIds.forEach((userId) => {
      const userRef = db.collection("users").doc(userId);
      batch.update(userRef, { status: "active" });
    });

    await batch.commit();
    res.json({ message: "Users have been successfully unblocked!" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Delete user endpoint
app.post("/delete-users", authenticateToken, async (req, res) => {
  const { userIds } = req.body; // Array of user IDs or emails to delete

  try {
    const batch = db.batch();

    userIds.forEach((userId) => {
      const userRef = db.collection("users").doc(userId);
      batch.delete(userRef); // Deleting the user document
    });

    await batch.commit();
    res.json({ message: "Users have been successfully deleted!" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Example protected route
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "This is a protected route!", user: req.user });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
