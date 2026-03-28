/**
 * Test JavaScript application with intentional vulnerabilities
 */

const express = require('express');
const app = express();

// Hardcoded credentials - VULNERABILITY
const DB_PASSWORD = "password123";
const API_SECRET = "secret_key_abc";

// XSS vulnerability
app.get('/hello', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello, ${name}</h1>`); // XSS vulnerability
});

// Command injection
app.get('/ping', (req, res) => {
    const host = req.query.host;
    const output = eval(`ping -c 4 ${host}`); // Code injection
    res.send(output);
});

// SQL injection simulation
app.get('/user', async (req, res) => {
    const id = req.query.id;
    const query = `SELECT * FROM users WHERE id = ${id}`; // SQL injection
    res.send(query);
});

// Unsafe innerHTML
app.get('/profile', (req, res) => {
    const bio = req.query.bio;
    document.getElementById('bio').innerHTML = bio; // XSS via innerHTML
});

// Path traversal
app.get('/file', (req, res) => {
    const filename = req.query.file;
    const filePath = path.join('/uploads', filename);
    res.sendFile(filePath); // Path traversal
});

// Unsafe redirect
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url); // Open redirect
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
