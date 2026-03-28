// Test vulnerable JavaScript code for security audit

const express = require('express');
const { exec } = require('child_process');
const app = express();

// XSS vulnerability
app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${name}</h1>`);  // XSS!
});

// Command Injection
app.get('/execute', (req, res) => {
    const cmd = req.query.cmd;
    exec(cmd, (error, stdout, stderr) => {  // Command Injection!
        res.send(stdout);
    });
});

// eval usage
app.get('/calc', (req, res) => {
    const expr = req.query.expr;
    const result = eval(expr);  // Code Injection!
    res.send(String(result));
});

// innerHTML XSS
app.get('/render', (req, res) => {
    const content = req.query.content;
    res.send(`
        <script>
            document.getElementById('output').innerHTML = "${content}";  // XSS!
        </script>
    `);
});

// Hardcoded credentials
const DB_PASSWORD = "mysql_root_password_123";  // Hardcoded password!
const AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE";  // Hardcoded secret!

// SQL Injection (simulated)
app.get('/search', (req, res) => {
    const keyword = req.query.q;
    const query = `SELECT * FROM products WHERE name LIKE '%${keyword}%'`;  // SQL Injection!
    res.json({ query });
});

// SSRF vulnerability
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const response = await fetch(url);  // SSRF!
    const data = await response.text();
    res.send(data);
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
