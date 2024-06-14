const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
// const users = require("./model/user")
// const mongoose = require("mongoose")
// require('./connection/db')
app.use(express.json());

let users = [];
app.post('/register', async (req, res) => {
    const existingUser = users.find(user => user.id === req.body.id);
    if (existingUser) {
      return res.status(400).send('User with this ID already exists');
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = {
      id: req.body.id,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: req.body.email,
      mobile: req.body.mobile,
      password: hashedPassword
    };
    users.push(user);
    res.status(201).send('User registered successfully');
  });
app.post('/login', async (req, res) => {
   
    let user = users.find(user => user.email == req.body.email);
   
    if (user == null) {
        return res.status(400).send('Cannot find user');
    }
    try {
        if(await bcrypt.compare(req.body.password, user.password)) {
            const accessToken = jwt.sign(user, '5645455');
            res.json(accessToken);
        } else {
            res.send('Not Allowed');
        }
    } catch {
        res.status(500).send();
    }
});

app.get('/users', authenticateToken, (req, res) => {
    res.json(users);
});

app.get('/users/:name', authenticateToken, (req, res) => {
    const user = users.find(user => user.name === req.params.name);
    res.json(user);
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.listen(3000);