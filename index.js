require("./utils.js");
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const app = express();
const Joi = require("joi");
const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour (hours * minutes * seconds * millis)

const port = process.env.PORT || 3000;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    if (req.session.authenticated) {
        res.send(`
            <h1>Hello ${req.session.username}!</h1>     
            <form action="/members" method="get">
                <button>Go to members area</button> 
            </form>
            <form action="/logout" method="get">
                <button>Logout</button>
            </form>
        `)
    } else {
    res.send(`
        <form action="/signup" method="get">
            <button>Sign up</button>
        </form>
        <form action="/login" method="get">
            <button>Log in</button>
        </form>
    `);
    }
});

app.get('/signup', (req,res) => {
    res.send(`
    <p>Create user</p>
    <form action='/signupSubmit' method='post'>
        <input name='username' type='text' placeholder='username'>
        <br>
        <input name='email' type='email' placeholder='example@example.com'>
        <br>
        <input name='password' type='password' placeholder='password'>
        <br>
        <button>Submit</button>
    </form>
    `);
});

app.post('/signupSubmit', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

	const schema = Joi.object({
		username: Joi.string().alphanum().max(20).required(),
		password: Joi.string().max(20).required(),
        email: Joi.string().email(),
	});
	
	const validationResult = schema.validate({username, password, email});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       res.send(`
        <p>${validationResult.error.details[0].message}</p>
        <a href="/signup">Try Again</a>
       `)
	   return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, password: hashedPassword, email: email});

    createSession(req, username);
    res.redirect("/members");
});

app.get('/login', (req,res) => {
    res.send(`
    <p>log in</p>
    <form action='/loggingIn' method='post'>
        <input name='email' type='email' placeholder='example@example.com'>
        <br>
        <input name='password' type='password' placeholder='password'>
        <br>
        <button>Submit</button>
    </form>
    `);
});

app.post('/loggingIn', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object({
        email: Joi.string().email(),
		password: Joi.string().max(20).required(),
    })
	const validationResult = schema.validate({email, password});
	if (validationResult.error != null) {
       res.send(`
        <p>${validationResult.error.details[0].message}</p>
        <a href="/login">Try Again</a>
       `)
	   return;
	}
    
	const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();
    const invalidHTML = `
        <p>Invalid email/password combination</p>     
        <a href="/login">Try Again</a>
    `
	if (result.length != 1) {
        res.send(invalidHTML);
		return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
        createSession(req, result[0].username)
		res.redirect('/');
		return;
	} else {
        res.send(invalidHTML);
		return;
	}
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect("/");
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect("/")
        return;
    }
    
    const publicDir = path.join(__dirname, 'public');

    fs.readdir(publicDir, (err, files) => {
        if (err) {
            console.error("Error reading public directory:", err);
            res.send("Could not load images");
            return;
        }

        const images = files.filter(file => /\.(jpg|jpeg|png|gif)$/i.test(file));
        if (images.length === 0) {
            res.send("No images found");
            return;
        }

        const randomImage = images[Math.floor(Math.random() * images.length)];
        const imageUrl = `${randomImage}`;

        res.send(`
            <h1>Hello, ${req.session.username}.</h1>
            <img src="${imageUrl}" style="max-width: 300px; height: auto;" />
            <br>
            <form action="/logout" method="get">
                <button>Logout</button>
            </form>
        `);
    })
})

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application on http://localhost:"+port);
}); 

function createSession(req, username) {
	req.session.authenticated = true;
	req.session.username = username;
	req.session.cookie.maxAge = expireTime;
}