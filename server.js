const fs = require('fs');
const https = require('https');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');

require('dotenv').config();

const PORT = 3000;

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET
}

const verifyCallback = (accesstoken, refreshtoken, profile, done) => {
    console.log('Google profile', profile);
    done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

//Write Cookie from Session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

//Read the Session from Cookie
passport.deserializeUser((id, done) => {
    done(null, id);
});

const app = express();

app.use(helmet());

app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [ process.env.COOKIE_KEY_1, process.env.COOKIE_KEY_2 ],
}));

app.use(passport.initialize());
app.use(passport.session());

const checkLoggedIn = (req, res, next) => {
    console.log('Current User: ', req.user);
    const isLoggedIn = req.isAuthenticated() && req.user;

    if (!isLoggedIn) {
        return res.status(401).json({
            error: 'You must Login!'
        });
    }

    next();
}

app.get('/auth/google', 
    passport.authenticate('google', {
        scope: ['email']
    })
);

app.get('/auth/google/callback', 
    passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        session: true,
    }), 
    (req, res) => {
        console.log('Google called us back!');
    }
);

app.get('/auth/logout', (req, res) => {
    req.logOut();
    return res.redirect('/');
});

app.get('/failure', (req, res) => {
    res.status(401).send('Failed to Login!');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/secret', checkLoggedIn, (req, res) => {
    res.send('Your secret code is 24');
});

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
}, app).listen(PORT, () => {
    console.log(`Listening to ${PORT}...`);
});