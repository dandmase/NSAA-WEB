const express = require('express');
const logger = require('morgan');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
const scryptPbkdf = require('scrypt-pbkdf');

const app = express();
const port = 3000;

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/yourDB', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connection to MongoDB successful'))
  .catch((err) => console.error('Error connecting to MongoDB', err));

// User model
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

// Custom scrypt parameters
const scryptParams = {
  N: 1048576, // Customize N here
  r: 8,
  p: 1
};

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = scryptPbkdf.salt(16); // Generates a 16-byte salt
    const derivedKeyLength = 64; // Length of the derived key in bytes

    // Hashing the password with scrypt
    const key = await scryptPbkdf.scrypt(this.password, salt, derivedKeyLength, scryptParams);
    this.password = Buffer.from(key).toString('hex') + ':' + Buffer.from(salt).toString('hex');
    next();
  } catch (err) {
    console.error("Error hashing password:", err);
    next(err);
  }
});

UserSchema.methods.comparePassword = function(candidatePassword) {
  return new Promise(async (resolve, reject) => {
    const [hash, saltHex] = this.password.split(':');
    const salt = Buffer.from(saltHex, 'hex');

    try {
      const derivedKeyLength = 64; // Same length as when hashing
      const key = await scryptPbkdf.scrypt(candidatePassword, salt, derivedKeyLength, scryptParams);
      resolve(hash === Buffer.from(key).toString('hex'));
    } catch (err) {
      reject(err);
    }
  });
};

const User = mongoose.model('User', UserSchema);

// JWT secret generation
const jwtSecret = crypto.randomBytes(16).toString('hex');

app.use(logger('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(cookieParser());

passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username: username });
    if (!user) {
      return done(null, false, { message: 'User not found.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return done(null, false, { message: 'Incorrect password.' });
    }
    
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.use(new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromExtractors([(req) => req?.cookies?.jwt]),
  secretOrKey: jwtSecret
}, async (jwtPayload, done) => {
  try {
    const user = await User.findById(jwtPayload.sub);
    if (user) {
      return done(null, user);
    } else {
      return done(null, false);
    }
  } catch (err) {
    return done(err, false);
  }
}));

// Routes
app.get('/login', (req, res) => {
  res.sendFile('login.html', { root: __dirname });
});

app.post('/login', passport.authenticate('local', { failureRedirect: '/login', session: false }), (req, res) => {
  const jwtClaims = {
    sub: req.user.id,
    iss: 'localhost:3000',
    aud: 'localhost:3000',
    exp: Math.floor(Date.now() / 1000) + 604800, // 1 week
  };

  const token = jwt.sign(jwtClaims, jwtSecret);
  res.cookie('jwt', token, { httpOnly: true, secure: true });
  res.redirect('/welcome');
});

app.get('/register', (req, res) => {
  res.sendFile('register.html', { root: __dirname });
});

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username: username });

    if (existingUser) {
      return res.status(400).send('<p>User already exists. <a href="/register">Go back</a></p>');
    }

    const user = new User({ username, password });
    await user.save();
    res.status(201).send('<p>User registered successfully. <a href="/login">Log in</a></p>');
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).send('Error registering user');
  }
});

app.get('/welcome', passport.authenticate('jwt', { session: false, failureRedirect: '/login' }), (req, res) => {
  res.sendFile(path.join(__dirname, 'welcome.html'));
});

app.get('/logout', (req, res) => {
  res.clearCookie('jwt');
  res.redirect('/login');
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
});





