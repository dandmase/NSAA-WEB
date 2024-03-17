const express = require('express');
const logger = require('morgan');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const port = 3000;
// Genera un secreto para firmar el JWT. Debe mantenerse seguro y consistente.
const jwtSecret = require('crypto').randomBytes(16).toString('hex');

app.use(logger('dev'));
app.use(express.urlencoded({ extended: true })); // necesario para analizar los cuerpos de las solicitudes de tipo application/x-www-form-urlencoded
app.use(passport.initialize()); // inicializa Passport
app.use(cookieParser()); // necesario para leer las cookies

// Configuración de la estrategia local para Passport.
passport.use('username-password', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  function(username, password, done) {
    if (username === 'walrus' && password === 'walrus') {
      const user = {
        username: 'walrus',
        description: 'the only user that deserves to get to this server'
      };
      return done(null, user);
    }
    return done(null, false);
  }
));

// Configuración de la estrategia JWT para Passport.
passport.use('jwtCookie', new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromExtractors([
      (req) => { return req?.cookies?.jwt; }
    ]),
    secretOrKey: jwtSecret
  },
  function(jwtPayload, done) {
    if (jwtPayload.sub === 'walrus') {
      const user = {
        username: jwtPayload.sub,
        description: 'one of the users that deserves to get to this server',
        role: jwtPayload.role ?? 'user'
      };
      return done(null, user);
    }
    return done(null, false);
  }
));

app.get('/welcome', passport.authenticate('jwtCookie', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    res.sendFile(path.join(__dirname, 'welcome.html')); // Asegúrate de que welcome.html esté en el directorio correcto
  }
);

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }),
  (req, res) => { 
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 semana desde ahora
      role: 'user'
    };

    const token = jwt.sign(jwtClaims, jwtSecret);
    res.cookie('jwt', token, { httpOnly: true, secure: true });
    res.redirect('/welcome'); // Redirecciona a la ruta '/welcome'
    
    console.log(`Token enviado. Debug en https://jwt.io/?value=${token}`);
    console.log(`Secreto del token (para verificar la firma): ${jwtSecret}`);
  }
);

app.get('/logout', (req, res) => {
  res.clearCookie('jwt'); // Elimina la cookie jwt
  res.redirect('/login'); // Redirige al usuario a la página de login
});

app.get('/',
  passport.authenticate('jwtCookie', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    res.send(`Welcome to your private page, ${req.user.username}!`);
  }
);

app.use(function(err, req, res, next) {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`App escuchando en http://localhost:${port}`);
});


