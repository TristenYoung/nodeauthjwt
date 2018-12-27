var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local');
var User = require('../models/user');
var jwt = require('jsonwebtoken');

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.get('/register', function(req, res, next) {
  res.render('register');
});

router.post('/register', function(req, res, next) {
  var email = req.body.email;
  var username = req.body.username;
  var password = req.body.password;
  var password2 = req.body.password2;
  var country = req.body.country;
  var province = req.body.province;
  var city = req.body.city;
  var street = req.body.city;
  var apartment = req.body.apartment;

  // Form Validator
  req.checkBody('email', 'Email field is required').notEmpty();
  req.checkBody('email', 'Email is not valid').isEmail();
  req.checkBody('username', 'Username field is required').notEmpty();
  req.checkBody('password', 'Password field is required').notEmpty();
  req.checkBody('password2', 'Passwords must match').equals(req.body.password);
  req.checkBody('country', 'Country field is required').notEmpty();
  req.checkBody('province', 'Province field is required').notEmpty();
  req.checkBody('city', 'City field is required').notEmpty();
  req.checkBody('street', 'Street field is required').notEmpty();
  req.checkBody('apartment', 'Apartment field is required').notEmpty();

  // Check Errors
  var errors = req.validationErrors();

  if(errors){
    res.render('register', {
        errors: errors
    });
  }else{
    var newUser = new User({
      email: email,
      username: username,
      password: password,
      country: country,
      province: province,
      street: street,
      apartment: apartment
      });
    
     newUser.save();

    res.location('/');
    res.redirect('/');
  }
});

router.get('/login', function(req, res, next) {
  res.render('login');
});

function getUserById (id, callback){
  User.findById(id, callback);
}

function getUserByEmail(email, callback){
  var query = {email: email};
  User.findOne(query, callback);
}

function comparePassword (candidatePassword, hash, callback){
  bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
  callback(null, isMatch);
})}

router.post(
    '/login', 
    passport.authenticate('local', {
        failureRedirect: '/users/login', 
        failureFlash: true, 
        badRequestMessage: 'Please enter your account credentials to login.'
    }), 
    function(req, res) {
        if(req.isAuthenticated(req, res)) {
            res.redirect('/');
        } else {
            var errors = req.flash('error');
            if(errors) {
                assign['errors'] = errors;
            }
            res.render('login.html', {errors: errors});
        }
    }
);

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new LocalStrategy({usernameField: 'email', passwordField: 'password'}, function(email, password, done){
 User.getUserByEmail(email, function(err, user){
   if(err) throw err;
    if(!user){
      return done(null, false, {message: 'Uknown User'}); 
    }
    User.comparePassword(password, user.password, function(err, isMatch){
      if(err){ 
         return done(null, user); 
      }else{ 
        return done(null, false, {message: 'Invalid Password'});
      }
   });
  });
}));

router.get('/logout', function(req, res){
  req.logout();
  req.flash('sucess', ' You are now logged out');
  res.redirect('/users/login');
});

///////////////////////////////////////////////////////////

router.get('/api', function(req, res){
  res.json({
    message: 'Welcome to the API'
  });
});

router.post('/api/posts', verifyToken, function(req, res){
  jwt.verify(req.token, 'secretkey', function(err, authData){
    if(err){
	res.sendStatus(403);
    }else{
	  res.json({
    message: 'Post created...',
    authData
      });
    }
  });
});

router.post('/api/login', function(req, res){
  //Mock Users

  const user1 = {
    id: 1,
    username: 'Tommy',
    email: 'Tommy@aol.com'
  }
  jwt.sign({user1}, 'secretkey', function(err, token){
    res.json({
      token
    });
  });
});

// FORMAT OF TOKEN
//Authorization: Bearer <access_token>

// Verify token
function verifyToken(req, res, next){
  //Get auth header value
  const bearerHeader = req.headers['authorization'];
  //Check if bearer is undefined
  if(typeof bearerHeader !== 'undefined'){
    //Split at the space
    const bearer = bearerHeader.split(' ');
    //Get troken from array
    const bearerToken = bearer[1];
    //Set the token
    req.token = bearerToken;
    //Next middleware
    next();
  }else{
    //Forbidden
    res.sendStatus(403);

  }
}
///////////////////////////////////////////////////////////
module.exports = router;
