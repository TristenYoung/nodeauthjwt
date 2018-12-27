var dotenv = require('dotenv');
dotenv.config();
var express = require('express');
var router = express.Router();
const passport = require('passport');
const passportJWT = require('passport-jwt');
const JwtStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;
const parser = require('body-parser');
const knex = require('knex');
const knexDb  = knex({client: 'pg', connection: 'postgres://zala:Thisistheminecr@ftpassword@localhost/jwt_test'});
const bookshelf = require('bookshelf');
const securePassword = require('bookshelf-secure-password');
const db = bookshelf(knexDb);
db.plugin(securePassword);
const jwt = require('jsonwebtoken');


//=====================================================
//Passport Api=========================================
//=====================================================

const User = db.Model.extend({
  tableName: 'login_user',
  hasSecurePassword: true

});

const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: 'godsofdeathloveapples'
}

const strategy = new JwtStrategy(opts, function(payload, next) {
  User.forge({id: payload.id }).fetch().then(function(res){

  next(null, res);
  });
});

//Utilizing Imported Packages--------------
passport.use(strategy);
router.use(passport.initialize());
router.use(parser.urlencoded({
  extended: false
}));
router.use(parser.json());


//=========================================
//Routes===================================
//=========================================

/* GET home page. */
router.get('/', function(req, res, next) {
  res.send('Hello World');
});

router.post('/seedUser', function(req, res){
  if(!req.body.email || !req.body.password){
    return res.status(401).send('no fields');
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password
  });

  user.save().then(function(){res.send('ok')})
});

router.post('/getToken', function(req, res){
  if(!req.body.email || !req.body.password) {
    return res.status(401).send('Fields not sent');
  }

  User.forge({email: req.body.email}).fetch().then(function(result){
    if(!result){
	return res.status(400).send('user not found');
    }
    
    result.authenticate(req.body.password).then(function(user){
      const payload = {id:user.id};
      const token = jwt.sign(payload, 'godsofdeathloveapples');
      res.send(token);
    }).catch(function(err){
	return res.status(401).send({err: err});
    });
  });
});

//Protected Routes----------
router.get('/protected', passport.authenticate('jwt', {session: false}), function(req, res){
  res.send('I am Protect!');
});

module.exports = router;
