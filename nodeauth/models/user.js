const mongoose = require('mongoose');
const Schema = mongoose.Schema;
var bcrypt = require('bcryptjs');
mongoose.connect('mongodb://localhost/nodeauth', {useNewUrlParser: true});

var db = mongoose.connection;

//User Schema
const UserSchema = new Schema({
  username: {
    type: String,
    index: true
  },
  password: {
    type: String
  },
  email: {
    type: String
  },
  country: {
    type: String
  },
  province: {
    type: String
  },
  street: {
    type: String
  },
  apartment: {
    type: String
  }
});

UserSchema.pre('save', async function(next){
  try{
    // Generate a salt
    this.password = JSON.stringify(this.password);
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(this.password, salt);
    this.password = passwordHash;
    next();
  }catch{
   next(error);
  }
});

const User = mongoose.model('User', UserSchema);
module.exports = User;

module.exports.getUserById = function(id, callback){
  User.findById(id, callback);
}

module.exports.getUserByEmail = function(email, callback){
  var query = {email: email};
  User.findOne(query, callback);
}

module.exports.comparePassword = function(candidatePassword, hash, callback){
 bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
          if(isMatch) {
             callback(isMatch);
          } else {
           callback(null);
          }
        });
}

