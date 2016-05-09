'use strict';

var mongoose = require('mongoose');
var moment = require('moment');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

if(!JWT_SECRET) {
  throw new Error('Missing JWT_SECRET');
}

var userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  messages: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Message' }]
});

// IT'S MIDDLEWARE!!
userSchema.statics.isLoggedIn = function(req, res, next) {
  var token = req.cookies.accessToken;

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if(err) return res.status(401).send({error: 'Must be authenticated.'});

    User
      .findById(payload._id)
      .select({password: false})
      .exec((err, user) => {
        if(err || !user) {
          return res.clearCookie('accessToken').status(400).send(err || {error: 'User not found.'});
        }

        req.user = user;
        next();
      });
  });
};

userSchema.statics.register = function(userObj, cb) {
  User.findOne({username: userObj.username}, (err, dbUser) => {
    if(err || dbUser) return cb(err || { error: 'Username not available.' })


    bcrypt.hash(userObj.password, 12, (err, hash) => {
      if(err) return cb(err);

      var user = new User({
        username: userObj.username,
        password: hash
      });

      user.save(cb);
    });
  });
};

userSchema.statics.authenticate = function(userObj, cb) {
  this.findOne({username: userObj.username}, (err, dbUser) => {
    if(err || !dbUser) return cb(err || { error: 'Login failed. Username or password incorrect.' });

    bcrypt.compare(userObj.password, dbUser.password, (err, isGood) => {
      if(err || !isGood) return cb(err || { error: 'Login failed. Username or password incorrect.' });

      var token = dbUser.makeToken();

      cb(null, token);
    });
  });
};

userSchema.methods.makeToken = function() {
  var token = jwt.sign({
    _id: this._id,
    exp: moment().add(1, 'day').unix() // in seconds
  }, JWT_SECRET);
  return token;
};

userSchema.statics.like = function(userId, messageId, cb) {
  User.findById(userId, (err1, user) => {
    Message.findById(messageId, (err2, message) => {
      if(err1 || err2) return cb(err1 || err2);

      var alreadyLiked = message.likes.indexOf(user._id) !== -1;

      if(alreadyLiked) {
        return cb({error: "You already like this!"});
      }

      user1.friends.push(user2._id);
      user2.friends.push(user1._id);

      user1.save((err1) => {
        user2.save((err2) => {
          cb(err1 || err2);
        });
      });
    });
  });
};

userSchema.statics.unfriendify = function(user1Id, user2Id, cb) {
  User.findById(user1Id, (err1, user1) => {
    User.findById(user2Id, (err2, user2) => {
      if(err1 || err2) return cb(err1 || err2);

      user1.friends = user1.friends.filter(friendId => {
        return friendId.toString() !== user2._id.toString();
      });

      user2.friends = user2.friends.filter(friendId => {
        return friendId.toString() !== user1._id.toString();
      });

      user1.save((err1) => {
        user2.save((err2) => {
          cb(err1 || err2);
        });
      });

    });
  });
};


var User = mongoose.model('User', userSchema);

module.exports = User;
