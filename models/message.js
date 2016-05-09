'use strict';

var mongoose = require('mongoose');

var messageSchema = new mongoose.Schema({
  message: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  likes: { type: Number, default: 0 },
  timestamps: { type: Date }
});


//  schema.methods.methodName  -->  instance / document method
//
//   book.read( /* someCallback */ )



messageSchema.methods.like = function(cb) {
  this.likeCount++;
  this.save(cb);
};

var Message = mongoose.model('Message', messageSchema);

module.exports = Message;
