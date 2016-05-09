'use strict';

var express = require('express');
var router = express.Router();

var Message = require('../models/message');

router.route('/')
  .get((req, res) => {
    Message.find({}, (err, messages) => {
      res.status(err ? 400 : 200).send(err || messages);
    });
  })
  .post((req, res) => {
    console.log('req.body:', req.body);
    Message.create(req.body, (err, message) => {
      console.log('err:', err);
      res.status(err ? 400 : 200).send(err || message);
    });
  });

module.exports = router;
