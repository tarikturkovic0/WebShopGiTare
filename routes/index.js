var express = require('express');
var router = express.Router();
const fileUpload = require('express-fileupload');
const { Pool, Client } = require('pg')
const pool = new Pool({
  user: 'yqeejuyl',
  host: 'abul.db.elephantsql.com',
  database: 'yqeejuyl',
  password: 'J-g27cNqQvkY8jFqvK3lLWX5EJ0XsxT6',
  port: 5432,
  max: 10,
  idleTimeoutMillis: 30000
});
router.use(fileUpload());

/* GET home page. */
router.get('/', function(req, res, next) {
  res.redirect('/home');
});

module.exports = router;
