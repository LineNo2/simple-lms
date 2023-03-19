require('dotenv').config();
const env = process.env;

module.exports = {
  host : env.MYSQL_HOST,
  user : env.MYSQL_USER,
  password : env.MYSQL_PASSWORD,
  database : env.MYSQL_DATABASE
};
