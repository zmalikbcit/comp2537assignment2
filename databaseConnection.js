const { MongoClient } = require('mongodb');

const mongodb_host     = process.env.MONGODB_HOST;
const mongodb_user     = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true`;

let database = new MongoClient(atlasURI);

// Explicitly connect so queries don't run on an unready client
database.connect();

module.exports = { database };