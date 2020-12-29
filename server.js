const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const bcrypt = require('bcrypt')

const app = express();

const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());


const HASURA_OPERATION = `
mutation ($name: String!, $email: String!, $password: String!, $username: String!) {
  insert_user_one(object: {name: $name, email: $email, password: $password, username: $username}) {
    id
  }
}
`;

// execute the parent operation in Hasura
const execute = async (variables) => {
  const hasuraSecret = process.env.HASURA_SECRET
  const meta = {
    'Content-Type': 'application/json',
    'x-hasura-admin-secret': hasuraSecret
  };
  const headers = new Headers(meta)
  const fetchResponse = await fetch(
    "https://station-work.herokuapp.com/v1/graphql",
    {
      method: 'POST',
      headers: headers
      body: JSON.stringify({
        query: HASURA_OPERATION,
        variables
      })
    }
  );
  const data = await fetchResponse.json();
  console.log('DEBUG: ', data);
  return data;
};

// generate password in hash
const generatePassword = async (password) => {
  const salt = await bcrypt.genSalt()
  const hash = await bcrypt.hash(password, salt)
  
  return hash
}

app.post('/signup', async (req, res) => {
  // get request input
  const { name, email, password, username } = req.body.input;

  // run some business logic
  const hash = await generatePassword(password)
 
 
  // execute the Hasura operation
  const { data, errors } = await execute({ name, email, password: hash, username });

  // if Hasura operation errors, then throw error
  if (errors) {
    return res.status(400).json(errors[0])
  }

  // success
  return res.json({
    ...data.insert_user_one
  })
});

app.listen(PORT);
