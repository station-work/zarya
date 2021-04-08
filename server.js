const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

require('dotenv').config()

const app = express();

const ZARYA_PORT = process.env.ZARYA_PORT || 3000;

app.use(bodyParser.json());

const HASURA_SIGNUP = `
  mutation ($name: String!, $email: String!, $password: String!, $username: String!) {
    insert_users_one(object: {name: $name, email: $email, password: $password, username: $username}) {
      id
    }
  }
`;

const HASURA_LOGIN = `
  query login($email: String!) {
    users(where:{ email: {_eq: $email}}) {
      email,
      password,
      id,
      name
    }
  }
`

// execute the parent operation in Hasura
const execute = async (variables, query) => {
  const hasuraSecret = process.env.HASURA_GRAPHQL_ADMIN_SECRET;
  const meta = {
    "Content-Type": "application/json",
    "x-hasura-admin-secret": hasuraSecret,
  };
  const headers = meta
  const baseUrl = process.env.HASURA_APP_URL
  const fetchResponse = await fetch(
    `${baseUrl}/v1/graphql`,
    {
      method: "POST",
      headers: headers,
      body: JSON.stringify({
        query,
        variables,
      }),
    }
  );
  const data = await fetchResponse.json();
  return data;
};

// generate password in hash
const generatePassword = async (password) => {
  const salt = await bcrypt.genSalt();
  const hash = await bcrypt.hash(password, salt);

  return hash;
};

const comparaPassword = async (password, hashPassword) => {
  const isMatch = await bcrypt.compare(password, hashPassword)
  return isMatch
}

app.post("/signup", async (req, res) => {
  try {
    if (!req.body.input) {
      return res.status(400).json({
        message: "is required input object"
      });
    }
    // get request input
    const { name, email, password, username } = req.body.input;
    // run some business logic
    const hash = await generatePassword(password);

    // execute the Hasura operation
    const { data, errors } = await execute({
      name,
      email,
      password: hash,
      username,
    }, HASURA_SIGNUP);
    // if Hasura operation errors, then throw error
    if (errors) {
      return res.status(400).json(errors[0]);
    }

    const tokenContents = {
      sub: data.insert_users_one.id.toString(),
      name: name,
      iat: Date.now() / 1000,
      iss: 'https://myapp.com/',
      "https://hasura.io/jwt/claims": {
        "x-hasura-allowed-roles": ["user"],
        "x-hasura-user-id": data.insert_users_one.id.toString(),
        "x-hasura-default-role": "user",
        "x-hasura-role": "user"
      },
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60)
    }

    const token = jwt.sign(tokenContents, process.env.ENCRYPTION_KEY);

    // success
    return res.json({
      ...data.insert_users_one,
      token: token
    });
  } catch (err) {
    return res.status(500).json(err);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body.input;
    // execute the Hasura operation
    const { data, errors } = await execute({
      email,
    }, HASURA_LOGIN);

    // if Hasura operation errors, then throw error
    if (errors) {
      return res.status(400).json(errors[0]);
    }

    const isMatch = await comparaPassword(password, data.users[0].password)
    if (!isMatch) {
      return res.status(401).json({
        message: `email or password is incorrect`
      });
    }


    const tokenContents = {
      sub: data.users[0].id.toString(),
      name: data.users[0].name,
      iat: Date.now() / 1000,
      iss: 'https://myapp.com/',
      "https://hasura.io/jwt/claims": {
        "x-hasura-allowed-roles": ["user"],
        "x-hasura-user-id": data.users[0].id.toString(),
        "x-hasura-default-role": "user",
        "x-hasura-role": "user"
      },
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60)
    }

    const token = jwt.sign(tokenContents, process.env.ENCRYPTION_KEY);

    return res.status(200).json({
      id: data.users[0].id,
      token: token
    });
  } catch (err) {
    if (err instanceof TypeError) {
      return res.status(400).json(err.message);
    }
    if (err.message) {
      return res.status(500).json(err.message);
    }
    return res.status(500).json("Internal error");
  }
})

app.listen(ZARYA_PORT);
