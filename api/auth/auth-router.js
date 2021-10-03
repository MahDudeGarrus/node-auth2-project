const router = require("express").Router();
const bcrypt = require('bcryptjs')

const { JWT_SECRET } = require("../secrets/index.js"); // use this secret!
const jwt = require('jsonwebtoken')

const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const User = require('../users/users-model.js')

// BUILDING TOKEN FUNCTION
function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role: user.role_name,
  }
  const options = {
    expiresIn: "1d",
  }

  return jwt.sign(payload, JWT_SECRET, options)
}

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const { username, password, role_name } = req.body
  const hash = bcrypt.hashSync(password, 8)

  User.add({ username, password: hash, role_name })
    .then(saved => {
      res.status(201).json(saved)
    })
    .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const { username, password } = req.body
  User.findBy({ username })
   .then(([user]) => {
      if (bcrypt.compareSync(password, user.password)) {
        const token = buildToken(user)
        res.status(200).json({
          message: `${user.username} is back!`, 
          token: token
        })
      } else {
        next({
          status: 401,
          message: "Invalid Credentials"
        });
      }
   })
   .catch(next);
});

module.exports = router;
