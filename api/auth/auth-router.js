const router = require("express").Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model');

router.post("/register", validateRoleName, async (req, res, next) => {
  let users = req.body;
  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(users.password, rounds);
  users.password = hash;
  User.add(users).then(saved => {
    res.status(201).json(saved);
  })
  .catch(next);
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const [existingUser] = await User.findBy({ username });

    if (existingUser && bcrypt.compareSync(password, existingUser.password)) {
      const token = tokenBuilder(existingUser);
      res.status(200).json({
        message: `${existingUser.username} is back!`,
        token
      });
    } else {
      next({ status: 401, message: 'Invalid credentials' })
    }
  } catch (err) {
    next(err);
  }
  function tokenBuilder(user) {
    const payload = {
      subject: user.user_id,
      username: user.username,
      role_name: user.role_name
    };
    const options = {
      expiresIn: '1d'
    };
    return token;
  }
});

module.exports = router;
