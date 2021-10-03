const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return next({ status: 401, message: 'Token required' });
  }
  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return next({ status: 401, message: 'Token invalid' });
    }
    req.decodedToken = decodedToken;
    next();
  });
}

const only = role_name => (req, res, next) => {
  const { decodedToken } = req;
  if (decodedToken.role_name === role_name) {
    next();
  } else {
    next({ status: 403, message: 'This is not for you'})
  }
};


const checkUsernameExists = async (req, res, next) => {
 try {
   const { username } = req.body;
   const exist = await User.findBy({ username });
   if (!exist) {
     next({status: 401, message: 'Invalid credentials' });
   } else {
     next();
   }
 } catch (err) {
   next(err);
 }
};


const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;
  const validRole = (role_name) => {
    return role_name ? (typeof role_name === 'string' ? true : false) : false;
  };
  if (!req.body.role_name || req.body.role_name.trim() === '') {
    req.body.role_name = 'student';
    next();
  } else if (validRole(role_name)) {
    req.body.role_name = role_name.trim();
    if (req.body.role_name === 'admin') {
      next({status: 422, message: 'Role name can not be admin'});
    } else if (req.body.role_name.length >  32) {
      next({ status: 422, message: 'Role name can not be longer than 32 chars' });
    }
    next();
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
