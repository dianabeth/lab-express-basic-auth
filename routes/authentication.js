const express = require('express');
const bcrypt = require('bcryptjs');

const User = require('./../models/user');
const routeAuthenticationGuard = require('./../middleware/routeAuthenticationGuard');

const authenticationRouter = new express.Router();

authenticationRouter.get('/sign-up', (request, response, next) => {
  response.render('authentication/sign-up');
});

authenticationRouter.post('/sign-up', (request, response, next) => {
  const { name, email, password } = request.body;

  bcrypt
    .hash(password, 10)
    .then(hashAndSalt => {
      return User.create({
        name,
        email,
        passwordHashAndSalt: hashAndSalt
      });
    })
    .then(user => {
      request.session.userId = user._id;
      response.redirect('/');
    })
    .catch(error => {
      next(error);
    });
});

authenticationRouter.get('/log-in', (request, response, next) => {
  response.render('authentication/log-in');
});

authenticationRouter.post('/log-in', (request, response, next) => {
  const { email, password } = request.body;

  let user;

  User.findOne({ email })
    .then(document => {
      user = document;
      if (!user) {
        return Promise.reject(new Error('No user with that email.'));
      }
      const passwordHashAndSalt = user.passwordHashAndSalt;
      return bcrypt.compare(password, passwordHashAndSalt);
    })
    .then(comparison => {
      if (comparison) {
        request.session.userId = user._id;
        response.redirect('/authentication/private');
      } else {
        const error = new Error('Password did not match.');
        return Promise.reject(error);
      }
    })
    .catch(error => {
      response.render('authentication/log-in', { error: error });
    });
});

authenticationRouter.get('/private', routeAuthenticationGuard, (request, response, next) => {
  response.render('authentication/private');
});

module.exports = authenticationRouter;
