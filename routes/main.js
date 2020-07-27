const express = require('express');
const routeAuthenticationGuard = require('../middleware/routeAuthenticationGuard');
const mainRouter = new express.Router();

mainRouter.get('/main', routeAuthenticationGuard, (request, response, next) => {
  response.render('authenticated/main');
});

module.exports = mainRouter;
