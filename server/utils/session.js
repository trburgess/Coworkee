/**
 * https://jwt.io/introduction/
 */

"use strict";

var errors = require('./errors');
var config = require('./config');
var models = require('../models');
var jwt    = require('jsonwebtoken');
var helpers = require('./helpers.js');

module.exports = {

    readonly: config.session.readonly,

    initiate: function (username, password, res) {
        return models.Person.scope('auth').findOne({
            where: {
                $or: [
                    {username: username},
                    {email: username}
                ]
            }
        }).then(function (authUser) {
            if (!authUser || !helpers.hashCompareSync(password, authUser.password)) {
                throw errors.types.invalidParams({
                    path: 'username', message: 'Invalid username and/or password'
                });
            }

            return models.Person.scope('nested').findOne({
                where: {
                    id: authUser.id
                }
            });
        }).then(function (user) {
            var duration = config.session.duration;
            var expires  = new Date(Date.now() + duration * 1000);
            var token    = jwt.sign(
                {user_id: user.get('id')},
                config.session.secret,
                {expiresIn: duration});

            return {
                user: user,
                token: token,
                expires: expires
            };
        });
    },

    verify: function (request) {
        return new Promise(function (resolve, reject) {
            // https://jwt.io/introduction/#how-do-json-web-tokens-work-
            var header  = request.headers && request.headers.authorization;
            var matches = header ? /^Bearer (\S+)$/.exec(header) : null;
            var token   = matches && matches[1];

            if (!token) {
                return reject(errors.types.unauthorized('No authorization token was found'));
            }

            jwt.verify(token, config.session.secret, function (err, decoded) {
                if (err) {
                    return reject(errors.fromJwtError(err));
                }

                models.Person.scope('nested').findOne({
                    where: {
                        id: decoded.user_id
                    }
                }).then(function (user) {
                    if (!user) {
                        throw errors.types.authTokenInvalid();
                    }

                    resolve({
                        user: user,
                        token: token,
                        expires: new Date(decoded.exp)
                    });
                }).catch(function (err) {
                    reject(err);
                });
            });
        });
    }
};
