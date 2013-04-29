"use strict";

// Multiple changes from https://github.com/c4milo/connect-basic-auth:
//
// 1. Change req.remoteUser to req.user
//    <https://github.com/visionmedia/express/issues/1145>
// 2. When authentication successful, return entire user object
//    instead of just username (57)
// 3. Print out error if given one (51)
//
// Done by eshao on 1 Dec 2012

module.exports = function (callback, realm) {
    if (!callback || typeof callback != 'function') {
        throw new Error('You must provide a function ' +
        'callback as the first parameter');
    }

    realm = realm ? realm : 'Authorization required.';

    function unauthorized(res, sendResponse) {
        res.statusCode = 401;
        res.setHeader('WWW-Authenticate', 'Basic realm="' + realm + '"');

        if (sendResponse) {
            res.end('Unauthorized');
        }
    }

    return function(req, res, next) {
        req.requireAuthorization = function(req, res, next) {
            var authorization = req.headers.authorization;

            if (req.user) return next();
            if (!authorization) return unauthorized(res, true);

            var parts = authorization.split(' ');
            var scheme = parts[0];
            if ('Basic' != scheme) {
                return next(new Error('Authorization header ' +
                'does not have the correct scheme. \'Basic\' ' +
                'scheme was expected.'));
            }

            var _credentials = new Buffer(parts[1], 'base64').toString().split(':');

            var credentials = { username: _credentials[0],
                                password: _credentials[1] };

            callback(credentials, req, res, function(err, user) {
                if (err) {
//                    unauthorized(res);
                      res.jsonp(err.statusCode || 500, err.serialize())
                    next(err);
                    return;
                }

                req.user = user
                next();
            });
        };
        next();
    };
};

