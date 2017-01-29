/**
 * Created by User on 18/01/2017.
 */

const jwt = require('express-jwt');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const router = require('express').Router();
const providerOpts = ['auth0'];
const jwks = require('jwks-rsa');
var jwtDecode = require('jwt-decode');
const request = require('request');
var Promise = require('promise');

let authRoute;
let access_token;

function initStrategy(name, credentials) {
    let strategy;
    switch (name){
        case 'auth0':{
            const Auth0Strategy = require('passport-auth0');
            strategy = new Auth0Strategy({
                domain:       credentials.domain,
                clientID:     credentials.client_id,
                clientSecret: credentials.secret,
                callbackURL:  credentials.callback_url
            }, function(accessToken, refreshToken, extraParams, profile, done) {
                return done(null, extraParams);
            });

            break;
        }
    }
    // Configure Passport to use Auth0

    credentials = credentials;
    passport.use(strategy);
}

function initPassport() {
    router.use(passport.initialize());

    passport.serializeUser(function(user, done) {
        done(null, user);
    });

    passport.deserializeUser(function(user, done) {
        done(null, user);
    });
}

function initCookie() {
    router.use(cookieParser());
}

function initRoutes(providerName, credentials) {
    router.get('/login', passport.authenticate(providerName, { session: false }));

    router.get('/logout', function (req, res) {
        console.log('Logout...');
        res.redirect("https://" + credentials.domain + "/v2/logout?returnTo=" + req.protocol + '://' + req.get('host') + req.originalUrl + "callback&client_id=" +  credentials.client_id);
    });

    router.get('/callback', passport.authenticate(providerName, {
        session: false,
        failureRedirect: authRoute + '/login'
    }), function (req, res) {
        res.cookie('id_token', req.user.id_token).redirect('/');
    });

    router.get('/logoutcallback', function (req, res) {
        res.clearCookie("id_token");
        res.redirect('/');
    });

    return router;
}

module.exports = {
    jwt: function(options) {
        if(!options.cookieless){
            initCookie();
        }

        router.use(function (req, res, next) {
            if (options.excludeRoutes)
                for (let i = 0; i < options.excludeRoutes.length; i++)
                    if (req.path.startsWith(options.excludeRoutes[i]))
                        return next();

            if(authRoute){
                if (req.originalUrl.startsWith(authRoute))
                    return next();
            }

            jwt({
                secret: options.secret,
                audience: options.client_id || options.audience,
                getToken: function fromHeaderOrQuerystring(req) {
                    console.log("Validating Token...");
                    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
                        return req.headers.authorization.split(' ')[1];
                    } else if (req.cookies && req.cookies.id_token) {
                        return req.cookies.id_token;
                    }
                    return null;
                }
            })(req, res, next)
        });

        // Handle unauthorized
        router.use(function (err, req, res, next) {
            if (err.name === 'UnauthorizedError'){
                err.stack = "";
                console.log(`ShieldJS - UNAUTHORIZED`);
                res.status(401);
                next(err);
            }
        });

        return router;
    },
    authRoutes: function (options) {
        authRoute = options.authRoute ? options.authRoute : '/';

        if(options.provider && options.credentials){
            initPassport();
            initStrategy(options.provider, options.credentials);
            router.use(options.authRoute, initRoutes(options.provider, options.credentials));

            router.use(function (err, req, res, next) {
                if (res.statusCode === 401){
                    console.log(`ShieldJS Redirect to:  ${authRoute}/login!`);
                    return res.redirect(authRoute + '/login');
                }

                next();
            });
        }

        return router;
    },
    allowScopes: function(scopes){
        return function (req, res, next) {
            const has_scopes = scopes.every(function (scope) {
                return req.user.scope.indexOf(scope) > -1;
            });

            if (!has_scopes) { return res.sendStatus(401); }

            next();
        };
    },
    secretFromUrl: function(domain) {
        return jwks.expressJwtSecret({
            cache: true,
            rateLimit: true,
            jwksRequestsPerMinute: 5,
            jwksUri: `https://${domain}/.well-known/jwks.json`
        })
    },
    requestTokenForApi: function(api_url, credentials) {
        return new Promise(function (fulfill, reject) {
            if(!access_token || (jwtDecode(access_token)).exp >= new Date().getTime()){
                console.log("Requesting Token For API");
                var auth_opts = {
                    method: 'POST',
                    url: `https://${credentials.domain}/oauth/token`,
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({
                        client_id: credentials.client_id,
                        client_secret: credentials.secret,
                        audience: api_url,
                        grant_type: "client_credentials"
                    })
                };

                request(auth_opts, function(err, res) {
                    if(err) reject(err);
                    if(res.statusCode == 200){
                        const body = JSON.parse(res.body);
                        access_token = body.access_token;
                        fulfill('Bearer ' + access_token);
                    }
                })
            }

            else
                fulfill('Bearer ' + access_token);
        })
    }
}