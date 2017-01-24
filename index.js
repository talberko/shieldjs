const jwt = require('express-jwt');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const router = require('express').Router();
const providerOpts = ['auth0'];

let Provider;
let authRoute;

function initStrategy(name, provider) {
    let strategy;
    switch (name){
        case 'auth0':{
            const Auth0Strategy = require('passport-auth0');
            strategy = new Auth0Strategy({
                domain:       provider.DOMAIN,
                clientID:     provider.CLIENT_ID,
                clientSecret: provider.CLIENT_SECRET,
                callbackURL:  provider.CALLBACK_URL
            }, function(accessToken, refreshToken, extraParams, profile, done) {
                return done(null, extraParams);
            });

            break;
        }
    }
    // Configure Passport to use Auth0

    Provider = provider;
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

function initRoutes(providerName) {
    router.get('/login', passport.authenticate(providerName, { session: false }));

    router.get('/logout', function (req, res) {
        console.log('Logout...');
        res.redirect(`https://${Provider.DOMAIN}/v2/logout?returnTo=${req.protocol}://${req.get('host')}${req.originalUrl}callback&client_id=${Provider.CLIENT_ID}`);
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

module.exports = function(options) {
    if(!options.cookieless) {
        initCookie();
    }

    authRoute = options.authRoute ? options.authRoute : '/';

    // Init passport and strategy
    if(options.providers) {
        initPassport();
        for(let provider in options.providers){
            if(providerOpts.includes(provider)) {
                initStrategy(provider, options.providers[provider]);
                router.use(options.authRoute, initRoutes(provider));
                break;
            }
        }
    }

    router.use(function(req, res, next) {
        if (options.excludeRoutes) {
            for (let i = 0; i < options.excludeRoutes.length; i++) {
                if (req.path.startsWith(options.excludeRoutes[i])) {
                    return next();
                }
            }
        }

        jwt({
            secret: Buffer.from(Provider.CLIENT_SECRET),
            audience: Provider.CLIENT_ID,
            getToken: function fromHeaderOrQuerystring(req) {
                console.log("Getting Token...");
                const auth = req.headers.authorization && req.headers.authorization.split(/\s+/);
                if (auth && auth[0] === 'Bearer') {
                    return auth[1];
                } 
                if (req.cookies && req.cookies.id_token) {
                    return req.cookies.id_token;
                }
                return null;
            }
        })(req, res, next)
    });

    // Handle unauthorized
    router.use(function (err, req, res, next) {
        if (err.name === 'UnauthorizedError') {
            options.unauthorizedFunc ? options.unauthorizedFunc(req, res, next) : res.redirect(`${authRoute}/login`);
        }
    });

    return router;
}
