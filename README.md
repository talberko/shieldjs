<p align="center">
  <img src='https://cloud.githubusercontent.com/assets/25296482/22207186/d3d2a126-e186-11e6-9dc4-33b5e7aa84fe.png' height=250 />
</p>
---
# What is ShieldJS
#### ShieldJS makes it easier than ever to secure your server with auth2 and jwt. 
###### Currently, we only support auth0 (<https://www.auth0.com>) as auth2 provider. You are welcome to commit another provider's support to our library :)

# How ShieldJS Works?
#### The library contains two security parts:
1. JWT Middleware - By using ShieldJS, your server routes will be totally secured by JWT (JSON Web Token). This middleware will look for a bearer token in the request header, and if not found will look for it in the cookie.
2. Auth Routes - shieldJS will create the standard auth2 authentication routes for you. 

# What do I have to do?
1. Choose your auth2 provider. For now, we only support auth0 provider (<https://www.auth0.com>), and register.
2. Install ShieldJS.
3. Use ShieldJS as middleware.
4. Initialize ShieldJS with your provider's application data.
5. Be Secured :)

# How to implement?
#### Install ShieldJS from npm:

```bash
$ npm install --save shieldjs
```

#### Require ShieldJS, and use it as middleware for your app:
```js

const express = require('express');
const shield = require("shieldjs");

const app = express();

// Will be used as JWT Middleware
app.use(shield.jwt(
    {
        excludeRoutes: ['/abc'],
    	domain: AUTH0.DOMAIN,
    	client_id: AUTH0.CLIENT_ID,
    	secret: AUTH0.CLIENT_SECRET
    }
));

// Will create routes for authentication
app.use(shield.authRoutes({
    authRoute: '/auth',
    provider: 'auth0',
    credentials:{
        domain: AUTH0.DOMAIN,
        client_id: AUTH0.CLIENT_ID,
        secret: AUTH0.CLIENT_SECRET,
        callback_url: AUTH0.CALLBACK_URL
    }
}))
```

#### If authRoute will not be provided, not authentication routes will be created!

#### Authentication routes will be created in this example:
1. /auth/login
2. /auth/logout
3. /auth/callback
4. /auth/logoutcallback
