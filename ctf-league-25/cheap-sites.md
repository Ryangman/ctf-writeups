# CTF League - cheap-sites

## Flag 1
The first flag can be found from the `/reserve` endpoint the site exposes to reserve a room, among other verification, the site times the users actions while making the reservation, and rejects the booking if the user takes longer than 0.125 seconds. 

```js
app.get('/reserve', (request, response, next) => {
    // If we didn't get the needed parameters, handle as a static file
    if (!request.query.time || !request.query.room) {
        next();
    }
    ...

    // If they solved the Turing Test too slow, they're probably an AI model trying to figure it out
    if (time > 0.125) {
        return response.send("That took wayyy too long, are you AI?");
    }
    ...

    response.send(`You successfully booked room ${room}. Your confirmation code is ${process.env.FLAG_1}; please show this to the front desk to pick up your key.`);
});

```
However, because this happens on the client before the request is fired, we can modify the body of the request like so `{"time": 0.01, "room": 101 }`, and make the verification check pass, receiving the first flag.

## Flag 2
The second flag is presented in the `getAdminPassword` method, a function that is exported from the `admin.js` file. If we can trigger this function with the parameter `email`, we will get the flag.

```js
    getAdminPassword({ type }) {
        switch (type) {
            ...
            case 'email':    return process.env.FLAG_2;
            default:         return 'Invalid password';
        }
    },
```

Since the `getAdminPassword` function is in the `module.exports` field of `admin.js`, when the module is imported in `server.js`, the `getAdminPassword` method becomes bound in the api endpoints namespace.

```js
const admin = require('admin.js')

...

// Route to perform admin actions
app.post('/admin', async (request, response) => {
    try {
        const action = 'action' in request.body ? request.body.action : null;
    
        if (!action || !admin.verifyAction(action)) {
            return response.status(400).send('Invalid action');
        }
    
        // Received feedback that we need to be more DRY, so simplified from a huge if/else
        const result = await admin[action](request['body']);
        response.send(result);
    }
    catch (err) {
    }
});
```

Looking at the `/admin` route, there is no authentication/authorization, other than the `admin.verifyAction` which simply checks if the requested `action` is in the `this` namespace, which anything exported from `admin.js`, including our getAdminPassword`, would pass.

The line `await admin[action](request['body']);`is of particular interest, since it simply passes all elements of the request body to an exported function from `admin.js` of the name we request with the 'action' argument.

This means we can send a request to the `/admin` endpoint requesting the getAdminPassword method be invoked with whatever fields we like as such:

```json
{ "action": "getAdminPassword", "type": "email"}}
```

Which will grant us the second flag


## Flag 3
The final flag is present in another method from the `admin.js` exports `sendEmail`:

```js
    // We can save a variable definition by including the variable in the function header!
    async sendEmail({ adminPassword, recipient, subject, environment = process.env['NODE_ENV'] }) {
        if (environment == 'production')
            return `Could not email ${recipient}: email server not configured`

        // We'll actually start sending emails here once the school sets up an email server
        if (!await verifyPassword(adminPassword, this.getAdminPassword({ type: 'website' })))
            return 'You must be an admin to do that';
        
        if (!recipient || !subject) return 'Missing to/subject';

        // TODO: Add email logic here

        return `Email queued to ${recipient} (${subject}) with ID ${process.env.FLAG_3}`;
    },
```
Unfortunately, we only have a method of getting the hash for the admin password, not the password itself, but knowing that the flag is in `process.env.FLAG_3` does help us. Especially considering the grantAdmin route allows us to leak env vars.

```js
async grantAdmin({ adminPassword, user, env = 'NODE_ENV', environment = process.env[env] }) {
    if (environment != 'production')
        return `Cannot grant admin rights in the ${environment} environment`;
    ...
}
```

In addition to the `env.key` format, you can also index the env as an array like `env[key]`, since this function is exported the same way as `getAdminPassword` we can invoke it the same way, and provide the key `FLAG_3`


Filling in those fields of the request, and supplying arbitrary data for other fields we can submit the following payload for the flag:
```json
{"action":"grantAdmin", "adminPassword":"password123", "grant_admin_user":"asdf", "env":"FLAG_3"}
```