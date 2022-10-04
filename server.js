
// the traditional way is using sessions and session cookies
// once the client sends a POST request to the server with their login information in the POST request's body (JSON object), the server stores the session id in the server memory
// this session ID is sent as a cookie to the client and is stored locally on the client
// whenever the client sends a http request to the server, the session cookie is sent along with it, and the server verifies if the session cookie exists in the server memory and if it's expired or not, based off this, it sends back the relevant information



// the new way of doing it with JWT is...
// once the client sends a POST request to the server with their login information in the POST request's body (JSON object)
// the server creates a JWT for the user
// the JWT has 3 parts, seperated by full stops, the first part doesn't matter much. The middle part is a encrypted version of the login information itself. So the JSON object that was sent in the POST request's body has been encoded into a single string that is seemingly random
// this JWT is sent to the client and stored on the client just like a session cookie
// whenever the client sends a http request to the server, the JWT is sent along with it, we then you an authentication middleware, which is just a function that is run before every http request of our choosing, which authenticates this JWT
// if the JWT is verified successfully in the authentication process, it is decoded by using a secret key that is only available on the server (because our local device is the server, this secret key is located in the .env file on our device)
// the decoded response is sent to the client



// the massive difference here is, when using JWT, there is no need for session information to be stored on the server, all the information is stored on the client itself, it's just encrypted so no one can find out what it actually is
// if someone tampers with the JWT, once it's sent back to the server, the authentication process fails, and therefore the information won't be sent back



// when a JSON object that contains information is turned into a JWT, that process is called serialization
// when a JWT is decoded, that's called deserialization



// the user information is stored within the token itself, that token is stored on the client, and once it expires, it's no longer stored on the client
// the JWT is just sent along with every http request to the server, the server verifies the JWT with the secret key that is stored on the server and if it checks out, then the information is decoded and sent back to the user

// require .env package
require('dotenv').config()

// require express
const express = require('express')

// require jwt
const jwt = require('jsonwebtoken')

// create express app
const app = express()

// json middleware
app.use(express.json())

// create array of objects to mirror database
const posts = [
    {
        username: 'Kyle',
        title: 'Post 1'
    },
    {
        username: 'Jim',
        title: 'Post 2'
    },
    {
        username: 'Ishan',
        title: 'Post 3'
    }
]

// create an array of refresh tokens, this is mirroring a database where a list of refresh tokens would be present
let refreshTokenList = []



// create authentication middleware
// most http requests that are sent to the server by the client will include the JWT, you need to verify that JWT, best way to do that is to create an authentication middleware function that runs before every http route
const authenticateToken = (req, res, next) => {
    // the token will be in the authorization header
    // authHeader is a string that says 'BEARER tokenString'
    const authHeader = req.headers['authorization']

    // in order to just get the token part from 'BEARER tokenString' we split the string where there is a space and get the second element in that array
    // also check if authHeader exists, if it exists, then return authHeader.split(' ')[1], if it doesn't exist, then return undefined
    const token = authHeader && authHeader.split(' ')[1]

    // check if token exists, if not, send back an error to the client
    if(token == null) return res.status(401).send('You did not send a token with your request')

    // at this point we know the JWT definitely exists, now it's time to check if that JWT is the same as it always was or if it's been tampered with
    // now it's time to verify the token with the secret key we have on our local device (our server), if the JWT hasn't been tampered with and the secret key on the server is the same, the jwt will be verified
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, data) => {
        // this is a callback function that is executed when the verification process is completed

        // if the verification did not work, there was an error and we need to send something back in that case, we need to make sure the http request route logic is not executed, so something needs to be sent back here
        if(err) return res.status(403).send('You have a JWT token, but the token is no longer valid so you no longer have access')

        // if we get to this point, we know we have a valid JWT and the verification process was successful
        // the information that was stored on the JWT is the data variable, in this case, it was the login information of the user stored in an object
        // now all we have to do is add a user property to the req object and make that equal data
        // now, in our http request routes, we have access to req.user
        req.user = data

        // move to the next middleware or the http route logic
        next()
    })
}



// function that generates an access token
// all this function does is take in a userObject, which will just be an object that has user information in it, in this case it will be an object with a user's login information, and it returns an accessToken for that userObject, signed with the secret key, also giving it an expiration of 15 seconds
// the expiration of JWTs is built-in, you don't have to write logic to make it expire, just specify when you create that JWT how long you want it to last (expiresIn)
const generateAccessToken = (userObject) => {
    return jwt.sign(userObject, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' })
}



// get all posts
// if you want to test JWT tokens in insomnia, when you send a request, under the AUTH tab, click 'Bearer Token'
// put the token on top and write 'Bearer' for prefix
app.get('/posts', authenticateToken, (req, res) => {
    // this filters out and only retrieves the post whose username matches what was sent by the user in the JWT
    res.json(posts.filter(post => post.username === req.user.username))
})




// here we are mirroring a user logging in on a website
// all that's happening is the user submits a form, and then a POST request is sent to the server (backend), that POST http route is handled here, and the JWT authentication occurs here as well
app.post('/login', (req, res) => {
    // extract username from request body
    const username = req.body.username

    // create user object that has all the information the user posted to us
    const userObject = {
        username: username
    }

    // create JSON web token
    // the first argument is the userObject and the second argument needs to be a secret key which we get from our .env file
    // the best way to create a secret key is to use the built-in crypto library
    // go to a terminal and type the following to get a secret key
    // require('crypto').randomBytes(64).toString('hex')
    // what will be returned is a random string
    // we are signing this JWT with the secret key that is only on the server
    const accessToken = generateAccessToken(userObject)

    // we need to create a refresh token as well
    // we get REFRESH_TOKEN_SECRET from the built-in crypto library as well
    // the problem with just having an accessToken is that it never expires, if a bad actor gets access to someone's JWT, they will have access to that user's information forever, so it's essential that the accessToken has a reasonable expiration date
    // the refreshToken is used to get a new accessToken
    const refreshToken = jwt.sign(userObject, process.env.REFRESH_TOKEN_SECRET)

    // push refreshToken into refreshTokenList
    refreshTokenList.push(refreshToken)
    
    // return a json object with accessToken and refreshToken
    res.json({ accessToken: accessToken, refreshToken: refreshToken })
})



// create POST route for creating a token
app.post('/createtoken', (req, res) => {
    // extract refresh token from body of POST request
    const refreshToken = req.body.token

    // if the body did not contain a refresh token, return an error
    if(refreshToken == null) return res.status(401).send('Refresh token not sent in POST request')

    // if the refresh token sent in the body is not in the refreshTokenList array, then return an error
    if(!refreshTokenList.includes(refreshToken)) return res.status(403).send('Refresh token that was sent is not a valid refresh token')

    // if you get to this point and pass the two guard clauses above, then you can actually verify the refreshToken that was sent in the body of this POST request
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, data) => {
        // if there is an error in the verification process, return an error
        if(err) return res.status(403).send('Error occured during verification of refresh token')

        // now that all those guard clauses have been passed, we can create a new accessToken
        const accessToken = generateAccessToken({ username: data.username})

        res.json({ accessToken: accessToken})
    })
})



// when a user logs out, we need to delete the JWT
app.delete('/logout', (req, res) => {
    // alter refreshTokenList so that it removes the token related to the user that is logging out (basically deleting JWT for a user once their session is closed by the user themselves)
    // when the user logs out, in the DELETE request body, a JSON object is sent that contains the refreshToken that was relevant to their session, so then we delete that from the refreshTokenList array
    refreshTokenList = refreshTokenList.filter(token => token !== req.body.token)

    // send back a successful status
    res.status(204).send('Log out successful, associated JWT(s) deleted')
})



// listen on port 3000
app.listen(3000)