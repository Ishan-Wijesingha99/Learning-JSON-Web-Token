
require('dotenv').config()

const express = require('express')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const posts = [
    {
        username: 'Kyle',
        title: 'Post 1'
    },
    {
        username: 'Jim',
        title: 'Post 2'
    },
]

app.get('/post', (req, res) => {
    res.json(posts)
})


// create authentication middleware
const authenticateToken = (req, res, next) => {
    // the token will be in the authorization header
    // authHeader is a string that says 'BEARER token'
    const authHeader = req.headers['authorization']

    // in order to just get the token part from 'BEARER token' we split and get the second element in that array
    // also check if authHeader exists, if it exists, then return authHeader.split(' ')[1], if it doesn't exist, then return undefined
    const token = authHeader && authHeader.split(' ')[1]

    // check if token exists
    if(token === null) return res.status(400).send('Error')


    // at this point we know the token definitely exists
    // now it's time to verify the token with the secret key we have on our local device (our server)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
}


// here we are mirroring a user logging in on a website
// all that's happening is the user submits a form, and then a POST request is sent to the server (backend), that post http route is handled here, and the jwt authentication occurs here as well
app.post('/login', (req, res) => {
    // authenticate user
    const username = req.body.username

    // create user object that has all the information the user posted to us
    const userObject = {
        name: username
    }

    // create JSON web token
    // the first argument is the userObject and the second argument needs to be a secret key which we get from our .env file
    // the best way to create a secret key is to use the built in crypto library
    // go to a terminal and type the following to get a secret key
    // require('crypto').randomBytes(64).toString('hex')
    // what will be returned is an access token that is different to ACCESS_TOKEN_SECRET
    const accessToken = jwt.sign(userObject, process.env.ACCESS_TOKEN_SECRET)

    
    res.json({ accessToken: accessToken})
})

app.listen(3000)