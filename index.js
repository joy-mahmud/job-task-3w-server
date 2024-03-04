const express = require('express')
const app = express()
const cors = require('cors')
require('dotenv').config()
require('./db/connect')
var jwt = require('jsonwebtoken');
const port = process.env.PORT || 5000
const session = require('express-session')
const passport = require('passport')
const userDb = require('./model/userSchema')
const Oauth2Strategy = require('passport-google-oauth2').Strategy
const clientId = "1071073887434-lrkgoi5ugtdg22eb5h7au0co8tvicvbp.apps.googleusercontent.com"
const clientSecret = "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"
//middleware
app.use(cors({
    //origin:['https://foodfun-5c49a.web.app','https://foodfun-5c49a.firebaseapp.com'],
    origin: ['http://localhost:3000'],
    credentials: true
}))
app.use(express.json())

//setup session
app.use(session({
    secret: '46755858dhdhcnnvjdhjfhfjfhfh',
    resave: false,
    saveUninitialized: true
}))

// setup passport
app.use(passport.initialize())
app.use(passport.session())
//use passport
passport.use(
    new Oauth2Strategy({
        clientID: clientId,
        clientSecret: clientSecret,
        callbackURL: "/auth/google/callback",
        scope: ["profile", "email"]
    },
        async (accessToken, refreshToken, profile, done) => {
            try {
                let user = await userDb.findOne({ googleId: profile.id });
                console.log(profile.displayName)
                if (!user) {
                    user = new userDb({
                        googleId: profile.id,
                        displayName: profile.displayName,
                        email: profile.emails[0].value,
                        image: profile.photos[0].value,
                        password: '',
                        role:'user'
                    });

                    await user.save();
                }

                return done(null, user)
            } catch (error) {
                return done(error, null)
            }
        }
    )
)

passport.serializeUser((user, done) => {
    done(null, user);
})

passport.deserializeUser((user, done) => {
    done(null, user);
});

// initial google ouath login
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback", passport.authenticate("google", {
    successRedirect: "http://localhost:3000",
    failureRedirect: "http://localhost:3000/signin"
}))

//login success checking
app.get("/login/sucess", async (req, res) => {

    if (req.user) {
        res.status(200).json({ message: "user Login", user: req.user })
    } else {
        res.status(400).json({ message: "Not Authorized" })
    }
})
//handling logout
app.get("/logout", (req, res, next) => {
    req.logout(function (err) {
        if (err) { return next(err) }
        res.redirect("http://localhost:3000");
    })
})
//creating users by email and password
//middleware
const verifyToken = (req, res, next) => {
    if (!req.body.authorization) {
        return res.status(401).send({ message: 'forbidden access' })
    }

    const token = req.body.authorization.split(' ')[1]
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: 'forbidden access' })
        }

        req.decoded = decoded
        next()
    })
}
//create new user
app.post('/users', async (req, res) => {
    const user = req.body
    const email = user.email
    // console.log(user)
    //checking user exist or not
    const query = { email: user.email }
    const existingUser = await userDb.findOne(query)
    if (existingUser) {
        return res.send({ message: 'user already exist', insertedId: null })
    }
    const newUser = new userDb(user)
    const result = await newUser.save()
    const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
    // console.log({ ...result, token })
    res.send({ ...result, token })
})
//login user
app.post('/login', async (req, res) => {
    const user = req.body
    const email = user.email
    const password = user.password
    const query = { email: email }
    const userInfo = await userDb.findOne(query)
    if (userInfo) {

        // console.log("cp",password,userInfo.password)
        if (password === userInfo.password) {
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
            res.send({ ...userInfo, authorization: 'ok', token })
        } else {
            res.send("password doesn't match")
        }
    }
    else {
        res.send('register first')
    }
})
//authorization
app.post('/checkUser',verifyToken,async(req,res)=>{
    const userEmail = req.decoded.email
    console.log(userEmail)
    const query = {email:userEmail}
    const user = await userDb.findOne(query)
    const name =user.name
    const email = user.email
    const image =user.image
    const role = user.role
    const result ={name,email,image,role}
    res.send(result)
})


app.get('/', (req, res) => {
    res.send('Faucet server is running')
})

app.listen(port, () => {
    console.log(`faucet server is running on ${port}`)
})