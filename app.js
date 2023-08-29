require('dotenv').config()
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(express.json())
const mongoose = require("mongoose");
const md5 = require("md5")
const encrypt = require("mongoose-encryption")
const bcrypt = require('bcrypt');
const saltRounds = 10;
const session =  require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require("passport-google-oauth20").Strategy
const FacebookStrategy = require("passport-facebook")
const MicrosoftStrategy = require('passport-microsoft').Strategy;
const AmazonStrategy = require('passport-amazon').Strategy
const findOrCreate = require('mongoose-findorcreate')
app.use(session({
    secret: process.env.SECRETS, //For encrypting and signing the session data
    resave: false, //When a user triggers a session that is not needed
    saveUninitialized: true, //when a user comes into webpage without triggering a sesion but we want to save his session by must
    cookie: { secure: false } // ensures both http and https connection
  }))
app.use(passport.initialize());
app.use(passport.session());
const url = "mongodb://127.0.0.1:27017/userDB"
mongoose.connect(url, {
useNewUrlParser: true,
useUnifiedTopology:true }
)
const userSchema = new mongoose.Schema({
    username : String,
    password : String,
    googleId : String,
    googlePic : String,
    facebookId : String,
    microsoftId : String,
    amazonId : String,
    secret : String,
    isDeleted: { type: Boolean, default: false }
})
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)
//Mongoose Encryption works by encrypting when you call save and decrypting when you call find
console.log(process.env.SECRETS)
const secret = process.env.SECRETS
// userSchema.plugin(encrypt, { secret: secret,  encryptedFields: ['password']});
const userModel = mongoose.model("user", userSchema)
passport.use(userModel.createStrategy()); //passport plugin for local strategy
// passport.serializeUser(userModel.serializeUser());
// passport.deserializeUser(userModel.deserializeUser());//This version is only supported by the local strategy
passport.serializeUser(function(userModel, cb) {
    process.nextTick(function() {
      cb(null, { id: userModel.id, username: userModel.username });
    });
  });
  
  passport.deserializeUser(function(userModel, cb) {
    process.nextTick(function() {
      return cb(null, userModel);
    });
  });
  //passport plugin for google strategy
passport.use(new GoogleStrategy({ 
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    scope: ['profile', 'https://www.googleapis.com/auth/contacts.readonly'] // Add the contacts scope
  },
  function(accessToken, refreshToken, profile,  cb) {
    userModel.findOrCreate({ googleId: profile.id, googlePic : profile.photos[0].value }, function (err, userModel) {
      return cb(err, userModel);
    });
    console.log(profile)
    // console.log(refreshToken)
    // console.log(accessToken)
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret:process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    // profileFields: ['id', 'displayName', 'photos', 'email']
  },
  function(accessToken, refreshToken, profile, cb) {
    userModel.findOrCreate({ facebookId: profile.id }, function (err, userModel) {
      return cb(err, userModel);
    });
  }
));
passport.use(new MicrosoftStrategy({
  // Standard OAuth2 options
  clientID: process.env.MICROSOFT_CLIENT_ID ,
  clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/microsoft/secrets",
  scope: ['user.read'],

  // Microsoft specific options

  // [Optional] The tenant for the application. Defaults to 'common'. 
  // Used to construct the authorizationURL and tokenURL
  tenant: 'common',

  // [Optional] The authorization URL. Defaults to `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`
  authorizationURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',

  // [Optional] The token URL. Defaults to `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`
  tokenURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
},
function(accessToken, refreshToken, profile, done) {
  userModel.findOrCreate({ microsoftId: profile.id }, function (err, userModel) {
    return done(err, userModel);
  });
  console.log(accessToken);
  console.log(refreshToken)
}
));
passport.use(new AmazonStrategy({
  clientID: process.env.AMAZON_CLIENT_ID,
  clientSecret: process.env.AMAZON_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/amazon/secrets"
},
function(accessToken, refreshToken, profile, done) {
  userModel.findOrCreate({ amazonId: profile.id }, function (err, userModel) {
    return done(err, userModel);
  });
  console.log(accessToken)
  console.log(refreshToken)
}
));
app.get("/", (req, res)=>{
    res.render("home")
})
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets
    res.redirect('/secrets');
  });
  app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/facebook/secrets', passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });
  app.get('/auth/microsoft',
  passport.authenticate('microsoft', {
    // Optionally define any authentication parameters here
    // For example, the ones in https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

    prompt: 'select_account',
  }));
  app.get('/auth/microsoft/secrets', 
  passport.authenticate('microsoft', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrest.
    res.redirect('/secrets');
  });
  app.get('/auth/amazon', passport.authenticate('amazon', { scope: ['profile'] }));

app.get('/auth/amazon/secrets', 
  passport.authenticate('amazon', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/login", (req, res)=>{
    res.render("login")
})
app.get("/register", (req, res)=>{
    res.render("register")
})
app.get("/secrets", (req, res)=>{
    if(req.isAuthenticated()){
      userModel.find({secret : {$ne : null}})
      .then((data)=>{
        if(!data){
          res.render("secrets", {userSecrets : {secret : "No Secrets Yet"}})
          console.log("No Secrets Yet To Display")
        }
        else{
          res.render("secrets", {userSecrets : data})
        }
      })
      .catch((error)=>{
        console.log(error)
      })
    }
    else{
        res.redirect("/login")
    }
})
app.get("/logout", (req, res)=>{
    req.logOut((err)=>{
        if(err){
            console.log(err)
        }else{
        res.redirect("/")
        }
    })
   
    });

app.post("/register", (req, res)=>{
    //using bcrypt
    // const email = req.body.username;
    // // const password = md5(req.body.password);
    // const password = req.body.password;
    // bcrypt.hash(password, saltRounds, function(err, hash) {
    //     // Store hash in your password DB.
    //         // Store hash in your password DB.
    //         const entry = new userModel({
    //             email : email,
    //             password : hash
    //         })
    //         entry.save()
    //         .then((data)=>{
    //             res.render("secrets")
    //         })
    //         .catch((data)=>{
    //             console.log("Error In Registering user")
    //         })
    //     });
    userModel.register({username: req.body.username, active: true}, req.body.password, function(err) {
        if (err) {
            console.log(err)
    res.redirect("/register")
         }
         else{
passport.authenticate("local")(req, res, ()=>{
    res.redirect("/secrets")
})
}
    })
});
app.post("/login", (req, res)=>{
    //using bcrypt
    // const username = req.body.username
    // // const password = md5(req.body.password)
    // const password = req.body.password
    // userModel.findOne({email : username})
    // .then((data)=>{
    //     bcrypt.compare(password, data.password, function(err, result) {
    //         // result == true
    //         if(result === true){
    //             res.render("secrets")
    //         }
    //         else{
    //             res.render("login", {error : "Your password and username does not match"})
    //         }
    //     });
    // })
    // .catch((error)=>{
    //     console.log(error)
    // }) 
    const latestUser = new userModel({
        username : req.body.username,
        password: req.body.password
    })
req.login(latestUser, (err)=>{
    if(err){
    console.log(err)
    res.redirect("/login")
    console.log("You do not exist here")
    }
      else{
        passport.authenticate("local", { failureRedirect: '/login' })(req, res, ()=>{
            res.redirect("/secrets")
            console.log("success")
        })   
    }
})
})
app.get("/submit", (req, res)=>{
  if(req.isAuthenticated()){
    res.render("submit")
}
else{
    res.redirect("/login")
}
})
app.post("/submit", (request, response)=>{
  console.log(request.user);
  console.log(request.body.secret)
  userModel.findById({_id: request.user.id})
  .then((data)=>{
data.secret = request.body.secret
data.save()
.then(()=>{
  response.redirect("/secrets")
})
.catch((error)=>{
  console.log(error)
})
  })
.catch((error)=>{
  console.log(error)
})
    
})
app.get("/usercount", (req, res) => {
  userModel.countDocuments({ isDeleted: false })
.then((data)=>{
  res.render("userCount", {count : data})
})
.catch((error)=>{
  console.log(error)
})
});

app.listen(3000 || process.env.PORT, ()=>{
console.log("server is running on port 3000")
})
//Hash functions are mathematical equations that makes it almost impossible to revert to the real password
//plaintextOffenders.com
//passwordrandom.com
// npm install @version//So Far We Have Used
//mongoose-encryption
//md5
//bcrypt
//Packages For Passport JS
// passport require (second) and setup as second
// passport-local
// passport-local-mongoose require (last), add it as a plugin into the mongoose schema
// express-session-firstly install require (first) and setup first
//passport-local is required by passport-local-mongoose, so passport local is already part of passport-local-mongoose
//passport-local-mongoose will salt and hash our password without having you to do it yourself.