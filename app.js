require('dotenv').config()
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(express.json())
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption")
const url = "mongodb://127.0.0.1:27017/userDB"
mongoose.connect(url, {
useNewUrlParser: true,
useUnifiedTopology:true }
)
const userSchema = new mongoose.Schema({
    email : String,
    password : String
})
//Mongoose Encryption works by encrypting when you call save and decrypting when you call find
//Level 2 Authentication
console.log(process.env.SECRETS)
const secret = process.env.SECRETS
userSchema.plugin(encrypt, { secret: secret,  encryptedFields: ['password']});
const userModel = mongoose.model("user", userSchema)
app.get("/", (req, res)=>{
    res.render("home")
})
app.get("/login", (req, res)=>{
    res.render("login", {error : null})
})
app.get("/register", (req, res)=>{
    res.render("register")
})
app.post("/register", (req, res)=>{
    const email = req.body.username;
    const password = req.body.password;
    const entry = new userModel({
        email : email,
        password : password
    })
    entry.save()
    .then((data)=>{
        res.render("secrets")
    })
    .catch((data)=>{
        console.log("Error In Registering user")
    })
})
//Level one authentication 
app.post("/login", (req, res)=>{
    const username = req.body.username
    const password = req.body.password
    userModel.findOne({email : username})
    .then((data)=>{
        if(data.password === password){
            console.log(data.password)
            res.render("secrets")
        }
        else{
            res.render("login", {error : "Your password and username does not match"})
        }
    })
    .catch((error)=>{
        console.log(error)
    })
})
app.listen(3000, ()=>{
console.log("server is running on port 3000")
})