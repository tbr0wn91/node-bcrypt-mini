require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  app.set('db', db);
  console.log("db connected")
});


app.post('/auth/signup', (req, res, next) => {
  // set db = to req.app.get("db") so we have access to the datbase instance set up when we connected with massive
  const db = req.app.get("db")

  // destructure email and password from the body or the request
  const {email, password } = req.body;


  // before allowing someone to signup, we first want to see if they are lready in the database
  //if so , we dont want them to signup again so we send an error
  db.check_user_exists(email).then(user => {
    // database calls always return an array, so if we check the length of the returned array, it will tell us if a user is found i.e 1 = user found, 0= no user found
    if(user.length){
      // error message if eamil isn't found
      res.status(400).send("email already exists in database");
    }

    // else{
      // allow user to signup if no user was found
    const saltRounds = 12;
    // pass declared saltRounds to the genSalt function to get a unique salt value to be used when hashing our users password
    bcrypt.genSalt(saltRounds).then(salt => {
      // use the unique salt value and the password passed from req.body to generate a hashed password for the user
      bcrypt.hash(password, salt).then(hashedPassword => {
        //insert the email address  and the hashed password  into the database
        db.create_user([email, hashedPassword]).then(createdUser => {
          // return newly created user and set them to a session.user so they can begin their unique user experience
          req.session.user = {
            id: createdUser[0].id,
            email: createdUser[0].email
          };
          // send session to the front end
          res.status(200).send(req.session.user)
        });
      });


    });

    
    

  });
  

});


app.post('/auth/login', (req, res, next) => {
  const {email, password} = req.body;
  const db = req.app.get("db")

  db.check_user_exists(email).then(user => {
    if(!user.length){
      res.status(400).send("incorrect email/password")
    }
    else {
      bcrypt.compare(password, user[0].user_password).then(isAuthenticated => {
        if(isAuthenticated){
          req.session.user = {
            id: user[0].id,
            email: user[0].email
          }

          res.status(200).send(req.session.user)
        } else {
          res.status(400).send(`that is the incorrect email/password`)
        }
      })
    }
  })

})




app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
