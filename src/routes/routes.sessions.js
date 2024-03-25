// Imports

import { Router } from 'express';
import { usersModel } from '../dao/models/users.model.js';
import crypto from 'crypto'


// Definitions

export const router = Router()

// Middlewares

function auth (req, res, next) { // Middleware to check if a user is authenticated
  console.log('Req Session on ROUTER Sessions', req.session.user)
  if (!req.session.user){
    res.setHeader('Content-Type', 'application/json');
    return res.status(401).json({error: 'Not authorized. There are no logged in users, go to /login'})
  }
  next();
}

// Methods

router.post('/login', async (req,res) => {
  let {email, password} = req.body; // Load the name and password from the form body
  if(!email || !password) {
    return res.redirect('/login?error=Complete all the required fields');
  }
  password = crypto.createHmac('sha256', 'CoderCoder').update(password).digest('hex'); // Hash password
  try {
    let findUser = await usersModel.findOne({email, password});
    if (!findUser) { // User not found
      return res.redirect(`/login?error=User and password credentials not found`)
    } 
    req.session.user={ // We create a user session that stores the user that logged in
      name: findUser.name,
      email: findUser.email,
      role: findUser.role
    } 
    console.log("Req session on LOGIN: ", req.session)
    return res.redirect('/products')
  } catch (error) {
    console.log(error)
    return res.redirect('/login?error=Unexpected error in login')
  }

})


router.post('/signup', async (req,res) => {
  let {name, age, email, password, role='user'} = req.body; // Load the name and password from the URL query
  if(!email || !password || !age || !name) {
    return res.redirect('/signup?error=Complete all the required fields');
  } else {
    try {
      let findUser = await usersModel.findOne({email});
      if (findUser) {
        return res.redirect(`/signup?error=Email ${email} already exists`)
      } 
      password = crypto.createHmac('sha256', 'CoderCoder').update(password).digest('hex');
      let newUser = await usersModel.create({name, age, email, password, role})
      console.log('New User: ', newUser)
      req.session.user=newUser // We create a user session that stores the user that logged in
      console.log('Req session on LOGIN: ', req.session);
      return res.redirect(`/login?message=Account ${email} created`);
    } catch (error) {
      console.log(error)
      return res.redirect('/signup?error=Unexpected error in signup')
    }
  }
})

router.get('/data', auth, async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  try {
    res.status(200).json({
      message: 'Success'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/logout', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  try {
    req.session.destroy();
    return res.redirect(`/login?message=You have logged out`);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});





