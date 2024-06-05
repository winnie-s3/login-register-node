// config inicial
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Config JSON repsonse
app.use(express.json())

// Models
const User = require('./models/User')

// Open Route - Public Route
app.get('/', (req, res) => {
  res.status(200).json({msg: 'Bem vindo a API de login e registro de usuários!'})
})

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {

  const id = req.params.id

  // Check if user exists
  const user = await User.findById(id, "-password")

  if(!user) {
    return res.status(404).json({msg: 'Usário não encontrado'})
  }

  res.status(200).json({user})
})

function checkToken(req, res, next) {

  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if(!token) {
    return res.status(401).json({msg: 'Acesso negado!'})
  }

  try {

    const secret = process.env.SECRET

    jwt.verify(token, secret)

    next()

  } catch(error) {
    res.status(400).json({msg: 'Token inválido!'})
  }

}

// Register User
app.post('/auth/register', async(req, res) => {

  const { name, email, password, confirmpassword } = req.body

  // Validation
  if(!name) {
    return res.status(422).json({msg: 'Nome obrigatório'})
  }

  if(!email) {
    return res.status(422).json({msg: 'Email obrigatório'})
  }

  if(!password) {
    return res.status(422).json({msg: 'Senha obrigatória'})
  }

  if (password !== confirmpassword) {
    return res.status(422).json({msg: 'As senhas precisam ser iguais'})
  }

  // Check if user exists
  const userExists = await User.findOne({ email: email })

  if(userExists) {
    return res.status(422).json({msg: 'Por favor, utilize outro email'})
  }

  // Create password
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  // Create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  })

  try {

    await user.save()

    res.status(201).json({ msg: 'Usário criado com sucesso!' })

  } catch(error) {
    console.log(error)

    res.status(500).json({msg: 'Erro no servidor'})

  }
})

// Login User
app.post('/auth/login', async(req, res) => {

  const { email, password } = req.body

  // Validation
  if(!email) {
    return res.status(422).json({msg: 'Email obrigatório'})
  }

  if(!password) {
    return res.status(422).json({msg: 'Senha obrigatória'})
  }

  // Check if user exists
  const user = await User.findOne({ email: email })

  if(!user) {
    return res.status(404).json({msg: 'Usário não encontrado'})
  }

  // Check if password match
  const checkPassword = await bcrypt.compare(password, user.password)

  if(!checkPassword) {
    return res.status(404).json({msg: 'Senha inválida'})
  }

  try {

    const secret = process.env.SECRET

    const token = jwt.sign({
      id: user._id
    },
    secret,
  )

  res.status(200).json({msg: 'Autenticado com sucesso!', token})


  } catch(error) {
    console.log(error)

    res.status(500).json({
      msg: 'Erro no servidor'
    })
  }

})

// Credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@salon-booking.qc6oola.mongodb.net/?retryWrites=true&w=majority&appName=salon-booking`,
  )
  .then(() => {
    app.listen(3000)
    console.log('Conectou ao banco!')
  })
  .catch((err) => console.log(err))