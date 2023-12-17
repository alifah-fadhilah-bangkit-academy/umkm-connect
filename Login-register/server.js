const express = require('express')
const app = express();
const port = process.env.PORT || 3000;
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const gensalt = bcrypt.genSaltSync(saltRounds)
const jwt = require('jsonwebtoken')

app.use(express.json())

const db = mysql.createConnection({
    host:'localhost',
    user:'root',
    password:'',
    database:'db_uconnect'
})

db.connect((err) =>{
    if (err) throw err;
    console.log('Databases connected')
}) 


const isAuthorized = (req, res, next) => {
    const token = req.headers.authorization;
    const splitToken = token.split(' ')[1];
    if(token == null) {
        return res.status(401).json ({
            msg: "Unauthorized"
        })
    }
jwt.verify(splitToken, 'secret', (err, result) => {
    if (err) {
        return res.status(401).json({
            msg: 'Unauthorized'
        })
    }
    req.user = result;
    next()
})
}

app.post('/register', (req, res) => {
    const {username, email, password, confirmPassword} = req.body;
    if (!username || !email || !password || !confirmPassword ){
        return res.status(400).json({
            msg:"harap isi semua"   
        })
    }
    if(password !== confirmPassword){
        return res.status(400).json({
         msg: "password anda berbeda"
         })
     }
     const queryEmail = "SELECT * from tb_login WHERE email = ?";
     db.query(queryEmail,[email], (err, result)=> {
     if (err) throw err;
     if (result.length > 0) {
        return res.status(400).json ({
            msg: 'email sudah digunakan'
        })
     }
     const query = "INSERT INTO tb_login (username, email, password) VALUES (?, ?, ?)";
     db.query(query, [username, email, bcrypt.hashSync(password, saltRounds)], (err, result) => {
       if(err) throw err;
       return res.status(201).json({
        msg: "user berhasil ditambahkan"
            })
        })
    })
})

app.post('/login', (req, res) => {
    const {email, password} = req.body;
    const cekEmail = "SELECT * FROM tb_login WHERE email = ?";
    db.query(cekEmail, [email], (err, result) => {
        if(err) throw(err);
        if(result.length === 0) {
            return res.status(400).json ({
                msg: "email tidak ditemukan"
            })
        }
    const cekPassword = bcrypt.compareSync(password, result[0].password);
    if (!cekPassword) {
        return res.status(400).json({
            msg: "password tidak valid"
        })
    }
    const token = jwt.sign ({
        id: result[0].id,
        email: result[0]
    }, 'secret', {expiresIn: '1d'} );

    return res.status(200).json( { 
        msg: "login berhasil",
        token
    })
    })
})

app.get('/getuser', (req, res) => {
    const query = "SELECT * FROM tb_login";
    db.query(query, (err, result) => {
        if (err) throw err;
        return res.status(200).json({
            data: result
        })
    })
})

app.get('/profile', isAuthorized, (req, res) => {
    return res.status(200).json({
        user: req.user
    });
});

app.listen(port, () =>{
    console.log(`server is running on port ${port}`)
})