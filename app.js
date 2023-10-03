const express = require('express');
const app = express();

app.use(express.urlencoded({extended:false}));
app.use(express.json());

const dotenv = require('dotenv');
dotenv.config({path:'./env/.env'});

app.use('/resources', express.static('public'));
app.use('resources', express.static(__dirname + '/public'));
console.log(__dirname);

app.set('view engine', 'ejs');

const bcryptjs = require('bcryptjs');

const session = require('express-session');
app.use(session({
    secret:'secret',
    resave: true,
    saveUninitialized: true
}));

//invocacion al modulo de conexion a la base de datos
const connection = require('./database/db');


//ENDPOINTS

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

//registro
app.post('/register', async (req, res) => {
    const user = req.body.user;
    const name = req.body.name;
    const rol = req.body.rol;
    const pass = req.body.pass;
    let passwordHaash = await bcryptjs.hash(pass, 8);
    connection.query('INSERT INTO users SET ?', {user:user, name:name, rol:rol, pass:passwordHaash}, async(error, results) => {
        if(error){
            console.log(error);
        }else{
            res.render('register', {
                alert:true,
                alertTitle:"Registration",
                alertMessage: "Successfull registration!",
                alertIcon:'success',
                showConfirmButton:false,
                timer:1500,
                ruta:''
            });
        }
    });
});


//Autenticacion
app.post('/auth', async(req, res) => {
    const user = req.body.user;
    const pass = req.body.pass;
    // let passwordHaash = await bcryptjs.hash(pass, 8);
    if(user && pass){
        connection.query('SELECT * FROM users WHERE user = ?', [user], async(error, results) => {
            if(results.length == 0 || !(await bcryptjs.compare(pass, results[0].pass))){
                res.render('login', {
                alert:true,
                alertTitle:"Error",
                alertMessage: "Usuario y/o password incorrecto/s",
                alertIcon:'error',
                showConfirmButton:false,
                timer:10000,
                ruta:'login'
                });
            }else{
                req.session.loggedin = true;
                req.session.name = results[0].name;
                res.render('login', {
                    alert:true,
                    alertTitle:"Conexion exitosa",
                    alertMessage: "Login correcto!",
                    alertIcon:'success',
                    showConfirmButton:true,
                    timer:2000,
                    ruta:''
                });
            }
        })
    } else {
        req.session.loggedin = false;
        res.render('login', {
            alert:true,
            alertTitle:"Advertencia",
            alertMessage: "Por favor ingrese un usuario y/o password!",
            alertIcon:"error",
            showConfirmButton:false,
            timer:5000,
            ruta:'login'
        });
    }
});

app.get('/', (req, res) => {
    if(req.session.loggedin){
        res.render('index', {
            login: true,
            name: req.session.name
        });
    } else {
        res.render('index', {
            login: false,
            name: 'Debe iniciar sesion'
        })
    }
    res.end();
});


//logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
})


app.listen(3000, (req, res) => {
    console.log('Server running in http://localhost:3000')
});