const express = require('express')
const mysql = require('mysql2');

const app = express()
app.use(express.json())
const port = 3000

// SELECT `id`, `email`, `password` FROM `usuarios` WHERE 1 //
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    database: 'barberia',
    password: '',

});




app.post('/login', async (req, res) => {
    const { email, password } = req.body
    const [rows] = await pool.promise().query('SELECT `id`, `email`, `password` FROM `usuarios` WHERE email = ? AND password = ?', [email, password]);
    if (rows.length > 0) {
        res.send('login exitoso')
    } else {
        res.send('login fallido')
    }
})


app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const [rows] = await pool.promise().query('insert into usuarios (email, password) values (?, ?)', [email, password]);
    if (rows.length > 0) {
        res.send('registro exitoso')
    } else {
        res.send('registro fallido')
    }
})







app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})




