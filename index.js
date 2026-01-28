const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');

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
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email y contraseña son requeridos.' });
        }
        const [rows] = await pool.promise().query('SELECT id, email, password FROM usuarios WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }
        const user = rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }
        res.json({ mensaje: 'Login exitoso', usuario: { id: user.id, email: user.email } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error durante el login, vuelve a intentarlo.' });
    }
});



app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email y contraseña son requeridos.' });
        }
        // Verificar si el usuario ya existe
        const [existing] = await pool.promise().query('SELECT id FROM usuarios WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(409).json({ error: 'El email ya está registrado.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.promise().query('INSERT INTO usuarios (email, password) VALUES (?, ?)', [email, hashedPassword]);
        res.json({ mensaje: 'Registro exitoso' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error durante el registro, vuelve a intentarlo.' });
    }
});



app.get('/usuarios', async (req, res) => {
    try {
        const [rows] = await pool.promise().query('SELECT id, email FROM usuarios');
        res.status(200).json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error durante la consulta, vuelve a intentarlo.' });
    }
});








app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})




