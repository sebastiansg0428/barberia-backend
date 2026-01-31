
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json());
const port = 3000;

// SELECT `id`, `email`, `password` FROM `usuarios` WHERE 1 //
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    database: 'barberia',
    password: '',

});

// Registrar usuario (POST /register)
app.post('/register', async (req, res) => {
    try {
        const { email, password, nombre, telefono, rol } = req.body;
        if (!email || !password || !nombre) {
            return res.status(400).json({ error: 'Debes ingresar nombre, email y contraseña.' });
        }
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
            return res.status(400).json({ error: 'El email no es válido.' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
        }
        const [existing] = await pool.promise().query('SELECT id FROM usuarios WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(409).json({ error: 'El email ya está registrado.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const rolFinal = rol || 'cliente';
        const telefonoFinal = telefono || null;
        await pool.promise().query(
            'INSERT INTO usuarios (email, password, nombre, telefono, rol, activo, fecha_registro) VALUES (?, ?, ?, ?, ?, 1, NOW())',
            [email, hashedPassword, nombre, telefonoFinal, rolFinal]
        );
        res.json({ mensaje: 'Usuario creado exitosamente', usuario: { email, nombre, telefono: telefonoFinal, rol: rolFinal, activo: 1 } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno al intentar crear usuario.' });
    }
});





// Endpoint para iniciar sesión (login) y devolver todos los campos relevantes
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Debes ingresar email y contraseña por favor.' });
        }
        const [rows] = await pool.promise().query(
            'SELECT id, email, password, nombre, telefono, rol, activo, fecha_registro FROM usuarios WHERE email = ?',
            [email]
        );
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }
        const user = rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }
        res.json({
            mensaje: 'Login exitoso',
            usuario: {
                id: user.id,
                email: user.email,
                nombre: user.nombre,
                telefono: user.telefono,
                rol: user.rol,
                activo: user.activo,
                fecha_registro: user.fecha_registro
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno al intentar iniciar sesión.' });
    }
});







// (Eliminada la ruta duplicada POST /usuarios)






// Listar todos los usuarios (GET /usuarios)
app.get('/usuarios', async (req, res) => {
    try {
        const [rows] = await pool.promise().query(
            'SELECT id, email, nombre, telefono, rol, activo, fecha_registro FROM usuarios'
        );
        res.status(200).json({ usuarios: rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno al consultar usuarios.' });
    }
});

// Ver usuario por id (GET /usuarios/:id)
app.get('/usuarios/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.promise().query(
            'SELECT id, email, nombre, telefono, rol, activo, fecha_registro FROM usuarios WHERE id = ?',
            [id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }
        res.status(200).json({ usuario: rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno al consultar usuario.' });
    }
});


// Actualizar usuario por id
app.put('/usuarios/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, telefono, rol, activo } = req.body;
        // Solo actualiza los campos que se envían
        await pool.promise().query(
            'UPDATE usuarios SET nombre = ?, telefono = ?, rol = ?, activo = ? WHERE id = ?',
            [nombre, telefono, rol, activo, id]
        );
        res.json({ mensaje: 'Usuario actualizado correctamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al actualizar usuario.' });
    }
});


// Eliminar usuario por id
app.delete('/usuarios/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.promise().query('DELETE FROM usuarios WHERE id = ?', [id]);
        res.json({ mensaje: 'Usuario eliminado correctamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al eliminar usuario.' });
    }
});






app.listen(port, () => {
    console.log(`Servidor de Barbería escuchando en http://localhost:${port}`);
    console.log('RUTAS DISPONIBLES 🚌:');
    console.log('POST   /register   -> Registrar usuario');
    console.log('POST   /login      -> Iniciar sesión');


    // Listar usuarios
    console.log('GET    /usuarios   -> Listar usuarios');
    console.log('PUT    /usuarios/:id   -> Actualizar usuario');
    console.log('DELETE /usuarios/:id   -> Eliminar usuario');
    console.log('GET    /usuarios/:id   -> Ver usuario por id');

});




