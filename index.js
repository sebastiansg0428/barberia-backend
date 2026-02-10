require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json());
const port = process.env.PORT || 3000;

// Configuración de la base de datos con variables de entorno
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    database: process.env.DB_NAME || 'barberia',
    password: process.env.DB_PASSWORD || '',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ==================== MIDDLEWARES DE AUTORIZACIÓN ====================

// Middleware para verificar roles
const verificarRol = (...rolesPermitidos) => {
    return async (req, res, next) => {
        try {
            const id_usuario =
                (req.body && req.body.id_usuario) ||
                (req.query && req.query.id_usuario) ||
                req.headers['id_usuario'];
            if (!id_usuario) {
                return res.status(400).json({ error: 'ID de usuario requerido.' });
            }

            const [usuario] = await pool.promise().query(
                'SELECT rol FROM usuarios WHERE id = ?',
                [id_usuario]
            );

            if (usuario.length === 0) {
                return res.status(404).json({ error: 'Usuario no encontrado.' });
            }

            if (!rolesPermitidos.includes(usuario[0].rol)) {
                return res.status(403).json({ error: 'No tienes permisos para realizar esta acción.' });
            }

            next();
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error al verificar permisos.' });
        }
    };
};

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

        // Validar que el rol sea válido
        const rolesValidos = ['admin', 'barbero', 'cliente'];
        if (!rolesValidos.includes(rolFinal)) {
            return res.status(400).json({ error: 'Rol no válido. Debe ser: admin, barbero o cliente.' });
        }

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


// ==================== SERVICIOS CRUD ====================

// Crear servicio (POST /servicios)
app.post('/servicios', async (req, res) => {
    try {
        const { nombre, descripcion, precio, duracion } = req.body;
        if (!nombre || !precio) {
            return res.status(400).json({ error: 'Debes ingresar nombre y precio del servicio.' });
        }
        await pool.promise().query(
            'INSERT INTO servicios (nombre, descripcion, precio, duracion) VALUES (?, ?, ?, ?)',
            [nombre, descripcion || null, precio, duracion || null]
        );
        res.json({ mensaje: 'Servicio creado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al crear servicio.' });
    }
});

// Listar todos los servicios (GET /servicios)
app.get('/servicios', async (req, res) => {
    try {
        const [rows] = await pool.promise().query('SELECT * FROM servicios');
        res.status(200).json({ servicios: rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar servicios.' });
    }
});

// Ver servicio por id (GET /servicios/:id)
app.get('/servicios/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.promise().query('SELECT * FROM servicios WHERE id = ?', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Servicio no encontrado.' });
        }
        res.status(200).json({ servicio: rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar servicio.' });
    }
});

// Actualizar servicio por id (PUT /servicios/:id)
app.put('/servicios/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, descripcion, precio, duracion } = req.body;
        await pool.promise().query(
            'UPDATE servicios SET nombre = ?, descripcion = ?, precio = ?, duracion = ? WHERE id = ?',
            [nombre, descripcion, precio, duracion, id]
        );
        res.json({ mensaje: 'Servicio actualizado correctamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al actualizar servicio.' });
    }
});

// Eliminar servicio por id (DELETE /servicios/:id)
app.delete('/servicios/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.promise().query('DELETE FROM servicios WHERE id = ?', [id]);
        res.json({ mensaje: 'Servicio eliminado correctamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al eliminar servicio.' });
    }
});


// ==================== CITAS CRUD ====================

// Crear cita (POST /citas)
app.post('/citas', async (req, res) => {
    try {
        const { id_usuario, id_servicio, fecha_hora, notas } = req.body;
        if (!id_usuario || !id_servicio || !fecha_hora) {
            return res.status(400).json({ error: 'Debes ingresar usuario, servicio y fecha/hora.' });
        }
        // Validar que no exista otra cita en la misma fecha y hora
        const [existing] = await pool.promise().query(
            'SELECT id FROM citas WHERE fecha_hora = ? AND estado != ?',
            [fecha_hora, 'cancelada']
        );
        if (existing.length > 0) {
            return res.status(409).json({ error: 'Ya existe una cita para esta fecha y hora.' });
        }
        await pool.promise().query(
            'INSERT INTO citas (id_usuario, id_servicio, fecha_hora, estado, notas) VALUES (?, ?, ?, ?, ?)',
            [id_usuario, id_servicio, fecha_hora, 'pendiente', notas || null]
        );
        res.json({ mensaje: 'Cita creada exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al crear cita.' });
    }
});

// Listar todas las citas (GET /citas)

app.get('/citas', async (req, res) => {
    try {
        const [rows] = await pool.promise().query(`
            SELECT c.id, c.id_usuario, c.id_servicio, 
                   DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') as fecha_hora, 
                   c.estado, c.notas,
                   u.nombre as nombre_usuario, u.email, u.telefono,
                   s.nombre as nombre_servicio, s.precio, s.duracion
            FROM citas c
            INNER JOIN usuarios u ON c.id_usuario = u.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            ORDER BY c.fecha_hora DESC
        `);
        res.status(200).json({ citas: rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar citas.' });
    }
});

// Ver cita por id (GET /citas/:id)
app.get('/citas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.promise().query(`
            SELECT c.id, c.id_usuario, c.id_servicio,
                   DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') as fecha_hora,
                   c.estado, c.notas,
                   u.nombre as nombre_usuario, u.email, u.telefono,
                   s.nombre as nombre_servicio, s.precio, s.duracion
            FROM citas c
            INNER JOIN usuarios u ON c.id_usuario = u.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            WHERE c.id = ?
        `, [id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada.' });
        }
        res.status(200).json({ cita: rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar cita.' });
    }
});

// Actualizar cita por id (PUT /citas/:id)
app.put('/citas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { id_usuario, id_servicio, fecha_hora, estado, notas } = req.body;
        // Validar que no exista otra cita en la misma fecha y hora (excluyendo la cita actual)
        const [existing] = await pool.promise().query(
            'SELECT id FROM citas WHERE fecha_hora = ? AND estado != ? AND id != ?',
            [fecha_hora, 'cancelada', id]
        );
        if (existing.length > 0) {
            return res.status(409).json({ error: 'Ya existe una cita para esta fecha y hora.' });
        }
        await pool.promise().query(
            'UPDATE citas SET id_usuario = ?, id_servicio = ?, fecha_hora = ?, estado = ?, notas = ? WHERE id = ?',
            [id_usuario, id_servicio, fecha_hora, estado, notas, id]
        );
        res.json({ mensaje: 'Cita actualizada correctamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al actualizar cita.' });
    }
});

// Eliminar cita por id (DELETE /citas/:id)
app.delete('/citas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.promise().query('DELETE FROM citas WHERE id = ?', [id]);
        res.json({ mensaje: 'Cita eliminada correctamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al eliminar cita.' });
    }
});

// Verificar disponibilidad de horario (GET /citas/disponibilidad/:fecha_hora)
app.get('/citas/disponibilidad/:fecha_hora', async (req, res) => {
    try {
        const { fecha_hora } = req.params;
        const [existing] = await pool.promise().query(
            'SELECT id FROM citas WHERE fecha_hora = ? AND estado != ?',
            [fecha_hora, 'cancelada']
        );
        const disponible = existing.length === 0;
        res.status(200).json({ disponible, mensaje: disponible ? 'Horario disponible' : 'Horario ocupado' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al verificar disponibilidad.' });
    }
});


// ==================== DASHBOARD ADMIN ====================

// Endpoint consolidado para todas las estadísticas del dashboard - Solo Admin
app.post('/dashboard/stats', verificarRol('admin'), async (req, res) => {
    try {
        // Total de usuarios
        const [usuarios] = await pool.promise().query('SELECT COUNT(*) as total FROM usuarios');

        // Total de citas
        const [citas] = await pool.promise().query('SELECT COUNT(*) as total FROM citas');

        // Total de servicios
        const [servicios] = await pool.promise().query('SELECT COUNT(*) as total FROM servicios');

        // Citas por estado
        const [citasPorEstado] = await pool.promise().query('SELECT estado, COUNT(*) as total FROM citas GROUP BY estado');

        // Citas por día
        const [citasPorDia] = await pool.promise().query(`
            SELECT DATE(fecha_hora) as dia, COUNT(*) as total 
            FROM citas 
            GROUP BY DATE(fecha_hora) 
            ORDER BY DATE(fecha_hora) DESC 
            LIMIT 30
        `);

        // Citas por mes
        const [citasPorMes] = await pool.promise().query(`
            SELECT DATE_FORMAT(fecha_hora, '%Y-%m') as mes, COUNT(*) as total 
            FROM citas 
            GROUP BY DATE_FORMAT(fecha_hora, '%Y-%m') 
            ORDER BY DATE_FORMAT(fecha_hora, '%Y-%m') DESC 
            LIMIT 12
        `);

        res.json({
            totalUsuarios: usuarios[0]?.total || 0,
            totalCitas: citas[0]?.total || 0,
            totalServicios: servicios[0]?.total || 0,
            citasPorEstado: citasPorEstado || [],
            citasPorDia: citasPorDia || [],
            citasPorMes: citasPorMes || []
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: 'Error al obtener estadísticas del dashboard.',
            totalUsuarios: 0,
            totalCitas: 0,
            totalServicios: 0,
            citasPorEstado: [],
            citasPorDia: [],
            citasPorMes: []
        });
    }
});

// Total de usuarios (POST /dashboard/total-usuarios) - Solo Admin
app.post('/dashboard/total-usuarios', verificarRol('admin'), async (req, res) => {
    try {
        const [rows] = await pool.promise().query('SELECT COUNT(*) as total FROM usuarios');
        res.json({ totalUsuarios: rows[0]?.total || 0 });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener total de usuarios.', totalUsuarios: 0 });
    }
});

// Total de citas (POST /dashboard/total-citas) - Solo Admin
app.post('/dashboard/total-citas', verificarRol('admin'), async (req, res) => {
    try {
        const [rows] = await pool.promise().query('SELECT COUNT(*) as total FROM citas');
        res.json({ totalCitas: rows[0]?.total || 0 });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener total de citas.', totalCitas: 0 });
    }
});

// Total de servicios (POST /dashboard/total-servicios) - Solo Admin
app.post('/dashboard/total-servicios', verificarRol('admin'), async (req, res) => {
    try {
        const [rows] = await pool.promise().query('SELECT COUNT(*) as total FROM servicios');
        res.json({ totalServicios: rows[0]?.total || 0 });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener total de servicios.', totalServicios: 0 });
    }
});

// Citas por estado (POST /dashboard/citas-por-estado) - Solo Admin
app.post('/dashboard/citas-por-estado', verificarRol('admin'), async (req, res) => {
    try {
        const [rows] = await pool.promise().query('SELECT estado, COUNT(*) as total FROM citas GROUP BY estado');
        res.json({ citasPorEstado: rows || [] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener citas por estado.', citasPorEstado: [] });
    }
});

// Citas por día (POST /dashboard/citas-por-dia) - Solo Admin
app.post('/dashboard/citas-por-dia', verificarRol('admin'), async (req, res) => {
    try {
        const [rows] = await pool.promise().query(`
            SELECT DATE(fecha_hora) as dia, COUNT(*) as total 
            FROM citas 
            GROUP BY DATE(fecha_hora) 
            ORDER BY DATE(fecha_hora) DESC 
            LIMIT 30
        `);
        res.json({ citasPorDia: rows || [] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener citas por día.', citasPorDia: [] });
    }
});

// Citas por mes (POST /dashboard/citas-por-mes) - Solo Admin
app.post('/dashboard/citas-por-mes', verificarRol('admin'), async (req, res) => {
    try {
        const [rows] = await pool.promise().query(`
            SELECT DATE_FORMAT(fecha_hora, '%Y-%m') as mes, COUNT(*) as total 
            FROM citas 
            GROUP BY DATE_FORMAT(fecha_hora, '%Y-%m') 
            ORDER BY DATE_FORMAT(fecha_hora, '%Y-%m') DESC 
            LIMIT 12
        `);
        res.json({ citasPorMes: rows || [] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener citas por mes.', citasPorMes: [] });
    }
});


app.listen(port, () => {
    console.log(`Servidor de Barbería escuchando en http://localhost:${port}`);
    console.log('RUTAS DISPONIBLES 🚌:');
    console.log('POST   /register   -> Registrar usuario');
    console.log('POST   /login      -> Iniciar sesión');
    // Listar usuarios
    console.log('USUARIOS⚙️');
    console.log('GET    /usuarios   -> Listar usuarios');
    console.log('PUT    /usuarios/:id   -> Actualizar usuario');
    console.log('DELETE /usuarios/:id   -> Eliminar usuario');
    console.log('GET    /usuarios/:id   -> Ver usuario por id');

    // Listar servicios
    console.log('SERVICIOS⚙️');
    console.log('GET    /servicios   -> Listar servicios');
    console.log('POST   /servicios   -> Crear servicio');
    console.log('PUT    /servicios/:id   -> Actualizar servicio');
    console.log('DELETE /servicios/:id   -> Eliminar servicio');
    console.log('GET    /servicios/:id   -> Ver servicio por id');

    // Listar citas
    console.log('CITAS📅');
    console.log('GET    /citas   -> Listar citas');
    console.log('POST   /citas   -> Crear cita (valida disponibilidad)');
    console.log('PUT    /citas/:id   -> Actualizar cita (valida disponibilidad)');
    console.log('DELETE /citas/:id   -> Eliminar cita');
    console.log('GET    /citas/:id   -> Ver cita por id');
    console.log('GET    /citas/disponibilidad/:fecha_hora   -> Verificar disponibilidad');

    // Dashboard Admin
    console.log('DASHBOARD ADMIN 📊 (Solo rol: admin)');
    console.log('POST   /dashboard/stats   -> Todas las estadísticas (recomendado)');
    console.log('POST   /dashboard/total-usuarios   -> Total de usuarios');
    console.log('POST   /dashboard/total-citas   -> Total de citas');
    console.log('POST   /dashboard/total-servicios   -> Total de servicios');
    console.log('POST   /dashboard/citas-por-estado   -> Citas por estado');
    console.log('POST   /dashboard/citas-por-dia   -> Citas por día');
    console.log('POST   /dashboard/citas-por-mes   -> Citas por mes');
});




