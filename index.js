require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();
app.use(cors());
app.use(express.json());
// Deshabilitar ETag globalmente para evitar respuestas 304 con datos desactualizados
app.disable('etag');
// Forzar no-cache en todas las respuestas de la API
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});
const port = process.env.PORT || 3000;

// ==================== CONFIGURACIÓN DE ARCHIVOS (COMPROBANTES) ====================
// Carpeta donde se guardan los comprobantes de pago
const UPLOADS_DIR = path.join(__dirname, 'uploads', 'comprobantes');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Servir comprobantes públicamente en /uploads/comprobantes/:archivo
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configuración de Multer: guarda el archivo con nombre único
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        const nombre = `comprobante_${Date.now()}_${Math.random().toString(36).slice(2)}${ext}`;
        cb(null, nombre);
    }
});
const fileFilter = (req, file, cb) => {
    const permitidos = ['.jpg', '.jpeg', '.png', '.pdf'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (permitidos.includes(ext)) return cb(null, true);
    cb(new Error('Solo se permiten imágenes JPG, PNG o archivos PDF.'));
};
const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5 MB máx
});

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
    let connection;
    try {
        const { id } = req.params;
        console.log('🗑️ Intentando eliminar usuario con ID:', id);

        connection = await pool.promise().getConnection();

        // Iniciar transacción
        await connection.beginTransaction();
        console.log('✅ Transacción iniciada');

        // 1. Obtener las citas del usuario
        const [citas] = await connection.query('SELECT id FROM citas WHERE id_usuario = ?', [id]);
        console.log(`📋 Citas encontradas para usuario ${id}:`, citas.length);

        // 2. Eliminar pagos asociados a las citas del usuario
        if (citas.length > 0) {
            const citaIds = citas.map(c => c.id);
            console.log('💰 IDs de citas a eliminar pagos:', citaIds);
            const placeholders = citaIds.map(() => '?').join(',');
            const [resultPagos] = await connection.query(`DELETE FROM pagos WHERE id_cita IN (${placeholders})`, citaIds);
            console.log('✅ Pagos eliminados:', resultPagos.affectedRows);
        }

        // 3. Eliminar citas del usuario
        const [resultCitas] = await connection.query('DELETE FROM citas WHERE id_usuario = ?', [id]);
        console.log('✅ Citas eliminadas:', resultCitas.affectedRows);

        // 4. Eliminar el usuario
        const [resultUsuario] = await connection.query('DELETE FROM usuarios WHERE id = ?', [id]);
        console.log('✅ Usuario eliminado:', resultUsuario.affectedRows);

        // Confirmar transacción
        await connection.commit();
        console.log('✅ Transacción confirmada');
        connection.release();

        res.json({ mensaje: 'Usuario eliminado correctamente junto con sus citas y pagos.' });
    } catch (error) {
        console.error('❌ Error al eliminar usuario:', error.message);
        console.error('Stack completo:', error);
        if (connection) {
            await connection.rollback();
            connection.release();
        }
        res.status(500).json({ error: 'Error al eliminar usuario: ' + error.message });
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
        // Validar duracion: debe ser un entero positivo (en minutos)
        if (duracion !== undefined && duracion !== null && duracion !== '') {
            const duracionNum = parseInt(duracion);
            if (isNaN(duracionNum) || duracionNum <= 0 || !Number.isInteger(Number(duracion))) {
                return res.status(400).json({ error: 'La duración debe ser un número entero positivo (en minutos).' });
            }
        }
        await pool.promise().query(
            'INSERT INTO servicios (nombre, descripcion, precio, duracion) VALUES (?, ?, ?, ?)',
            [nombre, descripcion || null, precio, duracion ? parseInt(duracion) : null]
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
        // Validar duracion: debe ser un entero positivo (en minutos)
        if (duracion !== undefined && duracion !== null && duracion !== '') {
            const duracionNum = parseInt(duracion);
            if (isNaN(duracionNum) || duracionNum <= 0 || !Number.isInteger(Number(duracion))) {
                return res.status(400).json({ error: 'La duración debe ser un número entero positivo (en minutos).' });
            }
        }
        await pool.promise().query(
            'UPDATE servicios SET nombre = ?, descripcion = ?, precio = ?, duracion = ? WHERE id = ?',
            [nombre, descripcion, precio, duracion ? parseInt(duracion) : null, id]
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

// Crear cita (POST /citas) con opción de pago
app.post('/citas', async (req, res) => {
    const connection = await pool.promise().getConnection();
    try {
        const { id_usuario, id_servicio, fecha_hora, notas, metodo_pago } = req.body;
        if (!id_usuario || !id_servicio || !fecha_hora) {
            return res.status(400).json({ error: 'Debes ingresar usuario, servicio y fecha/hora.' });
        }

        // Validar método de pago si se proporciona
        if (metodo_pago) {
            const metodosValidos = ['efectivo', 'transferencia', 'tarjeta'];
            if (!metodosValidos.includes(metodo_pago)) {
                return res.status(400).json({ error: 'Método de pago no válido. Debe ser: efectivo, transferencia o tarjeta.' });
            }
        }

        // Validar formato de fecha
        const fechaRegex = /^\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}(:\d{2})?$/;
        if (!fechaRegex.test(fecha_hora)) {
            return res.status(400).json({ error: 'Formato de fecha inválido. Use: YYYY-MM-DD HH:mm:ss' });
        }

        // Validar que la fecha sea válida
        const fecha = new Date(fecha_hora);
        if (isNaN(fecha.getTime())) {
            return res.status(400).json({ error: 'Fecha inválida.' });
        }

        // Validar que el año tenga 4 dígitos
        const year = fecha_hora.split(/[\sT-]/)[0];
        if (year.length !== 4) {
            return res.status(400).json({ error: `Año inválido: ${year}. Debe tener 4 dígitos (ej: 2026).` });
        }

        const estadosValidos = ['confirmada', 'completada', 'cancelada'];
        const estadoInicial = 'confirmada';
        if (!estadosValidos.includes(estadoInicial)) {
            return res.status(400).json({ error: 'Estado no válido. Debe ser: confirmada, completada o cancelada.' });
        }

        // Obtener el servicio (duracion en minutos y precio)
        const [servicioCheck] = await connection.query(
            'SELECT duracion, precio FROM servicios WHERE id = ?',
            [id_servicio]
        );
        if (servicioCheck.length === 0) {
            connection.release();
            return res.status(404).json({ error: 'Servicio no encontrado.' });
        }
        const duracionNueva = servicioCheck[0].duracion || 0;
        const precioServicio = servicioCheck[0].precio;

        // Verificar solapamiento de horarios considerando la duración de cada servicio
        // Conflicto si: nueva_inicio < existente_fin AND nueva_fin > existente_inicio
        const [existing] = await connection.query(`
            SELECT c.id FROM citas c
            INNER JOIN servicios s ON c.id_servicio = s.id
            WHERE c.estado != 'cancelada'
            AND ? < DATE_ADD(c.fecha_hora, INTERVAL COALESCE(s.duracion, 0) MINUTE)
            AND DATE_ADD(?, INTERVAL ? MINUTE) > c.fecha_hora
        `, [fecha_hora, fecha_hora, duracionNueva]);
        if (existing.length > 0) {
            connection.release();
            return res.status(409).json({ error: 'El horario se solapa con otra cita existente.' });
        }

        // Iniciar transacción
        await connection.beginTransaction();

        // Crear la cita
        const [citaResult] = await connection.query(
            'INSERT INTO citas (id_usuario, id_servicio, fecha_hora, estado, notas) VALUES (?, ?, ?, ?, ?)',
            [id_usuario, id_servicio, fecha_hora, estadoInicial, notas || null]
        );

        const id_cita = citaResult.insertId;

        // Si se proporcionó método de pago, crear el pago automáticamente
        if (metodo_pago) {
            const monto = precioServicio;
            const fecha = new Date().toISOString().slice(0, 19).replace('T', ' ');

            // Registrar el pago con estado 'pendiente' (admin debe aprobar)
            await connection.query(
                "INSERT INTO pagos (id_cita, id_usuario, monto, metodo, estado, fecha) VALUES (?, ?, ?, ?, 'pendiente', ?)",
                [id_cita, id_usuario, monto, metodo_pago, fecha]
            );
        }

        // Confirmar transacción
        await connection.commit();
        connection.release();

        res.json({
            mensaje: 'Cita creada exitosamente' + (metodo_pago ? ' y pago registrado' : ''),
            id_cita,
            pago_registrado: !!metodo_pago
        });
    } catch (error) {
        await connection.rollback();
        connection.release();
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
                   s.nombre as nombre_servicio, s.precio, s.duracion,
                   p.id AS id_pago,
                   p.estado AS estado_pago,
                   p.metodo AS metodo_pago
            FROM citas c
            INNER JOIN usuarios u ON c.id_usuario = u.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN pagos p ON p.id_cita = c.id AND p.estado != 'rechazado'
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

        // Validar formato de fecha si se envía
        if (fecha_hora) {
            const fechaRegex = /^\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}(:\d{2})?$/;
            if (!fechaRegex.test(fecha_hora)) {
                return res.status(400).json({ error: 'Formato de fecha inválido. Use: YYYY-MM-DD HH:mm:ss' });
            }

            const fecha = new Date(fecha_hora);
            if (isNaN(fecha.getTime())) {
                return res.status(400).json({ error: 'Fecha inválida.' });
            }

            const year = fecha_hora.split(/[\sT-]/)[0];
            if (year.length !== 4) {
                return res.status(400).json({ error: `Año inválido: ${year}. Debe tener 4 dígitos (ej: 2026).` });
            }
        }

        const estadosValidos = ['confirmada', 'completada', 'cancelada'];
        if (estado && !estadosValidos.includes(estado)) {
            return res.status(400).json({ error: 'Estado no válido. Debe ser: confirmada, completada o cancelada.' });
        }
        // Obtener la duración del servicio (en minutos)
        const [servicioCheck] = await pool.promise().query(
            'SELECT duracion FROM servicios WHERE id = ?',
            [id_servicio]
        );
        if (servicioCheck.length === 0) {
            return res.status(404).json({ error: 'Servicio no encontrado.' });
        }
        const duracionNueva = servicioCheck[0].duracion || 0;

        // Verificar solapamiento excluyendo la cita actual (al editar)
        const [existing] = await pool.promise().query(`
            SELECT c.id FROM citas c
            INNER JOIN servicios s ON c.id_servicio = s.id
            WHERE c.estado != 'cancelada'
            AND c.id != ?
            AND ? < DATE_ADD(c.fecha_hora, INTERVAL COALESCE(s.duracion, 0) MINUTE)
            AND DATE_ADD(?, INTERVAL ? MINUTE) > c.fecha_hora
        `, [id, fecha_hora, fecha_hora, duracionNueva]);
        if (existing.length > 0) {
            return res.status(409).json({ error: 'El horario se solapa con otra cita existente.' });
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

// Actualizar solo el estado de una cita (PATCH /citas/:id/estado)
app.patch('/citas/:id/estado', async (req, res) => {
    try {
        const { id } = req.params;
        const { estado } = req.body;

        if (!estado) {
            return res.status(400).json({ error: 'Debes enviar el estado.' });
        }

        const estadosValidos = ['confirmada', 'completada', 'cancelada'];
        if (!estadosValidos.includes(estado)) {
            return res.status(400).json({ error: 'Estado no válido. Debe ser: confirmada, completada o cancelada.' });
        }

        // Verificar que la cita existe y obtener info relevante
        const [citaRows] = await pool.promise().query('SELECT * FROM citas WHERE id = ?', [id]);
        if (citaRows.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada.' });
        }
        const cita = citaRows[0];

        // Actualizar solo el estado
        await pool.promise().query(
            'UPDATE citas SET estado = ? WHERE id = ?',
            [estado, id]
        );

        // Nota: el registro de pago en efectivo lo hace el admin manualmente desde POST /admin/pagos
        res.json({ mensaje: 'Estado de la cita actualizado correctamente', estado });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al actualizar estado de la cita.' });
    }
});

// Eliminar cita por id (DELETE /citas/:id)
app.delete('/citas/:id', async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        connection = await pool.promise().getConnection();
        await connection.beginTransaction();

        // 1. Eliminar pagos asociados a la cita
        await connection.query('DELETE FROM pagos WHERE id_cita = ?', [id]);

        // 2. Eliminar la cita
        const [result] = await connection.query('DELETE FROM citas WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            await connection.rollback();
            connection.release();
            return res.status(404).json({ error: 'Cita no encontrada.' });
        }

        await connection.commit();
        connection.release();
        res.json({ mensaje: 'Cita eliminada correctamente' });
    } catch (error) {
        if (connection) {
            await connection.rollback();
            connection.release();
        }
        console.error('❌ Error al eliminar cita:', error.message);
        res.status(500).json({ error: 'Error al eliminar cita: ' + error.message });
    }
});

// Verificar disponibilidad de horario (GET /citas/disponibilidad/:fecha_hora?id_servicio=X)
// id_servicio es opcional: si se provee, usa la duración del servicio para detectar solapamientos
app.get('/citas/disponibilidad/:fecha_hora', async (req, res) => {
    try {
        const { fecha_hora } = req.params;
        const { id_servicio } = req.query;

        let duracionNueva = 0;
        if (id_servicio) {
            const [servicioRows] = await pool.promise().query(
                'SELECT duracion FROM servicios WHERE id = ?',
                [parseInt(id_servicio)]
            );
            if (servicioRows.length === 0) {
                return res.status(404).json({ error: 'Servicio no encontrado.' });
            }
            duracionNueva = servicioRows[0].duracion || 0;
        }

        // Verificar solapamiento considerando duración
        const [existing] = await pool.promise().query(`
            SELECT c.id FROM citas c
            INNER JOIN servicios s ON c.id_servicio = s.id
            WHERE c.estado != 'cancelada'
            AND ? < DATE_ADD(c.fecha_hora, INTERVAL COALESCE(s.duracion, 0) MINUTE)
            AND DATE_ADD(?, INTERVAL ? MINUTE) > c.fecha_hora
        `, [fecha_hora, fecha_hora, duracionNueva]);

        const disponible = existing.length === 0;
        res.status(200).json({
            disponible,
            mensaje: disponible ? 'Horario disponible' : 'Horario ocupado',
            duracion_minutos: duracionNueva || null
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al verificar disponibilidad.' });
    }
});

// ==================== PAGOS ====================
/*
  ⚠️  SQL MIGRATION - Ejecuta esto en tu base de datos MySQL si aún no lo has hecho:

  -- Estructura actual de la tabla pagos (confirma con DESCRIBE pagos):
  ALTER TABLE pagos
    CHANGE COLUMN fecha_pago fecha DATETIME NOT NULL,
    ADD COLUMN id_usuario INT NULL AFTER id_cita,
    ADD COLUMN estado ENUM('pendiente','aprobado','rechazado') DEFAULT 'pendiente' AFTER metodo,
    ADD COLUMN comprobante TEXT NULL AFTER estado,
    ADD COLUMN referencia VARCHAR(500) NULL AFTER comprobante;

  -- Si comprobante ya existe como VARCHAR(500), ampliar a TEXT para rutas largas:
  ALTER TABLE pagos MODIFY COLUMN comprobante TEXT NULL;

  -- Rellenar id_usuario de pagos existentes
  UPDATE pagos p INNER JOIN citas c ON p.id_cita = c.id SET p.id_usuario = c.id_usuario WHERE p.id_usuario IS NULL;

  -- Marcar pagos existentes de citas completadas como aprobados
  UPDATE pagos p INNER JOIN citas c ON p.id_cita = c.id SET p.estado = 'aprobado' WHERE c.estado = 'completada';
*/

// ── CLIENTE: Registrar pago con comprobante (POST /pagos) ──
// Solo transferencia o tarjeta. El comprobante es OBLIGATORIO.
// Enviar como multipart/form-data: id_cita, id_usuario, metodo, referencia (opcional), comprobante (archivo)
app.post('/pagos', upload.single('comprobante'), async (req, res) => {
    // Si multer rechazó el archivo, el error llega aquí
    try {
        const { id_cita, id_usuario, metodo, referencia } = req.body;

        if (!id_cita || !id_usuario || !metodo) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Faltan datos obligatorios: id_cita, id_usuario, metodo.' });
        }

        const metodosValidos = ['transferencia', 'tarjeta'];
        if (!metodosValidos.includes(metodo)) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Solo puedes registrar pagos por transferencia o tarjeta. El efectivo lo registra el administrador.' });
        }

        // Comprobante obligatorio para transferencia y tarjeta
        if (!req.file) {
            return res.status(400).json({ error: 'Debes adjuntar el comprobante de pago (imagen JPG/PNG o PDF, máx. 5 MB).' });
        }

        // Verificar que la cita existe y pertenece al usuario
        const [citaRows] = await pool.promise().query(
            `SELECT c.id, c.estado, s.precio, s.nombre AS nombre_servicio
             FROM citas c
             INNER JOIN servicios s ON c.id_servicio = s.id
             WHERE c.id = ? AND c.id_usuario = ?`,
            [id_cita, id_usuario]
        );
        if (citaRows.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(404).json({ error: 'Cita no encontrada o no pertenece al usuario.' });
        }
        if (citaRows[0].estado === 'cancelada') {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'No se puede registrar pago para una cita cancelada.' });
        }
        if (citaRows[0].estado === 'completada') {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Esta cita ya fue completada y pagada.' });
        }

        // Verificar que no exista ya un pago pendiente o aprobado para esta cita
        const [pagoExistente] = await pool.promise().query(
            "SELECT id, estado FROM pagos WHERE id_cita = ? AND estado IN ('pendiente','aprobado')",
            [id_cita]
        );
        if (pagoExistente.length > 0) {
            fs.unlinkSync(req.file.path);
            const estadoActual = pagoExistente[0].estado;
            return res.status(409).json({
                error: estadoActual === 'aprobado'
                    ? 'Esta cita ya tiene un pago aprobado.'
                    : 'Ya enviaste un comprobante para esta cita. Espera la aprobación del administrador.'
            });
        }

        const monto = citaRows[0].precio;
        const fecha = new Date().toISOString().slice(0, 19).replace('T', ' ');
        // Guardar ruta relativa del comprobante (accesible vía /uploads/comprobantes/:archivo)
        const urlComprobante = `/uploads/comprobantes/${req.file.filename}`;

        const [result] = await pool.promise().query(
            "INSERT INTO pagos (id_cita, id_usuario, monto, metodo, estado, comprobante, referencia, fecha) VALUES (?, ?, ?, ?, 'pendiente', ?, ?, ?)",
            [id_cita, id_usuario, monto, metodo, urlComprobante, referencia || null, fecha]
        );

        res.status(201).json({
            mensaje: 'Comprobante enviado correctamente. El administrador revisará y confirmará tu pago.',
            id_pago: result.insertId,
            monto,
            nombre_servicio: citaRows[0].nombre_servicio,
            comprobante: urlComprobante,
            comprobante_url: `${req.protocol}://${req.get('host')}${urlComprobante}`,
            estado: 'pendiente'
        });
    } catch (error) {
        if (req.file) fs.unlinkSync(req.file.path);
        console.error(error);
        res.status(500).json({ error: 'Error al registrar pago.' });
    }
});

// ── CLIENTE: Ver mis pagos (GET /mis-pagos?id_usuario=X) ──
app.get('/mis-pagos', async (req, res) => {
    try {
        const { id_usuario } = req.query;
        if (!id_usuario) {
            return res.status(400).json({ error: 'ID de usuario requerido.' });
        }
        const [rows] = await pool.promise().query(`
            SELECT
                p.id, p.id_cita, p.id_usuario, p.monto, p.metodo, p.estado,
                DATE_FORMAT(p.fecha, '%Y-%m-%d %H:%i:%s') AS fecha,
                p.comprobante, p.referencia,
                s.nombre AS nombre_servicio,
                DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_cita,
                c.estado AS estado_cita
            FROM pagos p
            INNER JOIN citas c ON p.id_cita = c.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            WHERE p.id_usuario = ?
            ORDER BY p.fecha DESC
        `, [parseInt(id_usuario)]);
        res.status(200).json({ pagos: rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar tus pagos.' });
    }
});

// ── ADMIN: Pagos pendientes de revisión (GET /pagos/pendientes) ──
// Devuelve solo los pagos con comprobante enviado y estado 'pendiente'
app.get('/pagos/pendientes', async (req, res) => {
    try {
        const [rows] = await pool.promise().query(`
            SELECT
                p.id, p.id_cita, p.id_usuario, p.monto, p.metodo, p.estado,
                DATE_FORMAT(p.fecha, '%Y-%m-%d %H:%i:%s') AS fecha,
                p.comprobante, p.referencia,
                u.nombre AS nombre_cliente, u.email AS email_cliente, u.telefono AS telefono_cliente,
                s.nombre AS nombre_servicio, s.precio,
                DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_cita,
                c.estado AS estado_cita
            FROM pagos p
            LEFT JOIN citas c ON p.id_cita = c.id
            LEFT JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN usuarios u ON p.id_usuario = u.id
            WHERE p.estado = 'pendiente'
              AND p.comprobante IS NOT NULL
            ORDER BY p.fecha ASC
        `);
        const base = `${req.protocol}://${req.get('host')}`;
        const pendientesConUrl = rows.map(r => ({
            ...r,
            comprobante_url: r.comprobante ? `${base}${r.comprobante}` : null
        }));
        res.status(200).json({ pendientes: pendientesConUrl, total: pendientesConUrl.length });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar pagos pendientes.' });
    }
});

// ── ADMIN: Listar todos los pagos con filtros (GET /pagos) ──
app.get('/pagos', async (req, res) => {
    try {
        const { estado, metodo, id_usuario, fecha_desde, fecha_hasta } = req.query;
        let query = `
            SELECT
                p.id, p.id_cita, p.id_usuario, p.monto, p.metodo, p.estado,
                DATE_FORMAT(p.fecha, '%Y-%m-%d %H:%i:%s') AS fecha,
                p.comprobante, p.referencia,
                u.nombre AS nombre_cliente, u.email AS email_cliente,
                s.nombre AS nombre_servicio,
                DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_cita,
                c.estado AS estado_cita
            FROM pagos p
            INNER JOIN citas c ON p.id_cita = c.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN usuarios u ON p.id_usuario = u.id
        `;
        const conditions = [];
        const params = [];
        if (estado) { conditions.push('p.estado = ?'); params.push(estado); }
        if (metodo) { conditions.push('p.metodo = ?'); params.push(metodo); }
        if (id_usuario) { conditions.push('p.id_usuario = ?'); params.push(parseInt(id_usuario)); }
        if (fecha_desde) { conditions.push('DATE(p.fecha) >= ?'); params.push(fecha_desde); }
        if (fecha_hasta) { conditions.push('DATE(p.fecha) <= ?'); params.push(fecha_hasta); }
        if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
        query += ' ORDER BY p.fecha DESC';
        const [rows] = await pool.promise().query(query, params);
        const base = `${req.protocol}://${req.get('host')}`;
        const pagosConUrl = rows.map(r => ({
            ...r,
            comprobante_url: r.comprobante ? `${base}${r.comprobante}` : null
        }));
        res.status(200).json({ pagos: pagosConUrl });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar pagos.' });
    }
});

// ── ADMIN/CLIENTE: Ver pago por id (GET /pagos/:id) ──
app.get('/pagos/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.promise().query(`
            SELECT
                p.id, p.id_cita, p.id_usuario, p.monto, p.metodo, p.estado,
                DATE_FORMAT(p.fecha, '%Y-%m-%d %H:%i:%s') AS fecha,
                p.comprobante, p.referencia,
                u.nombre AS nombre_cliente, u.email AS email_cliente, u.telefono AS telefono_cliente,
                s.nombre AS nombre_servicio, s.precio,
                DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_cita,
                c.notas AS notas_cita,
                c.estado AS estado_cita
            FROM pagos p
            INNER JOIN citas c ON p.id_cita = c.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN usuarios u ON p.id_usuario = u.id
            WHERE p.id = ?
        `, [id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Pago no encontrado.' });
        }
        const pago = rows[0];
        const base = `${req.protocol}://${req.get('host')}`;
        res.status(200).json({
            pago: {
                ...pago,
                comprobante_url: pago.comprobante ? `${base}${pago.comprobante}` : null
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar pago.' });
    }
});

// ── ADMIN: Aprobar pago (PUT /pagos/:id/aprobar) ──
// Aprueba el comprobante de pago y marca la cita como completada
app.put('/pagos/:id/aprobar', async (req, res) => {
    try {
        const { id } = req.params;
        const [pagoRows] = await pool.promise().query(`
            SELECT p.*, u.nombre AS nombre_cliente, s.nombre AS nombre_servicio
            FROM pagos p
            LEFT JOIN usuarios u ON p.id_usuario = u.id
            LEFT JOIN citas c ON p.id_cita = c.id
            LEFT JOIN servicios s ON c.id_servicio = s.id
            WHERE p.id = ?
        `, [id]);
        if (pagoRows.length === 0) {
            return res.status(404).json({ error: 'Pago no encontrado.' });
        }
        const pago = pagoRows[0];
        if (pago.estado === 'aprobado') {
            return res.status(400).json({ error: 'Este pago ya fue aprobado anteriormente.' });
        }
        if (pago.estado === 'rechazado') {
            return res.status(400).json({ error: 'No se puede aprobar un pago que fue rechazado.' });
        }
        await pool.promise().query("UPDATE pagos SET estado = 'aprobado' WHERE id = ?", [id]);
        await pool.promise().query("UPDATE citas SET estado = 'completada' WHERE id = ?", [pago.id_cita]);
        res.json({
            mensaje: 'Pago aprobado correctamente. Cita marcada como completada.',
            nombre_cliente: pago.nombre_cliente,
            nombre_servicio: pago.nombre_servicio,
            monto: pago.monto,
            metodo: pago.metodo
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al aprobar pago.' });
    }
});

// ── ADMIN: Rechazar pago (PUT /pagos/:id/rechazar) ──
// El motivo se almacena en el campo 'referencia' del pago
app.put('/pagos/:id/rechazar', async (req, res) => {
    try {
        const { id } = req.params;
        const { motivo } = req.body;
        if (!motivo || motivo.trim() === '') {
            return res.status(400).json({ error: 'Debes indicar el motivo del rechazo para notificar al cliente.' });
        }
        const [pagoRows] = await pool.promise().query('SELECT * FROM pagos WHERE id = ?', [id]);
        if (pagoRows.length === 0) {
            return res.status(404).json({ error: 'Pago no encontrado.' });
        }
        if (pagoRows[0].estado === 'rechazado') {
            return res.status(400).json({ error: 'El pago ya fue rechazado anteriormente.' });
        }
        if (pagoRows[0].estado === 'aprobado') {
            return res.status(400).json({ error: 'No se puede rechazar un pago que ya fue aprobado.' });
        }
        // Guardar motivo en campo referencia prefijado
        const motivoGuardado = `RECHAZO: ${motivo.trim()}`;
        await pool.promise().query(
            "UPDATE pagos SET estado = 'rechazado', referencia = ? WHERE id = ?",
            [motivoGuardado, id]
        );
        res.json({
            mensaje: 'Pago rechazado. El cliente deberá enviar un nuevo comprobante.',
            motivo: motivo.trim()
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al rechazar pago.' });
    }
});

// ── ADMIN: Registrar pago en efectivo (POST /admin/pagos) ──
// El admin registra manualmente cuando el cliente paga en efectivo en la barbería.
// El pago se aprueba directamente (no requiere comprobante).
// Acepta: id_cita, id_usuario (del admin), notas (opcional), monto_personalizado (opcional para descuentos/extras)
app.post('/admin/pagos', async (req, res) => {
    try {
        const { id_cita, id_usuario, notas, monto_personalizado } = req.body;
        if (!id_cita || !id_usuario) {
            return res.status(400).json({ error: 'Faltan datos obligatorios: id_cita, id_usuario.' });
        }

        // Verificar que quien registra es admin
        const [adminCheck] = await pool.promise().query(
            'SELECT rol FROM usuarios WHERE id = ?', [id_usuario]
        );
        if (adminCheck.length === 0 || adminCheck[0].rol !== 'admin') {
            return res.status(403).json({ error: 'Solo un administrador puede registrar pagos en efectivo.' });
        }

        // Obtener la cita con info completa del servicio y del cliente
        const [citaRows] = await pool.promise().query(`
            SELECT c.id, c.estado, c.id_usuario AS cliente_id,
                   s.precio, s.nombre AS nombre_servicio,
                   u.nombre AS nombre_cliente, u.email AS email_cliente, u.telefono AS telefono_cliente
            FROM citas c
            INNER JOIN servicios s ON c.id_servicio = s.id
            INNER JOIN usuarios u ON c.id_usuario = u.id
            WHERE c.id = ?
        `, [id_cita]);

        if (citaRows.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada.' });
        }

        const cita = citaRows[0];

        if (cita.estado === 'cancelada') {
            return res.status(400).json({ error: 'No se puede registrar pago para una cita cancelada.' });
        }
        if (cita.estado === 'completada') {
            return res.status(400).json({ error: 'Esta cita ya fue completada y no requiere registro adicional de pago.' });
        }

        // Verificar que no existe ya un pago aprobado
        const [pagoExistente] = await pool.promise().query(
            "SELECT id FROM pagos WHERE id_cita = ? AND estado = 'aprobado'",
            [id_cita]
        );
        if (pagoExistente.length > 0) {
            return res.status(409).json({ error: 'Esta cita ya tiene un pago aprobado registrado.' });
        }

        // Si hay un pago pendiente (comprobante enviado por el cliente), cancelarlo
        // porque ahora pagó en efectivo presencialmente
        const [pagoPendiente] = await pool.promise().query(
            "SELECT id FROM pagos WHERE id_cita = ? AND estado = 'pendiente'",
            [id_cita]
        );
        if (pagoPendiente.length > 0) {
            await pool.promise().query(
                "UPDATE pagos SET estado = 'rechazado', referencia = 'RECHAZO: Reemplazado por pago en efectivo presencial.' WHERE id = ?",
                [pagoPendiente[0].id]
            );
        }

        // Validar monto personalizado si se proporciona
        let monto = cita.precio;
        if (monto_personalizado !== undefined && monto_personalizado !== null && monto_personalizado !== '') {
            const montoNum = parseFloat(monto_personalizado);
            if (isNaN(montoNum) || montoNum <= 0) {
                return res.status(400).json({ error: 'El monto personalizado debe ser un número positivo.' });
            }
            monto = montoNum;
        }

        const fecha = new Date().toISOString().slice(0, 19).replace('T', ' ');

        const [result] = await pool.promise().query(
            "INSERT INTO pagos (id_cita, id_usuario, monto, metodo, estado, referencia, fecha) VALUES (?, ?, ?, 'efectivo', 'aprobado', ?, ?)",
            [id_cita, cita.cliente_id, monto, notas || null, fecha]
        );

        // Marcar la cita como completada
        await pool.promise().query("UPDATE citas SET estado = 'completada' WHERE id = ?", [id_cita]);

        res.status(201).json({
            mensaje: `Cobro en efectivo registrado correctamente.`,
            id_pago: result.insertId,
            monto,
            precio_servicio: cita.precio,
            nombre_cliente: cita.nombre_cliente,
            email_cliente: cita.email_cliente,
            nombre_servicio: cita.nombre_servicio,
            notas: notas || null,
            fecha
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al registrar pago en efectivo.' });
    }
});

// ── ADMIN: Reporte de ingresos (GET /reportes/ingresos) ──
// Filtra por fecha_desde y fecha_hasta (query params opcionales)
app.get('/reportes/ingresos', async (req, res) => {
    try {
        const { fecha_desde, fecha_hasta } = req.query;
        let whereClause = "WHERE p.estado = 'aprobado'";
        const params = [];
        if (fecha_desde) { whereClause += ' AND DATE(p.fecha) >= ?'; params.push(fecha_desde); }
        if (fecha_hasta) { whereClause += ' AND DATE(p.fecha) <= ?'; params.push(fecha_hasta); }

        const [[{ totalIngresos }]] = await pool.promise().query(
            `SELECT COALESCE(SUM(p.monto), 0) AS totalIngresos FROM pagos p ${whereClause}`, params
        );
        const [[{ totalPagos }]] = await pool.promise().query(
            `SELECT COUNT(*) AS totalPagos FROM pagos p ${whereClause}`, params
        );
        const [porMetodo] = await pool.promise().query(
            `SELECT p.metodo, COUNT(*) AS total, SUM(p.monto) AS monto FROM pagos p ${whereClause} GROUP BY p.metodo`, params
        );
        const [porMes] = await pool.promise().query(
            `SELECT DATE_FORMAT(p.fecha, '%Y-%m') AS mes, COUNT(*) AS total, SUM(p.monto) AS monto
             FROM pagos p ${whereClause} GROUP BY mes ORDER BY mes DESC LIMIT 12`, params
        );
        const [porDia] = await pool.promise().query(
            `SELECT DATE(p.fecha) AS dia, COUNT(*) AS total, SUM(p.monto) AS monto
             FROM pagos p ${whereClause} GROUP BY dia ORDER BY dia DESC LIMIT 30`, params
        );
        const [topServicios] = await pool.promise().query(
            `SELECT s.nombre AS servicio, COUNT(*) AS total, SUM(p.monto) AS monto
             FROM pagos p
             INNER JOIN citas c ON p.id_cita = c.id
             INNER JOIN servicios s ON c.id_servicio = s.id
             ${whereClause} GROUP BY s.id ORDER BY monto DESC LIMIT 5`, params
        );
        res.json({ totalIngresos, totalPagos, porMetodo, porMes, porDia, topServicios });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al generar reporte de ingresos.' });
    }
});

// Ver pagos de una cita (GET /pagos/cita/:id_cita)
app.get('/pagos/cita/:id_cita', async (req, res) => {
    try {
        const { id_cita } = req.params;
        const [rows] = await pool.promise().query(`
            SELECT p.id, p.id_cita, p.id_usuario, p.monto, p.metodo, p.estado,
                   DATE_FORMAT(p.fecha, '%Y-%m-%d %H:%i:%s') AS fecha,
                   p.comprobante, p.referencia
            FROM pagos p WHERE p.id_cita = ?
        `, [id_cita]);
        const base = `${req.protocol}://${req.get('host')}`;
        const pagosConUrl = rows.map(r => ({
            ...r,
            comprobante_url: r.comprobante ? `${base}${r.comprobante}` : null
        }));
        res.status(200).json({ pagos: pagosConUrl });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar pagos de la cita.' });
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

// ==================== DASHBOARD PAGOS ====================

// Endpoint consolidado para estadísticas de pagos - Solo Admin
app.post('/dashboard/pagos-stats', verificarRol('admin'), async (req, res) => {
    try {
        // Total de pagos aprobados
        const [totalPagosRows] = await pool.promise().query(
            "SELECT COUNT(*) as total FROM pagos WHERE estado = 'aprobado'"
        );
        const totalPagos = totalPagosRows[0]?.total || 0;

        // Total monto pagado (pagos aprobados)
        const [totalMontoRows] = await pool.promise().query(
            "SELECT SUM(monto) as totalMonto FROM pagos WHERE estado = 'aprobado'"
        );
        const totalMontoPagado = totalMontoRows[0]?.totalMonto || 0;

        // Pagos pendientes de aprobación
        const [[{ totalPendientes }]] = await pool.promise().query(
            "SELECT COUNT(*) as totalPendientes FROM pagos WHERE estado = 'pendiente'"
        );

        // Pagos por método (solo aprobados)
        const [pagosPorMetodoRows] = await pool.promise().query(
            "SELECT metodo, COUNT(*) as total, SUM(monto) as montoTotal FROM pagos WHERE estado = 'aprobado' GROUP BY metodo"
        );
        const pagosPorMetodo = pagosPorMetodoRows || [];

        // Pagos por mes (solo aprobados)
        const [pagosPorMesRows] = await pool.promise().query(`
            SELECT DATE_FORMAT(pagos.fecha, '%Y-%m') as mes, COUNT(*) as total, SUM(pagos.monto) as montoTotal
            FROM pagos
            WHERE pagos.estado = 'aprobado'
            GROUP BY DATE_FORMAT(pagos.fecha, '%Y-%m')
            ORDER BY mes DESC
            LIMIT 12
        `);
        const pagosPorMes = pagosPorMesRows || [];

        // Pagos por día (solo aprobados)
        const [pagosPorDiaRows] = await pool.promise().query(`
            SELECT DATE(pagos.fecha) as dia, COUNT(*) as total, SUM(pagos.monto) as montoTotal
            FROM pagos
            WHERE pagos.estado = 'aprobado'
            GROUP BY DATE(pagos.fecha)
            ORDER BY dia DESC
            LIMIT 30
        `);
        const pagosPorDia = pagosPorDiaRows || [];

        res.json({
            totalPagos,
            totalMontoPagado,
            totalPendientes,
            pagosPorMetodo,
            pagosPorMes,
            pagosPorDia
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: 'Error al obtener estadísticas de pagos.',
            totalPagos: 0,
            totalMontoPagado: 0,
            pagosPorMetodo: [],
            pagosPorMes: [],
            pagosPorDia: []
        });
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
    console.log('PUT    /citas/:id   -> Actualizar cita completa (valida disponibilidad)');
    console.log('PATCH  /citas/:id/estado   -> Actualizar solo el estado de la cita');
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
    console.log('POST   /dashboard/pagos-stats   -> Estadísticas de pagos');



    // ==================== PAGOS ====================
    console.log('PAGOS 💸');
    console.log('── CLIENTE ──');
    console.log('POST   /pagos                  -> Registrar pago con comprobante (multipart/form-data: transferencia/tarjeta)');
    console.log('GET    /mis-pagos?id_usuario=X -> Ver mis pagos');
    console.log('── ADMIN ──');
    console.log('GET    /pagos                  -> Listar todos los pagos (filtros: estado, metodo, id_usuario, fecha_desde, fecha_hasta)');
    console.log('GET    /pagos/pendientes        -> Pagos pendientes de revisión (con comprobante)');
    console.log('GET    /pagos/:id              -> Ver pago por id');
    console.log('GET    /pagos/cita/:id_cita    -> Ver pagos de una cita');
    console.log('PUT    /pagos/:id/aprobar      -> Aprobar comprobante (marca cita como completada)');
    console.log('PUT    /pagos/:id/rechazar     -> Rechazar comprobante (requiere motivo)');
    console.log('POST   /admin/pagos            -> Registrar cobro en efectivo (aprobado directo)');
    console.log('GET    /reportes/ingresos      -> Reporte de ingresos (filtros: fecha_desde, fecha_hasta)');
    console.log('📁 Comprobantes disponibles en: /uploads/comprobantes/:archivo');
});




