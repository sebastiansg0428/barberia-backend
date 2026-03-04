require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const PDFDocument = require('pdfkit');
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

// Configuración de Multer: guarda el archivo organizado por año/mes (mejora #6)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const now = new Date();
        const sub = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, '0')}`;
        const dir = path.join(UPLOADS_DIR, sub);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
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

// POST /citas — Reservar cita + auto-crea pago PENDIENTE
// Body JSON: { id_usuario, id_barbero?, servicios: [id1,id2,...], fecha_hora, notas? }
app.post('/citas', async (req, res) => {
    const connection = await pool.promise().getConnection();
    try {
        const { id_usuario, id_barbero, servicios, fecha_hora, notas } = req.body;

        if (!id_usuario || !fecha_hora || !Array.isArray(servicios) || servicios.length === 0) {
            connection.release();
            return res.status(400).json({ error: 'Requeridos: id_usuario, servicios (array de IDs), fecha_hora.' });
        }

        const fechaRegex = /^\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}(:\d{2})?$/;
        if (!fechaRegex.test(fecha_hora) || isNaN(new Date(fecha_hora).getTime())) {
            connection.release();
            return res.status(400).json({ error: 'Formato de fecha inválido. Use: YYYY-MM-DD HH:mm:ss' });
        }

        // Obtener precio + duración de todos los servicios
        const ids = [...new Set(servicios.map(Number).filter(n => !isNaN(n) && n > 0))];
        const placeholders = ids.map(() => '?').join(',');
        const [serviciosRows] = await connection.query(
            `SELECT id, nombre, precio, duracion FROM servicios WHERE id IN (${placeholders})`, ids
        );
        if (serviciosRows.length !== ids.length) {
            connection.release();
            return res.status(404).json({ error: 'Uno o más servicios no existen.' });
        }

        const totalDuracion = serviciosRows.reduce((s, r) => s + (r.duracion || 0), 0);
        const subtotal = serviciosRows.reduce((s, r) => s + parseFloat(r.precio), 0);
        const barberoId = id_barbero ? parseInt(id_barbero) : null;

        // Verificar solapamiento (por barbero si se especifica)
        const overlapBase = `
            SELECT c.id FROM citas c
            LEFT JOIN (SELECT id_cita, SUM(duracion) AS dur FROM cita_servicios GROUP BY id_cita) cs ON cs.id_cita = c.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            WHERE c.estado NOT IN ('cancelada')
            AND ? < DATE_ADD(c.fecha_hora, INTERVAL COALESCE(cs.dur, s.duracion, 0) MINUTE)
            AND DATE_ADD(?, INTERVAL ? MINUTE) > c.fecha_hora
        `;
        const overlapParams = barberoId
            ? [fecha_hora, fecha_hora, totalDuracion, barberoId]
            : [fecha_hora, fecha_hora, totalDuracion];
        const overlapSuffix = barberoId ? ' AND c.id_barbero = ?' : '';
        const [existing] = await connection.query(overlapBase + overlapSuffix, overlapParams);
        if (existing.length > 0) {
            connection.release();
            return res.status(409).json({ error: 'El horario se solapa con otra cita existente.' });
        }

        await connection.beginTransaction();

        // Cita en estado RESERVADA (pago aún pendiente)
        const [citaResult] = await connection.query(
            'INSERT INTO citas (id_usuario, id_servicio, id_barbero, fecha_hora, estado, notas) VALUES (?, ?, ?, ?, "reservada", ?)',
            [id_usuario, ids[0], barberoId, fecha_hora, notas || null]
        );
        const id_cita = citaResult.insertId;

        // Registrar cada servicio en cita_servicios
        for (const s of serviciosRows) {
            await connection.query(
                'INSERT INTO cita_servicios (id_cita, id_servicio, nombre, precio, duracion) VALUES (?, ?, ?, ?, ?)',
                [id_cita, s.id, s.nombre, s.precio, s.duracion || 0]
            );
        }

        await connection.commit();
        connection.release();

        res.status(201).json({
            mensaje: 'Cita reservada. Para confirmarla, el cliente debe subir un comprobante de pago (POST /pagos) o el administrador registrar el cobro en efectivo (POST /admin/pagos).',
            id_cita,
            estado_cita: 'reservada',
            estado_pago: null,
            metodo_pago: null,
            servicios: serviciosRows.map(s => ({ id: s.id, nombre: s.nombre, precio: parseFloat(s.precio) })),
            subtotal: parseFloat(subtotal.toFixed(2)),
            total: parseFloat(subtotal.toFixed(2)),
            duracion_total_minutos: totalDuracion,
            fecha_hora
        });
    } catch (error) {
        await connection.rollback();
        connection.release();
        console.error(error);
        res.status(500).json({ error: 'Error al crear cita.' });
    }
});

// GET /citas — listado con barbero, multi-servicios y pago activo
app.get('/citas', async (req, res) => {
    try {
        const [rows] = await pool.promise().query(`
            SELECT c.id, c.id_usuario, c.id_servicio, c.id_barbero,
                   DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_hora,
                   c.estado, c.notas,
                   u.nombre AS nombre_usuario, u.email, u.telefono,
                   s.nombre AS nombre_servicio, s.precio, s.duracion,
                   b.nombre AS nombre_barbero,
                   (SELECT GROUP_CONCAT(
                       JSON_OBJECT('id', cs.id_servicio, 'nombre', cs.nombre, 'precio', cs.precio, 'duracion', cs.duracion)
                       SEPARATOR ','
                    ) FROM cita_servicios cs WHERE cs.id_cita = c.id) AS servicios_raw,
                   COALESCE(
                       (SELECT SUM(cs.precio) FROM cita_servicios cs WHERE cs.id_cita = c.id),
                       s.precio
                   ) AS total_servicios,
                   (
                       SELECT id FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS id_pago,
                   (
                       SELECT monto FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS total_pago,
                   (
                       SELECT estado FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS estado_pago,
                   (
                       -- Retorna el metodo real; NULL si aun no hay pago registrado
                       SELECT metodo
                       FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS metodo_pago,
                   (
                       SELECT comprobante FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS comprobante,
                   ROUND(
                       COALESCE(
                           (SELECT SUM(cs2.precio) FROM cita_servicios cs2 WHERE cs2.id_cita = c.id), s.precio
                       ) - COALESCE(
                           (SELECT SUM(p2.monto) FROM pagos p2 WHERE p2.id_cita = c.id AND p2.estado = 'completado'), 0
                       )
                   , 2) AS saldo_pendiente
            FROM citas c
            INNER JOIN usuarios u ON c.id_usuario = u.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN  usuarios b ON c.id_barbero  = b.id
            ORDER BY c.fecha_hora ASC
        `);
        const citas = rows.map(r => ({
            ...r,
            servicios: r.servicios_raw
                ? JSON.parse('[' + r.servicios_raw + ']')
                : [{ id: r.id_servicio, nombre: r.nombre_servicio, precio: parseFloat(r.precio) }],
            servicios_raw: undefined
        }));
        res.status(200).json({ citas });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar citas.' });
    }
});

// GET /citas/:id — detalle con servicios, barbero y pago activo
app.get('/citas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.promise().query(`
            SELECT c.id, c.id_usuario, c.id_servicio, c.id_barbero,
                   DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_hora,
                   c.estado, c.notas,
                   u.nombre AS nombre_usuario, u.email, u.telefono,
                   s.nombre AS nombre_servicio, s.precio, s.duracion,
                   b.nombre AS nombre_barbero,
                   (
                       SELECT id FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS id_pago,
                   (
                       SELECT monto FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS total_pago,
                   (
                       SELECT estado FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS estado_pago,
                   (
                       SELECT metodo FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS metodo_pago,
                   (
                       SELECT comprobante FROM pagos WHERE id_cita = c.id AND estado != 'rechazado' ORDER BY fecha DESC LIMIT 1
                   ) AS comprobante,
                   -- Mejora #10: saldo pendiente de pago
                   ROUND(
                       COALESCE(
                           (SELECT SUM(cs2.precio) FROM cita_servicios cs2 WHERE cs2.id_cita = c.id), s.precio
                       ) - COALESCE(
                           (SELECT SUM(p2.monto) FROM pagos p2 WHERE p2.id_cita = c.id AND p2.estado = 'completado'), 0
                       )
                   , 2) AS saldo_pendiente
            FROM citas c
            INNER JOIN usuarios u ON c.id_usuario = u.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN  usuarios b ON c.id_barbero  = b.id
            WHERE c.id = ?
        `, [id]);
        if (rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada.' });

        const [serviciosRows] = await pool.promise().query(
            'SELECT id_servicio AS id, nombre, precio, duracion FROM cita_servicios WHERE id_cita = ?', [id]
        );
        const cita = {
            ...rows[0],
            comprobante_url: rows[0].comprobante ? buildUrl(req, rows[0].comprobante) : null,
            servicios: serviciosRows.length > 0
                ? serviciosRows
                : [{ id: rows[0].id_servicio, nombre: rows[0].nombre_servicio, precio: parseFloat(rows[0].precio) }],
            total_servicios: serviciosRows.length > 0
                ? serviciosRows.reduce((s, r) => s + parseFloat(r.precio), 0)
                : parseFloat(rows[0].precio)
        };
        res.status(200).json({ cita });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar cita.' });
    }
});

// PUT /citas/:id — actualizar cita
app.put('/citas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { id_usuario, id_servicio, id_barbero, fecha_hora, estado, notas } = req.body;

        if (fecha_hora) {
            const fechaRegex = /^\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}(:\d{2})?$/;
            if (!fechaRegex.test(fecha_hora) || isNaN(new Date(fecha_hora).getTime()))
                return res.status(400).json({ error: 'Formato de fecha inválido.' });
        }
        const estadosValidos = ['reservada', 'confirmada', 'completada', 'cancelada'];
        if (estado && !estadosValidos.includes(estado))
            return res.status(400).json({ error: `Estado no válido. Opciones: ${estadosValidos.join(', ')}.` });

        if (fecha_hora && id_servicio) {
            const [svc] = await pool.promise().query('SELECT duracion FROM servicios WHERE id = ?', [id_servicio]);
            if (svc.length === 0) return res.status(404).json({ error: 'Servicio no encontrado.' });
            const duracion = svc[0].duracion || 0;
            const [existing] = await pool.promise().query(`
                SELECT c.id FROM citas c INNER JOIN servicios s ON c.id_servicio = s.id
                WHERE c.estado != 'cancelada' AND c.id != ?
                AND ? < DATE_ADD(c.fecha_hora, INTERVAL COALESCE(s.duracion,0) MINUTE)
                AND DATE_ADD(?, INTERVAL ? MINUTE) > c.fecha_hora
            `, [id, fecha_hora, fecha_hora, duracion]);
            if (existing.length > 0) return res.status(409).json({ error: 'El horario se solapa con otra cita.' });
        }
        await pool.promise().query(
            'UPDATE citas SET id_usuario=?, id_servicio=?, id_barbero=?, fecha_hora=?, estado=?, notas=? WHERE id=?',
            [id_usuario, id_servicio, id_barbero || null, fecha_hora, estado, notas, id]
        );
        res.json({ mensaje: 'Cita actualizada correctamente.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al actualizar cita.' });
    }
});

// PATCH /citas/:id/estado — cambio rápido de estado
app.patch('/citas/:id/estado', async (req, res) => {
    try {
        const { id } = req.params;
        const { estado, motivo_cancelacion } = req.body;
        if (!estado) return res.status(400).json({ error: 'Debes enviar el estado.' });
        const estadosValidos = ['reservada', 'confirmada', 'completada', 'cancelada'];
        if (!estadosValidos.includes(estado))
            return res.status(400).json({ error: `Estado no válido. Opciones: ${estadosValidos.join(', ')}.` });
        const [citaRows] = await pool.promise().query('SELECT id, estado FROM citas WHERE id = ?', [id]);
        if (citaRows.length === 0) return res.status(404).json({ error: 'Cita no encontrada.' });

        await pool.promise().query('UPDATE citas SET estado = ? WHERE id = ?', [estado, id]);

        // Mejora #9: al cancelar cita, rechazar todos los pagos pendientes
        if (estado === 'cancelada') {
            const nota = motivo_cancelacion ? `Cita cancelada: ${motivo_cancelacion}` : 'Cita cancelada';
            const [pagosPendientes] = await pool.promise().query(
                "SELECT id, estado, comprobante, id_usuario FROM pagos WHERE id_cita = ? AND estado IN ('pendiente', 'pendiente_aprobacion')",
                [id]
            );
            for (const p of pagosPendientes) {
                eliminarArchivo(p.comprobante);
                await pool.promise().query(
                    "UPDATE pagos SET estado='rechazado', admin_note=? WHERE id=?",
                    [nota, p.id]
                );
                await registrarHistorial(p.id, p.estado, 'rechazado', null, nota);
                // Notificar al cliente (mejora #5)
                if (p.id_usuario) {
                    await crearNotificacion(
                        p.id_usuario, 'cita_cancelada',
                        '❌ Cita cancelada',
                        `Tu cita #${id} fue cancelada. ${motivo_cancelacion ? 'Motivo: ' + motivo_cancelacion : ''}`,
                        p.id
                    );
                }
            }
        }

        res.json({ mensaje: 'Estado actualizado.', estado });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al actualizar estado.' });
    }
});

// PUT /citas/:id/completar — barbero/admin marca el servicio como prestado
// Solo aplica a citas CONFIRMADAS (ya pagadas)
app.put('/citas/:id/completar', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'ID inválido.' });
        const [rows] = await pool.promise().query('SELECT id, estado FROM citas WHERE id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada.' });
        if (rows[0].estado === 'completada') return res.status(400).json({ error: 'La cita ya fue completada.' });
        if (rows[0].estado === 'cancelada') return res.status(400).json({ error: 'No se puede completar una cita cancelada.' });
        if (rows[0].estado === 'reservada') return res.status(400).json({ error: 'La cita aún no está confirmada (pago pendiente).' });
        await pool.promise().query("UPDATE citas SET estado = 'completada' WHERE id = ?", [id]);
        res.json({ mensaje: 'Servicio prestado. Cita marcada como completada.', id_cita: id, estado: 'completada' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al completar cita.' });
    }
});

// DELETE /citas/:id — elimina cita, servicios asociados y pagos
app.delete('/citas/:id', async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        connection = await pool.promise().getConnection();
        await connection.beginTransaction();
        await connection.query('DELETE FROM cita_servicios WHERE id_cita = ?', [id]);
        await connection.query('DELETE FROM pagos WHERE id_cita = ?', [id]);
        const [result] = await connection.query('DELETE FROM citas WHERE id = ?', [id]);
        if (result.affectedRows === 0) {
            await connection.rollback();
            connection.release();
            return res.status(404).json({ error: 'Cita no encontrada.' });
        }
        await connection.commit();
        connection.release();
        res.json({ mensaje: 'Cita eliminada correctamente.' });
    } catch (error) {
        if (connection) { await connection.rollback(); connection.release(); }
        console.error(error);
        res.status(500).json({ error: 'Error al eliminar cita: ' + error.message });
    }
});

// GET /citas/disponibilidad/:fecha_hora?id_servicio=X&id_barbero=Y
app.get('/citas/disponibilidad/:fecha_hora', async (req, res) => {
    try {
        const { fecha_hora } = req.params;
        const { id_servicio, id_barbero } = req.query;
        let duracion = 0;
        if (id_servicio) {
            const [svc] = await pool.promise().query('SELECT duracion FROM servicios WHERE id = ?', [parseInt(id_servicio)]);
            if (svc.length === 0) return res.status(404).json({ error: 'Servicio no encontrado.' });
            duracion = svc[0].duracion || 0;
        }
        const barberoId = id_barbero ? parseInt(id_barbero) : null;
        const baseQ = `
            SELECT c.id FROM citas c
            LEFT JOIN (SELECT id_cita, SUM(duracion) AS dur FROM cita_servicios GROUP BY id_cita) cs ON cs.id_cita = c.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            WHERE c.estado NOT IN ('cancelada')
            AND ? < DATE_ADD(c.fecha_hora, INTERVAL COALESCE(cs.dur, s.duracion, 0) MINUTE)
            AND DATE_ADD(?, INTERVAL ? MINUTE) > c.fecha_hora
        `;
        const params = barberoId ? [fecha_hora, fecha_hora, duracion, barberoId] : [fecha_hora, fecha_hora, duracion];
        const suffix = barberoId ? ' AND c.id_barbero = ?' : '';
        const [existing] = await pool.promise().query(baseQ + suffix, params);
        const disponible = existing.length === 0;
        res.status(200).json({ disponible, mensaje: disponible ? 'Horario disponible' : 'Horario ocupado', duracion_minutos: duracion });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al verificar disponibilidad.' });
    }
});

// ==================== PAGOS ====================
/*
  ⚠️  SQL MIGRATION v2 — Ejecuta en phpMyAdmin ANTES de arrancar:

  -- 1. Tabla multi-servicio por cita
  CREATE TABLE IF NOT EXISTS cita_servicios (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    id_cita     INT NOT NULL,
    id_servicio INT NOT NULL,
    nombre      VARCHAR(255) NOT NULL,
    precio      DECIMAL(10,2) NOT NULL,
    duracion    INT NOT NULL DEFAULT 0,
    FOREIGN KEY (id_cita)     REFERENCES citas(id)    ON DELETE CASCADE,
    FOREIGN KEY (id_servicio) REFERENCES servicios(id)
  );

  -- 2. Barbero en citas
  ALTER TABLE citas
    ADD COLUMN IF NOT EXISTS id_barbero INT NULL AFTER id_servicio;

  -- 3. Campos nuevos en pagos
  ALTER TABLE pagos
    ADD COLUMN IF NOT EXISTS subtotal        DECIMAL(10,2) NOT NULL DEFAULT 0    AFTER monto,
    ADD COLUMN IF NOT EXISTS discount_amount DECIMAL(10,2) NOT NULL DEFAULT 0    AFTER subtotal,
    ADD COLUMN IF NOT EXISTS tip_amount      DECIMAL(10,2) NOT NULL DEFAULT 0    AFTER discount_amount,
    ADD COLUMN IF NOT EXISTS monto_recibido  DECIMAL(10,2) NULL                  AFTER tip_amount,
    ADD COLUMN IF NOT EXISTS cambio          DECIMAL(10,2) NULL                  AFTER monto_recibido,
    ADD COLUMN IF NOT EXISTS admin_id        INT NULL                             AFTER referencia,
    ADD COLUMN IF NOT EXISTS admin_note      TEXT NULL                            AFTER admin_id,
    ADD COLUMN IF NOT EXISTS reviewed_at     DATETIME NULL                        AFTER admin_note,
    ADD COLUMN IF NOT EXISTS transaction_id  VARCHAR(255) NULL                    AFTER reviewed_at,
    ADD COLUMN IF NOT EXISTS reference_code  VARCHAR(100) NULL                    AFTER transaction_id,
    ADD COLUMN IF NOT EXISTS paid_at         DATETIME NULL                        AFTER reference_code;

  -- 4. Ampliar ENUMs
  ALTER TABLE pagos
    MODIFY COLUMN metodo ENUM('efectivo','tarjeta','transferencia','nequi','daviplata') NOT NULL DEFAULT 'efectivo',
    MODIFY COLUMN estado ENUM('pendiente','pendiente_aprobacion','autorizado','completado','rechazado','fallido','reembolsado') NOT NULL DEFAULT 'pendiente';

  ALTER TABLE citas
    MODIFY COLUMN estado ENUM('reservada','confirmada','completada','cancelada') NOT NULL DEFAULT 'reservada';

  -- 5. Migrar datos existentes
  UPDATE pagos SET estado = 'completado'           WHERE estado = 'aprobado';
  UPDATE pagos SET estado = 'pendiente_aprobacion' WHERE estado = 'pendiente' AND comprobante IS NOT NULL;
  UPDATE pagos SET subtotal = monto                WHERE subtotal = 0;
  UPDATE citas SET estado = 'confirmada'           WHERE estado = 'pendiente';

  -- 6. Historial de cambios de estado en pagos (mejora #2)
  CREATE TABLE IF NOT EXISTS pagos_historial (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    id_pago         INT NOT NULL,
    estado_anterior VARCHAR(50) NULL,
    estado_nuevo    VARCHAR(50) NOT NULL,
    admin_id        INT NULL,
    nota            TEXT NULL,
    fecha           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_pago) REFERENCES pagos(id) ON DELETE CASCADE
  );

  -- 7. Notificaciones automáticas (mejora #5)
  CREATE TABLE IF NOT EXISTS notificaciones (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    id_usuario  INT NOT NULL,
    tipo        VARCHAR(50) NOT NULL,
    titulo      VARCHAR(255) NOT NULL,
    mensaje     TEXT NOT NULL,
    leida       TINYINT(1) NOT NULL DEFAULT 0,
    id_ref      INT NULL COMMENT 'id_pago o id_cita relacionado',
    fecha       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_usuario) REFERENCES usuarios(id) ON DELETE CASCADE
  );

  -- 8. Índices de rendimiento
  CREATE INDEX IF NOT EXISTS idx_pagos_id_cita   ON pagos (id_cita);
  CREATE INDEX IF NOT EXISTS idx_pagos_id_usuario ON pagos (id_usuario);
  CREATE INDEX IF NOT EXISTS idx_pagos_estado     ON pagos (estado);
  CREATE INDEX IF NOT EXISTS idx_notif_usuario    ON notificaciones (id_usuario, leida);
*/

/*
  ── FLUJO COMPLETO ──────────────────────────────────────────
  POST /citas               → cita: RESERVADA   + pago: PENDIENTE

  ── EFECTIVO (en el local) ────────────────────────────
  POST /admin/pagos/efectivo → pago: COMPLETADO + cita: CONFIRMADA
  PUT  /citas/:id/completar  → cita: COMPLETADA (servicio prestado)

  ── TRANSFERENCIA / NEQUI / DAVIPLATA ────────────────
  POST /pagos                    → pago: PENDIENTE_APROBACION
  PUT  /pagos/:id/aprobar        → pago: COMPLETADO + cita: CONFIRMADA ✅
  PUT  /pagos/:id/rechazar       → pago: RECHAZADO (admin explica motivo) ❌
  PATCH /pagos/:id/solicitar-info→ admin pide datos (sin cambiar estado)

  ── DESPUÉS DEL SERVICIO ───────────────────────────
  PUT /citas/:id/completar       → cita: COMPLETADA (barbero marcó servicio prestado)
  PUT /pagos/:id/reembolsar      → pago: REEMBOLSADO

  GET /comprobante/:id_pago      → PDF comprobante de pago
*/

// Helper interno
const buildUrl = (req, filePath) => filePath ? `${req.protocol}://${req.get('host')}${filePath}` : null;

// ── Helper: registrar historial de cambio de estado en pago (mejora #2) ─────────
const registrarHistorial = async (id_pago, estado_anterior, estado_nuevo, admin_id = null, nota = null) => {
    try {
        await pool.promise().query(
            'INSERT INTO pagos_historial (id_pago, estado_anterior, estado_nuevo, admin_id, nota) VALUES (?, ?, ?, ?, ?)',
            [id_pago, estado_anterior || null, estado_nuevo, admin_id || null, nota || null]
        );
    } catch (e) { console.error('[historial] Error:', e.message); }
};

// ── Helper: crear notificación para un usuario (mejora #5) ───────────────────────
const crearNotificacion = async (id_usuario, tipo, titulo, mensaje, id_ref = null) => {
    try {
        await pool.promise().query(
            'INSERT INTO notificaciones (id_usuario, tipo, titulo, mensaje, id_ref) VALUES (?, ?, ?, ?, ?)',
            [id_usuario, tipo, titulo, mensaje, id_ref || null]
        );
    } catch (e) { console.error('[notificacion] Error:', e.message); }
};

// ── Helper: notificar a todos los admins (mejora #5) ─────────────────────────────
const notificarAdmins = async (tipo, titulo, mensaje, id_ref = null) => {
    try {
        const [admins] = await pool.promise().query("SELECT id FROM usuarios WHERE rol = 'admin'");
        for (const a of admins) {
            await crearNotificacion(a.id, tipo, titulo, mensaje, id_ref);
        }
    } catch (e) { console.error('[notif-admins] Error:', e.message); }
};

// ── Helper: limpiar comprobante del disco ────────────────────────────────────────
const eliminarArchivo = (rutaRelativa) => {
    if (!rutaRelativa) return;
    try {
        const ruta = path.join(__dirname, rutaRelativa);
        if (fs.existsSync(ruta)) fs.unlinkSync(ruta);
    } catch (e) { console.error('[archivo] Error al eliminar:', e.message); }
};

// ── POST /pagos ── Cliente sube comprobante de pago ─────────────────────────────
// multipart/form-data: id_cita, id_usuario, metodo, referencia?, transaction_id?, comprobante(file)
app.post('/pagos', upload.single('comprobante'), async (req, res) => {
    try {
        const { id_cita, id_usuario, metodo, referencia, transaction_id } = req.body;

        if (!id_cita || !id_usuario || !metodo) {
            if (req.file) eliminarArchivo('/' + path.relative(__dirname, req.file.path).replace(/\\/g, '/'));
            return res.status(400).json({ error: 'Faltan datos: id_cita, id_usuario, metodo.' });
        }

        const metodosValidos = ['transferencia', 'tarjeta', 'nequi', 'daviplata'];
        if (!metodosValidos.includes(metodo)) {
            if (req.file) eliminarArchivo('/' + path.relative(__dirname, req.file.path).replace(/\\/g, '/'));
            return res.status(400).json({ error: 'Método inválido. Usa: transferencia, tarjeta, nequi o daviplata. El efectivo lo registra el administrador.' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'Debes adjuntar el comprobante de pago (JPG/PNG/PDF, máx. 5 MB).' });
        }

        // Verificar que la cita existe y pertenece al usuario
        const [citaRows] = await pool.promise().query(
            `SELECT c.id, c.estado, s.precio, s.nombre AS nombre_servicio
             FROM citas c INNER JOIN servicios s ON c.id_servicio = s.id
             WHERE c.id = ? AND c.id_usuario = ?`,
            [id_cita, id_usuario]
        );
        if (citaRows.length === 0) {
            eliminarArchivo('/' + path.relative(__dirname, req.file.path).replace(/\\/g, '/'));
            return res.status(404).json({ error: 'Cita no encontrada o no pertenece al usuario.' });
        }
        if (citaRows[0].estado === 'cancelada') {
            eliminarArchivo('/' + path.relative(__dirname, req.file.path).replace(/\\/g, '/'));
            return res.status(400).json({ error: 'No se puede pagar una cita cancelada.' });
        }
        if (citaRows[0].estado === 'completada') {
            eliminarArchivo('/' + path.relative(__dirname, req.file.path).replace(/\\/g, '/'));
            return res.status(400).json({ error: 'Esta cita ya fue completada y pagada.' });
        }

        // Permitir múltiples pagos: solo bloquear si el total de pagos completados cubre el monto total
        const [pagosCita] = await pool.promise().query(
            "SELECT monto, estado FROM pagos WHERE id_cita = ?",
            [id_cita]
        );
        const pagosCompletados = pagosCita.filter(p => p.estado === 'completado');
        const sumaPagos = pagosCompletados.reduce((s, p) => s + parseFloat(p.monto), 0);
        // Obtener el total de la cita (sumando servicios)
        const [serviciosRows] = await pool.promise().query(
            'SELECT precio FROM cita_servicios WHERE id_cita = ?', [id_cita]
        );
        const totalCita = serviciosRows.reduce((s, r) => s + parseFloat(r.precio), 0);
        if (sumaPagos >= totalCita) {
            eliminarArchivo('/' + path.relative(__dirname, req.file.path).replace(/\\/g, '/'));
            return res.status(409).json({
                error: 'Esta cita ya está pagada en su totalidad.'
            });
        }

        // Ruta relativa desde __dirname (incluye subdirectorio año/mes) (mejora #6)
        const urlComprobante = '/' + path.relative(__dirname, req.file.path).replace(/\\/g, '/');
        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');

        // Buscar pago activo: primero 'pendiente', luego 'pendiente_aprobacion'
        // (cubre el caso de re-envío de comprobante sin haber sido rechazado)
        const [pagoPendiente] = await pool.promise().query(
            `SELECT * FROM pagos
             WHERE id_cita = ? AND estado IN ('pendiente', 'pendiente_aprobacion')
             ORDER BY FIELD(estado,'pendiente','pendiente_aprobacion'), fecha DESC
             LIMIT 1`,
            [id_cita]
        );

        let id_pago, subtotal, total;

        if (pagoPendiente.length > 0) {
            // ACTUALIZAR el pago con el comprobante y método real elegido por el usuario
            const p = pagoPendiente[0];
            subtotal = parseFloat(p.subtotal || p.monto);
            total = subtotal;
            // Borrar comprobante anterior si existe
            if (p.comprobante) {
                const fAnterior = path.join(__dirname, p.comprobante);
                if (fs.existsSync(fAnterior)) fs.unlinkSync(fAnterior);
            }
            await pool.promise().query(
                `UPDATE pagos SET metodo=?, estado='pendiente_aprobacion',
                  comprobante=?, referencia=?, transaction_id=?, fecha=? WHERE id=?`,
                [metodo, urlComprobante, referencia || null, transaction_id || null, now, p.id]
            );
            id_pago = p.id;
            // Registrar historial (mejora #2)
            await registrarHistorial(id_pago, p.estado, 'pendiente_aprobacion', null, 'Comprobante subido por cliente');
        } else {
            // Sin pago activo: limpiar rechazado anterior y crear nuevo
            const [pagoRechazado] = await pool.promise().query(
                "SELECT id, comprobante FROM pagos WHERE id_cita = ? AND estado = 'rechazado' ORDER BY fecha DESC LIMIT 1",
                [id_cita]
            );
            if (pagoRechazado.length > 0) {
                eliminarArchivo(pagoRechazado[0].comprobante);
                await pool.promise().query('DELETE FROM pagos WHERE id = ?', [pagoRechazado[0].id]);
            }
            subtotal = parseFloat(citaRows[0].precio);
            total = subtotal;
            const [result] = await pool.promise().query(
                `INSERT INTO pagos
                   (id_cita, id_usuario, subtotal, monto, metodo, estado,
                    comprobante, referencia, transaction_id, fecha)
                 VALUES (?, ?, ?, ?, ?, 'pendiente_aprobacion', ?, ?, ?, ?)`,
                [id_cita, id_usuario, subtotal, total, metodo,
                    urlComprobante, referencia || null, transaction_id || null, now]
            );
            id_pago = result.insertId;
            // Registrar historial (mejora #2)
            await registrarHistorial(id_pago, null, 'pendiente_aprobacion', null, 'Comprobante subido por cliente');
        }

        // Notificar a admins que hay un nuevo comprobante pendiente (mejora #5)
        await notificarAdmins(
            'pago_pendiente',
            'Nuevo comprobante de pago',
            `El cliente ${id_usuario} subió comprobante para la cita #${id_cita} (método: ${metodo}).`,
            id_pago
        );

        res.status(201).json({
            mensaje: 'Comprobante enviado. El administrador revisará y confirmará tu pago.',
            id_pago,
            subtotal,
            total,
            nombre_servicio: citaRows[0].nombre_servicio,
            estado: 'pendiente_aprobacion',
            comprobante_url: buildUrl(req, urlComprobante)
        });
    } catch (error) {
        if (req.file) {
            try { fs.unlinkSync(req.file.path); } catch (_) { }
        }
        console.error(error);
        res.status(500).json({ error: 'Error al registrar pago.' });
    }
});

// ── GET /mis-pagos?id_usuario=X ── Cliente ve su historial ──────────────────────
app.get('/mis-pagos', async (req, res) => {
    try {
        const { id_usuario } = req.query;
        if (!id_usuario || isNaN(parseInt(id_usuario)))
            return res.status(400).json({ error: 'id_usuario requerido y debe ser número.' });

        const [rows] = await pool.promise().query(`
            SELECT p.id, p.id_cita, p.id_usuario,
                   p.subtotal, p.monto AS total, p.discount_amount, p.tip_amount,
                   p.metodo, p.estado,
                   DATE_FORMAT(p.fecha,        '%Y-%m-%d %H:%i:%s') AS created_at,
                   DATE_FORMAT(p.paid_at,      '%Y-%m-%d %H:%i:%s') AS paid_at,
                   DATE_FORMAT(p.reviewed_at,  '%Y-%m-%d %H:%i:%s') AS reviewed_at,
                   p.comprobante, p.referencia, p.transaction_id, p.reference_code,
                   p.admin_note,
                   s.nombre AS nombre_servicio, s.precio,
                   DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_cita,
                   c.estado AS estado_cita
            FROM pagos p
            INNER JOIN citas    c ON p.id_cita    = c.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            WHERE p.id_usuario = ?
            ORDER BY p.fecha DESC
        `, [parseInt(id_usuario)]);

        res.status(200).json({
            pagos: rows.map(r => ({ ...r, comprobante_url: buildUrl(req, r.comprobante) })),
            total: rows.length
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar pagos.' });
    }
});

// ── GET /pagos/pendientes ── Admin: comprobantes esperando revisión ───────────────
app.get('/pagos/pendientes', async (req, res) => {
    try {
        const [rows] = await pool.promise().query(`
            SELECT p.id, p.id_cita, p.id_usuario,
                   p.subtotal, p.monto AS total, p.metodo, p.estado,
                   DATE_FORMAT(p.fecha, '%Y-%m-%d %H:%i:%s') AS created_at,
                   p.comprobante, p.referencia, p.transaction_id,
                   u.nombre AS nombre_cliente, u.email AS email_cliente, u.telefono AS telefono_cliente,
                   s.nombre AS nombre_servicio, s.precio,
                   DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_cita,
                   c.estado AS estado_cita
            FROM pagos p
            LEFT JOIN citas    c  ON p.id_cita    = c.id
            LEFT JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN usuarios  u ON p.id_usuario  = u.id
            WHERE p.estado = 'pendiente_aprobacion'
            ORDER BY p.fecha ASC
        `);
        res.status(200).json({
            pendientes: rows.map(r => ({ ...r, comprobante_url: buildUrl(req, r.comprobante) })),
            total: rows.length
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar pagos pendientes.' });
    }
});

// ── GET /pagos ── Admin: listado completo con filtros ────────────────────────────
app.get('/pagos', async (req, res) => {
    try {
        const { estado, metodo, id_usuario, fecha_desde, fecha_hasta } = req.query;
        let query = `
            SELECT p.id, p.id_cita, p.id_usuario,
                   p.subtotal, p.monto AS total, p.discount_amount, p.tip_amount,
                   p.metodo, p.estado,
                   DATE_FORMAT(p.fecha,       '%Y-%m-%d %H:%i:%s') AS created_at,
                   DATE_FORMAT(p.paid_at,     '%Y-%m-%d %H:%i:%s') AS paid_at,
                   DATE_FORMAT(p.reviewed_at, '%Y-%m-%d %H:%i:%s') AS reviewed_at,
                   p.comprobante, p.referencia, p.transaction_id, p.reference_code,
                   p.admin_note, p.admin_id,
                   u.nombre AS nombre_cliente, u.email AS email_cliente,
                   s.nombre AS nombre_servicio,
                   DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_cita,
                   c.estado AS estado_cita
            FROM pagos p
            INNER JOIN citas    c ON p.id_cita    = c.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN  usuarios  u ON p.id_usuario  = u.id
        `;
        const conditions = [], params = [];
        if (estado) { conditions.push('p.estado = ?'); params.push(estado); }
        if (metodo) { conditions.push('p.metodo = ?'); params.push(metodo); }
        if (id_usuario) { conditions.push('p.id_usuario = ?'); params.push(parseInt(id_usuario)); }
        if (fecha_desde) { conditions.push('DATE(p.fecha) >= ?'); params.push(fecha_desde); }
        if (fecha_hasta) { conditions.push('DATE(p.fecha) <= ?'); params.push(fecha_hasta); }
        if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
        query += ' ORDER BY p.fecha DESC';

        const [rows] = await pool.promise().query(query, params);
        res.status(200).json({
            pagos: rows.map(r => ({ ...r, comprobante_url: buildUrl(req, r.comprobante) }))
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar pagos.' });
    }
});

// ── GET /pagos/cita/:id_cita ── Todos los pagos de una cita ──────────────────────
app.get('/pagos/cita/:id_cita', async (req, res) => {
    try {
        const { id_cita } = req.params;
        const [rows] = await pool.promise().query(`
            SELECT p.id, p.id_cita, p.id_usuario,
                   p.subtotal, p.monto AS total, p.discount_amount, p.tip_amount,
                   p.metodo, p.estado,
                   DATE_FORMAT(p.fecha,   '%Y-%m-%d %H:%i:%s') AS created_at,
                   DATE_FORMAT(p.paid_at, '%Y-%m-%d %H:%i:%s') AS paid_at,
                   p.comprobante, p.referencia, p.transaction_id, p.reference_code,
                   p.admin_note
            FROM pagos p WHERE p.id_cita = ?
            ORDER BY p.fecha DESC
        `, [id_cita]);
        res.status(200).json({
            pagos: rows.map(r => ({ ...r, comprobante_url: buildUrl(req, r.comprobante) }))
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar pagos de la cita.' });
    }
});

// ── GET /pagos/:id ── Ver detalle de un pago ─────────────────────────────────────
app.get('/pagos/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'ID de pago inválido.' });

        const [rows] = await pool.promise().query(`
            SELECT p.*,
                   DATE_FORMAT(p.fecha,       '%Y-%m-%d %H:%i:%s') AS created_at,
                   DATE_FORMAT(p.paid_at,     '%Y-%m-%d %H:%i:%s') AS paid_at,
                   DATE_FORMAT(p.reviewed_at, '%Y-%m-%d %H:%i:%s') AS reviewed_at,
                   u.nombre  AS nombre_cliente,  u.email AS email_cliente, u.telefono AS telefono_cliente,
                   s.nombre  AS nombre_servicio, s.precio,
                   DATE_FORMAT(c.fecha_hora, '%Y-%m-%d %H:%i:%s') AS fecha_cita,
                   c.estado  AS estado_cita,     c.notas AS notas_cita,
                   a.nombre  AS nombre_admin
            FROM pagos p
            INNER JOIN citas    c ON p.id_cita    = c.id
            INNER JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN  usuarios  u ON p.id_usuario  = u.id
            LEFT JOIN  usuarios  a ON p.admin_id    = a.id
            WHERE p.id = ?
        `, [id]);
        if (rows.length === 0) return res.status(404).json({ error: 'Pago no encontrado.' });

        const pago = rows[0];
        res.status(200).json({
            pago: { ...pago, total: pago.monto, comprobante_url: buildUrl(req, pago.comprobante) }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar pago.' });
    }
});

// ── DELETE /pagos/:id ── Cliente cancela pago pendiente o rechazado ──────────────
app.delete('/pagos/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'ID de pago inválido.' });

        const [pagoRows] = await pool.promise().query('SELECT * FROM pagos WHERE id = ?', [id]);
        if (pagoRows.length === 0) return res.status(404).json({ error: 'Pago no encontrado.' });
        const pago = pagoRows[0];

        // Permitir eliminar solo si el pago no está completado ni reembolsado
        if (pago.estado === 'completado')
            return res.status(400).json({ error: 'No puedes cancelar un pago ya completado.' });
        if (pago.estado === 'reembolsado')
            return res.status(400).json({ error: 'No puedes cancelar un pago reembolsado.' });

        if (pago.comprobante) eliminarArchivo(pago.comprobante);
        await pool.promise().query('DELETE FROM pagos WHERE id = ?', [id]);
        res.json({ mensaje: 'Pago cancelado. Ya puedes registrar un nuevo comprobante.', id_pago_eliminado: id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al cancelar el pago.' });
    }
});

// ── PUT /pagos/:id/aprobar ── Admin aprueba comprobante ──────────────────────────
// Body JSON: { admin_id, admin_note? }
app.put('/pagos/:id/aprobar', async (req, res) => {
    const connection = await pool.promise().getConnection();
    try {
        const id = parseInt(req.params.id);
        const { admin_id, admin_note } = req.body;
        if (isNaN(id)) { connection.release(); return res.status(400).json({ error: 'ID de pago inválido.' }); }
        if (!admin_id) { connection.release(); return res.status(400).json({ error: 'Se requiere admin_id.' }); }

        const [adminRows] = await connection.query('SELECT rol FROM usuarios WHERE id = ?', [parseInt(admin_id)]);
        if (adminRows.length === 0 || adminRows[0].rol !== 'admin') {
            connection.release();
            return res.status(403).json({ error: 'Solo un administrador puede aprobar pagos.' });
        }

        const [pagoRows] = await connection.query(`
            SELECT p.*, u.nombre AS nombre_cliente, u.email AS email_cliente, s.nombre AS nombre_servicio
            FROM pagos p
            LEFT JOIN usuarios  u ON p.id_usuario   = u.id
            LEFT JOIN citas     c ON p.id_cita       = c.id
            LEFT JOIN servicios s ON c.id_servicio   = s.id
            WHERE p.id = ?
        `, [id]);
        if (pagoRows.length === 0) { connection.release(); return res.status(404).json({ error: 'Pago no encontrado.' }); }
        const pago = pagoRows[0];

        if (pago.estado === 'completado') { connection.release(); return res.status(400).json({ error: 'Este pago ya fue aprobado.' }); }
        if (pago.estado === 'rechazado') { connection.release(); return res.status(400).json({ error: 'No se puede aprobar un pago rechazado. El cliente debe re-enviar comprobante.' }); }
        if (pago.estado === 'reembolsado') { connection.release(); return res.status(400).json({ error: 'No se puede aprobar un pago reembolsado.' }); }

        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
        await connection.beginTransaction();
        await connection.query(
            "UPDATE pagos SET estado='completado', admin_id=?, admin_note=?, reviewed_at=?, paid_at=? WHERE id=?",
            [parseInt(admin_id), admin_note || null, now, now, id]
        );
        // Verificar si la suma de pagos completados cubre el total de la cita
        const [pagosCita] = await connection.query(
            "SELECT monto, estado FROM pagos WHERE id_cita = ?",
            [pago.id_cita]
        );
        const pagosCompletados = pagosCita.filter(p => p.estado === 'completado');
        const sumaPagos = pagosCompletados.reduce((s, p) => s + parseFloat(p.monto), 0);
        const [serviciosRows] = await connection.query(
            'SELECT precio FROM cita_servicios WHERE id_cita = ?', [pago.id_cita]
        );
        const totalCita = serviciosRows.reduce((s, r) => s + parseFloat(r.precio), 0);
        if (sumaPagos >= totalCita) {
            await connection.query("UPDATE citas SET estado='confirmada' WHERE id=?", [pago.id_cita]);
        }
        await connection.commit();
        connection.release();

        // Registrar historial (mejora #2)
        await registrarHistorial(id, pago.estado, 'completado', parseInt(admin_id), admin_note || 'Aprobado por admin');
        // Notificar al cliente (mejora #5)
        if (pago.id_usuario) {
            await crearNotificacion(
                pago.id_usuario, 'pago_aprobado',
                '✅ Pago aprobado',
                `Tu pago de $${parseFloat(pago.monto).toLocaleString('es-CO')} para el servicio "${pago.nombre_servicio}" fue aprobado. Tu cita está confirmada.`,
                id
            );
        }

        res.json({
            mensaje: 'Pago aprobado. Cita marcada como completada.',
            id_pago: id, estado: 'completado',
            nombre_cliente: pago.nombre_cliente, email_cliente: pago.email_cliente,
            nombre_servicio: pago.nombre_servicio, total: pago.monto,
            metodo: pago.metodo, paid_at: now
        });
    } catch (error) {
        await connection.rollback(); connection.release();
        console.error(error);
        res.status(500).json({ error: 'Error al aprobar pago.' });
    }
});

// ── PUT /pagos/:id/rechazar ── Admin rechaza comprobante ─────────────────────────
// Body JSON: { admin_id, admin_note }   ← admin_note es OBLIGATORIO (motivo visible al cliente)
app.put('/pagos/:id/rechazar', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const { admin_id, admin_note } = req.body;
        if (isNaN(id)) return res.status(400).json({ error: 'ID de pago inválido.' });
        if (!admin_id) return res.status(400).json({ error: 'Se requiere admin_id.' });
        if (!admin_note || !admin_note.trim())
            return res.status(400).json({ error: 'Se requiere admin_note con el motivo del rechazo.' });

        const [adminRows] = await pool.promise().query('SELECT rol FROM usuarios WHERE id = ?', [parseInt(admin_id)]);
        if (adminRows.length === 0 || adminRows[0].rol !== 'admin')
            return res.status(403).json({ error: 'Solo un administrador puede rechazar pagos.' });

        const [pagoRows] = await pool.promise().query('SELECT * FROM pagos WHERE id = ?', [id]);
        if (pagoRows.length === 0) return res.status(404).json({ error: 'Pago no encontrado.' });
        const pago = pagoRows[0];

        if (pago.estado === 'rechazado') return res.status(400).json({ error: 'Este pago ya fue rechazado.' });
        if (pago.estado === 'completado') return res.status(400).json({ error: 'No se puede rechazar un pago ya completado.' });
        if (pago.estado === 'reembolsado') return res.status(400).json({ error: 'No se puede rechazar un pago reembolsado.' });

        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
        await pool.promise().query(
            "UPDATE pagos SET estado='rechazado', admin_id=?, admin_note=?, reviewed_at=? WHERE id=?",
            [parseInt(admin_id), admin_note.trim(), now, id]
        );
        // Eliminar archivo para liberar espacio (el cliente deberá subir uno nuevo)
        eliminarArchivo(pago.comprobante);
        // Registrar historial (mejora #2)
        await registrarHistorial(id, pago.estado, 'rechazado', parseInt(admin_id), admin_note.trim());
        // Notificar al cliente (mejora #5)
        if (pago.id_usuario) {
            await crearNotificacion(
                pago.id_usuario, 'pago_rechazado',
                '❌ Comprobante rechazado',
                `Tu comprobante fue rechazado. Motivo: ${admin_note.trim()}. Por favor envía un nuevo comprobante.`,
                id
            );
        }
        res.json({
            mensaje: 'Pago rechazado. El cliente deberá re-enviar comprobante.',
            id_pago: id, estado: 'rechazado', admin_note: admin_note.trim()
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al rechazar pago.' });
    }
});

// ── PATCH /pagos/:id/solicitar-info ── Admin pide más información ────────────────
// No cambia el estado — agrega una nota que el cliente puede ver en GET /mis-pagos
// Body JSON: { admin_id, admin_note }
app.patch('/pagos/:id/solicitar-info', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const { admin_id, admin_note } = req.body;
        if (isNaN(id)) return res.status(400).json({ error: 'ID de pago inválido.' });
        if (!admin_id) return res.status(400).json({ error: 'Se requiere admin_id.' });
        if (!admin_note || !admin_note.trim())
            return res.status(400).json({ error: 'Se requiere admin_note con la información solicitada.' });

        const [adminRows] = await pool.promise().query('SELECT rol FROM usuarios WHERE id = ?', [parseInt(admin_id)]);
        if (adminRows.length === 0 || adminRows[0].rol !== 'admin')
            return res.status(403).json({ error: 'Solo un administrador puede solicitar información.' });

        const [pagoRows] = await pool.promise().query('SELECT id, estado FROM pagos WHERE id = ?', [id]);
        if (pagoRows.length === 0) return res.status(404).json({ error: 'Pago no encontrado.' });
        if (pagoRows[0].estado !== 'pendiente_aprobacion')
            return res.status(400).json({ error: 'Solo se puede pedir información en pagos pendientes de aprobación.' });

        await pool.promise().query(
            'UPDATE pagos SET admin_id = ?, admin_note = ? WHERE id = ?',
            [parseInt(admin_id), admin_note.trim(), id]
        );
        res.json({
            mensaje: 'Nota enviada. El pago continúa en revisión.',
            id_pago: id, admin_note: admin_note.trim()
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al solicitar información.' });
    }
});

// ── PUT /pagos/:id/reembolsar ── Admin registra devolución ───────────────────────
// Body JSON: { admin_id, admin_note }
app.put('/pagos/:id/reembolsar', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const { admin_id, admin_note } = req.body;
        if (isNaN(id)) return res.status(400).json({ error: 'ID de pago inválido.' });
        if (!admin_id) return res.status(400).json({ error: 'Se requiere admin_id.' });
        if (!admin_note || !admin_note.trim())
            return res.status(400).json({ error: 'Se requiere admin_note con el motivo del reembolso.' });

        const [adminRows] = await pool.promise().query('SELECT rol FROM usuarios WHERE id = ?', [parseInt(admin_id)]);
        if (adminRows.length === 0 || adminRows[0].rol !== 'admin')
            return res.status(403).json({ error: 'Solo un administrador puede registrar reembolsos.' });

        const [pagoRows] = await pool.promise().query(`
            SELECT p.*, s.nombre AS nombre_servicio, u.nombre AS nombre_cliente
            FROM pagos p
            LEFT JOIN citas     c ON p.id_cita    = c.id
            LEFT JOIN servicios s ON c.id_servicio = s.id
            LEFT JOIN usuarios  u ON p.id_usuario  = u.id
            WHERE p.id = ?
        `, [id]);
        if (pagoRows.length === 0) return res.status(404).json({ error: 'Pago no encontrado.' });
        const pago = pagoRows[0];

        if (pago.estado !== 'completado')
            return res.status(400).json({ error: 'Solo se puede reembolsar un pago completado.' });

        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
        await pool.promise().query(
            "UPDATE pagos SET estado='reembolsado', admin_id=?, admin_note=?, reviewed_at=? WHERE id=?",
            [parseInt(admin_id), admin_note.trim(), now, id]
        );
        // Registrar historial (mejora #2)
        await registrarHistorial(id, pago.estado, 'reembolsado', parseInt(admin_id), admin_note.trim());

        // Mejora #9: si todos los pagos completados de la cita están reembolsados, cancelar la cita
        const [pagosCita] = await pool.promise().query(
            "SELECT estado FROM pagos WHERE id_cita = ?", [pago.id_cita]
        );
        const hayPagosActivos = pagosCita.some(p =>
            p.estado === 'completado' || p.estado === 'pendiente' || p.estado === 'pendiente_aprobacion'
        );
        if (!hayPagosActivos) {
            await pool.promise().query(
                "UPDATE citas SET estado='cancelada' WHERE id=? AND estado != 'completada'",
                [pago.id_cita]
            );
        }
        // Notificar al cliente (mejora #5)
        if (pago.id_usuario) {
            await crearNotificacion(
                pago.id_usuario, 'pago_reembolsado',
                '💰 Reembolso registrado',
                `Se registró el reembolso de $${parseFloat(pago.monto).toLocaleString('es-CO')} para "${pago.nombre_servicio}". Motivo: ${admin_note.trim()}.`,
                id
            );
        }
        res.json({
            mensaje: 'Reembolso registrado correctamente.',
            id_pago: id, estado: 'reembolsado',
            total: pago.monto, nombre_cliente: pago.nombre_cliente,
            nombre_servicio: pago.nombre_servicio, admin_note: admin_note.trim()
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al registrar reembolso.' });
    }
});

// ── POST /admin/pagos ── Admin registra cobro en efectivo presencial ─────────────
// Body JSON: { id_cita, id_admin, admin_note?, tip_amount?, discount_amount?, monto_recibido? }
app.post('/admin/pagos', async (req, res) => {
    try {
        const { id_cita, id_admin, id_usuario, admin_note, tip_amount, discount_amount, monto_recibido } = req.body;
        const adminId = parseInt(id_admin || id_usuario);
        if (!id_cita || !adminId)
            return res.status(400).json({ error: 'Faltan datos: id_cita, id_admin.' });

        const [adminCheck] = await pool.promise().query('SELECT rol FROM usuarios WHERE id = ?', [adminId]);
        if (adminCheck.length === 0 || adminCheck[0].rol !== 'admin')
            return res.status(403).json({ error: 'Solo un administrador puede registrar pagos en efectivo.' });

        const [citaRows] = await pool.promise().query(`
            SELECT c.id, c.estado, c.id_usuario AS cliente_id,
                   s.precio, s.nombre AS nombre_servicio,
                   u.nombre AS nombre_cliente, u.email AS email_cliente
            FROM citas c
            INNER JOIN servicios s ON c.id_servicio = s.id
            INNER JOIN usuarios  u ON c.id_usuario  = u.id
            WHERE c.id = ?
        `, [id_cita]);
        if (citaRows.length === 0) return res.status(404).json({ error: 'Cita no encontrada.' });

        const cita = citaRows[0];
        if (cita.estado === 'cancelada') return res.status(400).json({ error: 'No se puede cobrar una cita cancelada.' });
        if (cita.estado === 'completada') return res.status(400).json({ error: 'Esta cita ya fue completada.' });

        const [pagoExistente] = await pool.promise().query(
            "SELECT id FROM pagos WHERE id_cita = ? AND estado = 'completado'", [id_cita]
        );
        if (pagoExistente.length > 0) return res.status(409).json({ error: 'Esta cita ya tiene un pago completado.' });

        // Cancelar comprobante en revisión si existe (pagó en efectivo presencialmente)
        const [pagoPendiente] = await pool.promise().query(
            "SELECT id, comprobante FROM pagos WHERE id_cita = ? AND estado IN ('pendiente', 'pendiente_aprobacion')", [id_cita]
        );
        for (const p of pagoPendiente) {
            eliminarArchivo(p.comprobante);
            await pool.promise().query('DELETE FROM pagos WHERE id = ?', [p.id]);
        }

        // Mejora #3: calcular totales y validar monto_recibido
        const [serviciosCita] = await pool.promise().query(
            'SELECT precio FROM cita_servicios WHERE id_cita = ?', [id_cita]
        );
        const subtotal = serviciosCita.length > 0
            ? serviciosCita.reduce((s, r) => s + parseFloat(r.precio), 0)
            : parseFloat(cita.precio);
        const descuento = parseFloat(discount_amount) || 0;
        const propina = parseFloat(tip_amount) || 0;
        const total = subtotal - descuento + propina;

        // Validar monto_recibido (mejora #3)
        let montoRecibido = monto_recibido ? parseFloat(monto_recibido) : null;
        let cambio = null;
        if (montoRecibido !== null) {
            if (isNaN(montoRecibido) || montoRecibido < 0)
                return res.status(400).json({ error: 'monto_recibido debe ser un número positivo.' });
            if (montoRecibido < total)
                return res.status(400).json({
                    error: `El monto recibido ($${montoRecibido.toLocaleString('es-CO')}) es menor al total ($${total.toLocaleString('es-CO')}).`
                });
            cambio = parseFloat((montoRecibido - total).toFixed(2));
        }

        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');

        const [result] = await pool.promise().query(
            `INSERT INTO pagos
               (id_cita, id_usuario, subtotal, discount_amount, tip_amount, monto,
                monto_recibido, cambio, metodo, estado, admin_id, admin_note, reviewed_at, paid_at, fecha)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'efectivo', 'completado', ?, ?, ?, ?, ?)`,
            [id_cita, cita.cliente_id, subtotal, descuento, propina, total,
                montoRecibido, cambio, adminId, admin_note || null, now, now, now]
        );
        await pool.promise().query("UPDATE citas SET estado='confirmada' WHERE id=?", [id_cita]);

        // Registrar historial (mejora #2)
        await registrarHistorial(result.insertId, null, 'completado', adminId, 'Cobro en efectivo presencial');

        // Notificar al cliente (mejora #5)
        await crearNotificacion(
            cita.cliente_id, 'pago_completado',
            '✅ Pago registrado',
            `Tu pago de $${total.toLocaleString('es-CO')} en efectivo por "${cita.nombre_servicio}" fue registrado. ¡Tu cita está confirmada!`,
            result.insertId
        );

        res.status(201).json({
            mensaje: 'Cobro en efectivo registrado correctamente.',
            id_pago: result.insertId, estado: 'completado',
            subtotal, discount_amount: descuento, tip_amount: propina, total,
            monto_recibido: montoRecibido, cambio,
            nombre_cliente: cita.nombre_cliente, email_cliente: cita.email_cliente,
            nombre_servicio: cita.nombre_servicio, paid_at: now
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al registrar cobro en efectivo.' });
    }
});

// ── GET /reportes/ingresos ── Admin: reporte financiero ──────────────────────────
app.get('/reportes/ingresos', async (req, res) => {
    try {
        const { fecha_desde, fecha_hasta } = req.query;
        let whereClause = "WHERE p.estado = 'completado'";
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
             INNER JOIN citas    c ON p.id_cita    = c.id
             INNER JOIN servicios s ON c.id_servicio = s.id
             ${whereClause} GROUP BY s.id ORDER BY monto DESC LIMIT 5`, params
        );
        res.json({ totalIngresos, totalPagos, porMetodo, porMes, porDia, topServicios });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al generar reporte de ingresos.' });
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
        // Total de pagos completados
        const [totalPagosRows] = await pool.promise().query(
            "SELECT COUNT(*) as total FROM pagos WHERE estado = 'completado'"
        );
        const totalPagos = totalPagosRows[0]?.total || 0;

        // Total monto pagado (pagos completados)
        const [totalMontoRows] = await pool.promise().query(
            "SELECT SUM(monto) as totalMonto FROM pagos WHERE estado = 'completado'"
        );
        const totalMontoPagado = totalMontoRows[0]?.totalMonto || 0;

        // Pagos pendientes de aprobación
        const [[{ totalPendientes }]] = await pool.promise().query(
            "SELECT COUNT(*) as totalPendientes FROM pagos WHERE estado = 'pendiente_aprobacion'"
        );

        // Pagos por método (solo completados)
        const [pagosPorMetodoRows] = await pool.promise().query(
            "SELECT metodo, COUNT(*) as total, SUM(monto) as montoTotal FROM pagos WHERE estado = 'completado' GROUP BY metodo"
        );
        const pagosPorMetodo = pagosPorMetodoRows || [];

        // Pagos por mes (solo completados)
        const [pagosPorMesRows] = await pool.promise().query(`
            SELECT DATE_FORMAT(pagos.fecha, '%Y-%m') as mes, COUNT(*) as total, SUM(pagos.monto) as montoTotal
            FROM pagos
            WHERE pagos.estado = 'completado'
            GROUP BY DATE_FORMAT(pagos.fecha, '%Y-%m')
            ORDER BY mes DESC
            LIMIT 12
        `);
        const pagosPorMes = pagosPorMesRows || [];

        // Pagos por día (solo completados)
        const [pagosPorDiaRows] = await pool.promise().query(`
            SELECT DATE(pagos.fecha) as dia, COUNT(*) as total, SUM(pagos.monto) as montoTotal
            FROM pagos
            WHERE pagos.estado = 'completado'
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

// ── GET /comprobante/:id_pago ── Genera PDF del comprobante de pago ─────────────
app.get('/comprobante/:id_pago', async (req, res) => {
    try {
        const id = parseInt(req.params.id_pago);
        if (isNaN(id)) return res.status(400).json({ error: 'ID de pago inválido.' });

        const [pagos] = await pool.promise().query(`
            SELECT p.*,
                   u.nombre AS nombre_cliente, u.email, u.telefono,
                   DATE_FORMAT(c.fecha_hora, '%d/%m/%Y %H:%i') AS fecha_cita,
                   c.notas AS notas_cita,
                   b.nombre AS nombre_barbero
            FROM pagos p
            LEFT JOIN usuarios  u ON p.id_usuario = u.id
            LEFT JOIN citas     c ON p.id_cita    = c.id
            LEFT JOIN usuarios  b ON c.id_barbero = b.id
            WHERE p.id = ?
        `, [id]);
        if (pagos.length === 0) return res.status(404).json({ error: 'Pago no encontrado.' });
        const pago = pagos[0];

        // Servicios de la cita
        let [servicios] = await pool.promise().query(
            'SELECT nombre, precio FROM cita_servicios WHERE id_cita = ?', [pago.id_cita]
        );
        if (servicios.length === 0) {
            const [srvFallback] = await pool.promise().query(
                'SELECT s.nombre, s.precio FROM citas c INNER JOIN servicios s ON c.id_servicio = s.id WHERE c.id = ?',
                [pago.id_cita]
            );
            servicios = srvFallback;
        }

        const doc = new PDFDocument({ margin: 50, size: 'A5' });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="comprobante-${id}.pdf"`);
        doc.pipe(res);

        // ── Encabezado ──
        doc.fontSize(18).font('Helvetica-Bold').text('✂  BARBERÍA', { align: 'center' });
        doc.fontSize(10).font('Helvetica').text('Comprobante de Pago', { align: 'center' });
        doc.moveDown(0.5);
        doc.moveTo(50, doc.y).lineTo(395, doc.y).lineWidth(1).stroke(); doc.moveDown(0.5);

        // ── Número y fecha ──
        const emision = new Date().toLocaleDateString('es-CO', { dateStyle: 'long' });
        doc.fontSize(9);
        doc.text(`N° REC-${String(id).padStart(6, '0')}   |   Emisión: ${emision}`);
        doc.text(`Fecha de cita: ${pago.fecha_cita || '—'}`);
        if (pago.nombre_barbero) doc.text(`Barbero: ${pago.nombre_barbero}`);
        doc.moveDown();

        // ── Cliente ──
        doc.fontSize(10).font('Helvetica-Bold').text('Cliente');
        doc.fontSize(9).font('Helvetica');
        doc.text(pago.nombre_cliente || '—');
        if (pago.email) doc.text(pago.email);
        if (pago.telefono) doc.text(pago.telefono);
        doc.moveDown();

        // ── Tabla de servicios ──
        doc.fontSize(10).font('Helvetica-Bold').text('Servicios');
        doc.moveDown(0.2);
        doc.moveTo(50, doc.y).lineTo(395, doc.y).stroke(); doc.moveDown(0.2);
        doc.fontSize(9).font('Helvetica');
        for (const s of servicios) {
            const y = doc.y;
            doc.text(s.nombre, 50, y, { width: 260 });
            doc.text(`$${parseFloat(s.precio).toLocaleString('es-CO')}`, 310, y, { width: 85, align: 'right' });
            doc.moveDown(0.3);
        }
        doc.moveTo(50, doc.y).lineTo(395, doc.y).stroke(); doc.moveDown(0.3);

        // ── Totales ──
        const subtotal = parseFloat(pago.subtotal || pago.monto || 0);
        const descuento = parseFloat(pago.discount_amount || 0);
        const propina = parseFloat(pago.tip_amount || 0);
        const total = parseFloat(pago.monto || 0);
        const recibido = parseFloat(pago.monto_recibido || 0);
        const cambio = parseFloat(pago.cambio || 0);

        const addRow = (label, valor, bold = false) => {
            const y = doc.y;
            doc[bold ? 'font' : 'font']('Helvetica' + (bold ? '-Bold' : ''));
            doc.fontSize(bold ? 10 : 9).text(label, 210, y, { width: 140 });
            doc.text(`$${valor.toLocaleString('es-CO')}`, 310, y, { width: 85, align: 'right' });
            doc.moveDown(0.3);
        };
        if (descuento > 0) { addRow('Subtotal:', subtotal); addRow('Descuento:', -descuento); }
        if (propina > 0) addRow('Propina:', propina);
        addRow('TOTAL:', total, true);
        if (recibido > 0) { addRow('Recibido:', recibido); addRow('Cambio:', cambio); }
        doc.moveDown(0.5);

        // ── Método y estado ──
        doc.moveTo(50, doc.y).lineTo(395, doc.y).stroke(); doc.moveDown(0.3);
        const metodoLabel = { efectivo: 'Efectivo', tarjeta: 'Tarjeta', transferencia: 'Transferencia', nequi: 'Nequi', daviplata: 'Daviplata' };
        doc.fontSize(9).font('Helvetica-Bold').text('Información de Pago');
        doc.font('Helvetica');
        doc.text(`Método: ${metodoLabel[pago.metodo] || pago.metodo}`);
        doc.text(`Estado: ${(pago.estado || '').replace(/_/g, ' ').toUpperCase()}`);
        if (pago.paid_at) doc.text(`Pagado: ${pago.paid_at}`);
        if (pago.transaction_id) doc.text(`ID Transacción: ${pago.transaction_id}`);
        if (pago.reference_code) doc.text(`Referencia: ${pago.reference_code}`);
        if (pago.admin_note) doc.text(`Nota: ${pago.admin_note}`);
        doc.moveDown(1.5);

        // ── Pie ──
        doc.fontSize(8).fillColor('#888888').text('Documento generado automáticamente. Gracias por su preferencia.', { align: 'center' });
        doc.end();
    } catch (error) {
        console.error(error);
        if (!res.headersSent) res.status(500).json({ error: 'Error al generar comprobante.' });
    }
});

// ==================== NUEVOS ENDPOINTS (MEJORAS #2, #4, #5, #6, #7) ====================

// ── GET /pagos/:id/historial ── Mejora #2: historial de estados de un pago ────────
app.get('/pagos/:id/historial', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'ID de pago inválido.' });
        const [pagoCheck] = await pool.promise().query('SELECT id FROM pagos WHERE id = ?', [id]);
        if (pagoCheck.length === 0) return res.status(404).json({ error: 'Pago no encontrado.' });
        const [rows] = await pool.promise().query(`
            SELECT h.id, h.estado_anterior, h.estado_nuevo, h.nota,
                   DATE_FORMAT(h.fecha, '%Y-%m-%d %H:%i:%s') AS fecha,
                   u.nombre AS nombre_admin
            FROM pagos_historial h
            LEFT JOIN usuarios u ON h.admin_id = u.id
            WHERE h.id_pago = ?
            ORDER BY h.fecha ASC
        `, [id]);
        res.json({ id_pago: id, historial: rows, total: rows.length });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar historial.' });
    }
});

// ── GET /notificaciones?id_usuario=X&leida=false ── Mejora #5 ───────────────────
app.get('/notificaciones', async (req, res) => {
    try {
        const { id_usuario, leida } = req.query;
        if (!id_usuario) return res.status(400).json({ error: 'id_usuario requerido.' });
        let query = `
            SELECT id, tipo, titulo, mensaje, leida, id_ref,
                   DATE_FORMAT(fecha, '%Y-%m-%d %H:%i:%s') AS fecha
            FROM notificaciones WHERE id_usuario = ?
        `;
        const params = [parseInt(id_usuario)];
        if (leida !== undefined) {
            query += ' AND leida = ?';
            params.push(leida === 'true' || leida === '1' ? 1 : 0);
        }
        query += ' ORDER BY fecha DESC LIMIT 50';
        const [rows] = await pool.promise().query(query, params);
        const [[{ no_leidas }]] = await pool.promise().query(
            'SELECT COUNT(*) AS no_leidas FROM notificaciones WHERE id_usuario = ? AND leida = 0',
            [parseInt(id_usuario)]
        );
        res.json({ notificaciones: rows, no_leidas, total: rows.length });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar notificaciones.' });
    }
});

// ── PATCH /notificaciones/:id/leer ── Mejora #5: marcar notificación como leída ──
app.patch('/notificaciones/:id/leer', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'ID inválido.' });
        await pool.promise().query('UPDATE notificaciones SET leida = 1 WHERE id = ?', [id]);
        res.json({ mensaje: 'Notificación marcada como leída.', id });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar notificación.' });
    }
});

// ── PATCH /notificaciones/leer-todas ── Mejora #5: marcar todas como leídas ──────
app.patch('/notificaciones/leer-todas', async (req, res) => {
    try {
        const { id_usuario } = req.body;
        if (!id_usuario) return res.status(400).json({ error: 'id_usuario requerido.' });
        const [result] = await pool.promise().query(
            'UPDATE notificaciones SET leida = 1 WHERE id_usuario = ? AND leida = 0',
            [parseInt(id_usuario)]
        );
        res.json({ mensaje: 'Notificaciones marcadas como leídas.', actualizadas: result.affectedRows });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar notificaciones.' });
    }
});

// ── POST /admin/pagos/mixto ── Mejora #4: pago mixto (efectivo + digital) ─────────
// Body JSON: { id_cita, id_admin, pagos: [{metodo, monto, referencia?, transaction_id?}], admin_note? }
app.post('/admin/pagos/mixto', async (req, res) => {
    const connection = await pool.promise().getConnection();
    try {
        const { id_cita, id_admin, pagos, admin_note } = req.body;
        const adminId = parseInt(id_admin);
        if (!id_cita || !adminId || !Array.isArray(pagos) || pagos.length === 0)
            return res.status(400).json({ error: 'Requeridos: id_cita, id_admin, pagos (array).' });

        const [adminCheck] = await connection.query('SELECT rol FROM usuarios WHERE id = ?', [adminId]);
        if (adminCheck.length === 0 || adminCheck[0].rol !== 'admin') {
            connection.release();
            return res.status(403).json({ error: 'Solo un administrador puede registrar pagos mixtos.' });
        }

        const [citaRows] = await connection.query(`
            SELECT c.id, c.estado, c.id_usuario AS cliente_id, u.nombre AS nombre_cliente
            FROM citas c INNER JOIN usuarios u ON c.id_usuario = u.id
            WHERE c.id = ?
        `, [id_cita]);
        if (citaRows.length === 0) { connection.release(); return res.status(404).json({ error: 'Cita no encontrada.' }); }
        const cita = citaRows[0];
        if (cita.estado === 'cancelada') { connection.release(); return res.status(400).json({ error: 'Cita cancelada.' }); }

        // Total de la cita
        const [srvRows] = await connection.query('SELECT precio FROM cita_servicios WHERE id_cita = ?', [id_cita]);
        const totalCita = srvRows.reduce((s, r) => s + parseFloat(r.precio), 0);

        // Suma de los pagos del body
        const totalPagos = pagos.reduce((s, p) => s + parseFloat(p.monto || 0), 0);
        if (parseFloat(totalPagos.toFixed(2)) < parseFloat(totalCita.toFixed(2)))
            return res.status(400).json({
                error: `La suma de los pagos ($${totalPagos}) es menor al total de la cita ($${totalCita}).`
            });

        const metodosValidos = ['efectivo', 'transferencia', 'tarjeta', 'nequi', 'daviplata'];
        for (const p of pagos) {
            if (!metodosValidos.includes(p.metodo))
                return res.status(400).json({ error: `Método inválido: ${p.metodo}` });
        }

        await connection.beginTransaction();
        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
        const ids_pagos = [];
        for (const p of pagos) {
            const [result] = await connection.query(
                `INSERT INTO pagos (id_cita, id_usuario, subtotal, monto, metodo, estado,
                    referencia, transaction_id, admin_id, admin_note, reviewed_at, paid_at, fecha)
                 VALUES (?, ?, ?, ?, ?, 'completado', ?, ?, ?, ?, ?, ?, ?)`,
                [id_cita, cita.cliente_id, parseFloat(p.monto), parseFloat(p.monto),
                    p.metodo, p.referencia || null, p.transaction_id || null,
                    adminId, admin_note || null, now, now, now]
            );
            ids_pagos.push(result.insertId);
            await registrarHistorial(result.insertId, null, 'completado', adminId, `Pago mixto - ${p.metodo}`);
        }
        await connection.query("UPDATE citas SET estado='confirmada' WHERE id=?", [id_cita]);
        await connection.commit();
        connection.release();

        // Notificar al cliente (mejora #5)
        await crearNotificacion(
            cita.cliente_id, 'pago_completado',
            '✅ Pago mixto registrado',
            `Tu pago de $${totalPagos.toLocaleString('es-CO')} fue registrado con múltiples métodos. ¡Tu cita está confirmada!`,
            ids_pagos[0]
        );

        res.status(201).json({
            mensaje: 'Pagos mixtos registrados correctamente.',
            ids_pagos, total: totalPagos, cita_estado: 'confirmada'
        });
    } catch (error) {
        await connection.rollback(); connection.release();
        console.error(error);
        res.status(500).json({ error: 'Error al registrar pagos mixtos.' });
    }
});

// ── GET /pagos/usuario/:id_usuario/resumen ── Mejora #7: resumen financiero ──────
app.get('/pagos/usuario/:id_usuario/resumen', async (req, res) => {
    try {
        const id_usuario = parseInt(req.params.id_usuario);
        if (isNaN(id_usuario)) return res.status(400).json({ error: 'ID inválido.' });

        const [[totales]] = await pool.promise().query(`
            SELECT
                COUNT(*)                                       AS total_pagos,
                COALESCE(SUM(CASE WHEN estado='completado'            THEN monto  ELSE 0 END), 0) AS total_pagado,
                COALESCE(SUM(CASE WHEN estado='pendiente_aprobacion'  THEN monto  ELSE 0 END), 0) AS total_en_revision,
                COALESCE(SUM(CASE WHEN estado='pendiente'             THEN monto  ELSE 0 END), 0) AS total_pendiente,
                COALESCE(SUM(CASE WHEN estado='reembolsado'           THEN monto  ELSE 0 END), 0) AS total_reembolsado,
                COUNT(CASE WHEN estado='completado'           THEN 1 END) AS pagos_completados,
                COUNT(CASE WHEN estado='pendiente_aprobacion' THEN 1 END) AS pagos_en_revision,
                COUNT(CASE WHEN estado='rechazado'            THEN 1 END) AS pagos_rechazados
            FROM pagos WHERE id_usuario = ?
        `, [id_usuario]);

        const [ultimos] = await pool.promise().query(`
            SELECT p.id, p.monto, p.metodo, p.estado,
                   DATE_FORMAT(p.fecha, '%Y-%m-%d %H:%i:%s') AS fecha,
                   s.nombre AS servicio
            FROM pagos p
            LEFT JOIN citas    c ON p.id_cita    = c.id
            LEFT JOIN servicios s ON c.id_servicio = s.id
            WHERE p.id_usuario = ?
            ORDER BY p.fecha DESC LIMIT 5
        `, [id_usuario]);

        res.json({ id_usuario, resumen: totales, ultimos_pagos: ultimos });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al consultar resumen.' });
    }
});

// ── GET /admin/comprobantes/huerfanos ── Mejora #6: listar archivos sin pago ─────
app.get('/admin/comprobantes/huerfanos', async (req, res) => {
    try {
        // Obtener todos los comprobantes registrados en DB
        const [rows] = await pool.promise().query('SELECT comprobante FROM pagos WHERE comprobante IS NOT NULL');
        const enDB = new Set(rows.map(r => path.join(__dirname, r.comprobante)));

        // Listar todos los archivos físicos
        const huerfanos = [];
        const walk = (dir) => {
            if (!fs.existsSync(dir)) return;
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                const full = path.join(dir, entry.name);
                if (entry.isDirectory()) walk(full);
                else if (!enDB.has(full)) huerfanos.push(full.replace(__dirname, '').replace(/\\/g, '/'));
            }
        };
        walk(UPLOADS_DIR);
        res.json({ huerfanos, total: huerfanos.length });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al buscar archivos huérfanos.' });
    }
});

// ── DELETE /admin/comprobantes/limpiar ── Mejora #6: eliminar archivos huérfanos ─
app.delete('/admin/comprobantes/limpiar', async (req, res) => {
    try {
        const [rows] = await pool.promise().query('SELECT comprobante FROM pagos WHERE comprobante IS NOT NULL');
        const enDB = new Set(rows.map(r => path.join(__dirname, r.comprobante)));

        let eliminados = 0;
        const walk = (dir) => {
            if (!fs.existsSync(dir)) return;
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                const full = path.join(dir, entry.name);
                if (entry.isDirectory()) walk(full);
                else if (!enDB.has(full)) {
                    try { fs.unlinkSync(full); eliminados++; } catch (_) { }
                }
            }
        };
        walk(UPLOADS_DIR);
        res.json({ mensaje: `${eliminados} archivo(s) huérfano(s) eliminado(s).`, eliminados });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al limpiar archivos.' });
    }
});

app.listen(port, () => {
    console.log(`Servidor de Barbería escuchando en http://localhost:${port}`);
    console.log('RUTAS DISPONIBLES 🚌');

    console.log('\nAUTH');
    console.log('  POST   /register');
    console.log('  POST   /login');

    console.log('\nCITAS 📅');
    console.log('  POST   /citas                          → RESERVADA + pago PENDIENTE auto');
    console.log('  GET    /citas                          → listado con servicios y barbero');
    console.log('  GET    /citas/:id                      → detalle');
    console.log('  PUT    /citas/:id                      → actualizar');
    console.log('  PATCH  /citas/:id/estado               → cambiar estado');
    console.log('  PUT    /citas/:id/completar            → servicio prestado → COMPLETADA');
    console.log('  DELETE /citas/:id                      → eliminar');
    console.log('  GET    /citas/disponibilidad/:fecha_hora?id_servicio&id_barbero');

    console.log('\nPAGOS 💸 — flujo completo');
    console.log('  POST   /pagos                          (comprobante) → PENDIENTE_APROBACION');
    console.log('  GET    /mis-pagos?id_usuario=X');
    console.log('  DELETE /pagos/:id                      (cancelar pendiente/rechazado)');
    console.log('  GET    /pagos                          listado completo con filtros');
    console.log('  GET    /pagos/pendientes               comprobantes en revisión');
    console.log('  GET    /pagos/:id                      detalle de un pago');
    console.log('  GET    /pagos/cita/:id_cita            todos los pagos de una cita');
    console.log('  PUT    /pagos/:id/aprobar              → COMPLETADO + cita CONFIRMADA');
    console.log('  PUT    /pagos/:id/rechazar');
    console.log('  PATCH  /pagos/:id/solicitar-info');
    console.log('  PUT    /pagos/:id/reembolsar');
    console.log('  GET    /pagos/:id/historial            historial de cambios de estado');
    console.log('  GET    /pagos/usuario/:id/resumen      resumen financiero del usuario');
    console.log('  POST   /admin/pagos                    cobro efectivo presencial');
    console.log('  POST   /admin/pagos/mixto              pago con multiples metodos');
    console.log('  GET    /admin/comprobantes/huerfanos   archivos sin pago asociado');
    console.log('  DELETE /admin/comprobantes/limpiar     eliminar archivos huerfanos');
    console.log('  GET    /reportes/ingresos');
    console.log('  GET    /comprobante/:id_pago           PDF comprobante de pago');

    console.log('\nNOTIFICACIONES 🔔');
    console.log('  GET    /notificaciones?id_usuario=X&leida=false');
    console.log('  PATCH  /notificaciones/:id/leer');
    console.log('  PATCH  /notificaciones/leer-todas');

    console.log('\nDASHBOARD ADMIN 📊  (Solo rol: admin)');
    console.log('  POST   /dashboard/stats               todas las estadisticas');
    console.log('  POST   /dashboard/total-usuarios');
    console.log('  POST   /dashboard/total-citas');
    console.log('  POST   /dashboard/total-servicios');
    console.log('  POST   /dashboard/citas-por-estado');
    console.log('  POST   /dashboard/citas-por-dia');
    console.log('  POST   /dashboard/citas-por-mes');
    console.log('  POST   /dashboard/pagos-stats');

    console.log('\n──────────────────────────────────────────────────');
    console.log('  Estados cita: reservada → confirmada → completada | cancelada');
    console.log('  Estados pago: pendiente → pendiente_aprobacion → completado | rechazado | reembolsado');
    console.log('\n  Mejoras activas:');
    console.log('  #1  Multiples pagos/abonos por cita');
    console.log('  #2  Historial de cambios de estado en pagos');
    console.log('  #3  Validacion monto_recibido y calculo de cambio en efectivo');
    console.log('  #4  Pagos mixtos (efectivo + digital simultaneo)');
    console.log('  #5  Notificaciones automaticas al cliente y admins');
    console.log('  #6  Archivos organizados por anio/mes + limpieza de huerfanos');
    console.log('  #7  API resumen financiero por usuario');
    console.log('  #9  Cancelacion automatica de pagos al cancelar cita');
    console.log('  #10 saldo_pendiente en GET /citas y GET /citas/:id');
    console.log('──────────────────────────────────────────────────');
});


