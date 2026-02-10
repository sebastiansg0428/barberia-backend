require('dotenv').config();
const mysql = require('mysql2');

console.log('🔍 Verificando configuración de variables de entorno...\n');

console.log('Variables de entorno cargadas:');
console.log('- PORT:', process.env.PORT || '3000 (default)');
console.log('- NODE_ENV:', process.env.NODE_ENV || 'development (default)');
console.log('- DB_HOST:', process.env.DB_HOST || 'localhost (default)');
console.log('- DB_USER:', process.env.DB_USER || 'root (default)');
console.log('- DB_PASSWORD:', process.env.DB_PASSWORD ? '***' : '(vacío)');
console.log('- DB_NAME:', process.env.DB_NAME || 'barberia (default)');
console.log('- DB_PORT:', process.env.DB_PORT || '3306 (default)');

console.log('\n🔄 Intentando conectar a la base de datos...\n');

const connection = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'barberia',
    port: process.env.DB_PORT || 3306
});

connection.connect((err) => {
    if (err) {
        console.error('❌ Error al conectar a la base de datos:');
        console.error(err.message);
        process.exit(1);
    }

    console.log('✅ Conexión exitosa a la base de datos MySQL');
    console.log('📊 Verificando tablas...\n');

    connection.query('SHOW TABLES', (err, results) => {
        if (err) {
            console.error('❌ Error al consultar tablas:', err.message);
            connection.end();
            process.exit(1);
        }

        console.log('Tablas encontradas:');
        results.forEach(row => {
            console.log('  -', Object.values(row)[0]);
        });

        console.log('\n✅ Todo está configurado correctamente!');
        console.log('🚀 Puedes iniciar el servidor con: npm start\n');

        connection.end();
    });
});
