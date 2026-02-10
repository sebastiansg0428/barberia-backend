# Barbería Backend API

Backend API para el sistema de gestión de barbería.

## 🚀 Configuración Local

### 1. Instalar dependencias

```bash
npm install
```

### 2. Configurar variables de entorno

Crea un archivo `.env` en la raíz del proyecto basándote en `.env.example`:

```env
PORT=3000
NODE_ENV=development
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=barberia
DB_PORT=3306
```

### 3. Iniciar el servidor

```bash
npm start
```

El servidor estará disponible en `http://localhost:3000`

---

## 🌐 Despliegue en Render

### Paso 1: Crear Base de Datos MySQL en Render

1. Ve a tu [Dashboard de Render](https://dashboard.render.com/)
2. Click en "New +" → "MySQL"
3. Configura tu base de datos:
   - **Name**: `barberia-db`
   - **Database**: `barberia`
   - **User**: genera automáticamente
   - **Region**: elige la más cercana
4. Click en "Create Database"
5. **Guarda las credenciales** que aparecen (las necesitarás en el siguiente paso)

### Paso 2: Importar tu Base de Datos

1. Descarga el cliente MySQL o usa phpMyAdmin localmente
2. Exporta tu base de datos local `barberia` a un archivo SQL
3. Conéctate a tu base de datos de Render usando las credenciales:
   ```bash
   mysql -h <MYSQL_HOST> -u <MYSQL_USER> -p<MYSQL_PASSWORD> <MYSQL_DATABASE> < barberia.sql
   ```

### Paso 3: Desplegar el Backend

1. Ve a tu Dashboard de Render
2. Click en "New +" → "Web Service"
3. Conecta tu repositorio de GitHub
4. Configura el servicio:
   - **Name**: `barberia-backend`
   - **Region**: misma región que la base de datos
   - **Branch**: `main` (o tu rama principal)
   - **Root Directory**: dejar vacío
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`

### Paso 4: Configurar Variables de Entorno en Render

En la sección "Environment Variables", agrega:

```
PORT=3000
NODE_ENV=production
DB_HOST=<tu_host_de_render>
DB_USER=<tu_usuario_de_render>
DB_PASSWORD=<tu_contraseña_de_render>
DB_NAME=barberia
DB_PORT=3306
```

**Importante**: Obtén estos valores de tu base de datos MySQL creada en el Paso 1.

### Paso 5: Desplegar

1. Click en "Create Web Service"
2. Render iniciará el despliegue automáticamente
3. Una vez completado, tu API estará disponible en: `https://barberia-backend.onrender.com`

---

## 📌 Endpoints Disponibles

### Autenticación

- `POST /register` - Registrar usuario
- `POST /login` - Iniciar sesión

### Usuarios

- `GET /usuarios` - Listar usuarios
- `GET /usuarios/:id` - Ver usuario por ID
- `PUT /usuarios/:id` - Actualizar usuario
- `DELETE /usuarios/:id` - Eliminar usuario

### Servicios

- `GET /servicios` - Listar servicios
- `POST /servicios` - Crear servicio
- `GET /servicios/:id` - Ver servicio por ID
- `PUT /servicios/:id` - Actualizar servicio
- `DELETE /servicios/:id` - Eliminar servicio

### Citas

- `GET /citas` - Listar citas
- `POST /citas` - Crear cita
- `GET /citas/:id` - Ver cita por ID
- `PUT /citas/:id` - Actualizar cita
- `DELETE /citas/:id` - Eliminar cita
- `GET /citas/disponibilidad/:fecha_hora` - Verificar disponibilidad

### Dashboard Admin (Solo rol: admin)

- `POST /dashboard/stats` - Todas las estadísticas
- `POST /dashboard/total-usuarios` - Total de usuarios
- `POST /dashboard/total-citas` - Total de citas
- `POST /dashboard/total-servicios` - Total de servicios
- `POST /dashboard/citas-por-estado` - Citas por estado
- `POST /dashboard/citas-por-dia` - Citas por día
- `POST /dashboard/citas-por-mes` - Citas por mes

---

## 🔒 Roles de Usuario

- **admin**: Acceso completo + dashboard
- **barbero**: Gestión de servicios y citas
- **cliente**: Reservar citas

---

## 🛠️ Tecnologías

- Node.js
- Express.js
- MySQL2
- bcryptjs (encriptación de contraseñas)
- CORS
- dotenv (variables de entorno)

---

## 📝 Notas Importantes para Render

1. **Base de datos**: Render ofrece MySQL como servicio independiente. No uses bases de datos gratuitas de terceros si requieres persistencia.

2. **Conexiones**: El plan gratuito de Render tiene límites de conexión. Ajusta `connectionLimit` en la configuración de MySQL si es necesario.

3. **Sleep Mode**: Los servicios gratuitos entran en "sleep" después de 15 minutos de inactividad. La primera petición puede tardar hasta 30 segundos.

4. **CORS**: Actualiza las URLs permitidas en producción si es necesario.

5. **Logs**: Revisa los logs en el Dashboard de Render para debugging.

---

## 🐛 Troubleshooting

### Error de conexión a la base de datos

- Verifica que las variables de entorno en Render coincidan con las credenciales de tu base de datos
- Asegúrate de que la base de datos esté en la misma región que tu servicio

### El servidor no inicia

- Revisa los logs en Render Dashboard
- Verifica que el comando de inicio sea `npm start`
- Confirma que todas las dependencias estén instaladas

### Error 502 Bad Gateway

- Espera unos minutos si el servicio estaba en "sleep"
- Verifica que el puerto use `process.env.PORT`
