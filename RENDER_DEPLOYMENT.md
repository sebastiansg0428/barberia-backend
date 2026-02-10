# 🚀 Guía Rápida de Despliegue en Render

## Variables de Entorno para Render

Copia y pega estas variables en la sección "Environment" de tu Web Service en Render.
**Reemplaza los valores entre `<>` con tus credenciales reales.**

```
PORT=3000
NODE_ENV=production
DB_HOST=<tu-mysql-host.render.com>
DB_USER=<tu-usuario>
DB_PASSWORD=<tu-contraseña>
DB_NAME=barberia
DB_PORT=3306
```

---

## 📋 Checklist de Despliegue

### Antes de Desplegar:

- [ ] Crear repositorio Git
- [ ] Subir código a GitHub
- [ ] Asegurarte de que `.env` NO esté en el repositorio (debe estar en .gitignore)

### En Render:

#### 1. Crear Base de Datos MySQL

- [ ] New + → MySQL
- [ ] Nombrar: `barberia-db`
- [ ] Guardar credenciales (Host, User, Password, Database)
- [ ] Esperar a que esté disponible (puede tardar 2-3 minutos)

#### 2. Importar Base de Datos

Desde tu terminal local:

```bash
# Exportar tu base de datos local
mysqldump -u root -p barberia > barberia.sql

# Importar a Render (reemplaza con tus credenciales)
mysql -h <RENDER_HOST> -u <RENDER_USER> -p<RENDER_PASSWORD> barberia < barberia.sql
```

#### 3. Crear Web Service

- [ ] New + → Web Service
- [ ] Conectar repositorio GitHub
- [ ] Configurar:
  - **Name**: `barberia-backend`
  - **Region**: Misma que la base de datos
  - **Build Command**: `npm install`
  - **Start Command**: `npm start`

#### 4. Agregar Variables de Entorno

- [ ] Copiar las credenciales de tu base de datos MySQL
- [ ] Pegar en Environment Variables
- [ ] Verificar que todos los campos estén completos

#### 5. Desplegar

- [ ] Click en "Create Web Service"
- [ ] Esperar al despliegue (3-5 minutos)
- [ ] Verificar logs por si hay errores

---

## ✅ Verificación Post-Despliegue

Prueba estos endpoints con Postman o tu navegador:

1. **Health Check**:

   ```
   GET https://tu-app.onrender.com/usuarios
   ```

   Debe devolver la lista de usuarios.

2. **Login de prueba**:
   ```
   POST https://tu-app.onrender.com/login
   Body: {
     "email": "tu_email@ejemplo.com",
     "password": "tu_password"
   }
   ```

---

## 🔧 Actualizar Frontend

Una vez desplegado, actualiza las URLs del frontend:

```javascript
// Antes (desarrollo)
const API_URL = "http://localhost:3000";

// Después (producción)
const API_URL = "https://tu-app.onrender.com";
```

O mejor, usa variables de entorno en tu frontend también:

```javascript
const API_URL = process.env.REACT_APP_API_URL || "http://localhost:3000";
```

---

## 📞 Soporte

Si tienes problemas:

1. **Revisa los logs** en Render Dashboard
2. **Verifica las variables de entorno** - son case-sensitive
3. **Prueba la conexión a la base de datos** desde Render Shell
4. **Asegúrate** de que la base de datos esté en la misma región

---

## 💡 Tips

- El plan gratuito entra en "sleep" después de 15 minutos sin actividad
- La primera petición después del "sleep" puede tardar 30 segundos
- Render reinicia automáticamente si detecta cambios en GitHub
- Usa la misma región para base de datos y backend (menor latencia)
