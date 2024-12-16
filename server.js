const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

// Conexión a la base de datos
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});


// Middleware para verificar roles (debe ir antes de las rutas)
const verificarRol = (rolesPermitidos) => (req, res, next) => {
    if (!rolesPermitidos.includes(req.user.rol)) {
        return res.status(403).json({ error: 'Acceso denegado: rol no autorizado' });
    }
    next();
};

// Middleware para verificar tokens
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No autorizado' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; 
        next();
    } catch {
        res.status(401).json({ error: 'Token inválido o expirado' });
    }
};

// Configuración de Multer para guardar archivos con su nombre original
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');  // Carpeta donde se guardarán los archivos
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);  // Usar el nombre original del archivo
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // Limitar tamaño del archivo a 10MB
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (ext !== '.pdf' && ext !== '.png') {
            return cb(new Error('Solo se permiten archivos PDF o PNG'), false);
        }
        cb(null, true); // Si el archivo tiene la extensión permitida, se acepta
    }
});


// Ruta para registrar usuarios
app.post('/registro', async (req, res) => {
    const { nombre_usuario, correo, contrasena, codigo_acceso } = req.body;

    try {
        // Verificar si el código de acceso es válido y obtener el tipo de usuario
        const [rows] = await db.query(
            'SELECT * FROM codigos_acceso WHERE codigo = ?',
            [codigo_acceso]
        );

        if (rows.length === 0) {
            return res.status(400).json({ error: 'Código de acceso inválido' });
        }

        // Obtener el tipo de usuario del código de acceso
        const codigo = rows[0];
        const tipo_usuario = codigo.tipo_usuario;  // 'A' para admin, 'U' para usuario, etc.

        // Hashear la contraseña
        const hashedPassword = await bcrypt.hash(contrasena, 10);

        // Insertar el nuevo usuario con el rol obtenido del código de acceso
        await db.query(
            'INSERT INTO usuarios (nombre_usuario, correo, contrasena, rol) VALUES (?, ?, ?, ?)',
            [nombre_usuario, correo, hashedPassword, tipo_usuario]  // Asignamos el rol basado en el código
        );

        res.status(201).json({ message: 'Usuario registrado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});



// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
    const { correo, contrasena } = req.body;

    try {
        const [rows] = await db.query('SELECT * FROM usuarios WHERE correo = ?', [correo]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
        }

        const usuario = rows[0];
        const esValido = await bcrypt.compare(contrasena, usuario.contrasena);
        if (!esValido) {
            return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
        }

        const token = jwt.sign(
            { id: usuario.id_usuario, rol: usuario.rol },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({ message: 'Inicio de sesión exitoso', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Ruta para subir manuales (solo usuarios autenticados)
app.post('/manuales', authMiddleware, upload.single('archivo'), async (req, res) => {
    const { titulo, descripcion, id_categoria } = req.body;
    const archivo = req.file;

    if (!archivo) {
        return res.status(400).json({ error: 'Debe proporcionar un archivo' });
    }

    try {
        await db.query(
            'INSERT INTO manuales (titulo, descripcion, ruta_archivo, id_categoria, subido_por, fecha_subida) VALUES (?, ?, ?, ?, ?, ?)',
            [titulo, descripcion, archivo.filename, id_categoria, req.user.id, new Date()]
        );

        res.status(201).json({ message: 'Manual subido exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al subir el manual' });
    }
});



// Ruta para eliminar manuales (solo administradores)
app.delete('/manuales/:id', authMiddleware, verificarRol(['admin']), async (req, res) => {
    const { id } = req.params;

    try {
        await db.query('DELETE FROM manuales WHERE id_manual = ?', [id]);
        res.status(200).json({ message: 'Manual eliminado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al eliminar el manual' });
    }
});

// Ruta para obtener todos los manuales
app.get('/manuales', authMiddleware, async (req, res) => {
    try {
        const [manuales] = await db.query('SELECT * FROM manuales');
        res.status(200).json(manuales);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener los manuales' });
    }
});


// Ruta para editar un manual (solo administradores)
app.put('/manuales/:id', authMiddleware, verificarRol(['admin']), async (req, res) => {
    const { id } = req.params;
    const { titulo, descripcion, id_categoria } = req.body;

    try {
        await db.query(
            'UPDATE manuales SET titulo = ?, descripcion = ?, id_categoria = ? WHERE id_manual = ?',
            [titulo, descripcion, id_categoria, id]
        );

        res.status(200).json({ message: 'Manual actualizado exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al actualizar el manual' });
    }
});



// Ruta para descargar manuales
app.get('/download/:filename', (req, res) => {
    const filePath = path.join(__dirname, 'uploads', req.params.filename);

    // Verificar si el archivo existe
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            console.error('Archivo no encontrado:', filePath);
            return res.status(404).json({ error: 'Archivo no encontrado' });
        }

        // Establecer el tipo de contenido según la extensión del archivo
        const ext = path.extname(filePath).toLowerCase();
        let contentType = 'application/octet-stream';  // Tipo por defecto

        if (ext === '.pdf') {
            contentType = 'application/pdf';
        } else if (ext === '.png') {
            contentType = 'image/png';
        }

        // Enviar el archivo
        res.setHeader('Content-Disposition', `attachment; filename=${req.params.filename}`);
        res.setHeader('Content-Type', contentType);
        res.sendFile(filePath, (err) => {
            if (err) {
                console.error('Error al enviar el archivo:', err);
                res.status(500).json({ error: 'Error al enviar el archivo' });
            }
        });
    });
});



// Ruta para obtener el conteo de manuales por usuario sin restricciones de rol
app.get('/estadisticas/manuales-por-usuario', authMiddleware, async (req, res) => {
    try {
        const [resultados] = await db.query(`
            SELECT 
                u.nombre_usuario AS Usuario, 
                COUNT(m.id_manual) AS Manuales_Subidos
            FROM 
                usuarios u
            LEFT JOIN 
                manuales m
            ON 
                u.id_usuario = m.subido_por
            GROUP BY 
                u.id_usuario
        `);

        res.status(200).json(resultados);
    } catch (error) {
        console.error('Error al obtener las estadísticas:', error);
        res.status(500).json({ error: 'Error al obtener las estadísticas' });
    }
});


// Ruta para obtener todas las categorías
app.get('/categorias', authMiddleware, async (req, res) => {
    try {
        const [categorias] = await db.query('SELECT id_categoria, nombre FROM categorias');
        res.status(200).json(categorias);
    } catch (error) {
        console.error('Error al obtener categorías:', error);
        res.status(500).json({ error: 'Error al obtener categorías' });
    }
});

//FILTRAR MANUALES POR CATEGORIAS
app.get('/manuales/categoria/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;

    try {
        const [manuales] = await db.query('SELECT * FROM manuales WHERE id_categoria = ?', [id]);
        res.status(200).json(manuales);
    } catch (error) {
        console.error('Error al filtrar manuales:', error);
        res.status(500).json({ error: 'Error al filtrar manuales' });
    }
});

//Ruta para agregar una columna
app.post('/tabla/manuales/agregar-columna', authMiddleware, verificarRol(['admin']), async (req, res) => {
    const { nombre_columna, tipo_dato } = req.body;

    if (!nombre_columna || !tipo_dato) {
        return res.status(400).json({ error: 'Debe proporcionar el nombre de la columna y el tipo de dato' });
    }

    try {
        await db.query(`ALTER TABLE manuales ADD COLUMN ${mysql.escapeId(nombre_columna)} ${tipo_dato}`);
        res.status(200).json({ message: `Columna "${nombre_columna}" agregada exitosamente` });
    } catch (error) {
        console.error('Error al agregar columna:', error);
        res.status(500).json({ error: 'Error al agregar la columna' });
    }
});
 
//ruta para eliminar una columna 
app.delete('/tabla/manuales/eliminar-columna', authMiddleware, verificarRol(['admin']), async (req, res) => {
    const { columna_eliminar } = req.body;

    if (!columna_eliminar) {
        return res.status(400).json({ error: 'Debe proporcionar el nombre de la columna a eliminar' });
    }

    try {
        await db.query(`ALTER TABLE manuales DROP COLUMN ${mysql.escapeId(columna_eliminar)}`);
        res.status(200).json({ message: `Columna "${columna_eliminar}" eliminada exitosamente` });
    } catch (error) {
        console.error('Error al eliminar columna:', error);
        res.status(500).json({ error: 'Error al eliminar la columna' });
    }
});



// Servir archivos estáticos desde la carpeta "public"
app.use(express.static(path.join(__dirname, 'public')));

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
