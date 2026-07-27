const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'clave_secreta_para_pdi_cambiar_en_produccion';

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Base de datos local en JSON (para desarrollo sencillo)
const USERS_FILE = path.join(__dirname, 'users.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));

// Helpers
const getUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const saveUsers = (users) => fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

// Middleware de Autenticación
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acceso denegado' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// --- RUTAS DE AUTENTICACIÓN ---

// Registro de usuarios
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

    const users = getUsers();
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'El usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    saveUsers(users);

    // Crear carpeta del usuario para sus pizarras
    const userFolder = path.join(UPLOADS_DIR, username);
    if (!fs.existsSync(userFolder)) fs.mkdirSync(userFolder);

    res.json({ message: 'Usuario registrado con éxito' });
});

// Login de usuarios
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = getUsers();
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ token, username: user.username });
});

// --- RUTAS DE GUARDADO EN SERVIDO ---

// Guardar clase en el servidor
app.post('/api/save-board', authenticateToken, (req, res) => {
    const { title, boardData } = req.body;
    if (!title || !boardData) return res.status(400).json({ error: 'Datos incompletos' });

    const userFolder = path.join(UPLOADS_DIR, req.user.username);
    if (!fs.existsSync(userFolder)) fs.mkdirSync(userFolder);

    const safeTitle = title.replace(/[^a-z0-9_-]/gi, '_');
    const filePath = path.join(userFolder, `${safeTitle}.pdi`);

    fs.writeFileSync(filePath, JSON.stringify(boardData));
    res.json({ message: 'Pizarra guardada correctamente en el servidor' });
});

// Listar clases guardadas del usuario
app.get('/api/my-boards', authenticateToken, (req, res) => {
    const userFolder = path.join(UPLOADS_DIR, req.user.username);
    if (!fs.existsSync(userFolder)) return res.json([]);

    const files = fs.readdirSync(userFolder)
        .filter(file => file.endsWith('.pdi'))
        .map(file => file.replace('.pdi', ''));

    res.json(files);
});

// Cargar una clase específica
app.get('/api/load-board/:title', authenticateToken, (req, res) => {
    const safeTitle = req.params.title.replace(/[^a-z0-9_-]/gi, '_');
    const filePath = path.join(UPLOADS_DIR, req.user.username, `${safeTitle}.pdi`);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Archivo no encontrado' });
    }

    const data = JSON.parse(fs.readFileSync(filePath));
    res.json(data);
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor PDI ejecutándose en http://localhost:${PORT}`);
});