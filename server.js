const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'clave_secreta_pdi';

app.use(express.json({ limit: '50mb' }));
// Servir archivos directamente desde la raíz
app.use(express.static(__dirname));

const USERS_FILE = path.join(__dirname, 'users.json');
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

const getUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const saveUsers = (data) => fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado' });
    
    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = decoded;
        next();
    });
};

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

    const users = getUsers();
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'El usuario ya existe' });
    }

    users.push({ username, password });
    saveUsers(users);

    const userDir = path.join(__dirname, 'data', username);
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

    res.json({ message: 'Usuario registrado correctamente' });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const users = getUsers();
    const user = users.find(u => u.username === username && u.password === password);

    if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });

    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '8h' });
    res.json({ token });
});

app.post('/api/save-board', authenticate, (req, res) => {
    const { title, boardData } = req.body;
    if (!title || !boardData) return res.status(400).json({ error: 'Datos incompletos' });

    const userDir = path.join(__dirname, 'data', req.user.username);
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

    const filePath = path.join(userDir, `${title}.json`);
    fs.writeFileSync(filePath, JSON.stringify(boardData));

    res.json({ message: 'Pizarra guardada con éxito' });
});

app.get('/api/my-boards', authenticate, (req, res) => {
    const userDir = path.join(__dirname, 'data', req.user.username);
    if (!fs.existsSync(userDir)) return res.json([]);

    const files = fs.readdirSync(userDir)
        .filter(f => f.endsWith('.json'))
        .map(f => f.replace('.json', ''));

    res.json(files);
});

app.get('/api/load-board/:title', authenticate, (req, res) => {
    const filePath = path.join(__dirname, 'data', req.user.username, `${req.params.title}.json`);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Pizarra no encontrada' });

    const data = fs.readFileSync(filePath);
    res.json(JSON.parse(data));
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor ejecutándose en http://localhost:${PORT}`);
});