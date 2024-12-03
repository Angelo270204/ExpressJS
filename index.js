const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt'); // Asegúrate de que solo haya una declaración de bcrypt
const session = require('express-session');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'X#J9k*mP$q2vR7nL4wZ8tY5dC', // Ejemplo de cadena aleatoria segura
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Cambiar a true si usas HTTPS
}));

// Configuración de conexión a la base de datos
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '1234', // Cambia por tu contraseña
  database: 'encuesta' // Cambia por el nombre de tu base de datos
});

db.connect((err) => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err);
    return;
  }
  console.log('Conexión exitosa a MySQL');
});

// Agregar middleware para verificar autenticación
const verifyToken = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Usuario no autenticado' });
  }
  next();
};

// Middleware para verificar rol de administrador
const verifyAdmin = (req, res, next) => {
  if (!req.session.userId || req.session.userRole !== 'ADMIN') {
    return res.status(403).json({ error: 'Acceso denegado. Se requiere rol de administrador.' });
  }
  next();
};

// Ruta para la raíz
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

// Endpoint para obtener preguntas
app.get('/api/questions', (req, res) => {
  const query = 'SELECT id, descripcion FROM preguntas';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener preguntas:', err);
      return res.status(500).json({ error: 'Error al cargar preguntas' });
    }
    res.json(results);
  });
});

// Modificar el endpoint de envío de encuesta
app.post('/api/submit-survey', verifyToken, (req, res) => {
  const userId = req.session.userId; // ID del usuario autenticado
  const answers = req.body;
  
  // Procesar cada respuesta
  const values = Object.entries(answers).map(([questionKey, puntaje]) => {
    const questionId = questionKey.replace('question', '');
    return [userId, parseInt(questionId), parseInt(puntaje)];
  });

  // Insertar respuestas en la nueva tabla
  const insertQuery = 'INSERT INTO respuestas (usuario_id, pregunta_id, puntaje) VALUES ?';
  
  db.query(insertQuery, [values], (err, result) => {
    if (err) {
      console.error('Error al guardar respuestas:', err);
      return res.status(500).json({ error: 'Error al guardar respuestas' });
    }
    
    // Redirigir al usuario a gracias.html
    res.redirect('/gracias.html');
  });
});

// Endpoints para gestión de preguntas (CRUD)

// Crear nueva pregunta
app.post('/api/admin/questions', verifyAdmin, (req, res) => {
  const { descripcion } = req.body;
  const query = 'INSERT INTO preguntas (descripcion) VALUES (?)';
  
  db.query(query, [descripcion], (err, result) => {
    if (err) {
      console.error('Error al crear pregunta:', err);
      return res.status(500).json({ error: 'Error al crear pregunta' });
    }
    res.status(201).json({ 
      id: result.insertId, 
      descripcion,
      message: 'Pregunta creada exitosamente' 
    });
  });
});

// Actualizar pregunta existente
app.put('/api/admin/questions/:id', verifyAdmin, (req, res) => {
  const { id } = req.params;
  const { descripcion } = req.body;
  const query = 'UPDATE preguntas SET descripcion = ? WHERE id = ?';
  
  db.query(query, [descripcion, id], (err, result) => {
    if (err) {
      console.error('Error al actualizar pregunta:', err);
      return res.status(500).json({ error: 'Error al actualizar pregunta' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Pregunta no encontrada' });
    }
    res.json({ 
      message: 'Pregunta actualizada exitosamente',
      id: parseInt(id),
      descripcion 
    });
  });
});

// Eliminar pregunta
app.delete('/api/admin/questions/:id', verifyAdmin, (req, res) => {
  const { id } = req.params;
  const query = 'DELETE FROM preguntas WHERE id = ?';
  
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error al eliminar pregunta:', err);
      return res.status(500).json({ error: 'Error al eliminar pregunta' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Pregunta no encontrada' });
    }
    res.json({ message: 'Pregunta eliminada exitosamente' });
  });
});

// Obtener una pregunta específica
app.get('/api/admin/questions/:id', verifyAdmin, (req, res) => {
  const { id } = req.params;
  const query = 'SELECT * FROM preguntas WHERE id = ?';
  
  db.query(query, [id], (err, results) => {
    if (err) {
      console.error('Error al obtener pregunta:', err);
      return res.status(500).json({ error: 'Error al obtener pregunta' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Pregunta no encontrada' });
    }
    res.json(results[0]);
  });
});

// Ruta para registrar un usuario
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const insertQuery = 'INSERT INTO user (username, password) VALUES (?, ?)';
  db.query(insertQuery, [username, hashedPassword], (err) => {
    if (err) return res.status(500).send('Error interno del servidor');
    res.status(201).send('Usuario registrado exitosamente');
  });
});

// Modificar el login para guardar el ID del usuario en la sesión
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `
    SELECT u.id, u.username, u.password, ur.rol_id, r.nombre as rol_nombre
    FROM user u
    LEFT JOIN user_rol ur ON u.id = ur.user_id
    LEFT JOIN rol r ON ur.rol_id = r.id
    WHERE u.username = ?`;
  
  db.query(query, [username], async (err, result) => {
    if (err) {
      console.error('Error al buscar usuario:', err);
      return res.status(500).send('Error interno del servidor');
    }
    
    if (result.length === 0) {
      return res.status(400).send('Usuario o contraseña incorrectos');
    }
    
    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(400).send('Usuario o contraseña incorrectos');
    }

    // Guardar información del usuario y su rol en la sesión
    req.session.userId = user.id;
    req.session.userRole = user.rol_nombre;

    // Redirigir a todos los usuarios a survey.html
    res.redirect('/survey.html');
  });
});

// Endpoint para obtener preguntas y verificar rol
app.get('/api/check-role', (req, res) => {
  if (!req.session.userId) {
    return res.json({ role: 'USER' });
  }
  res.json({ role: req.session.userRole });
});

// Unificar endpoints de preguntas
app.post('/api/questions', verifyToken, (req, res) => {
  if (req.session.userRole !== 'ADMIN') {
    return res.status(403).json({ error: 'Acceso denegado' });
  }

  const { descripcion } = req.body;
  const query = 'INSERT INTO preguntas (descripcion) VALUES (?)';
  
  db.query(query, [descripcion], (err, result) => {
    if (err) {
      console.error('Error al crear pregunta:', err);
      return res.status(500).json({ error: 'Error al crear pregunta' });
    }
    res.status(201).json({ 
      id: result.insertId, 
      descripcion,
      message: 'Pregunta creada exitosamente' 
    });
  });
});

app.put('/api/questions/:id', verifyToken, (req, res) => {
  if (req.session.userRole !== 'ADMIN') {
    return res.status(403).json({ error: 'Acceso denegado' });
  }

  const { id } = req.params;
  const { descripcion } = req.body;
  const query = 'UPDATE preguntas SET descripcion = ? WHERE id = ?';
  
  db.query(query, [descripcion, id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Error al actualizar pregunta' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Pregunta no encontrada' });
    }
    res.json({ 
      message: 'Pregunta actualizada exitosamente',
      id: parseInt(id),
      descripcion 
    });
  });
});

app.delete('/api/questions/:id', verifyToken, (req, res) => {
  if (req.session.userRole !== 'ADMIN') {
    return res.status(403).json({ error: 'Acceso denegado' });
  }

  const { id } = req.params;
  const query = 'DELETE FROM preguntas WHERE id = ?';
  
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error al eliminar pregunta:', err);
      return res.status(500).json({ error: 'Error al eliminar pregunta' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Pregunta no encontrada' });
    }
    res.json({ message: 'Pregunta eliminada exitosamente' });
  });
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
