require('dotenv').config();
const express = require('express');
const mysql   = require('mysql2/promise');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
// Sesión no expira automáticamente — dura hasta que el usuario hace logout
const JWT_SECRET  = process.env.JWT_SECRET || 'aiotec_jwt_clave_secreta_2025';
const JWT_EXPIRES = '365d'; // 1 año — la sesión se cierra solo con logout

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PUBLIC = path.join(__dirname, 'public');
app.use(express.static(PUBLIC));

// ─── POOL MySQL ───────────────────────────────────────────────────────────────
const pool = mysql.createPool({
  host:             process.env.DB_HOST     || 'localhost',
  user:             process.env.DB_USER     || 'root',
  password:         process.env.DB_PASSWORD || '',
  database:         process.env.DB_NAME     || 'aiotec_db',
  port:             parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit:  10,
  queueLimit:       0
});

pool.getConnection()
  .then(c => { console.log('✅ MySQL conectado'); c.release(); })
  .catch(e => console.error('❌ Error MySQL:', e.message));

// ─── MIDDLEWARE AUTH ──────────────────────────────────────────────────────────
const auth = (req, res, next) => {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: 'Token inválido o expirado. Inicia sesión nuevamente.' });
  }
};

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (!rows.length) return res.status(400).json({ ok: false, error: 'Usuario no encontrado' });
    const user = rows[0];
    if (!user.activo) return res.status(403).json({ ok: false, error: 'Usuario desactivado' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ ok: false, error: 'Contraseña incorrecta' });
    // Token de larga duración — expira solo con logout
    const token = jwt.sign(
      { id: user.id, email: user.email, rol: user.rol },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );
    await pool.query('UPDATE usuarios SET ultimo_acceso = NOW() WHERE id = ?', [user.id]).catch(() => {});
    res.json({
      ok: true,
      token,
      user: { nombre: user.nombre, apellido: user.apellido, rol: user.rol }
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'Error en servidor: ' + err.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { nombre, apellido, email, password, telefono, rol } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO usuarios (nombre, apellido, email, password, telefono, rol) VALUES (?,?,?,?,?,?)',
      [nombre, apellido, email, hash, telefono || '', rol || 'Tecnico']
    );
    res.json({ ok: true, message: 'Usuario registrado' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ ok: false, error: 'Email ya registrado' });
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Logout — el frontend borra el token; el servidor solo confirma
app.post('/api/auth/logout', (req, res) => res.json({ ok: true }));

// ═══════════════════════════════════════════════════════════════════════════════
//  STATS (dashboard)
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/stats', auth, async (req, res) => {
  try {
    const [[total]]     = await pool.query("SELECT COUNT(*) as n FROM servicios");
    const [[pend]]      = await pool.query("SELECT COUNT(*) as n FROM servicios WHERE estado='Pendiente'");
    const [[proc]]      = await pool.query("SELECT COUNT(*) as n FROM servicios WHERE estado='En Proceso'");
    const [[comp]]      = await pool.query("SELECT COUNT(*) as n FROM servicios WHERE estado='Completado'");
    const [[cli]]       = await pool.query("SELECT COUNT(*) as n FROM clientes");
    const [[ingresos]]  = await pool.query("SELECT COALESCE(SUM(abono),0) as n FROM servicios");
    const [[saldo_tot]] = await pool.query("SELECT COALESCE(SUM(saldo),0) as n FROM servicios WHERE estado != 'Entregado'");
    const [recientes]   = await pool.query(`
      SELECT s.codigo, s.tipo_equipo, s.problema, s.total, s.abono, s.saldo,
             s.estado, s.fecha_ingreso,
             c.nombre, c.apellido, c.cedula
      FROM servicios s
      LEFT JOIN clientes c ON s.cedula_cliente = c.cedula
      ORDER BY s.fecha_ingreso DESC LIMIT 8`);
    res.json({
      ok: true,
      stats: {
        total_servicios: total.n,
        pendientes:      pend.n,
        en_proceso:      proc.n,
        completados:     comp.n,
        total_clientes:  cli.n,
        ingresos:        parseFloat(ingresos.n).toFixed(2),
        saldo_pendiente: parseFloat(saldo_tot.n).toFixed(2)
      },
      recientes
    });
  } catch (err) {
    res.json({ ok: true, stats: { total_servicios:0, pendientes:0, en_proceso:0, completados:0, total_clientes:0, ingresos:'0.00', saldo_pendiente:'0.00' }, recientes: [] });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  CLIENTES
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/clientes', auth, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM clientes ORDER BY fecha_registro DESC');
    res.json({ ok: true, data: rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// Buscar cliente por cédula (para autocompletar en servicios)
app.get('/api/clientes/:cedula', auth, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM clientes WHERE cedula = ?', [req.params.cedula]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'Cliente no encontrado' });
    res.json({ ok: true, data: rows[0] });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post('/api/clientes', auth, async (req, res) => {
  const { cedula, nombre, apellido, telefono, email, direccion } = req.body;
  try {
    await pool.query(
      'INSERT INTO clientes (cedula, nombre, apellido, telefono, email, direccion) VALUES (?,?,?,?,?,?)',
      [cedula, nombre, apellido, telefono || '', email || '', direccion || '']
    );
    res.json({ ok: true, message: 'Cliente registrado' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ ok: false, error: 'Cédula ya existe' });
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.put('/api/clientes/:cedula', auth, async (req, res) => {
  const { nombre, apellido, telefono, email, direccion } = req.body;
  try {
    await pool.query(
      'UPDATE clientes SET nombre=?, apellido=?, telefono=?, email=?, direccion=? WHERE cedula=?',
      [nombre, apellido, telefono || '', email || '', direccion || '', req.params.cedula]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.delete('/api/clientes/:cedula', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM clientes WHERE cedula = ?', [req.params.cedula]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  SERVICIOS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/servicios', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT s.*, c.nombre, c.apellido, c.telefono AS tel_cliente
      FROM servicios s
      LEFT JOIN clientes c ON s.cedula_cliente = c.cedula
      ORDER BY s.fecha_ingreso DESC`);
    res.json({ ok: true, data: rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get('/api/servicios/:codigo', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT s.*, c.nombre, c.apellido, c.telefono AS tel_cliente
      FROM servicios s
      LEFT JOIN clientes c ON s.cedula_cliente = c.cedula
      WHERE s.codigo = ?`, [req.params.codigo]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'Servicio no encontrado' });
    res.json({ ok: true, data: rows[0] });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.post('/api/servicios', auth, async (req, res) => {
  const { cedula_cliente, tipo_equipo, problema, total, abono, estado, observaciones } = req.body;
  try {
    const codigo = 'SRV-' + Date.now().toString().slice(-7);
    await pool.query(
      `INSERT INTO servicios
        (codigo, cedula_cliente, tipo_equipo, problema, total, abono, estado, observaciones)
       VALUES (?,?,?,?,?,?,?,?)`,
      [codigo, cedula_cliente, tipo_equipo, problema,
       parseFloat(total) || 0, parseFloat(abono) || 0,
       estado || 'Pendiente', observaciones || '']
    );
    res.json({ ok: true, message: 'Servicio creado', codigo });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.put('/api/servicios/:codigo', auth, async (req, res) => {
  const { tipo_equipo, problema, total, abono, estado, observaciones } = req.body;
  try {
    await pool.query(
      `UPDATE servicios
       SET tipo_equipo=?, problema=?, total=?, abono=?, estado=?, observaciones=?,
           fecha_actualizacion=NOW()
       WHERE codigo=?`,
      [tipo_equipo, problema, parseFloat(total) || 0, parseFloat(abono) || 0,
       estado, observaciones || '', req.params.codigo]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.delete('/api/servicios/:codigo', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM servicios WHERE codigo = ?', [req.params.codigo]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  USUARIOS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/usuarios', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, nombre, apellido, email, telefono, rol, activo, ultimo_acceso FROM usuarios ORDER BY nombre'
    );
    res.json({ ok: true, data: rows });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.delete('/api/usuarios/:email', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM usuarios WHERE email = ?', [decodeURIComponent(req.params.email)]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  PÁGINAS ESTÁTICAS
// ═══════════════════════════════════════════════════════════════════════════════
const page = (f) => (_, res) => res.sendFile(path.join(PUBLIC, f));

app.get('/',               page('index.html'));
app.get('/index.html',     page('index.html'));
app.get('/login',          page('login.html'));
app.get('/login.html',     page('login.html'));
app.get('/register',       page('register.html'));
app.get('/register.html',  page('register.html'));
app.get('/dashboard',      page('dashboard.html'));
app.get('/dashboard.html', page('dashboard.html'));
app.get('/clientes',       page('clientes.html'));
app.get('/clientes.html',  page('clientes.html'));
app.get('/servicios',      page('servicios.html'));
app.get('/servicios.html', page('servicios.html'));

app.listen(PORT, () => {
  console.log('\n🚀 AIOTEC corriendo en: http://localhost:' + PORT);
  console.log('📋 Login:     http://localhost:' + PORT + '/login.html');
  console.log('📊 Dashboard: http://localhost:' + PORT + '/dashboard.html\n');
});