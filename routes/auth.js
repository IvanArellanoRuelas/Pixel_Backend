const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const router = express.Router();
require("dotenv").config();
const { generateToken, authenticateToken } = require("../middleware");

// Configura la conexión a la base de datos
const pool = new Pool({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  allowExitOnIdle: true,
  port: parseInt(process.env.DATABASE_PORT, 10), // Parsear a entero
});

// Ruta para iniciar sesión
router.post("/login", async (req, res) => {
  const { email, contraseña } = req.body;
  try {
    const result = await pool.query(
      "SELECT usuariosID, nombre, email, contraseña FROM usuarios WHERE email = $1",
      [email]
    );
    const user = result.rows[0];

    if (!user || !bcrypt.compareSync(contraseña, user.contraseña)) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    console.log("Usuario encontrado:", user);

    const token = generateToken(user); //Aquí pasas el objeto user
    res.json({ token });
  } catch (error) {
    console.error("Error en la ruta /login:", error);
    res.status(500).json({ message: "Error del servidor" });
  }
});

// Ruta para registrar un nuevo usuario (opcional)
router.post("/register", async (req, res) => {
  const { nombre, email, contraseña } = req.body;

  try {
    // Verifica si el email ya existe (para evitar duplicados)
    const existingUser = await pool.query(
      "SELECT * FROM usuarios WHERE email = $1",
      [email]
    );
    if (existingUser.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "El correo electrónico ya está registrado" });
    }

    // Hashea la contraseña antes de guardarla en la base de datos
    const hashedPassword = await bcrypt.hash(contraseña, 10); // Usa bcrypt.hash (async)

    // Inserta el nuevo usuario en la base de datos
    const newUser = await pool.query(
      "INSERT INTO usuarios (nombre, email, contraseña, user_type) VALUES ($1, $2, $3, $4) RETURNING *",
      [nombre, email, hashedPassword, "User"]
    );

    // Genera el token JWT
    const token = generateToken(newUser.rows[0]);

    res.status(201).json({ message: "Usuario registrado con éxito", token });
  } catch (error) {
    console.error("Error al registrar usuario:", error);
    res.status(500).json({ message: "Error del servidor" });
  }
});

router.get("/profile", authenticateToken, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: "No autorizado" });
    }
    console.log("User ID from token:", req.user.id); //Imprime el ID desde req.user.id
    const userId = req.user.id;
    const result = await pool.query(
      "SELECT nombre, email, user_type FROM usuarios WHERE usuariosID = $1",
      [userId]
    );
    const userProfile = result.rows[0];
    if (!userProfile) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }
    res.json(userProfile);
  } catch (err) {
    console.error("Error al obtener el perfil del usuario:", err);
    res.status(500).json({ message: "Error del servidor" });
  }
});

module.exports = router;
