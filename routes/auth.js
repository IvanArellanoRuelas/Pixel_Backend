const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const router = express.Router();
require("dotenv").config();
//const authenticateToken = require("../middleware");

// Configura la conexión a la base de datos
const pool = new Pool({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  allowExitOnIdle: true,
  port: parseInt(process.env.DATABASE_PORT, 10), // Parsear a entero
});

// Genera un token JWT
const generateToken = (user) => {
  return jwt.sign({ id: user.usuariosID }, "AAA", { expiresIn: "1h" });
};

// Ruta para iniciar sesión
router.post("/login", async (req, res) => {
  const { email, contraseña } = req.body;
  try {
    const result = await pool.query("SELECT * FROM usuarios WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user || !bcrypt.compareSync(contraseña, user.contraseña)) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    console.log("Usuario encontrado:", user); // Asegúrate de que el ID exista aquí

    // Asegúrate de que `usuariosID` sea el campo correcto
    const token = jwt.sign({ id: user.usuariosID }, "AAA", {
      expiresIn: "1h",
    });

    console.log("Token generado:", token); // Verifica que el token se genera correctamente
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error de autenticación");
  }
});

// Ruta para registrar un nuevo usuario (opcional)
router.post("/register", async (req, res) => {
  const { nombre, email, contraseña } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(contraseña, 8);
    const result = await pool.query(
      "INSERT INTO usuarios(nombre, email, contraseña,user_type) VALUES($1, $2, $3,$4) RETURNING *",
      [nombre, email, hashedPassword, "User"]
    );
    const user = result.rows[0];

    const token = generateToken(user);
    res.status(201).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error al registrar el usuario");
  }
});

const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Obtener el token del encabezado

  if (!token) {
    return res.sendStatus(401); // No hay token
  }

  // Verificar el token
  jwt.verify(token, "AAA", (err, user) => {
    if (err) {
      console.error("Error verifying token:", err);
      return res.sendStatus(403); // Token no válido
    }

    console.log("Decoded user from token:", user); // Imprimir el usuario decodificado
    req.user = user; // Almacena la información del usuario en la solicitud
    next();
  });
};

// Ruta para que cada Usuario solo pueda acceder a su perfil
router.get("/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id; // Asegúrate de obtener el ID del usuario del token
    console.log("User ID from token:", userId); // Imprime el ID del usuario para depuración

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
    res.status(500).send("Error al obtener el perfil del usuario");
  }
});
module.exports = router;
