const express = require("express");
const router = express.Router();
const { Pool } = require("pg");
require("dotenv").config();

// Configura la conexión a la base de datos
const pool = new Pool({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  allowExitOnIdle: true,
  port: parseInt(process.env.DATABASE_PORT, 10), // Parsear a entero
});

// Ruta para obtener datos de la tabla productos
router.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM productos");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error al obtener datos de la tabla usuarios");
  }
});

module.exports = router;
