const express = require("express");
const router = express.Router();
const { Pool } = require("pg");

// Configura el pool de conexión (puedes mover esto a un archivo separado si lo prefieres)
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "Pixel",
  password: "Lula2024",
  allowExitOnIdle: true,
  port: 5432,
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
