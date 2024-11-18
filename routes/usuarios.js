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

// Ruta para obtener datos de la tabla usuario
router.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM usuarios"); // Asegúrate de que el nombre de la tabla sea correcto
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error al obtener datos de la tabla usuarios");
  }
});

module.exports = router;
