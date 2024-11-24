const express = require("express");
const router = express.Router();
const { Pool } = require("pg");
const { authenticateToken } = require("../middleware"); // Importa el middleware
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

// Ruta para obtener datos de la tabla pedidos (modificada)
router.get("/pedidos", authenticateToken, async (req, res) => {
  const userId = req.user.id; // Obtén el userId del objeto req.user

  try {
    const result = await pool.query(
      "SELECT * FROM pedidos WHERE usuariosid = $1",
      [userId]
    );
    const orders = result.rows;

    if (orders.length === 0) {
      return res
        .status(200)
        .json({ message: "No se encontraron pedidos para este usuario" }); // 200 OK
    }

    res.json(orders);
  } catch (err) {
    console.error("Error al obtener pedidos:", err);
    res.status(500).json({ message: "Error del servidor" });
  }
});

// Ruta para obtener datos de la tabla detalle pedidos (modificada)
router.get("/detalles", authenticateToken, async (req, res) => {
  const userId = req.user.id; // Obtén el userId del objeto req.user

  try {
    const result = await pool.query(
      "SELECT * FROM detalle_pedidos WHERE usuariosid = $1",
      [userId]
    );
    const orders = result.rows;

    if (orders.length === 0) {
      return res.status(200).json({
        message: "No se encontraron detalles de pedidos para este usuario",
      }); //200 OK
    }

    res.json(orders);
  } catch (err) {
    console.error("Error al obtener detalles de pedidos:", err);
    res.status(500).json({ message: "Error del servidor" });
  }
});

// Ruta para crear un nuevo pedido (modificada)
router.post("/nuevo", authenticateToken, async (req, res) => {
  const userId = req.user.id; // Obtén el ID del usuario desde req.user
  const { productos } = req.body; // usuariosID ya no es necesario en el body
  const date = new Date();

  try {
    // Inserta el nuevo pedido
    const result = await pool.query(
      "INSERT INTO pedidos (usuariosID, fecha) VALUES ($1, $2) RETURNING pedidosid",
      [userId, date]
    );
    const pedidosID = result.rows[0].pedidosid;

    // Inserta los detalles del pedido
    for (const producto of productos) {
      const { productosID, cantidad, precio } = producto;
      const subTotal = cantidad * precio; // Corrección: sub_total -> subTotal

      await pool.query(
        "INSERT INTO detalle_pedidos (pedidosID, usuariosID, productosID, cantidad, precio, sub_total) VALUES ($1, $2, $3, $4, $5, $6)",
        [pedidosID, userId, productosID, cantidad, precio, subTotal]
      );
    }

    res.status(201).json({ message: "Pedido creado con éxito", pedidosID });
  } catch (err) {
    console.error("Error al crear pedido:", err);
    res.status(500).json({ message: "Error del servidor", error: err.message }); // Incluye el mensaje de error
  }
});

module.exports = router;
