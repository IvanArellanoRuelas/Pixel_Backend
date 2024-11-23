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

// Ruta para obtener datos de la tabla pedidos
router.get("/pedidos/:id", async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res
      .status(400)
      .json({ message: "El ID del usuario debe ser un número válido" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM pedidos WHERE usuariosid = $1",
      [userId]
    );
    const orders = result.rows;

    if (orders.length === 0) {
      return res
        .status(404)
        .json({ message: "No se encontraron pedidos para este usuario" });
    }

    res.json(orders);
  } catch (err) {
    console.error("Error al obtener pedidos:", err);
    res.status(500).send("Error al obtener pedidos");
  }
});

// Ruta para obtener datos de la tabla detalle pedidos
router.get("/detalles/:id", async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res
      .status(400)
      .json({ message: "El ID del usuario debe ser un número válido" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM detalle_pedidos WHERE usuariosid = $1",
      [userId]
    );
    const orders = result.rows;

    if (orders.length === 0) {
      return res
        .status(404)
        .json({ message: "No se encontraron pedidos para este usuario" });
    }

    res.json(orders);
  } catch (err) {
    console.error("Error al obtener pedidos:", err);
    res.status(500).send("Error al obtener pedidos");
  }
});

// Ruta para crear un nuevo pedido
router.post("/nuevo", async (req, res) => {
  const { usuariosID, productos } = req.body;
  const date = new Date(); // Fecha actual

  try {
    // Inserta el nuevo pedido
    const result = await pool.query(
      "INSERT INTO pedidos (usuariosID, fecha) VALUES ($1, $2) RETURNING pedidosid",
      [usuariosID, date]
    );
    console.log("Resultado de la inserción:", result);
    const pedidosID = result.rows[0].pedidosid; // Obtén el ID del nuevo pedido
    console.log(pedidosID);

    // Inserta los detalles del pedido
    for (const producto of productos) {
      const { productosID, cantidad, precio } = producto;
      const sub_total = cantidad * precio;

      await pool.query(
        "INSERT INTO detalle_pedidos (pedidosID, usuariosID, productosID, cantidad, precio, sub_total) VALUES ($1, $2, $3, $4, $5, $6)",
        [pedidosID, usuariosID, productosID, cantidad, precio, sub_total]
      );
    }

    res.status(201).json({ message: "Pedido creado con éxito", pedidosID });
  } catch (err) {
    console.error("Error al crear pedido:", err);
    res.status(500).send("Error al crear pedido");
  }
});

module.exports = router;
