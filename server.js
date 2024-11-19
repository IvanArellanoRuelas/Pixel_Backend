const express = require("express");
const { Pool } = require("pg");
const app = express();
const PORT = 3000;
const cors = require("cors");

// Configura la conexión a la base de datos
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "Pixel",
  password: "Lula2024",
  allowExitOnIdle: true,
});

// Middleware para parsear JSON
app.use(express.json());
app.use(cors());

// Usuarios
const usuariosRoutes = require("./routes/usuarios");
app.use("/api/usuarios", usuariosRoutes);

// Autenticacion
const authRoutes = require("./routes/auth");
app.use("/api/auth", authRoutes);

// Productos
const productosRoutes = require("./routes/productos");
app.use("/api/productos", productosRoutes);

// Pedidos
const pedidosRoutes = require("./routes/pedidos");
app.use("/api/pedidos", pedidosRoutes);

// Carrito
const carritoRoutes = require("./routes/carrito");
app.use("/api/carrito", carritoRoutes);

// Inicia el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});

module.exports = app;
