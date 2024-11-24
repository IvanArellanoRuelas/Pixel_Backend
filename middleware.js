const jwt = require("jsonwebtoken");
require("dotenv").config();

const secretKey = process.env.JWT_SECRET;

// Función para generar un token JWT
const generateToken = (user) => {
  // Asegúrate de que user.usuariosid exista (minúscula "i")
  if (!user.usuariosid) {
    throw new Error("El objeto de usuario no contiene usuariosid");
  }
  return jwt.sign({ id: user.usuariosid }, secretKey, { expiresIn: "1h" });
};

// Middleware para autenticar el token JWT
const authenticateToken = (req, res, next) => {
  console.log("Middleware authenticateToken ejecutado.");
  const authHeader = req.headers["authorization"];
  console.log("Authorization header:", authHeader);
  const token = authHeader && authHeader.split(" ")[1];
  console.log("Token:", token);

  if (!token) {
    return res.status(401).json({ message: "Token faltante" });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      console.error("Error al verificar el token:", err);
      return res.status(403).json({ message: "Token inválido" });
    }
    req.user = user; //req.user debería tener la información del usuario
    console.log("Usuario autenticado:", user);
    next();
  });
};

module.exports = { generateToken, authenticateToken };
