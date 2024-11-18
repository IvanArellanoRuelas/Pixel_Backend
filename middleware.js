const jwt = require("jsonwebtoken");

const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Obtener el token del encabezado

  if (!token) {
    return res.sendStatus(401); // No hay token
  }

  jwt.verify(token, "tu_secreto", (err, user) => {
    if (err) {
      console.error("Error verifying token:", err);
      return res.sendStatus(403); // Token no válido
    }
    console.log("Decoded user from token:", user);
    req.user = user; // Almacena la información del usuario en la solicitud
    console.log(req.use);
    next();
  });
};

module.exports = authenticateToken;
