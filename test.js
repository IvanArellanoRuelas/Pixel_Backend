const request = require("supertest");
const app = require("./server"); // Asegúrate de exportar tu app

describe("Pruebas de rutas", () => {
  it("Debe obtener pedidos de un usuario", async () => {
    const res = await request(app).get("/api/pedidos/detalles/1");
    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("length");
  });

  it("Debe crear un nuevo pedido", async () => {
    const res = await request(app)
      .post("/api/pedidos/nuevo")
      .send({
        usuariosID: 3,
        productos: [{ productosID: 8, cantidad: 20, precio: 10.0 }],
      });
    expect(res.statusCode).toEqual(201);
    expect(res.body).toHaveProperty("message", "Pedido creado con éxito");
  });

  it("Debe generar un token", async () => {
    const res = await request(app).post("/api/auth/login").send({
      email: "nuevo.usuario@gmail.com",
      contraseña: "0000",
    });
    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("token"); // Debe haber una propiedad 'token'
    expect(typeof res.body.token).toBe("string"); // El token debe ser de tipo string
  });
  it("Debe obtener la base de usuarios", async () => {
    const res = await request(app).get("/api/usuarios");
    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("length");
  });
});
