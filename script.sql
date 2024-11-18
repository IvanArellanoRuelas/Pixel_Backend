CREATE TABLE pixel;
\c pixel;

CREATE TABLE productos(productosID SERIAL PRIMARY KEY,nombre_producto VARCHAR(60) NOT NULL, 
descripcion VARCHAR(255),categoria VARCHAR(60) NOT NULL,
precio INT NOT NULL, stock INT NOT NULL CHECK(stock>=0));

INSERT INTO productos(productosID,nombre_producto,descripcion,categoria,precio,stock) VALUES
(DEFAULT,'Tiburon','Aros Tiburon','Aros',5000,74),
(DEFAULT,'Calavera','Aros Calavera','Aros',6000,10),
(DEFAULT,'Totoro','Aros Totoro','Aros',5000,55),
(DEFAULT,'Ying-Yang','Aros Ying-Yang','Aros',5000,39),
(DEFAULT,'Corazon Arcoiris','Aros Corazon Arcoiris','Aros',5000,16),
(DEFAULT,'Huellitas','Aros Huellitas','Aros',5000,23),
(DEFAULT,'Rombos','Aros Rombos','Aros',5000,14),
(DEFAULT,'Fantasmas','Aros Fantasmas','Aros',6000,5),
(DEFAULT,'Yoshi','Aros Yoshi','Aros',8000,16),
(DEFAULT,'Samurai','Aros Samurai','Aros',7500,60),
(DEFAULT,'Helados','Aros Helados','Aros',7000,23),
(DEFAULT,'Mariposas','Aros Mariposas','Aros',9000,36),
(DEFAULT,'Hongos','Aros Hongos','Aros',7500,36),
(DEFAULT,'Chupón M. Jackson','Chupón Michael Jackson Mariposas','Chupon',10000,36),
(DEFAULT,'Chupón Ursula','Chupón Ursula','Chupon',10000,6),
(DEFAULT,'Luigui','Imán Luigui + Fantasma','Imanes',10000,6),
(DEFAULT,'Llavero Perro','Llavero Perro','Llaveros',8500,100),
(DEFAULT,'Llavero Gatos','Llavero Gatos','Llaveros',8500,100),
(DEFAULT,'Llavero Mario','Llavero Mario','Llaveros',8500,100),
(DEFAULT,'Llavero S. Universe','Llavero Steven Universe','Llaveros',8500,100),
(DEFAULT,'Llavero Stitch','Llavero Stitch','Llaveros',8500,100),
(DEFAULT,'Llavero Snitch','Llavero Snitch','Llaveros',8500,100),
(DEFAULT,'Llavero Lechuza','Llavero Lechuza','Llaveros',8500,100);



CREATE TABLE usuarios(usuariosID SERIAL PRIMARY KEY, nombre VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, contraseña VARCHAR(50) NOT NULL, user_type VARCHAR(50) NOT NULL);

INSERT INTO usuarios VALUES
(DEFAULT,'User','user@gmail.com','$2a$08$rKztHavXDAuG4ezN1.ak1uS.y.cp/TQACUwrbeAouFKA/u.gqE6d6','User'),
(DEFAULT,'Admin','admin@gmail.com','$2a$08$rKztHavXDAuG4ezN1.ak1uS.y.cp/TQACUwrbeAouFKA/u.gqE6d6','Admin');

CREATE TABLE pedidos (pedidosID SERIAL PRIMARY KEY, usuariosID INT , fecha DATE, FOREIGN KEY (usuariosID) REFERENCES usuarios(usuariosID));

INSERT INTO pedidos VALUES
(DEFAULT,1,'2024-11-15');

CREATE TABLE detalle_pedidos (pedidosID INT,usuariosID INT,productosID INT,cantidad INT,precio INT, sub_total INT, 
FOREIGN KEY (pedidosID) REFERENCES pedidos(pedidosID),
FOREIGN KEY (usuariosID) REFERENCES usuarios(usuariosID),
FOREIGN KEY (productosID) REFERENCES productos(productosID));

INSERT INTO detalle_pedidos VALUES
(1,1,2,5,6000,30000),
(1,1,5,1,5000,5000);

CREATE TABLE carrito (carritoID SERIAL PRIMARY KEY, usuariosID INT , fecha DATE, FOREIGN KEY (usuariosID) REFERENCES usuarios(usuariosID));

CREATE TABLE detalle_carrito(carritoID INT,usuariosID INT , productosID INT , cantidad INT,
FOREIGN KEY (carritoID) REFERENCES carrito(carritoID),
FOREIGN KEY (usuariosID) REFERENCES usuarios(usuariosID),
FOREIGN KEY (productosID) REFERENCES productos(productosID));

CREATE TABLE favoritos(usuariosID INT,productosID INT,
FOREIGN KEY (usuariosID) REFERENCES usuarios(usuariosID),
FOREIGN KEY (productosID) REFERENCES productos(productosID));



