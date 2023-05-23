const catchError = require("../utils/catchError");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../models/EmailCode");
const jwt = require('jsonwebtoken');

const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  //desestructuramos las propiedades del body necesarias
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  //encryptamos la contraseña
  const hashedPassword = await bcrypt.hash(password, 10);
  //creamos el usuario
  const result = await User.create({
    email,
    password: hashedPassword,
    firstName,
    lastName,
    country,
    image,
  });
  //creando codigo
  const code = require("crypto").randomBytes(32).toString("hex");
  //creamos el link con la url de front y la ruta del back mas el codigo
  const link = `${frontBaseUrl}/verify_email/${code}`;
  //luego de crear el usuario enviar el correo
  await sendEmail({
    to: email,
    subject: "Verificate email for user app",
    html: `
            <h1>Hello ${firstName} ${lastName} </h1>
            <b>verify your account clicking this link</b>
            <a href="${link}">${link}</a>
            <h3>Thank you</h3>
        `,
  });
  //guardar el codigo en el modelo EmailCode y el id de usuario
  await EmailCode.create({ code, userId: result.id });
  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.update(req.body, {
    where: { id },
    returning: true,
  });
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const verifycode = catchError(async (req, res) => {
  const { code } = req.params;
  const codeFount = await EmailCode.findOne({ where: { code } });
  if (!codeFount) return res.status(401).json({ message: "Invalid code" });
  const user = await User.update(
    { isVerified: true },
    { where: { id: codeFount.userId }, returning: true }
  );
  // eliminar el codigo
  //await codeFount.destroy();
  return res.json(user);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ message: "invalid credentials" });
  const isValid =  await bcrypt.compare(password, user.password);
  if(!isValid) return res.status(401).json({ message: "Invalid credentials"});
  if(!user.isVerified) return res.status(401).json({ message: "Invalid credentials"});
  const token = jwt.sign(
    { user},
    process.env.TOKEN_SECRET,
    { expiresIn: "1d"}
  )
  return res.json({ user, token })
});

const getLoggedUser = catchError(async(req, res) =>{
    const user = req.user;
    return res.json(user);
})

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifycode,
  login,
  getLoggedUser
};
