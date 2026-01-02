const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "storeforge100@gmail.com",
    pass: "ywsvmgouoykjzkzx"
  }
});

transporter.sendMail({
  from: "StoreForge <storeforge100@gmail.com>",
  to: "Shrishd242@gmail.com",
  subject: "Test Email",
  text: "Hello, this is a test from backend!"
}, (err, info) => {
  if (err) console.error("Email error:", err);
  else console.log("Email sent:", info.response);
});
