const express = require("express");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();

const serviceAccount = require("./key.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use('/weather-api', express.static(path.join(__dirname, 'weather-api')));

app.get("/register", (req, res) => {
  res.render("register", { errorMessage: null });
});

app.post("/register", async (req, res) => {
  const { username, email, phoneNumber, userPassword, confirmPassword } = req.body;

  if (userPassword !== confirmPassword) {
    return res.render("register", {
      errorMessage: "Passwords are not identical",
    });
  }

  if (!/^\d{10}$/.test(phoneNumber)) {
    return res.render("register", {
      errorMessage: "Phone number should consist of exactly 10 digits",
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.render("register", { errorMessage: "Invalid email format" });
  }

  try {
    const existingUser = await db
      .collection("users")
      .where("email", "==", email)
      .get();
    if (!existingUser.empty) {
      return res.render("register", {
        errorMessage: "Email is already registered",
      });
    }

    const hashedPassword = await bcrypt.hash(userPassword, 10);

    await db.collection("users").add({
      username,
      email,
      phoneNumber,
      userPassword: hashedPassword,
    });

    res.redirect("/signin");
  } catch (err) {
    res.status(500).send("Server Error: " + err.message);
  }
});

app.get("/signin", (req, res) => {
  res.render("signin", { errorMessage: null });
});

app.post("/signin", async (req, res) => {
  const { email, userPassword } = req.body;

  try {
    const existingUser = await db
      .collection("users")
      .where("email", "==", email)
      .get();
    if (existingUser.empty) {
      return res.render("signin", {
        errorMessage: "Incorrect email or password",
      });
    }

    const user = existingUser.docs[0].data();
    const passwordMatch = await bcrypt.compare(userPassword, user.userPassword);

    if (passwordMatch) {
      res.redirect('/dashboard');
    } else {
      return res.render("signin", {
        errorMessage: "Incorrect email or password",
      });
    }
  } catch (err) {
    res.status(500).send("Server Error: " + err.message);
  }
});

app.get('/dashboard', (req, res) => {
  res.render('dashboard');
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
