const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const sessions = require("client-sessions");
const csurf = require("csurf");

let app = express();

let User = mongoose.model(
  "User",
  new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  })
);
mongoose.connect("mongodb://localhost/ss-auth");

app.set("view engine", "pug");
app.use(csurf());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  sessions({
    cookieName: "session",
    secret: "fuershuifghriugh",
    duration: 30 * 60 * 1000, // 30min
  })
);
app.use((req, res, next) => {
  if (!(req.session && req.session.userId)) {
    return next();
  }
  User.findById(req.session.userId, (err, user) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return next();
    }
    user.password = undefined;
    req.user = user;
    res.locals.user = user;
    next();
  });
});

function loginRequired(req, res, next) {
  if (!req.user) {
    return res.redirect("/login");
  }
  next();
}

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/register", (req, res) => {
  res.render("register", { csrfToken: req.csrfToken() });
});

app.get("/login", (req, res) => {
  res.render("login", { csrfToken: req.csrfToken() });
});

app.get("/dashboard", loginRequired, (req, res, next) => {
  if (!(req.session && req.session.userId)) {
    return res.redirect("/login");
  }

  User.findById(req.sessions.userId, (err, user) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.redirect("/login");
    }
    res.render("dashboard");
  });
});

app.post("/register", (req, res) => {
  let hash = bcrypt.hashSync(req.body.password, 14);
  req.body.password = hash;
  let user = new User(req.body);

  user.save((err) => {
    if (err) {
      let error = "Something bad happened! Try again.";

      if (err.code === 11000) {
        error = "That email is already taken, try another.";
      }

      return res.render("register", { error: error });
    }
    res.redirect("/dashboard");
  });
});

app.post("/login", (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (!user || !bcrypt.compareSync(req.body.password, user.password)) {
      return res.render("login", {
        error: "Incorrect email / password.",
      });
    }
    req.sessions.userId = user._id;
    res.redirect("dashboard");
  });
});

app.listen(3000);
