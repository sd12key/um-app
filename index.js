const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");
const salt_rounds = 10;

const app = express();
const PORT = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "my_secret_key",
    resave: false,
    saveUninitialized: false,
  })
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const ERROR_MESSAGE_AUTH = "Invalid credentials. Please try again.";
const ERROR_MESSAGE_SIGNUP_EMPTY =
  "Username or email is empty. Please check your input.";
const ERROR_MESSAGE_SIGNUP =
  "Username or email already in use. Please try again.";
const ERROR_MESSAGE_PASSWORD_NOT_SECURE =
  "Password must be at least 8 characters long, no spaces.";
const ERROR_MESSAGE_PASSWORDS_NOT_MATCH =
  "Passwords do not match. Please try again.";
const ERROR_MESSAGE_AUTH_SESSION = "Unathorized access.";
const ERROR_MESSAGE_LOGOUT_SESSION = "Failed to log out.";
const ROLE_ADMIN = "admin";
const ROLE_USER = "user";

const USERS = [
  {
    id: 1,
    username: "AdminUser",
    email: "admin@example.com",
    password: bcrypt.hashSync("adminPassword", salt_rounds),
    role: ROLE_ADMIN,
  },
  {
    id: 2,
    username: "RegularUser",
    email: "user@example.com",
    password: bcrypt.hashSync("userPassword", salt_rounds),
    role: ROLE_USER,
  },
  {
    id: 3,
    username: "TestUser",
    email: "testuser@example.com",
    password: bcrypt.hashSync("testUserPassword", salt_rounds),
    role: ROLE_USER,
  },
  {
    id: 4,
    username: "Admin2User",
    email: "admin2@example.com",
    password: bcrypt.hashSync("admin2Password", salt_rounds),
    role: ROLE_ADMIN,
  },
];

// GET / - Render index page or redirect to landing if logged in
app.get("/", (request, response) => {
  if (request.session.user) {
    return response.redirect("/landing");
  }
  response.render("index");
});

// GET /login - Render login form
app.get("/login", (request, response) => {
  // is session open? redirect to landing
  if (request.session.user) {
    return response.redirect("/landing");
  }
  response.render("login");
});

// POST /login - Allows a user to login
// I do not like the idea of sending error message through the URL
// prefer to render the page with the error message
app.post("/login", (request, response) => {
  const { email, password } = request.body;

  // trimming is not actually needed here (but do it anyway)
  const normalized_email = email?.trim().toLowerCase();
  const normalized_password = password?.trim();

  // email not found
  const logged_in_user = USERS.find((user) => user.email === normalized_email);
  if (!logged_in_user) {
    console.log(ERROR_MESSAGE_AUTH, "(email not found)");
    return response.status(400).render("login", {
      auth_error: ERROR_MESSAGE_AUTH,
      email_value: normalized_email,
    });
  }

  const password_valid = bcrypt.compareSync(
    normalized_password,
    logged_in_user.password
  );

  // password incorrect
  if (!password_valid) {
    console.log(ERROR_MESSAGE_AUTH, "(incorrect password)");
    return response.status(400).render("login", {
      auth_error: ERROR_MESSAGE_AUTH,
      email_value: normalized_email,
    });
  }

  // tie session to logged-in username
  request.session.user = logged_in_user.username;
  console.log("Logged in successfully:", logged_in_user.username);
  return response.status(200).redirect("/landing");
});

// GET /signup - Render signup form
app.get("/signup", (request, response) => {
  // is session open? redirect to landing
  if (request.session.user) {
    return response.redirect("/landing");
  }
  response.render("signup");
});

// POST /signup - Allows a user to signup
// I do not like the idea of sending error message through the URL
// prefer to render the page with the error message
app.post("/signup", (request, response) => {
  const { email, username, password, reenter_password } = request.body;

  const normalized_email = email?.trim().toLowerCase();
  const normalized_username = username?.trim();
  const trimmed_password = password?.trim();
  const trimmed_reenter_password = reenter_password?.trim();

  // if username or email after trimming is empty, return an error
  if (!normalized_email || !normalized_username) {
    return response.status(400).render("signup", {
      auth_error: ERROR_MESSAGE_SIGNUP_EMPTY,
      email_value: normalized_email,
      username_value: normalized_username,
    });
  }

  // secure password check
  const has_min_length = trimmed_password.length >= 8;
  const has_no_whitespace = !/\s/.test(trimmed_password);

  if (!has_min_length || !has_no_whitespace) {
    return response.status(400).render("signup", {
      auth_error: ERROR_MESSAGE_PASSWORD_NOT_SECURE,
      email_value: normalized_email,
      username_value: normalized_username,
    });
  }

  // password match check
  if (trimmed_password !== trimmed_reenter_password) {
    return response.status(400).render("signup", {
      auth_error: ERROR_MESSAGE_PASSWORDS_NOT_MATCH,
      email_value: normalized_email,
      username_value: normalized_username,
    });
  }

  // uniqueness check
  // for security purposes - this is last check
  const username_taken = USERS.some((u) => u.username === normalized_username);
  const email_taken = USERS.some((u) => u.email === normalized_email);

  if (username_taken || email_taken) {
    return response.status(400).render("signup", {
      auth_error: ERROR_MESSAGE_SIGNUP,
      email_value: normalized_email,
      username_value: normalized_username,
    });
  }

  // create and store new user
  const new_user = {
    id: USERS.length + 1,
    username: normalized_username,
    email: normalized_email,
    password: bcrypt.hashSync(trimmed_password, salt_rounds),
    role: ROLE_USER,
  };

  USERS.push(new_user);
  console.log("Signed up successfully:", normalized_username);

  request.session.user = new_user.username;
  console.log("Logged in successfully:", new_user.username);
  return response.status(200).redirect("/landing");
});

// GET /landing - render landing page
app.get("/landing", (request, response) => {
  const session_user = request.session.user;

  // if no session, redirect to login
  if (!session_user) {
    console.error(ERROR_MESSAGE_AUTH_SESSION);
    return response.redirect("/login");
  }

  const landing_user = USERS.find((user) => user.username === session_user);

  return response.status(200).render("landing", {
    user: landing_user,
    users: landing_user.role === ROLE_ADMIN ? USERS : [],
  });
});

app.post("/logout", (request, response) => {
  request.session.destroy((error) => {
    if (error) {
      console.error(ERROR_MESSAGE_LOGOUT_SESSION);
      return response.status(500).send(ERROR_MESSAGE_LOGOUT_SESSION);
    }
    console.log("Logged out successfully");
    // redirect to home page
    return response.status(200).redirect("/");
  });
});

// start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
