import bcrypt from "bcryptjs";
import path from "node:path";
import { Pool } from "pg";
import express from "express";
import session from "express-session";
import passport from "passport";
import LocalStrategy from "passport-local";

const pool = new Pool ({
    connectionString: process.env.DB_CONNECTION_URL
});

const PORT = process.env.PORT;
const __dirname = import.meta.dirname;
const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");


app.use(session({secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false}));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

passport.use(
    new LocalStrategy(async (username, password, done) => {
        try {
            const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
            const user = rows[0];

            if (!user) {
                return done(null, false, { message: "Incorrect username" });
            }

            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return done(null, false, { message: "Incorrect password" });
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    })
)

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
        const user = rows[0];

        done(null, user);
    } catch (err) {
        done(err);
    }
});

app.get("/sign-up", (req, res) => {
    res.render("sign-up-form");
});
app.post("/sign-up", async (req, res, next) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
            req.body.username,
            hashedPassword,
        ]);
        res.redirect("/");
    } catch (err) {
        return next(err)
    }
})

app.post("/log-in", 
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/",
        failureMessage: true,
    })
);

app.get("/log-out", (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);

        res.redirect("/");
    });
});

app.get("/", (req, res) => {
    res.render("index", {user: req.user});
});

app.listen(PORT, (error) => {
    if (error) throw error;
    console.log(`Express server listening on port ${PORT}`);
})