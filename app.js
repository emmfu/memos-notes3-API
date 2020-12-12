const bodyParser = require('body-parser');
const express = require('express');
const cors = require('cors');
const jsonwebtoken = require('jsonwebtoken')
const scrypt = require('scrypt');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
const port = 3000;

const mysql = require('mysql2/promise');

require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});
app.use(cors());

app.use(bodyParser.json());

app.use(async function mysqlConnection(req, res, next) {
    try {
        req.db = await pool.getConnection();
        req.db.connection.config.namePlaceholders = true;

        await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
        await req.db.query(`SET time_zone = '-8:00'`);

        await next();

        req.db.release();
    } catch (e) {
        if (req.db) req.db.release();
        throw e;
    }
});



// Public endpoints - the user doesn't need to be authenticated in order to reach them
// Registration

app.post('/auth/register', async function (req, res) {
    try {
        let user;
        bcrypt.hash(req.body.password, saltRounds).then(async hash => {
            try {
                [user] = await req.db.query(`
                    INSERT INTO users(email, password)
                    VALUES(?, ?)
                `,
                    [
                        req.body.email,
                        hash
                    ]);
                    console.log('**user @ line 66**', user);
                    const payload = {
                        sub: user.id
                    };
                    const token = jsonwebtoken.sign(payload, process.env.JWT_KEY, {
                        expiresIn: '24h'
                    });
                    res.json({
                        jwt: token,
                        user: {
                            id: user.insertId,
                            email: req.body.email
                        }
                    });
            } catch (error) {
                console.log('error', error);
            }
        });
    } catch (err) {
        console.log('error', err);
    }
});

// Sign In and verify information 
app.post('/auth/signin', async function (req, res) {
    const [[user]] = await req.db.query(`
        SELECT * FROM users WHERE email = ?
    `,
        [
            req.body.email
        ],
        (error, results) => {
            if (error) {
                console.log("Error at signin: ", error);
                res.status(500).json({ status: 'error' });
            } else {
                res.status(200).json({ results });
            }
        }
    );
    if (!user) {
        res.json('Unknown user');
    } else {
        const passwordMatch = bcrypt.compareSync(req.body.password, String(user.password));

        if (passwordMatch) {
            const payload = {
                sub: user.id
            };
            const token = jsonwebtoken.sign(payload, process.env.JWT_KEY, {
                expiresIn: '24h'
            });

            res.cookie("jwt", token, { httpOnly: true, secure: true });
            res.json({
                jwt: token,
                user: {
                    id: user.id,
                    email: user.email
                }
            });
        } else {
            res.json('Nice try, dummy');
        }
    }
});
 
// authorization required passed this point
app.use(function (req, res, next) {
    console.log('*** req.headers @ validation:', req.headers);
    console.log('*** req.body @ validation:', req.body)
    if (!req.headers.authorization) {
        throw new Error('Authorization header is required');
    }

    const [scheme, token] = req.headers.authorization.split(' ');

    if (scheme !== 'Bearer') {
        throw new Error('Invalid authorization');
    }

    try {
        const payload = jsonwebtoken.verify(token, process.env.JWT_KEY);
        req.user = payload;
    } catch (err) {
        throw new Error(err);
    }
    next();
});

app.get('/notes', async function (req, res) {
    const [notes] = await req.db.query(
        `
        SELECT * FROM notes
        `,
        (error, results) => {
            if (error) {
                console.log('/notes error: ', error);
                res.status(500).json({ status: 'error' });
            } else {

                res.status(200).json({ results });
            }
        }
    );
    console.log("All Notes: ")
    res.json(notes);
});

app.get('/notes/:id', async function (req, res) {
    const [note] = await req.db.query(
        `SELECT * FROM notes WHERE id=?`,
        [req.params.id],
        (error, results) => {
            if (error) {
                console.log(error);
                res.status(500).json({ status: 'error' });
            } else {
                res.status(200).json({ results });
            }
        }
    );
    console.log("Single Note: ", note)
    res.json(note);
});

app.post('/notes/new', async function (req, res) {
    const note = await req.db.query(
        `INSERT INTO notes(title, body) VALUES (?, ?)`,
        [req.body.title, req.body.body],
        (error, results) => {
            if (error) {
                console.log(error);
                res.status(500).json({ status: 'error' });
            } else {
                res.status(200).json({ results });
            }
        }
    );
    res.json(note);
});

app.put('/notes/:id', async function (req, res, next) {
    console.log('update received: ', req.body);
    const [note] = await req.db.query(
        `UPDATE notes SET title=?, body=? WHERE id=?`,
        [req.body.title, req.body.body, req.body.id],
        (error) => {
            if (error) {
                res.status(500).json({ status: 'error' });
            } else {
                res.status(200).jsaon({ status: 'error' });
            }
        }
    );
    res.json(note);
});


app.delete('/notes/:id', async function (req, res, next) {
    await req.db.query(
        `DELETE FROM notes WHERE id=?`,
        [req.body.id],
        (error) => {
            if (error) {
                res.status(500).json({ status: 'error' });
            } else {
                res.status(200).json({ status: 'ok' });
            }
        }
    );
});


app.listen(port, () => {
    console.log(`Express server listening on port ${port}`);
});