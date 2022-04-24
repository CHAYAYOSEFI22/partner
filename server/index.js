

const users = [
    {
        "username": "a@gmail.com",
        "password": "AA!79hhh"
    }, {
        "username": "b@gmail.com",
        "password": "BB!79hhh"
    }, {
        "username": "c@gmail.com",
        "password": "CC!79hhh"
    }, {
        "username": "d@gmail.com",
        "password": "DD!79hhh"
    }, {
        "username": "e@gmail.com",
        "password": "EE!79hhh"
    }, {
        "username": "f@gmail.com",
        "password": "FF!79hhh"
    }, {
        "username": "g@gmail.com",
        "password": "GG!79hhh"
    }, {
        "username": "h@gmail.com",
        "password": "HH!79hhh"
    }, {
        "username": "i@gmail.com",
        "password": "II!79hhh"
    }, {
        "username": "j@gmail.com",
        "password": "JJ!79hhh"
    }
];

const express = require('express')
const Query = require('./db')
const jwt = require('jsonwebtoken')
const { genSaltSync, hashSync, compareSync } = require('bcryptjs');
const app = express()
const EXPRESS_PORT = process.env.EXPRESS_PORT || 3013;


app.use(express.json())

console.log("server work!!")

// REGISTER
app.post('/register', async (req, res) => {
    const { username, password } = req.body
    console.log("username:", username, "password:", password)
    if (username && password) {
        const patternEMAIL = /^[^ ]+@[^ ]+\.[a-z]{2,3}$/
        const patternPASSWORD = /^(?=.*[A-Z].*[A-Z])(?=.*[!@#$&*])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{8}$/
        if (!username.match(patternEMAIL)) {
            res.status(400).json({ error: true, msg: "incorrect username" })
            return
        }
        if (!password.match(patternPASSWORD)) {
            res.status(400).json({ error: true, msg: "incorrect password!!!!!!!!!!" })
            return
        }
        try {
            console.log("password:", password, "username:", username)
            const q = `SELECT * FROM userspartner WHERE username=?`
            const answer = await Query(q, [username])
            if (answer.length === 0) {
                const salt = genSaltSync(10)
                const hash = hashSync(password, salt)
                const q = `INSERT INTO userspartner(username,password)
                VALUES(?,?)`
                await Query(q, [username, hash])
                res.status(201).json({ error: false, msg: "username added successfully" })
            } else {
                res.status(400).json({ error: true, msg: "username already taken" })
            }
        } catch (error) {
            res.status(500)
        }
    } else {
        res.status(400).json({ error: true, msg: "missing some info" })
    }
})

// LOGIN
app.post("/login", async (req, res) => {
    const { username, password } = req.body
    if (username && password) {
        console.log("username:", username, "password:", password)
        const patternEMAIL = /^[^ ]+@[^ ]+\.[a-z]{2,3}$/
        const patternPASSWORD = /^(?=.*[A-Z].*[A-Z])(?=.*[!@#$&*])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{8}$/
        if (!username.match(patternEMAIL)) {
            res.status(400).json({ error: true, msg: "incorrect username" })
            return
        }
        if (!password.match(patternPASSWORD)) {
            res.status(400).json({ error: true, msg: "incorrect password!!!!!!!!!!" })
            return
        }
        try {
            const q = `SELECT * FROM userspartner WHERE username=?`
            const answer = await Query(q, [username])
            if (answer.length === 0) {
                res.status(401).json({ error: true, msg: "user not found" })
            } else {
                if (compareSync(password, answer[0].password)) {
                    const access_token = jwt.sign({ id: answer[0].id, fname: answer[0].fname, role: answer[0].role }, "BlAh", {
                        expiresIn: "10m"
                    })
                    res.status(200).json({ error: false, msg: "user login successfully", access_token })
                } else {
                    res.status(401).json({ error: true, msg: "wrong password" })
                }
            }
        } catch (error) {
            res.status(401)
        }
    } else {
        res.status(400).json({ error: true, msg: "missing some info" })
    }
})

app.post('/register/bulk', async function promises(req, res) {

    const unresolved = users.map(async(user) => {
        console.log("username:", user.username, "password:", user.password)

        if (user.username && user.password) {
            const patternEMAIL = /^[^ ]+@[^ ]+\.[a-z]{2,3}$/
            const patternPASSWORD = /^(?=.*[A-Z].*[A-Z])(?=.*[!@#$&*])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{8}$/
            if (!user.username.match(patternEMAIL)) {
                res.status(400).json({ error: true, msg: "incorrect username" })
                return
            }
            if (!user.password.match(patternPASSWORD)) {
                res.status(400).json({ error: true, msg: "incorrect password!!!!!!!!!!" })
                return
            }
            try {
                console.log("password:", user.password, "username:", user.username)
                const q = `SELECT * FROM userspartner WHERE username=?`
                const answer = await Query(q, [user.username])
                if (answer.length === 0) {
                    const salt = genSaltSync(10)
                    const hash = hashSync(user.password, salt)
                    const q = `INSERT INTO userspartner(username,password)
                VALUES(?,?)`
                    await Query(q, [user.username, hash])
                    return res.status(201).json({ error: false, msg: "username added successfully" })
                } else {
                    return res.status(400).json({ error: true, msg: "username already taken" })
                }
            } catch (error) {
                return res.status(500)
            }
        } else {
            return res.status(400).json({ error: true, msg: "missing some info" })
        }
    })

    const resolved = await Promise.all(unresolved)

    console.log(resolved);
})


// listener
app.listen(EXPRESS_PORT, err => {
    if (!err) {
        console.log(`Express web server is running at port ${EXPRESS_PORT}`)
    }
});