const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { 
  jwtSignAsync, 
  verifyToken, 
  mysqlConnection, 
  logger, 
  bcryptjs 
} = require('../utils/sharedHelpers');

router.post('/signin', (req, res) => {
  const email = req.body.email || null;
  const password = req.body.password || null;
  const remember = req.body.remember || null;
  console.log(req.body);

  mysqlConnection.query('SELECT user.id, \
                                  user.firstname, \
                                  user.lastname, \
                                  user.username, \
                                  user.email, \
                                  user.password, \
                                  user.reset_password as reset_password, \
                                  role.name AS role, \
                                  user.enabled as enabled\
                                  FROM user \
                                  INNER JOIN role ON role.id = user.role_id \
                                  WHERE (user.email = ? or user.username = ?) \
                                  AND user.enabled = "Y" \
                                  LIMIT 1',
    [email, email],
    async (err, rows, fields) => {
      if (!err) {
        console.log(rows);
        if (rows.length > 0) {
          const user = rows[0];

          // Verificar password
          const isPasswordValid = await bcryptjs.compare(password, user.password);

          if (isPasswordValid && user.enabled === 'Y') {
            const userData = {
              id: user.id,
              firstname: user.firstname,
              lastname: user.lastname,
              username: user.username,
              email: user.email,
              role: user.role,
              enabled: user.enabled
            };

            const jwtExpiresIn = remember ? '720h' : '1h';

            // Usar jwtSignAsync para manejar la promesa
            try {
              const token = await jwtSignAsync({ data: JSON.stringify(userData) }, process.env.JWT_SECRET, { expiresIn: jwtExpiresIn });
              res.status(200).json({ token, user: userData });
            } catch (jwtError) {
              logger.error(jwtError);
              console.log(jwtError);
              res.status(500).send();
            }
          } else {
            res.status(401).send();
          }
        } else {
          res.status(401).send();
        }
      } else {
        logger.error(err);
        console.log(err);
        res.status(500).send();
      }
    }
  );
});

router.get('/refresh-token', verifyToken, (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin' && cabecera.role !== 'content_manager') {
    jwt.sign({ data: req.data.data }, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      res.status(200).json({ token: token });
    });
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.put('/admin/reset-password', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    const { id, password } = req.body;
    if (id && password) {
      let passwordHash = await bcryptjs.hash(password, 8);
      try {
        const [rows] = await mysqlConnection.promise().query(
          `update client set password = '${passwordHash}' where id = '${id}'`
        );
        if (rows.affectedRows > 0) {
          res.status(200).json('Password actualizado correctamente');
        } else {
          res.status(404).json('No se encontro ningun cliente con ese ID');
        }
      } catch (err) {
        throw err;
      }
    } else {
      res.status(400).json('No se ingreso ningun parametro');
    }
  } else {
    res.status(401).send();
  }
});

module.exports = router;
