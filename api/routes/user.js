const express = require('express');
const router = express.Router();
const mysqlConnection = require('../connection/connection');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const axios = require('axios');
const logger = require('../utils/logger.js');
const createCsvStringifier = require('csv-writer').createObjectCsvStringifier;
const JSZip = require('jszip');
const multer = require('multer');
const storage = multer.memoryStorage();

// S3 INICIO
const S3Client = require("@aws-sdk/client-s3").S3Client;
const PutObjectCommand = require("@aws-sdk/client-s3").PutObjectCommand;
const GetObjectCommand = require("@aws-sdk/client-s3").GetObjectCommand;
const { DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { DeleteObjectsCommand } = require("@aws-sdk/client-s3");
const getSignedUrl = require("@aws-sdk/s3-request-presigner").getSignedUrl;

const bucketName = process.env.BUCKET_NAME;
const bucketRegion = process.env.BUCKET_REGION;
const accessKey = process.env.ACCESS_KEY;
const secretAccessKey = process.env.SECRET_ACCESS_KEY;

const crypto = require("crypto");
const randomImageName = (bytes = 32) =>
  crypto.randomBytes(bytes).toString("hex");

const s3 = new S3Client({
  credentials: {
    accessKeyId: accessKey,
    secretAccessKey: secretAccessKey,
  },
  region: bucketRegion,
});
// S3 FIN

router.get('/ping', (req, res) => {
  res.status(200).send();
});

const jwtSignAsync = (data, secret, options) => {
  return new Promise((resolve, reject) => {
    jwt.sign(data, secret, options, (err, token) => {
      if (err) {
        reject(err);
      } else {
        resolve(token);
      }
    });
  });
};

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
            const reset_password = user.reset_password;

            // Limpiar datos sensibles antes de crear el token
            delete user.reset_password;
            delete user.password;

            let data = JSON.stringify(user);
            console.log("los datos del token son: " + data);

            try {
              // Determinar duración del token basado en remember
              const tokenExpiration = remember === true ? '7d' : '1h';

              const token = await jwtSignAsync({ data }, process.env.JWT_SECRET, { expiresIn: tokenExpiration });

              logger.info(`user id: ${user.id} logueado - remember: ${remember} - token expires in: ${tokenExpiration}`);
              res.status(200).json({
                token: token,
                reset_password: reset_password
              });

            } catch (tokenErr) {
              logger.error(tokenErr);
              return res.status(500).send();
            }
          } else {
            logger.info(`user ${email} credenciales incorrectas`);
            res.status(401).send();
          }
        } else {
          logger.info(`user ${email} no encontrado`);
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

router.get('/categories', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { lang = 'en' } = req.query; // Idioma por defecto: inglés

      // Consulta SQL que incluye filtrado por idioma si tienes campos multiidioma
      const query = `
      SELECT 
      id,
      ${lang === 'en' ? 'name_en' : 'name_es'} AS name
      FROM category
      ORDER BY name ASC
    `;

      const [rows] = await mysqlConnection.promise().query(query, [lang]);

      if (rows.length > 0) {
        res.status(200).json(rows);
      } else {
        res.status(404).json('categories not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/article/status', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { lang = 'en' } = req.query;

      const query = `
        SELECT 
          id,
          ${lang === 'en' ? 'name_en' : 'name_es'} AS name
        FROM article_status
        ORDER BY name ASC
      `;

      const [rows] = await mysqlConnection.promise().query(query);

      if (rows.length > 0) {
        res.status(200).json(rows);
      } else {
        res.status(404).json('article status not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/refresh-token', verifyToken, (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'stocker' || cabecera.role === 'delivery' || cabecera.role === 'beneficiary' || cabecera.role === 'opsmanager' || cabecera.role === 'director' || cabecera.role === 'auditor') {
    jwt.sign({ data: req.data.data }, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      res.status(200).json({ token: token });
    });
  } else {
    res.status(401).json('Unauthorized');
  }
});


router.post('/signup', async (req, res) => {
  // const cabecera = JSON.parse(req.data.data);
  console.log(req.body);

  firstForm = req.body.firstForm;
  secondForm = req.body.secondForm;

  const role_id = 5;
  const username = firstForm.username || null;
  let passwordHash = await bcryptjs.hash(firstForm.password, 8);
  const firstname = firstForm.firstName || null;
  const lastname = firstForm.lastName || null;
  const dateOfBirth = firstForm.dateOfBirth || null;
  const email = firstForm.email || null;
  const phone = firstForm.phone.toString() || null;
  const zipcode = firstForm.zipcode.toString() || null;
  const location_id = firstForm.destination || null;
  const householdSize = firstForm.householdSize || null;
  const gender = firstForm.gender || null;
  const ethnicity = firstForm.ethnicity || null;
  const otherEthnicity = firstForm.otherEthnicity || null;

  try {

    const [rows_client_id] = await mysqlConnection.promise().query('SELECT client_id FROM client_location WHERE location_id = ?', [location_id]);
    let client_id = null;
    if (rows_client_id.length > 0) {
      client_id = rows_client_id[0].client_id;
    }

    const [rows] = await mysqlConnection.promise().query('insert into user(username, \
                                                          password, \
                                                          email, \
                                                          role_id, \
                                                          client_id, \
                                                          firstname, \
                                                          lastname, \
                                                          date_of_birth, \
                                                          phone, \
                                                          zipcode, \
                                                          first_location_id, \
                                                          location_id, \
                                                          household_size, \
                                                          gender_id, \
                                                          ethnicity_id, \
                                                          other_ethnicity) \
                                                          values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [username, passwordHash, email, role_id, client_id, firstname, lastname, dateOfBirth, phone, zipcode, location_id, location_id, householdSize, gender, ethnicity, otherEthnicity]);
    if (rows.affectedRows > 0) {
      // save inserted user id
      const user_id = rows.insertId;
      // insertar en tabla client_user el client_id y el user_id si client_id no es null
      if (client_id) {
        const [rows_client_user] = await mysqlConnection.promise().query('insert into client_user(client_id, user_id) values(?,?)', [client_id, user_id]);
      }
      // insert user_question, iterate array of questions and insert each question with its answer
      for (let i = 0; i < secondForm.length; i++) {
        const question_id = secondForm[i].question_id;
        const answer_type_id = secondForm[i].answer_type_id;
        const answer = secondForm[i].answer;
        var user_question_id = null;
        if (answer) {
          switch (answer_type_id) {
            case 1: // texto
              const [rows] = await mysqlConnection.promise().query('insert into user_question(user_id, question_id, answer_type_id, answer_text) values(?,?,?,?)',
                [user_id, question_id, answer_type_id, answer]);
              break;
            case 2: // numero
              const [rows2] = await mysqlConnection.promise().query('insert into user_question(user_id, question_id, answer_type_id, answer_number) values(?,?,?,?)',
                [user_id, question_id, answer_type_id, answer]);
              break;
            case 3: // opcion simple
              const [rows3] = await mysqlConnection.promise().query('insert into user_question(user_id, question_id, answer_type_id) values(?,?,?)',
                [user_id, question_id, answer_type_id]);
              user_question_id = rows3.insertId;
              const [rows4] = await mysqlConnection.promise().query('insert into user_question_answer(user_question_id, answer_id) values(?,?)',
                [user_question_id, answer]);
              break;
            case 4: // opcion multiple
              if (answer.length > 0) {
                const [rows5] = await mysqlConnection.promise().query('insert into user_question(user_id, question_id, answer_type_id) values(?,?,?)',
                  [user_id, question_id, answer_type_id]);
                user_question_id = rows5.insertId;
                for (let j = 0; j < answer.length; j++) {
                  const answer_id = answer[j];
                  const [rows6] = await mysqlConnection.promise().query('insert into user_question_answer(user_question_id, answer_id) values(?,?)',
                    [user_question_id, answer_id]);
                }
              }
              break;
            default:
              break;
          }
        }
      }

      res.status(200).json('Data inserted successfully');

      // After successful user creation, add to Mailchimp
      try {
        // get gender name and ethnicity name from their ids
        const [rowsGender] = await mysqlConnection.promise().query('SELECT name FROM gender WHERE id = ?', gender);
        const [rowsEthnicity] = await mysqlConnection.promise().query('SELECT name FROM ethnicity WHERE id = ?', ethnicity);

        const gender_name = rowsGender && rowsGender[0]?.name || '';
        const ethnicity_name = rowsEthnicity && rowsEthnicity[0]?.name || '';

        await addSubscriberToMailchimp({
          email: email,
          firstname: firstname,
          lastname: lastname,
          phone: phone,
          zipcode: zipcode,
          dateOfBirth: dateOfBirth,
          gender: gender_name,
          ethnicity: ethnicity_name,
          otherEthnicity: otherEthnicity
        });

      } catch (mailchimpError) {
        // Update user to set mailchimp_error to 'Y'
        await mysqlConnection.promise().query('UPDATE user SET mailchimp_error = "Y" WHERE id = ?', [user_id]);

      }
      await mysqlConnection.promise().query('UPDATE user SET mailchimp_error = "Y" WHERE id = ?', [user_id]);
    } else {
      res.status(500).json('Could not create user');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
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
          res.json('Contraseña actualizada correctamente');
        } else {
          res.status(500).json('No se pudo actualizar la contraseña');
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

// Modificar el middleware upload para aceptar un array de archivos
const upload = multer({ storage: storage }).array('ticket[]');
router.post('/upload/ticket', verifyToken, upload, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager') {
    try {
      if (req.files && req.files.length > 0) {
        formulario = JSON.parse(req.body.form);

        const donation_id = formulario.donation_id || null;
        const total_weight = formulario.total_weight || null;
        var provider = formulario.provider || null;
        var transported_by = formulario.transported_by || null;
        const destination = formulario.destination || null;
        const audit_status = formulario.audit_status || null;
        const notes = formulario.notes || null;
        var delivered_by = formulario.delivered_by || null;
        var products = formulario.products || [];
        var date = null;
        if (formulario.date) {
          fecha = new Date(formulario.date);
          // Formatear la fecha en el formato deseado (YYYY-MM-DD)
          date = fecha.toISOString().slice(0, 10);
        }
        if (!Number.isInteger(provider)) {
          const [rows] = await mysqlConnection.promise().query(
            'insert into provider(name) values(?)',
            [provider]
          );
          provider = rows.insertId;
          // insertar en stocker_log la operation 5 (create), el provider insertado y el id del usuario logueado
          const [rows2] = await mysqlConnection.promise().query(
            'insert into stocker_log(user_id, operation_id, provider_id) values(?,?,?)',
            [cabecera.id, 5, provider]
          );
        }
        if (!Number.isInteger(transported_by)) {
          const [rows] = await mysqlConnection.promise().query(
            'insert into transported_by(name) values(?)',
            [transported_by]
          );
          transported_by = rows.insertId;
          // insertar en stocker_log la operation 5 (create), el transported_by insertado y el id del usuario logueado
          const [rows2] = await mysqlConnection.promise().query(
            'insert into stocker_log(user_id, operation_id, transported_by_id) values(?,?,?)',
            [cabecera.id, 5, transported_by]
          );
        }
        if (!Number.isInteger(delivered_by)) {
          const [rows] = await mysqlConnection.promise().query(
            'insert into delivered_by(name) values(?)',
            [delivered_by]
          );
          delivered_by = rows.insertId;
          // insertar en stocker_log la operation 5 (create), el delivered_by insertado y el id del usuario logueado
          const [rows2] = await mysqlConnection.promise().query(
            'insert into stocker_log(user_id, operation_id, delivered_by_id) values(?,?,?)',
            [cabecera.id, 5, delivered_by]
          );
        }

        // iterar el array de objetos products (product,product_type,quantity) y si product no es un integer, entonces es un string con el nombre del producto nuevo, debe insertarse en tabla Products y obtener el id para reemplazarlo en el objeto en el campo product en la posicion i
        for (let i = 0; i < products.length; i++) {
          if (!Number.isInteger(products[i].product)) {
            const [rows] = await mysqlConnection.promise().query(
              'insert into product(name,product_type_id) values(?,?)',
              [products[i].product, products[i].product_type]
            );
            products[i].product = rows.insertId;
            // insertar en stocker_log la operation 5 (create), el product insertado y el id del usuario logueado
            const [rows2] = await mysqlConnection.promise().query(
              'insert into stocker_log(user_id, operation_id, product_id) values(?,?,?)',
              [cabecera.id, 5, products[i].product]
            );
          }
        }
        let query = 'INSERT INTO donation_ticket(donation_id, total_weight, provider_id, transported_by_id, location_id, date, delivered_by';
        let values = 'VALUES(?,?,?,?,?,?,?';
        let parametros_insert_donation_ticket = [donation_id, total_weight, provider, transported_by, destination, date, delivered_by];

        if (audit_status !== null) {
          query += ', audit_status_id';
          values += ', ?';
          parametros_insert_donation_ticket.push(audit_status);
        }

        query += ') ' + values + ')';

        const [rows] = await mysqlConnection.promise().query(query, parametros_insert_donation_ticket);

        if (rows.affectedRows > 0) {
          const donation_ticket_id = rows.insertId;
          try {
            if (notes) {
              await mysqlConnection.promise().query(
                'insert into donation_ticket_note(donation_ticket_id, user_id, note) values(?,?,?)',
                [donation_ticket_id, cabecera.id, notes]
              );
            }
            for (let i = 0; i < products.length; i++) {
              await mysqlConnection.promise().query(
                'insert into product_donation_ticket(product_id, donation_ticket_id, quantity) values(?,?,?)',
                [products[i].product, donation_ticket_id, products[i].quantity]
              );
            }
          } catch (error) {
            console.log(error);
            logger.error(error);
            res.status(500).json('Could not create product_donation_ticket');
          }
          try {
            for (let i = 0; i < req.files.length; i++) {
              // renombrar cada archivo con un nombre aleatorio
              req.files[i].filename = randomImageName();
              const paramsLogo = {
                Bucket: bucketName,
                Key: req.files[i].filename,
                Body: req.files[i].buffer,
                ContentType: req.files[i].mimetype,
              };
              const commandLogo = new PutObjectCommand(paramsLogo);
              const uploadLogo = await s3.send(commandLogo);
              await mysqlConnection.promise().query(
                'insert into donation_ticket_image(donation_ticket_id, file) values(?,?)',
                [donation_ticket_id, req.files[i].filename]
              );
            }
          } catch (error) {
            console.log(error);
            logger.error(error);
            res.status(500).json('Could not upload image');
          }
          try {
            // insertar en stocker_log la operation 5 (create), el ticket insertado y el id del usuario logueado
            const [rows2] = await mysqlConnection.promise().query(
              'insert into stocker_log(user_id, operation_id, donation_ticket_id, audit_status_id) values(?,?,?,?)',
              [cabecera.id, 5, donation_ticket_id, audit_status]
            );
          } catch (error) {
            console.log(error);
            logger.error(error);
            res.status(500).json('Could not create stocker_log');
          }
        } else {
          res.status(500).json('Not ticket inserted');
        }
        res.status(200).json('Data inserted successfully');

        const [rows_emails] = await mysqlConnection.promise().query(
          `select email
          from user_email_report
          where user_id = ?
          `,
          [cabecera.id]
        );

        // enviar correo de notificacion con los datos del ticket
        // Collect form data
        const formData = {
          'Donation ID': donation_id,
          'Total Weight': total_weight,
          'Provider': provider,
          'Transported By': transported_by,
          'Received By': delivered_by,
          'Destination': destination,
          'Audit Status': audit_status || '',
          'Notes': notes || '',
          'Date': date ? moment(date).format('MM/DD/YYYY') : '',
          'Creation Date': new Date().toLocaleDateString('en-US'),
        };

        // Fetch provider and destination names if necessary
        if (provider) {
          const [providerRows] = await mysqlConnection.promise().query(
            'SELECT name FROM provider WHERE id = ?',
            [provider]
          );
          formData['Provider'] = providerRows[0]?.name || provider;
        }

        if (transported_by) {
          const [transportedByRows] = await mysqlConnection.promise().query(
            'SELECT name FROM transported_by WHERE id = ?',
            [transported_by]
          );
          formData['Transported By'] = transportedByRows[0]?.name || transported_by;
        }

        if (delivered_by) {
          const [deliveredByRows] = await mysqlConnection.promise().query(
            'SELECT name FROM delivered_by WHERE id = ?',
            [delivered_by]
          );
          formData['Delivered By'] = deliveredByRows[0]?.name || delivered_by;
        }

        if (destination) {
          const [destinationRows] = await mysqlConnection.promise().query(
            'SELECT community_city FROM location WHERE id = ?',
            [destination]
          );
          formData['Destination'] = destinationRows[0]?.community_city || destination;
        }

        if (delivered_by) {
          const [deliveredByRows] = await mysqlConnection.promise().query(
            'SELECT name FROM delivered_by WHERE id = ?',
            [delivered_by]
          );
          formData['Delivered By'] = deliveredByRows[0]?.name || delivered_by;
        }

        // Get products with names
        let productsWithNames = [];
        for (let product of products) {
          const [productRows] = await mysqlConnection.promise().query(
            'SELECT name, product_type_id FROM product WHERE id = ?',
            [product.product]
          );
          const [productTypeRows] = await mysqlConnection.promise().query(
            'SELECT name FROM product_type WHERE id = ?',
            [productRows[0]?.product_type_id]
          );
          productsWithNames.push({
            productName: productRows[0]?.name || '',
            productType: productTypeRows[0]?.name || '',
            quantity: product.quantity,
          });
        }

        // Extract email addresses
        const emails = rows_emails.map(row => row.email);

        // Send the email
        sendTicketEmail(formData, productsWithNames, req.files, emails);
        return;
      } else {
        res.status(400).json('Donation ticket image is required');
      }
    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.put('/upload/ticket/:id', verifyToken, upload, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager' || cabecera.role === 'stocker' || cabecera.role === 'auditor') {
    try {
      const id = req.params.id || null;
      formulario = JSON.parse(req.body.form);

      if (req.files.length > 0) {
        var [rows_files] = await mysqlConnection
          .promise()
          .execute(
            "SELECT file FROM donation_ticket_image WHERE donation_ticket_id = ?",
            [id]
          );

        if (rows_files.length > 0) {
          var filesParaEliminar = [];
          params = {
            Bucket: bucketName,
            Delete: {
              Objects: [],
              Quiet: false,
            },
          };

          // Agregar todos los archivos a filesParaEliminar
          for (let row of rows_files) {
            if (row.file !== null && row.file !== "" && row.file !== undefined) {
              filesParaEliminar.push(row.file);
            }
          }

          // Agregar todos los archivos a params.Delete.Objects
          for (let file of filesParaEliminar) {
            params.Delete.Objects.push({
              Key: file,
            });
          }
          try {

            if (params.Delete.Objects.length > 0) {
              command = new DeleteObjectsCommand(params);
              await s3.send(command);
            }

            // Eliminar todos los archivos de la base de datos
            await mysqlConnection.promise().execute(
              "DELETE FROM donation_ticket_image WHERE donation_ticket_id = ?",
              [id]
            );

            for (let i = 0; i < req.files.length; i++) {
              // renombrar cada archivo con un nombre aleatorio
              req.files[i].filename = randomImageName();
              const paramsLogo = {
                Bucket: bucketName,
                Key: req.files[i].filename,
                Body: req.files[i].buffer,
                ContentType: req.files[i].mimetype,
              };
              const commandLogo = new PutObjectCommand(paramsLogo);
              const uploadLogo = await s3.send(commandLogo);
              await mysqlConnection.promise().query(
                'insert into donation_ticket_image(donation_ticket_id, file) values(?,?)',
                [id, req.files[i].filename]
              );
            }
          } catch (error) {
            console.log(error);
            logger.error(error);
            return res.status(500).json('Could not upload image');
          }
        } else {
          res.status(500).send("Error interno");
        }
      }
      const donation_id = formulario.donation_id || null;
      const total_weight = formulario.total_weight || null;
      var provider = formulario.provider || null;
      var transported_by = formulario.transported_by || null;
      const destination = formulario.destination || null;
      const audit_status = formulario.audit_status || null;
      const notes = formulario.notes || null;
      var delivered_by = formulario.delivered_by || null;
      var products = formulario.products || [];
      var date = null;
      if (formulario.date) {
        fecha = new Date(formulario.date);
        // Formatear la fecha en el formato deseado (YYYY-MM-DD)
        date = fecha.toISOString().slice(0, 10);
      }
      if (!Number.isInteger(provider)) {
        const [rows_insert_provider] = await mysqlConnection.promise().query(
          'insert into provider(name) values(?)',
          [provider]
        );
        provider = rows_insert_provider.insertId;
        // insertar en stocker_log la operation 5 (create), el provider insertado y el id del usuario logueado
        const [rows2] = await mysqlConnection.promise().query(
          'insert into stocker_log(user_id, operation_id, provider_id) values(?,?,?)',
          [cabecera.id, 5, provider]
        );
      }
      if (!Number.isInteger(transported_by)) {
        const [rows_insert_transported_by] = await mysqlConnection.promise().query(
          'insert into transported_by(name) values(?)',
          [transported_by]
        );
        transported_by = rows_insert_transported_by.insertId;
        // insertar en stocker_log la operation 5 (create), el transported_by insertado y el id del usuario logueado
        const [rows2] = await mysqlConnection.promise().query(
          'insert into stocker_log(user_id, operation_id, transported_by_id) values(?,?,?)',
          [cabecera.id, 5, transported_by]
        );
      }
      if (!Number.isInteger(delivered_by)) {
        const [rows_insert_delivered_by] = await mysqlConnection.promise().query(
          'insert into delivered_by(name) values(?)',
          [delivered_by]
        );
        delivered_by = rows_insert_delivered_by.insertId;
        // insertar en stocker_log la operation 5 (create), el delivered_by insertado y el id del usuario logueado
        const [rows2] = await mysqlConnection.promise().query(
          'insert into stocker_log(user_id, operation_id, delivered_by_id) values(?,?,?)',
          [cabecera.id, 5, delivered_by]
        );
      }

      // iterar el array de objetos products (product,product_type,quantity) y si product no es un integer, entonces es un string con el nombre del producto nuevo, debe insertarse en tabla Products y obtener el id para reemplazarlo en el objeto en el campo product en la posicion i
      for (let i = 0; i < products.length; i++) {
        if (!Number.isInteger(products[i].product)) {
          const [rows] = await mysqlConnection.promise().query(
            'insert into product(name,product_type_id) values(?,?)',
            [products[i].product, products[i].product_type]
          );
          products[i].product = rows.insertId;
          // insertar en stocker_log la operation 5 (create), el product insertado y el id del usuario logueado
          const [rows2] = await mysqlConnection.promise().query(
            'insert into stocker_log(user_id, operation_id, product_id) values(?,?,?)',
            [cabecera.id, 5, products[i].product]
          );
        }
      }
      // insertar en donation_ticket_note si notes no es null
      if (notes) {
        await mysqlConnection.promise().query(
          'insert into donation_ticket_note(donation_ticket_id, user_id, note) values(?,?,?)',
          [id, cabecera.id, notes]
        );
      }
      let query = 'UPDATE donation_ticket SET donation_id = ?, total_weight = ?, provider_id = ?, transported_by_id = ?, location_id = ?, date = ?, delivered_by = ?';
      let parametros_update_donation_ticket = [donation_id, total_weight, provider, transported_by, destination, date, delivered_by];

      if (audit_status !== null) {
        query += ', audit_status_id = ?';
        parametros_update_donation_ticket.push(audit_status);
      }

      query += ' WHERE id = ?';
      parametros_update_donation_ticket.push(id);

      const [rows_update_ticket] = await mysqlConnection.promise().query(query, parametros_update_donation_ticket);

      try {
        // delete all product_donation_ticket records for the ticket
        await mysqlConnection.promise().query(
          'delete from product_donation_ticket where donation_ticket_id = ?',
          [id]
        );

        for (let i = 0; i < products.length; i++) {
          await mysqlConnection.promise().query(
            'insert into product_donation_ticket(product_id, donation_ticket_id, quantity) values(?,?,?)',
            [products[i].product, id, products[i].quantity]
          );
        }
      } catch (error) {
        console.log(error);
        logger.error(error);
        res.status(500).json('Could not create product_donation_ticket');
      }

      try {
        // insertar en stocker_log la operation 6 (edit), el ticket insertado y el id del usuario logueado
        const [rows2] = await mysqlConnection.promise().query(
          'insert into stocker_log(user_id, operation_id, donation_ticket_id, audit_status_id) values(?,?,?,?)',
          [cabecera.id, 6, id, audit_status]
        );
      } catch (error) {
        console.log(error);
        logger.error(error);
        res.status(500).json('Could not create stocker_log');
      }

      res.status(200).json('Data edited successfully');

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/upload/ticket/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager' || cabecera.role === 'stocker' || cabecera.role === 'auditor') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `SELECT t.donation_id,
                t.total_weight,
                prov.name as provider,
                tb.name as transported_by,
                t.location_id as destination,
                t.date,
                db.name as delivered_by,
                t.audit_status_id as audit_status,
                p.name as product,
                p.product_type_id as product_type,
                pdt.quantity as quantity,
                COUNT(dti.id) as image_count
                FROM donation_ticket as t
                INNER JOIN donation_ticket_image as dti ON t.id = dti.donation_ticket_id
                INNER JOIN provider as prov ON t.provider_id = prov.id
                INNER JOIN transported_by as tb ON t.transported_by_id = tb.id
                INNER JOIN delivered_by as db ON t.delivered_by = db.id
                LEFT join product_donation_ticket as pdt on t.id = pdt.donation_ticket_id
                LEFT join product as p on pdt.product_id = p.id
                LEFT join product_type as pt on p.product_type_id = pt.id
                WHERE t.id = ? AND t.enabled = 'Y'
                GROUP BY t.id, pdt.product_id`,
        [id]
      );
      if (rows.length > 0) {
        let newTicket = {
          donation_id: rows[0].donation_id,
          total_weight: rows[0].total_weight,
          provider: rows[0].provider,
          transported_by: rows[0].transported_by,
          destination: rows[0].destination,
          date: rows[0].date,
          delivered_by: rows[0].delivered_by,
          audit_status: rows[0].audit_status,
          notes: [],
          image_count: rows[0].image_count,
          products: []
        };
        for (let row of rows) {
          newTicket.products.push({
            product: row.product,
            product_type: row.product_type,
            quantity: row.quantity
          });
        }

        const [rows_notes] = await mysqlConnection.promise().query(
          `SELECT dtn.id,
                  dtn.user_id,
                  u.firstname,
                  u.lastname,
                  dtn.note,
                  DATE_FORMAT(CONVERT_TZ(dtn.creation_date, "+00:00", "America/Los_Angeles"), "%m/%d/%Y %T") AS creation_date
                  FROM donation_ticket as t
                  INNER JOIN donation_ticket_note as dtn ON t.id = dtn.donation_ticket_id
                  INNER JOIN user as u ON dtn.user_id = u.id
                  WHERE t.id = ? AND t.enabled = 'Y'`,
          [id]
        );

        if (rows_notes.length > 0) {
          for (let row of rows_notes) {
            newTicket.notes.push({
              id: row.id,
              user_id: row.user_id,
              firstname: row.firstname,
              lastname: row.lastname,
              note: row.note,
              creation_date: row.creation_date
            });
          }
        }

        res.json(newTicket);
      } else {
        res.status(404).json('Ticket not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});


function verifyToken(req, res, next) {

  if (!req.headers.authorization) return res.status(401).json('No autorizado');

  const token = req.headers.authorization.substr(7);
  if (token !== '') {
    jwt.verify(token, process.env.JWT_SECRET, (error, authData) => {
      if (error) {
        res.status(403).json('Error en el token');
      } else {
        req.data = authData;
        next();
      }
    });
  } else {
    res.status(401).json('Token vacio');
  }

}

module.exports = router;