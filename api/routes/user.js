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

const upload_signature = multer({ storage: storage }).array('signature[]');
router.post('/signup/volunteer', upload_signature, async (req, res) => {
  let connection;
  try {
    connection = await mysqlConnection.promise().getConnection();
    await connection.beginTransaction();

    if (req.files && req.files.length > 0) {
      formulario = JSON.parse(req.body.form);

      const firstname = formulario.firstName || null;
      const lastname = formulario.lastName || null;
      const email = formulario.email || null;
      const phone = formulario.phone.toString() || null;
      const zipcode = formulario.zipcode.toString() || null;
      const location_id = formulario.destination || null;
      const dateOfBirth = formulario.dateOfBirth || null;
      const gender = formulario.gender || null;
      const ethnicity = formulario.ethnicity || null;
      const otherEthnicity = formulario.otherEthnicity || null;
      // const date = formulario.date || null;
      const language = formulario.language || 'en';

      const [rows] = await connection.query('insert into volunteer(firstname, \
                                          lastname, \
                                          email, \
                                          phone, \
                                          zipcode, \
                                          first_location_id, \
                                          location_id, \
                                          date_of_birth, \
                                          gender_id, \
                                          ethnicity_id, \
                                          other_ethnicity) \
                                          values(?,?,?,?,?,?,?,?,?,?,?)',
        [firstname, lastname, email, phone, zipcode, location_id, location_id, dateOfBirth, gender, ethnicity, otherEthnicity]);

      if (rows.affectedRows > 0) {
        const volunteer_id = rows.insertId;

        for (let i = 0; i < req.files.length; i++) {
          req.files[i].filename = randomImageName();
          const paramsLogo = {
            Bucket: bucketName,
            Key: req.files[i].filename,
            Body: req.files[i].buffer,
            ContentType: req.files[i].mimetype,
          };
          const commandLogo = new PutObjectCommand(paramsLogo);
          await s3.send(commandLogo);

          await connection.query(
            'insert into volunteer_signature(volunteer_id, file) values(?,?)',
            [volunteer_id, req.files[i].filename]
          );
        }

        // Get location details
        const [locationRows] = await connection.query(
          'SELECT community_city FROM location WHERE id = ?',
          [location_id]
        );

        await connection.commit();
        res.status(200).json('Data inserted successfully');

        // Send confirmation email
        if (locationRows.length > 0) {
          await sendVolunteerConfirmation(email, locationRows[0].community_city, language);
        }
      } else {
        throw new Error('Could not create volunteer');
      }
    } else {
      throw new Error('Volunteer signature is required');
    }
  } catch (err) {
    if (connection) {
      await connection.rollback();
    }
    console.log(err);

    if (err.message === 'Volunteer signature is required') {
      res.status(400).json(err.message);
    } else if (err.message === 'Could not create volunteer') {
      res.status(500).json(err.message);
    } else {
      res.status(500).json('Internal server error');
    }
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

router.put('/beneficiary/reset-password', async (req, res) => {

  try {
    const { email } = req.body;
    const { dateOfBirth } = req.body;

    const [rows] = await mysqlConnection.promise().query('SELECT user.id \
                                                          FROM user \
                                                          INNER JOIN role ON role.id = user.role_id \
                                                          WHERE (user.email = ? or user.username = ? or (user.phone = ? AND user.phone IS NOT NULL)) and user.date_of_birth = ?',
      [email, email, email, dateOfBirth]);

    if (rows.length > 0) {

      // const newPassword = Math.random().toString(36).slice(-8);
      const newPassword = 'communitydata';
      let passwordHash = await bcryptjs.hash(newPassword, 8);

      const [rows2] = await mysqlConnection.promise().query('update user set password = ?, reset_password = "Y" where id = ?',
        [passwordHash, rows[0].id]);

      if (rows2.affectedRows > 0) {
        res.json({ password: newPassword });
      } else {
        res.status(500).json('Could not update password');
      }

    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (error) {
    console.log(error);
    logger.error(error);
    res.status(500).json('Internal server error');
  }
});

router.put('/change-password/:idUser', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'stocker' || cabecera.role === 'delivery' || cabecera.role === 'beneficiary' || cabecera.role === 'opsmanager' || cabecera.role === 'director' || cabecera.role === 'auditor') {
    try {
      const { idUser } = req.params;
      const { password } = req.body;

      let passwordHash = await bcryptjs.hash(password, 8);

      const [rows] = await mysqlConnection.promise().query('update user set password = ?, reset_password = "N" where id = ?',
        [passwordHash, idUser]);

      if (rows.affectedRows > 0) {
        res.json('Password updated successfully');
      } else {
        res.status(500).json('Could not update password');
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

router.delete('/user/reset-password/:idUser', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { idUser } = req.params;

      // const newPassword = Math.random().toString(36).slice(-8);
      const newPassword = 'communitydata';
      let passwordHash = await bcryptjs.hash(newPassword, 8);

      const [rows2] = await mysqlConnection.promise().query('update user set password = ?, reset_password = "Y" where id = ?',
        [passwordHash, idUser]);

      if (rows2.affectedRows > 0) {
        res.json({ password: newPassword });
      } else {
        res.status(500).json('Could not update password');
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

router.get('/new/location/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select l.id,
        l.organization,
        l.community_city,
        l.address,
        GROUP_CONCAT(DISTINCT cl.client_id) as client_ids,
        CONCAT(ST_Y(l.coordinates), ', ', ST_X(l.coordinates)) as coordinates
        from location as l
        left join client_location as cl on l.id = cl.location_id
        where l.id = ?
        group by l.id
        order by l.id
        `,
        [id]
      );
      if (rows.length > 0) {
        // Convert client_ids from string to array of integers
        rows[0].client_ids = rows[0].client_ids ? rows[0].client_ids.split(',').map(Number) : [];
        res.json(rows[0]);
      } else {
        res.status(404).json('Location not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/location', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager') {
    try {
      formulario = req.body;
      const organization = formulario.organization || null;
      const community_city = formulario.community_city || null;
      const address = formulario.address || null;
      const coordinates = formulario.coordinates || null;
      const client_ids = formulario.client_ids || [];
      // separate coordinates into longitude and latitude and eliminate spaces
      const coordinatesArray = coordinates.split(',').map(coord => coord.trim());
      const longitude = coordinatesArray[0];
      const latitude = coordinatesArray[1];
      const point = `POINT(${latitude} ${longitude})`;

      const [rows] = await mysqlConnection.promise().query(
        `INSERT INTO location (organization, community_city, address, coordinates)
        VALUES (?, ?, ?, ST_GeomFromText(?))`,
        [organization, community_city, address, point]
      );

      if (rows.affectedRows > 0) {
        const location_id = rows.insertId;
        if (client_ids.length > 0) {
          for (let i = 0; i < client_ids.length; i++) {
            await mysqlConnection.promise().query(
              'insert into client_location(client_id, location_id) values(?,?)',
              [client_ids[i], location_id]
            );
          }
        }

        res.json('Location created successfully');
      } else {
        res.status(500).json('Could not create location');
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

router.put('/new/location/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const organization = formulario.organization || null;
      const community_city = formulario.community_city || null;
      const address = formulario.address || null;
      const coordinates = formulario.coordinates || null;
      const client_ids = formulario.client_ids || [];
      // separate coordinates into longitude and latitude and eliminate spaces
      const coordinatesArray = coordinates.split(',').map(coord => coord.trim());
      const longitude = coordinatesArray[0];
      const latitude = coordinatesArray[1];
      const point = `POINT(${latitude} ${longitude})`;

      const [rows] = await mysqlConnection.promise().query(
        `UPDATE location SET organization = ?, community_city = ?, address = ?, coordinates = ST_GeomFromText(?) WHERE id = ?`,
        [organization, community_city, address, point, id]
      );

      if (rows.affectedRows > 0) {
        // delete all client_location records for the location
        await mysqlConnection.promise().query(
          'delete from client_location where location_id = ?',
          [id]
        );
        // insert new client_location records
        if (client_ids.length > 0) {
          for (let i = 0; i < client_ids.length; i++) {
            await mysqlConnection.promise().query(
              'insert into client_location(client_id, location_id) values(?,?)',
              [client_ids[i], id]
            );
          }
        }

        res.json('Location updated successfully');
      }
      else {
        res.status(500).json('Could not update location');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/new/product/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select id,
        name,
        product_type_id,
        value_usd
        from product as p
        where p.id = ?`,
        [id]
      );
      if (rows.length > 0) {
        res.json(rows[0]);
      } else {
        res.status(404).json('Product not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/product', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      formulario = req.body;
      const name = formulario.name || null;
      const product_type_id = formulario.product_type_id || null;
      const value_usd = formulario.value_usd || null;

      const [rows] = await mysqlConnection.promise().query(
        'insert into product (name, product_type_id, value_usd) values(?,?,?)',
        [name, product_type_id, value_usd]
      );

      if (rows.affectedRows > 0) {
        res.json('Product created successfully');
      } else {
        res.status(500).json('Could not create product');
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

router.put('/new/product/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const name = formulario.name || null;
      const product_type_id = formulario.product_type_id || null;
      const value_usd = formulario.value_usd || null;

      const [rows] = await mysqlConnection.promise().query(
        'update product set name = ?, product_type_id = ?, value_usd = ? where id = ?',
        [name, product_type_id, value_usd, id]
      );

      if (rows.affectedRows > 0) {
        res.json('Product updated successfully');
      }
      else {
        res.status(500).json('Could not update product');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/new/product-type/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select id,
        name,
        name_es
        from product_type as pt
        where pt.id = ?`,
        [id]
      );
      if (rows.length > 0) {
        res.json(rows[0]);
      } else {
        res.status(404).json('Product type not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/product-type', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      formulario = req.body;
      const name = formulario.name || null;
      const name_es = formulario.name_es || null;

      const [rows] = await mysqlConnection.promise().query(
        'insert into product_type (name, name_es) values(?,?)',
        [name, name_es]
      );

      if (rows.affectedRows > 0) {
        res.json('Product type created successfully');
      } else {
        res.status(500).json('Could not create product type');
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

router.put('/new/product-type/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const name = formulario.name || null;
      const name_es = formulario.name_es || null;

      const [rows] = await mysqlConnection.promise().query(
        'update product_type set name = ?, name_es = ? where id = ?',
        [name, name_es, id]
      );

      if (rows.affectedRows > 0) {
        res.json('Product type updated successfully');
      }
      else {
        res.status(500).json('Could not update product type');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/new/delivered-by/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select id,
        name
        from delivered_by as db
        where db.id = ?`,
        [id]
      );
      if (rows.length > 0) {
        res.json(rows[0]);
      } else {
        res.status(404).json('Delivered by not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/delivered-by', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      formulario = req.body;
      const name = formulario.name || null;

      const [rows] = await mysqlConnection.promise().query(
        'insert into delivered_by (name) values(?)',
        [name]
      );

      if (rows.affectedRows > 0) {
        res.json('Delivered by created successfully');
      } else {
        res.status(500).json('Could not create delivered by');
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

router.put('/new/delivered-by/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const name = formulario.name || null;

      const [rows] = await mysqlConnection.promise().query(
        'update delivered_by set name = ? where id = ?',
        [name, id]
      );

      if (rows.affectedRows > 0) {
        res.json('Delivered by updated successfully');
      }
      else {
        res.status(500).json('Could not update delivered by');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/new/transported-by/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select id,
        name
        from transported_by as tb
        where tb.id = ?`,
        [id]
      );
      if (rows.length > 0) {
        res.json(rows[0]);
      } else {
        res.status(404).json('Transported by not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/transported-by', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      formulario = req.body;
      const name = formulario.name || null;

      const [rows] = await mysqlConnection.promise().query(
        'insert into transported_by (name) values(?)',
        [name]
      );

      if (rows.affectedRows > 0) {
        res.json('Transported by created successfully');
      } else {
        res.status(500).json('Could not create transported by');
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

router.put('/new/transported-by/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const name = formulario.name || null;

      const [rows] = await mysqlConnection.promise().query(
        'update transported_by set name = ? where id = ?',
        [name, id]
      );

      if (rows.affectedRows > 0) {
        res.json('Transported by updated successfully');
      }
      else {
        res.status(500).json('Could not update transported by');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/new/gender/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select id,
        name,
        name_es
        from gender as g
        where g.id = ?`,
        [id]
      );
      if (rows.length > 0) {
        res.json(rows[0]);
      } else {
        res.status(404).json('Gender not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/gender', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      formulario = req.body;
      const name = formulario.name || null;
      const name_es = formulario.name_es || null;

      const [rows] = await mysqlConnection.promise().query(
        'insert into gender (name, name_es) values(?,?)',
        [name, name_es]
      );

      if (rows.affectedRows > 0) {
        res.json('Gender created successfully');
      } else {
        res.status(500).json('Could not create gender');
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

router.put('/new/gender/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const name = formulario.name || null;
      const name_es = formulario.name_es || null;

      const [rows] = await mysqlConnection.promise().query(
        'update gender set name = ?, name_es = ? where id = ?',
        [name, name_es, id]
      );

      if (rows.affectedRows > 0) {
        res.json('Gender updated successfully');
      }
      else {
        res.status(500).json('Could not update gender');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/new/ethnicity/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select id,
        name,
        name_es
        from ethnicity as g
        where g.id = ?`,
        [id]
      );
      if (rows.length > 0) {
        res.json(rows[0]);
      } else {
        res.status(404).json('Ethnicity not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/ethnicity', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      formulario = req.body;
      const name = formulario.name || null;
      const name_es = formulario.name_es || null;

      const [rows] = await mysqlConnection.promise().query(
        'insert into ethnicity (name, name_es) values(?,?)',
        [name, name_es]
      );

      if (rows.affectedRows > 0) {
        res.json('Ethnicity created successfully');
      } else {
        res.status(500).json('Could not create ethnicity');
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

router.put('/new/ethnicity/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const name = formulario.name || null;
      const name_es = formulario.name_es || null;

      const [rows] = await mysqlConnection.promise().query(
        'update ethnicity set name = ?, name_es = ? where id = ?',
        [name, name_es, id]
      );

      if (rows.affectedRows > 0) {
        res.json('Ethnicity updated successfully');
      }
      else {
        res.status(500).json('Could not update ethnicity');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/new/provider/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select id,
        name
        from provider as p
        where p.id = ?`,
        [id]
      );
      if (rows.length > 0) {
        res.json(rows[0]);
      } else {
        res.status(404).json('Provider not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/provider', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      formulario = req.body;
      const name = formulario.name || null;

      const [rows] = await mysqlConnection.promise().query(
        'insert into provider (name) values(?)',
        [name]
      );

      if (rows.affectedRows > 0) {
        res.json('Provider created successfully');
      } else {
        res.status(500).json('Could not create provider');
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

router.put('/new/provider/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const name = formulario.name || null;

      const [rows] = await mysqlConnection.promise().query(
        'update provider set name = ? where id = ?',
        [name, id]
      );

      if (rows.affectedRows > 0) {
        res.json('Provider updated successfully');
      }
      else {
        res.status(500).json('Could not update provider');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/new/client/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select c.id,
        c.name,
        c.short_name,
        c.email,
        c.phone,
        c.address,
        c.webpage,
        GROUP_CONCAT(DISTINCT cl.location_id) as location_ids
        from client as c
        left join client_location as cl on c.id = cl.client_id
        where c.id = ?
        group by c.id
        order by c.id
        `,
        [id]
      );
      const [rows_emails] = await mysqlConnection.promise().query(
        `select email
        from client_email
        where client_id = ?
        `,
        [id]
      );

      if (rows.length > 0) {
        // Convert location_ids from string to array of integers
        rows[0].location_ids = rows[0].location_ids ? rows[0].location_ids.split(',').map(Number) : [];
        rows[0].emails_for_reporting = rows_emails;
        res.json(rows[0]);
      } else {
        res.status(404).json('Client not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/client', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      formulario = req.body;
      const name = formulario.name || null;
      const short_name = formulario.short_name || null;
      const email = formulario.email || null;
      const phone = formulario.phone || null;
      const address = formulario.address || null;
      const webpage = formulario.webpage || null;
      const location_ids = formulario.location_ids || [];
      const emails_for_reporting = formulario.emails_for_reporting || [];

      const [rows] = await mysqlConnection.promise().query(
        'insert into client (name, short_name, email, phone, address, webpage) values(?,?,?,?,?,?)',
        [name, short_name, email, phone, address, webpage]
      );

      if (rows.affectedRows > 0) {
        const client_id = rows.insertId;
        if (location_ids.length > 0) {
          for (let i = 0; i < location_ids.length; i++) {
            await mysqlConnection.promise().query(
              'insert into client_location(client_id, location_id) values(?,?)',
              [client_id, location_ids[i]]
            );
          }
        }
        if (emails_for_reporting.length > 0) {
          for (let i = 0; i < emails_for_reporting.length; i++) {
            await mysqlConnection.promise().query(
              'insert into client_email(client_id, email) values(?,?)',
              [client_id, emails_for_reporting[i].email]
            );
          }
        }

        res.json('Client created successfully');
      } else {
        res.status(500).json('Could not create client');
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

router.put('/new/client/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const name = formulario.name || null;
      const short_name = formulario.short_name || null;
      const email = formulario.email || null;
      const phone = formulario.phone || null;
      const address = formulario.address || null;
      const webpage = formulario.webpage || null;
      const location_ids = formulario.location_ids || [];
      const emails_for_reporting = formulario.emails_for_reporting || [];

      const [rows] = await mysqlConnection.promise().query(
        'update client set name = ?, short_name = ?, email = ?, phone = ?, address = ?, webpage = ? where id = ?',
        [name, short_name, email, phone, address, webpage, id]
      );

      if (rows.affectedRows > 0) {
        // delete all client_location records for the client
        await mysqlConnection.promise().query(
          'delete from client_location where client_id = ?',
          [id]
        );
        // insert new client_location records
        if (location_ids.length > 0) {
          for (let i = 0; i < location_ids.length; i++) {
            await mysqlConnection.promise().query(
              'insert into client_location(client_id, location_id) values(?,?)',
              [id, location_ids[i]]
            );
          }
        }
        // get all emails for reporting
        const [rows_emails] = await mysqlConnection.promise().query(
          'select email from client_email where client_id = ?',
          [id]
        );
        // compare emails for reporting and delete the ones that are not in the new list
        for (let i = 0; i < rows_emails.length; i++) {
          if (!emails_for_reporting.map(e => e.email).includes(rows_emails[i].email)) {
            await mysqlConnection.promise().query(
              'delete from client_email where client_id = ? and email = ?',
              [id, rows_emails[i].email]
            );
          }
        }
        // insert new emails that don't exist in the database
        for (let i = 0; i < emails_for_reporting.length; i++) {
          // compare emails for reporting with rows_emails and insert the ones that are not in the database
          if (!rows_emails.map(e => e.email).includes(emails_for_reporting[i].email)) {
            await mysqlConnection.promise().query(
              'insert into client_email(client_id, email) values(?,?)',
              [id, emails_for_reporting[i].email]
            );
          }
        }

        res.json('Client updated successfully');
      }
      else {
        res.status(500).json('Could not update client');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/new/user/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      const [rows] = await mysqlConnection.promise().query(
        `select id,
        username,
        firstname,
        lastname,
        email,
        date_of_birth,
        gender_id, 
        role_id, 
        client_id, 
        phone
        from user u
        where u.id = ?`,
        [id]
      );
      const [rows_emails] = await mysqlConnection.promise().query(
        `select email
        from user_email_report
        where user_id = ?
        `,
        [id]
      );
      if (rows.length > 0) {
        rows[0].emails_for_reporting = rows_emails;
        res.json(rows[0]);
      } else {
        res.status(404).json('User not found');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/new/user', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      formulario = req.body;
      const username = formulario.username || null;
      const password = formulario.password || null;
      const email = formulario.email || null;
      const firstname = formulario.firstname || null;
      const lastname = formulario.lastname || null;
      const date_of_birth = formulario.date_of_birth || null;
      const gender_id = formulario.gender_id || null;
      const role_id = formulario.role_id || null;
      const phone = formulario.phone || null;
      const client_id = formulario.client_id || null;
      const emails_for_reporting = formulario.emails_for_reporting || [];

      // const newPassword = Math.random().toString(36).slice(-8);
      var newPassword = 'communitydata';
      if (password) {
        newPassword = password;
      }
      let passwordHash = await bcryptjs.hash(newPassword, 8);
      var reset_password = "Y";
      const [rows2] = await mysqlConnection.promise().query(
        'insert into user (username, email, firstname, lastname, date_of_birth, password, reset_password, gender_id, role_id, client_id, phone) values(?,?,?,?,?,?,?,?,?,?,?)',
        [username, email, firstname, lastname, date_of_birth, passwordHash, reset_password, gender_id, role_id, client_id, phone]
      );

      if (rows2.affectedRows > 0) {
        const user_id = rows2.insertId;
        if (emails_for_reporting.length > 0) {
          for (let i = 0; i < emails_for_reporting.length; i++) {
            await mysqlConnection.promise().query(
              'insert into user_email_report(user_id, email) values(?,?)',
              [user_id, emails_for_reporting[i].email]
            );
          }
        }
        res.json({ password: newPassword });
      } else {
        res.status(500).json('Could not create user');
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

router.put('/new/user/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const id = req.params.id || null;
      formulario = req.body;
      const username = formulario.username || null;
      const email = formulario.email || null;
      const firstname = formulario.firstname || null;
      const lastname = formulario.lastname || null;
      const date_of_birth = formulario.date_of_birth || null;
      const gender_id = formulario.gender_id || null;
      const phone = formulario.phone || null;
      const client_id = formulario.client_id || null;
      const emails_for_reporting = formulario.emails_for_reporting || [];

      const [rows] = await mysqlConnection.promise().query(
        'update user set username = ?, email = ?, firstname = ?, lastname = ?, date_of_birth = ?, gender_id = ?, phone = ?, client_id = ? where id = ?',
        [username, email, firstname, lastname, date_of_birth, gender_id, phone, client_id, id]
      );

      if (rows.affectedRows > 0) {
        // get all emails for reporting
        const [rows_emails] = await mysqlConnection.promise().query(
          'select email from user_email_report where user_id = ?',
          [id]
        );
        // compare emails for reporting and delete the ones that are not in the new list
        for (let i = 0; i < rows_emails.length; i++) {
          if (!emails_for_reporting.map(e => e.email).includes(rows_emails[i].email)) {
            await mysqlConnection.promise().query(
              'delete from user_email_report where user_id = ? and email = ?',
              [id, rows_emails[i].email]
            );
          }
        }
        // insert new emails that don't exist in the database
        for (let i = 0; i < emails_for_reporting.length; i++) {
          // compare emails for reporting with rows_emails and insert the ones that are not in the database
          if (!rows_emails.map(e => e.email).includes(emails_for_reporting[i].email)) {
            await mysqlConnection.promise().query(
              'insert into user_email_report(user_id, email) values(?,?)',
              [id, emails_for_reporting[i].email]
            );
          }
        }

        res.json('User updated successfully');
      }
      else {
        res.status(500).json('Could not update user');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/upload/beneficiaryQR/:locationId/:clientId', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'delivery') {
    if (req.body && req.body.role === 'beneficiary') {
      try {
        const delivering_user_id = cabecera.id;
        // QR
        const receiving_user_id = req.body.id;
        const approved = req.body.approved;
        const receiving_location_id = req.body.location_id ? parseInt(req.body.location_id) : null;
        const location_id = req.params.locationId !== 'null' ? parseInt(req.params.locationId) : null;
        const client_id = req.params.clientId !== 'null' ? parseInt(req.params.clientId) : cabecera.client_id;
        if (receiving_user_id) {
          // if (receiving_location_id === location_id) {
          // actualizar location_id y client_id del user beneficiary
          const [rows2_update_user] = await mysqlConnection.promise().query(
            'update user set location_id = ?, client_id = ? where id = ?', [location_id, client_id, receiving_user_id]
          );
          // el caso en el que una locacion tiene varios client_id, corregir al beneficiario:
          // buscar en tabla client_user si existe un registro con user_id, client_id o con fecha de hoy con checked = 'N', 
          // si el de hoy es el mismo client_id, actualizarlo, sino eliminarlo y crear uno nuevo
          const [rows_client_user] = await mysqlConnection.promise().query(
            'select * from client_user where user_id = ? and (client_id = ? or (client_id <> ? and date(creation_date) = curdate() and checked = "N"))',
            [receiving_user_id, client_id, client_id]
          );
          let insertarClientUser = true;
          if (rows_client_user.length > 0) {
            // recorrer el array de rows_client_user y si el client_id es el mismo que el de hoy y tiene checked 'N', actualizarlo, sino eliminarlo y crear uno nuevo
            for (let i = 0; i < rows_client_user.length; i++) {
              if (rows_client_user[i].client_id === client_id) {
                insertarClientUser = false;
                if (rows_client_user[i].checked === 'N') {
                  // actualizar el campo checked de client_user por 'Y'
                  const [rows_checked] = await mysqlConnection.promise().query(
                    'update client_user set checked = "Y" where user_id = ? and client_id = ?', [receiving_user_id, client_id]
                  );
                }
              } else {
                // si el client_id tiene creation date de hoy y client_id diferente, eliminarlo
                if (rows_client_user[i].checked === 'N') {
                  const [rows_delete] = await mysqlConnection.promise().query(
                    'delete from client_user where user_id = ? and client_id = ?', [receiving_user_id, rows_client_user[i].client_id]
                  );
                }
              }
            }
            if (insertarClientUser) {
              // insertar en client_user
              const [rows_insert] = await mysqlConnection.promise().query(
                'insert into client_user(user_id, client_id, checked) values(?,?,?)', [receiving_user_id, client_id, 'Y']
              );
            }
          } else {
            // insertar en client_user
            const [rows_insert] = await mysqlConnection.promise().query(
              'insert into client_user(user_id, client_id, checked) values(?,?,?)', [receiving_user_id, client_id, 'Y']
            );
          }
          // buscar en tabla delivery_beneficiary si existe un registro con location_id, receiving_user_id en el dia de hoy y filtrar el más reciente
          const [rows] = await mysqlConnection.promise().query(
            'select id, approved, delivering_user_id, location_id, client_id \
              from delivery_beneficiary \
              where location_id = ? and receiving_user_id = ? and date(creation_date) = curdate() \
              order by creation_date desc limit 1',
            [location_id, receiving_user_id]
          );
          // si no tiene delivering_user_id quiere decir que no se ha escaneado el QR pero si se ha generado el QR
          if (rows.length > 0 && rows[0].delivering_user_id === null) {
            // TO-DO verificar si el beneficiary esta apto para recibir la entrega, sino enviar un 'N'

            // actualizar el campo delivering_user_id con el id del delivery user y el campo location_id
            const [rows2] = await mysqlConnection.promise().query(
              'update delivery_beneficiary set client_id = ?, delivering_user_id = ?, location_id = ? where id = ?', [client_id, delivering_user_id, location_id, rows[0].id]
            );

            if (rows2.affectedRows > 0) {
              return res.status(200).json({ could_approve: 'Y' });
            } else {
              console.log('error qr 501: ' + new Date() + 'delivery_user_id: ' + delivering_user_id + 'receiving_user_id: ' + receiving_user_id + 'location_id: ' + location_id + 'client_id: ' + client_id + 'approved: ' + approved + 'rows[0].id: ' + rows[0].id);
              return res.status(501).json('Could not update delivering_user_id');
            }
          } else {
            // ya existe el campo en delivery_beneficiary con delivering_user_id, verificar si el campo approved es 'N'
            if (rows.length > 0 && rows[0].approved === 'N') {
              if (approved === 'Y') {
                // actualizar el campo approved a 'Y'
                const [rows2] = await mysqlConnection.promise().query(
                  'update delivery_beneficiary set approved = "Y" where id = ?', [rows[0].id]
                );
                if (rows2.affectedRows > 0) {
                  res.json('Beneficiary approved successfully');
                } else {
                  console.log('error qr 502: ' + new Date() + 'delivery_user_id: ' + delivering_user_id + 'receiving_user_id: ' + receiving_user_id + 'location_id: ' + location_id + 'client_id: ' + client_id + 'approved: ' + approved + 'rows[0].id: ' + rows[0].id);
                  res.status(502).json('Could not approve beneficiary');
                }
              } else {
                res.json({ could_approve: 'Y' });
              }
            } else {
              // TO-DO verificar si el beneficiary esta apto para recibir la entrega, sino enviar un 'N'

              // si no existe en delivery_beneficiary o si ya pasó con un Y el approved, insertar una mas en tabla delivery_beneficiary para otro bolson
              const [rows3] = await mysqlConnection.promise().query(
                'insert into delivery_beneficiary(client_id, delivering_user_id, receiving_user_id, location_id) values(?,?,?,?)',
                [client_id, delivering_user_id, receiving_user_id, location_id]
              );

              if (rows3.affectedRows > 0) {
                return res.status(200).json({ could_approve: 'Y' });
              } else {
                console.log('error qr 503: ' + new Date() + 'delivery_user_id: ' + delivering_user_id + 'receiving_user_id: ' + receiving_user_id + 'location_id: ' + location_id + 'client_id: ' + client_id + 'approved: ' + approved + 'rows: ' + rows);
                return res.status(503).json('Could not create delivery_beneficiary');
              }

            }
          }
          // } else {
          // error si la locacion del beneficiario es distinta del delivery
          // res.status(200).json({ error: 'receiving_location' });
          // }
        } else {
          res.status(200).json({ error: 'receiving_user_null' });
          // error si no viene receiving_location_id
          // res.status(200).json({ error: 'receiving_location_null' });
        }
      } catch (error) {
        console.log(error + 'error qr 500: ' + new Date() + 'delivery_user_id: ' + delivering_user_id + 'receiving_user_id: ' + receiving_user_id + 'location_id: ' + location_id + 'client_id: ' + client_id + 'approved: ' + approved + 'rows[0].id: ' + rows[0].id);
        logger.error(error);
        res.status(500).json('Internal server error');
      }
    } else {
      console.log(json.stringify(req.body) + 'error qr 401: ' + new Date());
      res.status(402).json('Unauthorized');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/upload/beneficiaryPhone/:locationId/:clientId', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'delivery') {
    try {
      const delivering_user_id = cabecera.id;
      // PHONE
      const receiving_user_phone = req.body.phone;
      const user_id_from_phone_list = req.body.user_id;
      const location_id = req.params.locationId !== 'null' ? parseInt(req.params.locationId) : null;
      const client_id = req.params.clientId !== 'null' ? parseInt(req.params.clientId) : cabecera.client_id;
      let receiving_user_id = null;
      if (user_id_from_phone_list === 0) {
        const [row_receiving_user_id] = await mysqlConnection.promise().query(
          'select id from user where phone = ?', [receiving_user_phone]
        );
        receiving_user_id = row_receiving_user_id.length > 0 ? row_receiving_user_id[0].id : null;
      } else {
        receiving_user_id = user_id_from_phone_list;
      }
      if (receiving_user_phone && receiving_user_id) {
        // actualizar location_id y client_id del user beneficiary
        const [rows2_update_user] = await mysqlConnection.promise().query(
          'update user set location_id = ?, client_id = ? where id = ?', [location_id, client_id, receiving_user_id]
        );
        // el caso en el que una locacion tiene varios client_id, corregir al beneficiario:
        // buscar en tabla client_user si existe un registro con user_id, client_id o con fecha de hoy con checked = 'N', 
        // si el de hoy es el mismo client_id, actualizarlo, sino eliminarlo y crear uno nuevo
        const [rows_client_user] = await mysqlConnection.promise().query(
          'select * from client_user where user_id = ? and (client_id = ? or (client_id <> ? and date(creation_date) = curdate() and checked = "N"))',
          [receiving_user_id, client_id, client_id]
        );
        let insertarClientUser = true;
        if (rows_client_user.length > 0) {
          // recorrer el array de rows_client_user y si el client_id es el mismo que el de hoy y tiene checked 'N', actualizarlo, sino eliminarlo y crear uno nuevo
          for (let i = 0; i < rows_client_user.length; i++) {
            if (rows_client_user[i].client_id === client_id) {
              insertarClientUser = false;
              if (rows_client_user[i].checked === 'N') {
                // actualizar el campo checked de client_user por 'Y'
                const [rows_checked] = await mysqlConnection.promise().query(
                  'update client_user set checked = "Y" where user_id = ? and client_id = ?', [receiving_user_id, client_id]
                );
              }
            } else {
              // si el client_id tiene creation date de hoy y client_id diferente, eliminarlo
              if (rows_client_user[i].checked === 'N') {
                const [rows_delete] = await mysqlConnection.promise().query(
                  'delete from client_user where user_id = ? and client_id = ?', [receiving_user_id, rows_client_user[i].client_id]
                );
              }
            }
          }
          if (insertarClientUser) {
            // insertar en client_user
            const [rows_insert] = await mysqlConnection.promise().query(
              'insert into client_user(user_id, client_id, checked) values(?,?,?)', [receiving_user_id, client_id, 'Y']
            );
          }
        } else {
          // insertar en client_user
          const [rows_insert] = await mysqlConnection.promise().query(
            'insert into client_user(user_id, client_id, checked) values(?,?,?)', [receiving_user_id, client_id, 'Y']
          );
        }
        // buscar en tabla delivery_beneficiary si existe un registro con location_id, receiving_user_id en el dia de hoy y filtrar el más reciente
        const [rows] = await mysqlConnection.promise().query(
          'select id, approved, delivering_user_id, location_id, client_id \
              from delivery_beneficiary \
              where location_id = ? and receiving_user_id = ? and date(creation_date) = curdate() \
              order by creation_date desc limit 1',
          [location_id, receiving_user_id]
        );
        // si no tiene delivering_user_id quiere decir que no se ha escaneado el QR pero si se ha generado el QR
        if (rows.length > 0 && rows[0].delivering_user_id === null) {
          // TO-DO verificar si el beneficiary esta apto para recibir la entrega, sino enviar un 'N'

          // actualizar el campo delivering_user_id con el id del delivery user y el campo location_id
          const [rows2] = await mysqlConnection.promise().query(
            'update delivery_beneficiary set approved = "Y", client_id = ?, delivering_user_id = ?, location_id = ? where id = ?', [client_id, delivering_user_id, location_id, rows[0].id]
          );

          if (rows2.affectedRows > 0) {
            return res.json('Beneficiary approved successfully');
          } else {
            return res.status(500).json('Could not update delivering_user_id');
          }
        } else {
          // ya existe el campo en delivery_beneficiary con delivering_user_id, verificar si el campo approved es 'N'
          if (rows.length > 0 && rows[0].approved === 'N') {
            // actualizar el campo approved a 'Y'
            const [rows2] = await mysqlConnection.promise().query(
              'update delivery_beneficiary set approved = "Y" where id = ?', [rows[0].id]
            );
            if (rows2.affectedRows > 0) {
              res.json('Beneficiary approved successfully');
            } else {
              res.status(500).json('Could not approve beneficiary');
            }

          } else {
            // TO-DO verificar si el beneficiary esta apto para recibir la entrega, sino enviar un 'N'

            // si no existe en delivery_beneficiary o si ya pasó con un Y el approved, insertar una mas en tabla delivery_beneficiary para otro bolson
            const [rows3] = await mysqlConnection.promise().query(
              'insert into delivery_beneficiary(client_id, delivering_user_id, receiving_user_id, location_id, approved) values(?,?,?,?,?)',
              [client_id, delivering_user_id, receiving_user_id, location_id, 'Y']
            );

            if (rows3.affectedRows > 0) {
              return res.json('Beneficiary approved successfully');
            } else {
              return res.status(500).json('Could not create delivery_beneficiary');
            }

          }
        }
      } else {
        res.status(400).json({ error: 'receiving_user_null' });
        // error si no viene receiving_location_id
        // res.status(200).json({ error: 'receiving_location_null' });
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

router.get('/answer-types', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select id,name,name_es from answer_type',
      );
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/workers', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select id,username \
        from user \
        where role_id = 4 \
        order by username',
      );
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/locations', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'stocker' || cabecera.role === 'delivery' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select id,organization,community_city,address, ST_Y(coordinates) as latitude, ST_X(coordinates) as longitude from location order by community_city'
      );
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'admin') {
      try {
        const [rows] = await mysqlConnection.promise().query(
          'select id,organization,community_city,address, ST_Y(coordinates) as latitude, ST_X(coordinates) as longitude from location order by community_city'
        );
        res.json(rows);
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      if (cabecera.role === 'client') {
        try {
          const [rows] = await mysqlConnection.promise().query(
            `select l.id, l.organization, l.community_city, l.address, ST_Y(l.coordinates) as latitude, ST_X(l.coordinates) as longitude 
                  from location as l
                  inner join client_location as cl on l.id = cl.location_id
                  where cl.client_id = ? order by l.community_city`,
            [cabecera.client_id]
          );
          res.json(rows);
        } catch (err) {
          console.log(err);
          res.status(500).json('Internal server error');
        }
      } else {
        if (cabecera.role === 'beneficiary') {
          try {
            const [rows] = await mysqlConnection.promise().query(
              'select id,organization,community_city,address, ST_Y(coordinates) as latitude, ST_X(coordinates) as longitude from location where enabled = "Y" order by community_city'
            );
            res.json(rows);
          } catch (err) {
            console.log(err);
            res.status(500).json('Internal server error');
          }
        } else {
          res.status(401).json('Unauthorized');
        }
      }
    }
  }
});

router.get('/delivered-by', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'stocker' || cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select id, name from delivered_by where enabled = "Y" order by name'
      );
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/transported-by', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'stocker' || cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select id, name from transported_by where enabled = "Y" order by name'
      );
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/register/locations', async (req, res) => {

  try {
    const [rows] = await mysqlConnection.promise().query(
      'select id,organization,community_city,address from location where enabled = "Y" order by community_city'
    );
    res.json(rows);
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }

});

router.get('/providers', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select id,name from provider order by name',
      );
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/stocker-upload', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select DISTINCT u.id, u.username as name from user as u inner join stocker_log as sl on u.id = sl.user_id where sl.operation_id = 5 and u.enabled = "Y" order by u.username',
      );
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/products', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select id,name,product_type_id from product order by name',
      );
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/product_types', verifyToken, async (req, res) => {
  const id = req.query.id || null;
  const language = req.query.language || 'en';
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
    try {
      const query = `SELECT id, ${language === 'en' ? 'name' : 'name_es'} AS name 
                  FROM product_type ${id ? ' WHERE id = ?' : ''} ORDER BY name`;
      const params = id ? [id] : [];
      const [rows] = await mysqlConnection.promise().query(query, params);
      res.json(rows);
    } catch (error) {
      console.log(error);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/audit_status', verifyToken, async (req, res) => {
  const language = req.query.language || 'en';
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
    try {
      const query = `SELECT id, ${language === 'en' ? 'name' : 'name_es'} AS name 
                  FROM audit_status WHERE enabled = 'Y' ORDER BY name`;
      const [rows] = await mysqlConnection.promise().query(query);
      res.json(rows);
    } catch (error) {
      console.log(error);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/clients', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'delivery' || cabecera.role === 'opsmanager') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select c.id,c.name,c.short_name, \
        GROUP_CONCAT(DISTINCT cl.location_id) as location_ids \
        from client as c \
        left join client_location as cl on c.id = cl.client_id \
        group by c.id \
        order by name',
      );
      // Convert location_ids from string to array of integers
      rows.forEach(row => {
        row.location_ids = row.location_ids ? row.location_ids.split(',').map(Number) : [];
      });
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/roles', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select id,name \
        from role \
        where name != "beneficiary" and name != "thirdparty" \
        order by name',
      );
      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/onBoard/answers', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  console.log("req.body", req.body);
  if (cabecera.role === 'beneficiary') {
    const secondForm = req.body;
    const location_id = req.query.location_id || null;

    try {

      // recuperar el client_id de la location_id, para eso se debe revisar primero en la tabla delivery log en la fecha actual, si no hay registros, se debe buscar en la tabla client_location un client_id asociado a la location_id
      const [rows_client_id] = await mysqlConnection.promise().query('SELECT client_id FROM delivery_log WHERE date(creation_date) = CURDATE() and location_id = ?', [location_id]);
      let client_id = null;
      if (rows_client_id.length > 0) {
        client_id = rows_client_id[0].client_id;
      } else {
        const [rows_client_id2] = await mysqlConnection.promise().query('SELECT client_id FROM client_location WHERE location_id = ?', [location_id]);
        if (rows_client_id2.length > 0) {
          client_id = rows_client_id2[0].client_id;
        }
      }

      // save inserted user id
      const user_id = cabecera.id;
      // insertar en tabla client_user el client_id y el user_id si client_id no es null
      if (client_id) {
        // Check if record already exists before inserting
        const [existingRows] = await mysqlConnection.promise().query(
          'SELECT 1 FROM client_user WHERE client_id = ? AND user_id = ?',
          [client_id, user_id]
        );

        if (existingRows.length === 0) {
          // Only insert if it doesn't exist
          const [rows_client_user] = await mysqlConnection.promise().query(
            'insert into client_user(client_id, user_id) values(?,?)',
            [client_id, user_id]
          );
        }
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

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

// get value (true or false) from body and update user_status_id of user. If true update to 3, if false update to 2
router.post('/onBoard', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'delivery') {
    try {
      const user_id = cabecera.id;
      const { value } = req.body;
      const user_status_id = value ? 3 : 4;
      const location_id = value ? req.body.location_id : null;
      const client_id = value ? req.body.client_id : null;
      const [rows] = await mysqlConnection.promise().query(
        'update user set user_status_id = ?, location_id = ?, client_id = ? where id = ?',
        [user_status_id, location_id, client_id, user_id]
      );
      if (user_status_id == 3) {
        // insertar en tabla delivery_log la operation
        const [rows2] = await mysqlConnection.promise().query(
          'insert into delivery_log(user_id, operation_id, location_id, client_id) values(?,?,?,?)',
          [user_id, user_status_id, location_id, client_id]
        );
      } else {
        // modificar el campo offboarding_date en el ultimo elemento de la tabla delivery_log que tenga operation_id 3 y user_id ordenando por fecha descendente
        const [rows2] = await mysqlConnection.promise().query(
          'update delivery_log set offboarding_date = now() where user_id = ? and operation_id = 3 order by creation_date desc limit 1',
          [user_id]
        );
      }
      if (rows.affectedRows > 0) {
        // update token
        let object_token = {
          id: user_id,
          firstname: cabecera.firstname,
          username: cabecera.username,
          email: cabecera.email,
          client_id: client_id,
          role: 'delivery',
          enabled: 'Y'
        };
        let data = JSON.stringify(object_token);
        jwt.sign({ data }, process.env.JWT_SECRET, { expiresIn: '8h' }, (err, token) => {
          if (err) {
            console.error('Error signing token: ', err);
            res.status(500).json({ error: 'Error signing token' });
          } else {
            res.status(200).json({ token });
          }
        });

      } else {
        res.status(500).json('Could not update status');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'beneficiary') {
      try {
        const user_id = cabecera.id;
        const { value } = req.body;
        const user_status_id = value ? 3 : 4;
        const location_id = req.body.location_id ? req.body.location_id : null;

        // obtener client_id de la nueva locacion, como hay locaciones con mas de un client_id hay que 
        // revisar el onboarding que hizo el delivery en el dia de hoy
        // utilizando la tabla delivery_log y ordenando por creation_date desc
        // si no hubo onboarding de delivery en el dia de hoy, obtener algun client_id de la locacion
        const [rows5_client_id] = await mysqlConnection.promise().query(
          `select dl.client_id
          from delivery_log as dl
          where date(CONVERT_TZ(dl.creation_date, '+00:00', 'America/Los_Angeles')) = DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))
          AND dl.operation_id = 3 
          AND dl.client_id IS NOT NULL 
          AND dl.location_id = ?
          order by dl.creation_date desc
          limit 1`,
          [location_id]
        );
        let client_id_temp = null;
        if (rows5_client_id.length > 0) {
          client_id_temp = rows5_client_id[0].client_id;
        } else {
          const [rows6_client_id] = await mysqlConnection.promise().query(
            `select cl.client_id
            from client_location as cl
            where cl.location_id = ?`,
            [location_id]
          );
          if (rows6_client_id.length > 0) {
            client_id_temp = rows6_client_id[0].client_id;
          }
        }

        const client_id = client_id_temp ? client_id_temp : null;
        // si operation es 3 crear registro en tabla delivery_beneficiary con receiving_user_id y location_id
        if (user_status_id === 3) {
          // verificar si ya existe un registro en delivery_beneficiary con receiving_user_id en el dia de hoy 
          // filtrar el más reciente y si la location_id es igual actualizar last_onboarding_date por la fecha actual, sino eliminarla e insertar la nueva
          const [rows2] = await mysqlConnection.promise().query(
            `SELECT db.id, db.location_id
             FROM delivery_beneficiary AS db
             WHERE db.delivering_user_id IS NULL
               AND db.receiving_user_id = ?
               AND DATE(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')) = DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))
             ORDER BY db.creation_date DESC
             LIMIT 1`,
            [user_id]
          );
          // ver los client_id del receiving_user_id en la tabla client_user y si no existe el client_id, insertarlo
          const [rows2_client_id] = await mysqlConnection.promise().query(
            `SELECT cu.client_id, cu.checked, 
                    IF(DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles')) = DATE(CONVERT_TZ(cu.creation_date, '+00:00', 'America/Los_Angeles')), 'Y', 'N') as client_same_date
           FROM client_user AS cu 
           WHERE cu.user_id = ?`,
            [user_id]
          );
          if (rows2.length > 0) {
            if (rows2[0].location_id === location_id) {
              const [rows3] = await mysqlConnection.promise().query(
                'update delivery_beneficiary set last_onboarding_date = now() where id = ?',
                [rows2[0].id]
              );
            } else {
              // actualizar la locacion anterior por la nueva
              const [rows] = await mysqlConnection.promise().query(
                'UPDATE delivery_beneficiary SET client_id = ?, receiving_user_id = ?, location_id = ?, last_onboarding_date = now() WHERE id = ?',
                [client_id, user_id, location_id, rows2[0].id]
              );
            }
          } else {
            // insertar en tabla delivery_beneficiary la nueva locacion
            const [rows3] = await mysqlConnection.promise().query(
              'insert into delivery_beneficiary(client_id, receiving_user_id, location_id) values(?,?,?)',
              [client_id, user_id, location_id]
            );
          }
          // insertar el client_id en la tabla client_user
          if (client_id) {
            if (rows2_client_id.length > 0) {
              let client_id_exists = false;
              let update_client_id = false;
              let client_id_to_update = null;
              // verificar si el receiving_user_id tiene el client_id insertado en su tabla client_user (no importa la fecha),
              // si no es asi, insertar el nuevo client_id en la tabla client_user
              for (let i = 0; i < rows2_client_id.length; i++) {
                if (rows2_client_id[i].client_id === client_id) {
                  client_id_exists = true;
                } else {
                  if (rows2_client_id[i].checked === 'N') {
                    if (rows2_client_id[i].client_same_date === 'Y') {
                      update_client_id = true;
                      client_id_to_update = rows2_client_id[i].client_id;
                    }
                  }
                }
              }

              if (!client_id_exists) {
                if (update_client_id) {
                  const [rows6] = await mysqlConnection.promise().query(
                    `update client_user set client_id = ? where user_id = ? and client_id = ?`,
                    [client_id, user_id, client_id_to_update]
                  );
                } else {
                  const [rows7] = await mysqlConnection.promise().query(
                    'insert into client_user(user_id, client_id) values(?,?)',
                    [user_id, client_id]
                  );
                }
              } else {
                if (update_client_id) {
                  // eliminar el client_id que no es el actual
                  const [rows8] = await mysqlConnection.promise().query(
                    'delete from client_user where user_id = ? and client_id = ?',
                    [user_id, client_id_to_update]
                  );
                }
              }
            } else {
              const [rows7] = await mysqlConnection.promise().query(
                'insert into client_user(user_id, client_id) values(?,?)',
                [user_id, client_id]
              );
            }
          }

        }
        // actualizar user
        const [rows_update_user] = await mysqlConnection.promise().query(
          'update user set user_status_id = ?, location_id = ?, client_id = ? where id = ?',
          [user_status_id, location_id, client_id, user_id]
        );
        // insertar en tabla beneficiary_log la operation
        const [rows_insert_beneficiary_log] = await mysqlConnection.promise().query(
          'insert into beneficiary_log(user_id, operation_id, location_id) values(?,?,?)',
          [user_id, user_status_id, location_id]
        );

        if (rows_update_user.affectedRows > 0) {
          // update token
          let object_token = {
            id: user_id,
            firstname: cabecera.firstname,
            username: cabecera.username,
            email: cabecera.email,
            client_id: client_id,
            role: 'beneficiary',
            enabled: 'Y'
          };
          let data = JSON.stringify(object_token);
          jwt.sign({ data }, process.env.JWT_SECRET, { expiresIn: '8h' }, (err, token) => {
            if (err) {
              console.error('Error signing token: ', err);
              res.status(500).json({ error: 'Error signing token' });
            } else {
              res.status(200).json({ token });
            }
          });
        } else {
          res.status(500).json('Could not update status');
        }
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

// get status of user, inner join with user_status table and return id and name
router.get('/user/status', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'delivery') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select user_status.id, user_status.name, user.location_id, user.client_id \
        from user \
        inner join user_status on user.user_status_id = user_status.id \
        where user.id = ?',
        [cabecera.id]
      );
      if (rows.length > 0) {
        if (rows[0].id === 3) { //verificar si no pasaron 8hs desde que se acualizo el status a 3 usando tabla delivery_log
          const [rows2] = await mysqlConnection.promise().query(
            'select * from delivery_log where user_id = ? and operation_id = 3 order by creation_date desc limit 1',
            [cabecera.id]
          );
          if (rows2.length > 0) {
            const fecha = new Date(rows2[0].creation_date);
            const fechaActual = new Date();
            const diff = fechaActual.getTime() - fecha.getTime();
            const hours = Math.floor(diff / (1000 * 60 * 60));
            // const minutes = Math.floor(diff / (1000 * 60));
            if (hours >= 8) { // si pasaron 8hs, modificar el campo offboarding_date del ultimo delivery_log con operation_id 3, actualizar status de user a 4 y su location_id a null
              const [rows3] = await mysqlConnection.promise().query(
                'update delivery_log set offboarding_date = now() where id = ?',
                [rows2[0].id]
              );
              const [rows4] = await mysqlConnection.promise().query(
                'update user set user_status_id = 4, location_id = null where id = ?',
                [cabecera.id]
              );
              return res.json({ id: 4, name: 'Off boarded', location_id: null, client_id: rows[0].client_id });
            } else {
              return res.json(rows[0]);
            }
          } else {
            return res.json(rows[0]);
          }
        } else {
          return res.json(rows[0]);
        }
      } else {
        return res.json({ id: null, name: null, location_id: null, client_id: null });
      }

    } catch (err) {
      console.log(err);
      return res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'beneficiary') {
      try {
        const [rows] = await mysqlConnection.promise().query(
          'select user_status.id, user_status.name, user.location_id, user.client_id \
          from user \
          inner join user_status on user.user_status_id = user_status.id \
          where user.id = ?',
          [cabecera.id]
        );
        if (rows.length > 0) {
          if (rows[0].id === 3) { //verificar si no pasaron 8hs desde que se acualizo el status a 3 usando su ultimo registor en la tabla delivery_beneficiary
            const [rows2] = await mysqlConnection.promise().query(
              'select * from delivery_beneficiary where receiving_user_id = ? order by creation_date desc limit 1',
              [cabecera.id]
            );
            if (rows2.length > 0) {
              const fecha = new Date(rows2[0].creation_date);
              const fechaActual = new Date();
              const diff = fechaActual.getTime() - fecha.getTime();
              const hours = Math.floor(diff / (1000 * 60 * 60));
              // const minutes = Math.floor(diff / (1000 * 60));
              if (hours >= 8) { // si pasaron 8hs, actualizar status de user a 4
                const [rows3] = await mysqlConnection.promise().query(
                  'insert into beneficiary_log(user_id, operation_id, location_id) values(?,?,?)',
                  [cabecera.id, 4, rows[0].location_id]
                );
                const [rows4] = await mysqlConnection.promise().query(
                  'update user set user_status_id = 4 where id = ?',
                  [cabecera.id]
                );
                return res.json({ id: 4, name: 'Off boarded', location_id: rows[0].location_id, client_id: rows[0].client_id });
              } else {
                return res.json(rows[0]);
              }
            } else {
              return res.json(rows[0]);
            }
          } else {
            return res.json(rows[0]);
          }
        } else {
          return res.json({ id: null, name: null, location_id: null, client_id: null });
        }
      } catch (err) {
        console.log(err);
        return res.status(500).json('Internal server error');
      }

    } else {
      return res.status(401).json('Unauthorized');
    }
  }
});

router.get('/user/location', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'delivery' || cabecera.role === 'beneficiary') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        'select location.id, location.organization, location.community_city, location.address \
        from user \
        inner join location on user.location_id = location.id \
        where user.id = ?',
        [cabecera.id]
      );
      if (rows.length > 0) {
        res.json(rows[0]);
      } else {
        res.json({ id: null, organization: null, community_city: null, address: null });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/userName/exists/search', async (req, res) => {
  const username = req.query.username || null;
  try {
    if (username) {
      const [rows] = await mysqlConnection.promise().query('select username from user where username = ?', [username]);
      if (rows.length > 0) {
        res.json(true);
      } else {
        res.json(false);
      }
    } else {
      res.json(false);
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/phone/exists/search', async (req, res) => {
  const phone = req.query.phone || null;
  try {
    if (phone) {
      const [rows] = await mysqlConnection.promise().query('select id, \
                                                            firstname, \
                                                            lastname, \
                                                            DATE_FORMAT(CONVERT_TZ(creation_date, "+00:00", "America/Los_Angeles"), "%m/%d/%Y") AS creation_date \
                                                            from user where phone = ? AND enabled = "Y" AND role_id = 5 \
                                                            order by id desc', [phone]);
      if (rows.length > 0) {
        res.json(rows);
      } else {
        res.json([]);
      }
    } else {
      res.json([]);
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/email/exists/search', async (req, res) => {
  const email = req.query.email || null;
  try {
    if (email) {
      const [rows] = await mysqlConnection.promise().query('select email from user where email = ?', [email]);
      if (rows.length > 0) {
        res.json(true);
      } else {
        res.json(false);
      }
    } else {
      res.json(false);
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/donation_id/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const donation_id = req.query.donation_id || null;
  try {
    if (cabecera.role === 'admin' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
      if (donation_id) {
        const [rows] = await mysqlConnection.promise().query('select donation_id from donation_ticket where donation_id = ? AND enabled = "Y"', [donation_id]);
        if (rows.length > 0) {
          res.json(true);
        } else {
          res.json(false);
        }
      } else {
        res.json(false);
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/product/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const name = req.query.name || null;
  try {
    if (cabecera.role === 'admin' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
      if (name) {
        const [rows] = await mysqlConnection.promise().query('select name from product where REPLACE(LOWER(name), " ", "") = REPLACE(LOWER(?), " ", "")', [name]);
        if (rows.length > 0) {
          res.json(true);
        } else {
          res.json(false);
        }
      } else {
        res.json(false);
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/product-type/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const name = req.query.name || null;
  try {
    if (cabecera.role === 'admin' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
      if (name) {
        const [rows] = await mysqlConnection.promise().query('select name from product_type where REPLACE(LOWER(name), " ", "") = REPLACE(LOWER(?), " ", "")', [name]);
        if (rows.length > 0) {
          res.json(true);
        } else {
          res.json(false);
        }
      } else {
        res.json(false);
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/delivered-by/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const name = req.query.name || null;
  try {
    if (cabecera.role === 'admin') {
      if (name) {
        const [rows] = await mysqlConnection.promise().query('select name from delivered_by where REPLACE(LOWER(name), " ", "") = REPLACE(LOWER(?), " ", "")', [name]);
        if (rows.length > 0) {
          res.json(true);
        } else {
          res.json(false);
        }
      } else {
        res.json(false);
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/transported-by/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const name = req.query.name || null;
  try {
    if (cabecera.role === 'admin') {
      if (name) {
        const [rows] = await mysqlConnection.promise().query('select name from transported_by where REPLACE(LOWER(name), " ", "") = REPLACE(LOWER(?), " ", "")', [name]);
        if (rows.length > 0) {
          res.json(true);
        } else {
          res.json(false);
        }
      } else {
        res.json(false);
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/gender/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const name = req.query.name || null;
  try {
    if (cabecera.role === 'admin') {
      if (name) {
        const [rows] = await mysqlConnection.promise().query('select name from gender where REPLACE(LOWER(name), " ", "") = REPLACE(LOWER(?), " ", "")', [name]);
        if (rows.length > 0) {
          res.json(true);
        } else {
          res.json(false);
        }
      } else {
        res.json(false);
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/ethnicity/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const name = req.query.name || null;
  try {
    if (cabecera.role === 'admin') {
      if (name) {
        const [rows] = await mysqlConnection.promise().query('select name from ethnicity where REPLACE(LOWER(name), " ", "") = REPLACE(LOWER(?), " ", "")', [name]);
        if (rows.length > 0) {
          res.json(true);
        } else {
          res.json(false);
        }
      } else {
        res.json(false);
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/provider/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const name = req.query.name || null;
  try {
    if (cabecera.role === 'admin' || cabecera.role === 'stocker' || cabecera.role === 'opsmanager' || cabecera.role === 'auditor') {
      if (name) {
        const [rows] = await mysqlConnection.promise().query('select name from provider where REPLACE(LOWER(name), " ", "") = REPLACE(LOWER(?), " ", "")', [name]);
        if (rows.length > 0) {
          res.json(true);
        } else {
          res.json(false);
        }
      } else {
        res.json(false);
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/client/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const name = req.query.name || null;
  const short_name = req.query.short_name || null;
  try {
    if (cabecera.role === 'admin') {
      let nameExists = false;
      let shortNameExists = false;

      if (name) {
        const [rows] = await mysqlConnection.promise().query('select name from client where REPLACE(LOWER(name), " ", "") = REPLACE(LOWER(?), " ", "")', [name]);
        if (rows.length > 0) {
          nameExists = true;
        }
      }

      if (short_name) {
        const [rows] = await mysqlConnection.promise().query('select short_name from client where REPLACE(LOWER(short_name), " ", "") = REPLACE(LOWER(?), " ", "")', [short_name]);
        if (rows.length > 0) {
          shortNameExists = true;
        }
      }
      res.json({ name: nameExists, short_name: shortNameExists });
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.get('/location/exists/search', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const community_city = req.query.community_city || null;
  try {
    if (cabecera.role === 'admin' || cabecera.role === 'opsmanager') {
      if (community_city) {
        const [rows] = await mysqlConnection.promise().query('select community_city from location where REPLACE(LOWER(community_city), " ", "") = REPLACE(LOWER(?), " ", "")', [community_city]);
        if (rows.length > 0) {
          res.json(true);
        } else {
          res.json(false);
        }
      } else {
        res.json(false);
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  } catch (err) {
    console.log(err);
    res.status(500).json('Internal server error');
  }
});

router.post('/survey/question', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    const connection = await mysqlConnection.promise().getConnection();
    try {
      const { name, name_es, depends_on_question_id, depends_on_answer_id, answer_type_id, answers, locations } = req.body;

      // si depends_on_question_id tiene valor, entonces depends_on_answer_id debe tener valor
      if (depends_on_question_id && !depends_on_answer_id) {
        throw new Error('depends_on_answer_id is required when depends_on_question_id is provided');
      }

      await connection.beginTransaction();

      // Insertar la pregunta
      const [rows] = await connection.query(
        'insert into question(name, name_es, depends_on_question_id, depends_on_answer_id, answer_type_id) values(?,?,?,?,?)',
        [name, name_es, depends_on_question_id, depends_on_answer_id, answer_type_id]
      );
      if (rows.affectedRows === 0) {
        throw new Error('Could not insert question');
      }
      const question_id = rows.insertId;

      // Si answer_type_id es 3 o 4, insertar las respuestas
      if (answer_type_id === 3 || answer_type_id === 4) {
        for (let answer of answers) {
          const [rows] = await connection.query(
            'insert into answer(question_id, id, name, name_es) values(?,?,?,?)',
            [question_id, answer.id, answer.name, answer.name_es]
          );
          if (rows.affectedRows === 0) {
            throw new Error('Could not insert answer');
          }
        }
      }

      // insertar las ubicaciones (si hay) y agregarlas a todas las preguntas padres
      if (locations && locations.length > 0) {

        // si hay valor de 0 en el array de locations, quitarlo
        const index = locations.indexOf(0);
        if (index > -1) {
          locations.splice(index, 1);
        }

        await addLocationsToQuestionAndParent(connection, question_id, locations);
      }

      await connection.commit();

      // devolver question_id como id
      res.json({ id: question_id });
    } catch (err) {
      if (connection) {
        await connection.rollback();
      }
      console.log(err);
      res.status(500).json('Internal server error');
    } finally {
      if (connection) {
        connection.release();
      }
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

async function addLocationsToQuestionAndParent(connection, question_id, locations) {
  // Obtener las ubicaciones existentes para la pregunta actual
  const [existingLocations] = await connection.query(
    'select location_id from question_location where question_id = ?',
    [question_id]
  );
  const existingLocationIds = existingLocations.map(row => row.location_id);

  // Agregar las ubicaciones a la pregunta actual, omitiendo las que ya existen
  for (let location_id of locations) {
    if (!existingLocationIds.includes(location_id)) {
      const [rows] = await connection.query(
        'insert into question_location(question_id, location_id) values(?,?)',
        [question_id, location_id]
      );
      if (rows.affectedRows === 0) {
        throw new Error('Could not insert location');
      }
    }
  }

  // Buscar la pregunta padre
  const [rows] = await connection.query(
    'select depends_on_question_id from question where id = ?',
    [question_id]
  );
  const parentQuestionId = rows[0]?.depends_on_question_id;

  // Si existe una pregunta padre, agregar las ubicaciones a la pregunta padre
  if (parentQuestionId) {
    await addLocationsToQuestionAndParent(connection, parentQuestionId, locations);
  }
}

router.post('/survey/location', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    const connection = await mysqlConnection.promise().getConnection();
    try {
      const { question_id, locations } = req.body;

      // si question_id y locations tienen valor
      if (!question_id || !locations) {
        throw new Error('Missing question_id or locations');
      }

      // si hay valor de 0 en el array de locations, quitarlo
      const index = locations.indexOf(0);
      if (index > -1) {
        locations.splice(index, 1);
      }

      await connection.beginTransaction();

      // Agregar las ubicaciones a la pregunta y a todas sus preguntas padres
      await addLocationsToQuestionAndParent(connection, question_id, locations);

      await connection.commit();
      res.json('Locations inserted');
    } catch (err) {
      if (connection) {
        await connection.rollback();
      }
      console.log(err);
      res.status(500).json('Internal server error');
    } finally {
      if (connection) {
        connection.release();
      }
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.post('/survey/answer', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    const connection = await mysqlConnection.promise().getConnection();
    try {
      const { question_id, answers } = req.body;

      // si question_id y answers tienen valor
      if (!question_id || !answers) {
        throw new Error('Missing question_id or answers');
      }

      await connection.beginTransaction();

      // El array de answers tiene id, name y name_es, agregar a la tabla answer
      for (let answer of answers) {
        const [rows] = await connection.query(
          'insert into answer(question_id, id, name, name_es) values(?,?,?,?)',
          [question_id, answer.id, answer.name, answer.name_es]
        );
        if (rows.affectedRows === 0) {
          throw new Error('Could not insert answer');
        }
      }

      await connection.commit();
      res.json('Answers inserted');
    } catch (err) {
      if (connection) {
        await connection.rollback();
      }
      console.log(err);
      res.status(500).json('Internal server error');
    } finally {
      if (connection) {
        connection.release();
      }
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

async function disableQuestions(connection, question_id, enabled, answer_id = null) {

  var rows = null;
  if (!answer_id) {
    // Desactivar la pregunta
    [rows] = await connection.query(
      'update question set enabled = ? where id = ?',
      [enabled, question_id]
    );
  }
  if ((rows && rows.affectedRows > 0) || answer_id) {
    // Buscar todas las preguntas que dependen de esta pregunta y, opcionalmente, de una respuesta específica
    const [dependentQuestions] = await connection.query(
      'select id from question where depends_on_question_id = ?' + (answer_id ? ' and depends_on_answer_id = ?' : ''),
      [question_id, answer_id].filter(Boolean)
    );

    // Desactivar todas las preguntas dependientes
    for (let question of dependentQuestions) {
      await disableQuestions(connection, question.id, enabled);
    }
  } else {
    throw new Error('Could not update question');
  }
}

router.post('/survey/modify-checkbox', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    const connection = await mysqlConnection.promise().getConnection();
    try {
      const { question_id, answer_id, location_id, enabled } = req.body;

      await connection.beginTransaction();

      // modificar answer
      if (answer_id) {
        const [rows] = await connection.query(
          'update answer set enabled = ? where id = ? and question_id = ?',
          [enabled, answer_id, question_id]
        );
        if (rows.affectedRows > 0) {
          // tambien modificar las question que dependen de esta respuesta
          await disableQuestions(connection, question_id, enabled, answer_id);
          await connection.commit();
          res.json('Answer updated');
        } else {
          await connection.rollback();
          res.status(500).json('Could not update answer');
        }
      } else {
        // modificar question_location
        if (location_id) {
          const [rows] = await connection.query(
            'update question_location set enabled = ? where question_id = ? and location_id = ?',
            [enabled, question_id, location_id]
          );
          if (rows.affectedRows > 0) {
            await connection.commit();
            res.json('Location updated');
          } else {
            await connection.rollback();
            res.status(500).json('Could not update location');
          }
        } else {
          // modificar question y las question que dependen de esta pregunta
          await disableQuestions(connection, question_id, enabled);
          await connection.commit();
          res.json('Question updated');
        }
      }
    } catch (err) {
      if (connection) {
        await connection.rollback();
      }
      console.log(err);
      res.status(500).json('Internal server error');
    } finally {
      if (connection) {
        connection.release();
      }
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/survey/questions', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const language = req.query.language || 'en';

  if (cabecera.role === 'admin') {
    try {
      // get all questions and answers from table question and answer, if language === 'es' then get name_es, else get name
      const query = `SELECT q.id as question_id, 
                  q.name AS question_name, 
                  q.name_es AS question_name_es, 
                  q.answer_type_id,
                  ${language === 'en' ? 'at.name' : 'at.name_es'}  AS answer_type_name,
                  q.depends_on_question_id,
                  q.depends_on_answer_id,
                  q.enabled as question_enabled,
                  a.id as answer_id, 
                  a.name AS answer_name,
                  a.name_es AS answer_name_es,
                  a.enabled as answer_enabled,
                  l.id as location_id, 
                  l.community_city AS location_name,
                  ql.enabled as question_location_enabled
                  FROM question as q
                  INNER JOIN answer_type as at ON q.answer_type_id = at.id
                  LEFT JOIN answer as a ON q.id = a.question_id
                  LEFT JOIN question_location as ql ON q.id = ql.question_id
                  LEFT JOIN location as l ON ql.location_id = l.id
                  ORDER BY q.id, a.id, ql.location_id ASC`;
      const [rows] = await mysqlConnection.promise().query(query);
      var questions = [];
      var question_id = 0;
      var answer_id = 0;
      var stop_save_locations = false;
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (row.question_id !== question_id) {
          questions.push({
            id: row.question_id,
            name: row.question_name,
            name_es: row.question_name_es,
            depends_on_question_id: row.depends_on_question_id,
            depends_on_answer_id: row.depends_on_answer_id,
            answer_type_id: row.answer_type_id,
            answer_type: row.answer_type_name,
            enabled: row.question_enabled,
            loading: 'N',
            answers: [],
            locations: []
          });
          question_id = row.question_id;
          stop_save_locations = false;
          answer_id = 0;
          location_id = 0;
        }
        if (row.answer_id && row.answer_id !== answer_id) {
          questions[questions.length - 1].answers.push({
            question_id: row.question_id,
            id: row.answer_id,
            name: row.answer_name,
            name_es: row.answer_name_es,
            enabled: row.answer_enabled,
            loading: 'N',
          });
          answer_id = row.answer_id;
          // si no es la primera respuesta, se debe evitar que se guarden las locaciones hasta que cambie de pregunta
          if (questions[questions.length - 1].answers.length > 1) {
            stop_save_locations = true;
          } else {
            stop_save_locations = false;
          }
        }
        if (row.location_id && row.location_id !== location_id && !stop_save_locations) {
          questions[questions.length - 1].locations.push({
            question_id: row.question_id,
            id: row.location_id,
            name: row.location_name,
            enabled: row.question_location_enabled,
            loading: 'N',
          });
          location_id = row.location_id;
        }

      }

      res.json(questions);

    } catch (error) {
      console.log(error);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/onBoard/questions', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'beneficiary') {
    const language = req.query.language || 'en';
    const location_id = req.query.location_id || null;
    try {
      const query = `
      WITH RECURSIVE answered_or_dependent_questions AS (
        SELECT question_id FROM user_question WHERE user_id = ${cabecera.id}
        UNION ALL
        SELECT q.id FROM question q INNER JOIN answered_or_dependent_questions adq ON q.depends_on_question_id = adq.question_id
      )
      SELECT q.id as question_id, 
        ${language === 'en' ? 'q.name' : 'q.name_es'} AS question_name, 
        q.answer_type_id,
        q.depends_on_question_id,
        q.depends_on_answer_id,
        a.id as answer_id, 
        ${language === 'en' ? 'a.name' : 'a.name_es'} AS answer_name
      FROM question as q
      INNER JOIN question_location as ql ON q.id = ql.question_id
      LEFT JOIN answer as a ON q.id = a.question_id
      WHERE q.enabled = 'Y' AND (a.enabled = 'Y' OR a.id IS NULL) AND (ql.location_id = ? AND ql.enabled = 'Y')
      AND q.id NOT IN (SELECT question_id FROM answered_or_dependent_questions)
      ORDER BY q.id, a.id ASC`;

      const [rows] = await mysqlConnection.promise().query(query, [location_id]);
      var questions = [];
      var question_id = 0;
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (row.question_id !== question_id) {
          questions.push({
            id: row.question_id,
            name: row.question_name,
            depends_on_question_id: row.depends_on_question_id,
            depends_on_answer_id: row.depends_on_answer_id,
            answer_type_id: row.answer_type_id,
            answers: []
          });
          question_id = row.question_id;
        }
        if (row.answer_id) {
          questions[questions.length - 1].answers.push({
            question_id: row.question_id,
            id: row.answer_id,
            name: row.answer_name
          });
        }
      }

      res.json(questions);

    } catch (error) {
      console.log(error);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/register/questions', verifyTokenOptional, async (req, res) => {
  const cabecera = req.data ? JSON.parse(req.data.data) : null;
  const language = req.query.language || 'en';
  let location_id = req.query.location_id || null;
  if (location_id === 'null' || location_id === 'undefined') {
    location_id = null;
  }
  var client_questions = '';
  if (cabecera && cabecera.role === 'client') {
    client_questions = `AND EXISTS (SELECT 1 \
                                    FROM question_location ql \
                                    INNER JOIN client_location cl ON ql.location_id = cl.location_id \
                                    WHERE ql.question_id = q.id AND cl.client_id = ${cabecera.client_id})`;
  }
  try {
    // get all questions and answers from table question and answer, if language === 'es' then get name_es, else get name
    const query = `SELECT q.id as question_id, 
                  ${language === 'en' ? 'q.name' : 'q.name_es'} AS question_name, 
                  q.answer_type_id,
                  q.depends_on_question_id,
                  q.depends_on_answer_id,
                  a.id as answer_id, 
                  ${language === 'en' ? 'a.name' : 'a.name_es'} AS answer_name
                  FROM question as q
                  ${location_id ? 'INNER JOIN question_location as ql ON q.id = ql.question_id' : ''}
                  LEFT JOIN answer as a ON q.id = a.question_id
                  WHERE q.enabled = 'Y' AND (a.enabled = 'Y' OR a.id IS NULL) 
                  ${location_id ? 'AND (ql.location_id = ? AND ql.enabled = \'Y\')' : 'AND q.answer_type_id IN (3, 4)'}
                  ${client_questions}
                  ORDER BY q.id, a.id ASC`;
    const [rows] = await mysqlConnection.promise().query(query, [location_id]);
    var questions = [];
    var question_id = 0;
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (row.question_id !== question_id) {
        questions.push({
          id: row.question_id,
          name: row.question_name,
          depends_on_question_id: row.depends_on_question_id,
          depends_on_answer_id: row.depends_on_answer_id,
          answer_type_id: row.answer_type_id,
          answers: []
        });
        question_id = row.question_id;
      }
      if (row.answer_id) {
        questions[questions.length - 1].answers.push({
          question_id: row.question_id,
          id: row.answer_id,
          name: row.answer_name
        });
      }
    }

    res.json(questions);

  } catch (error) {
    console.log(error);
    res.status(500).json('Internal server error');
  }
});

router.get('/gender', async (req, res) => {
  const id = req.query.id || null;
  const language = req.query.language || 'en';
  try {
    const query = `SELECT id, ${language === 'en' ? 'name' : 'name_es'} AS name 
                  FROM gender 
                  WHERE enabled = 'Y'
                  ${id ? ' AND id = ?' : ''} 
                  ORDER BY name`;
    const params = id ? [id] : [];
    const [rows] = await mysqlConnection.promise().query(query, params);
    res.json(rows);
  } catch (error) {
    console.log(error);
    res.status(500).json('Internal server error');
  }
});

router.get('/ethnicity', async (req, res) => {
  const id = req.query.id || null;
  const language = req.query.language || 'en';
  try {
    const query = `SELECT id, ${language === 'en' ? 'name' : 'name_es'} AS name 
                  FROM ethnicity 
                  WHERE enabled = 'Y'
                  ${id ? ' AND id = ?' : ''} 
                  ORDER BY name`;
    const params = id ? [id] : [];
    const [rows] = await mysqlConnection.promise().query(query, params);
    res.json(rows);
  } catch (error) {
    console.log(error);
    res.status(500).json('Internal server error');
  }
});

router.get('/pounds-delivered', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      // sum total_weight from donation_ticket
      const [rows] = await mysqlConnection.promise().query(
        `select sum(total_weight) as pounds_delivered 
        from donation_ticket
        where enabled = 'Y'`
      );
      if (rows[0].pounds_delivered === null) {
        rows[0].pounds_delivered = 0;
      }
      res.json(rows[0].pounds_delivered);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      try {
        const [rows] = await mysqlConnection.promise().query(
          `select sum(dt.total_weight) as pounds_delivered 
          from donation_ticket as dt
          inner join client_location as cl on dt.location_id = cl.location_id
          where cl.client_id = ? AND dt.enabled = 'Y'`,
          [cabecera.client_id]
        );
        if (rows[0].pounds_delivered === null) {
          rows[0].pounds_delivered = 0;
        }
        res.json(rows[0].pounds_delivered);
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }

    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

router.get('/total-locations', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        `select count(id) as total_locations 
        from location
        `
      );
      res.json(rows[0].total_locations);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      try {
        const [rows] = await mysqlConnection.promise().query(
          `select count(l.id) as total_locations 
          from location as l
          inner join client_location as cl on l.id = cl.location_id
          where cl.client_id = ?`,
          [cabecera.client_id]
        );
        res.json(rows[0].total_locations);
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

router.get('/total-days-operation', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      // count distinct days from field creation_date in table delivery_beneficiary, if cabecera.role === 'client' then sum only days from client_id (cabecera.client_id)
      const [rows] = await mysqlConnection.promise().query(
        `select count(distinct date(creation_date)) as total_days_operation 
        from delivery_beneficiary
        where approved = 'Y' 
        ${cabecera.role === 'client' ? 'AND client_id = ?' : ''}`,
        [cabecera.client_id]
      );
      res.json(rows[0].total_days_operation);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/house-hold-size-average', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {

      const [rows] = await mysqlConnection.promise().query(
        `SELECT AVG(u.household_size) AS house_hold_size_average
        FROM user u
        ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
        WHERE u.enabled = 'Y' AND u.role_id = 5 
        ${cabecera.role === 'client' ? 'AND cu.client_id = ?' : ''}`,
        [cabecera.client_id]
      );
      if (rows[0].house_hold_size_average === null) {
        rows[0].house_hold_size_average = 0;
      }
      res.json(rows[0].house_hold_size_average);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/total-from-role/:role', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      const { role } = req.params;
      if (role === 'beneficiary' || role === 'stocker' || role === 'delivery') {
        // count users with role in table user inner join role
        const [rows] = await mysqlConnection.promise().query(
          `select count(user.id) as total 
          from user
          inner join role on user.role_id = role.id
          where role.name = ?`,
          [role]
        );
        res.json(rows[0].total);
      } else {
        res.status(400).json('Bad request');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      try {
        const { role } = req.params;
        if (role === 'beneficiary') {
          // cuenta los beneficiarios que tienen el client_id en la tabla client_user
          const [rows] = await mysqlConnection.promise().query(
            `SELECT COUNT(DISTINCT(u.id)) AS total
             FROM client_user as cu
             INNER JOIN user as u ON cu.user_id = u.id
              WHERE u.role_id = 5 AND cu.client_id = ?`,
            [cabecera.client_id]
          );
          res.json(rows[0].total);
        } else {
          res.status(400).json('Bad request');
        }
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

router.get('/total-beneficiaries-served', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      // get percentage of users with role 'beneficiary' that are approved in table 'delivery_beneficiary' compared to the total of beneficiaries in table user
      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
          COUNT(DISTINCT user.id) AS total_beneficiaries_served,
          (SELECT COUNT(DISTINCT(user.id)) FROM user WHERE role_id = 5 and enabled = 'Y') AS total_beneficiaries
        FROM user
        INNER JOIN delivery_beneficiary ON user.id = delivery_beneficiary.receiving_user_id
        WHERE user.role_id = 5 AND user.enabled = 'Y' AND delivery_beneficiary.approved = 'Y'`
      );
      const totalBeneficiariesServed = rows[0].total_beneficiaries_served;
      const totalBeneficiaries = rows[0].total_beneficiaries;
      const percentage = (totalBeneficiariesServed / totalBeneficiaries * 100).toFixed(2);
      if (isNaN(percentage)) {
        res.json(0);
      } else {
        res.json(percentage);
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      // get percentage of users with role 'beneficiary' that are approved in table 'delivery_beneficiary' using field client_id and compared to the total of beneficiaries in table client_user with client_id
      try {
        const [rows] = await mysqlConnection.promise().query(
          `SELECT 
            COUNT(DISTINCT u.id) AS total_beneficiaries_served,
            (SELECT COUNT(DISTINCT(u.id)) 
            FROM user as u
            INNER JOIN client_user as cu ON u.id = cu.user_id
            WHERE u.role_id = 5 and u.enabled = 'Y' and cu.client_id = ?) AS total_beneficiaries
          FROM user AS u
          INNER JOIN delivery_beneficiary AS db ON u.id = db.receiving_user_id
          WHERE u.role_id = 5 AND u.enabled = 'Y' AND db.approved = 'Y' AND db.client_id = ?`,
          [cabecera.client_id, cabecera.client_id]
        );
        const totalBeneficiariesServed = rows[0].total_beneficiaries_served;
        const totalBeneficiaries = rows[0].total_beneficiaries;
        const percentage = (totalBeneficiariesServed / totalBeneficiaries * 100).toFixed(2);
        if (isNaN(percentage)) {
          res.json(0);
        } else {
          res.json(percentage);
        }
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }

    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

router.get('/total-beneficiaries-without-health-insurance', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    // contar los beneficiarios que en la tabla user_question tengan question_id = 1 y en la tabla user_question_answer tengan answer_id = 2
    // finalmente devolver el porcentaje de beneficiarios que no tienen seguro de salud sobre el total de beneficiarios
    try {
      const [rows] = await mysqlConnection.promise().query(
        `SELECT
          COUNT(DISTINCT user.id) AS total_beneficiaries_without_health_insurance,
          (SELECT COUNT(DISTINCT(user.id)) FROM user WHERE role_id = 5 and enabled = 'Y') AS total_beneficiaries
        FROM user
        INNER JOIN user_question ON user.id = user_question.user_id
        INNER JOIN user_question_answer ON user_question.id = user_question_answer.user_question_id
        WHERE user.role_id = 5 AND user.enabled = 'Y' AND user_question.question_id = 1 AND user_question_answer.answer_id = 2`
      );
      const totalBeneficiariesWithoutHealthInsurance = rows[0].total_beneficiaries_without_health_insurance;
      const totalBeneficiaries = rows[0].total_beneficiaries;
      const percentage = (totalBeneficiariesWithoutHealthInsurance / totalBeneficiaries * 100).toFixed(2);
      if (isNaN(percentage)) {
        res.json(0);
      } else {
        res.json(percentage);
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      // contar los beneficiarios que en la tabla user_question tengan question_id = 1 y en la tabla user_question_answer tengan answer_id = 2
      // finalmente devolver el porcentaje de beneficiarios que no tienen seguro de salud sobre el total de beneficiarios
      try {
        const [rows] = await mysqlConnection.promise().query(
          `SELECT
            COUNT(DISTINCT u.id) AS total_beneficiaries_without_health_insurance,
            (SELECT COUNT(DISTINCT(u.id)) 
              FROM user as u
              INNER JOIN client_user as cu ON u.id = cu.user_id
              INNER JOIN user_question AS uq ON u.id = uq.user_id 
              WHERE u.role_id = 5 and u.enabled = 'Y' and cu.client_id = ?) AS total_beneficiaries
          FROM user AS u
          INNER JOIN client_user AS cu ON u.id = cu.user_id
          INNER JOIN user_question AS uq ON u.id = uq.user_id
          INNER JOIN user_question_answer AS uqa ON uq.id = uqa.user_question_id
          WHERE u.role_id = 5 AND u.enabled = 'Y' AND uq.question_id = 1 AND uqa.answer_id = 2 AND cu.client_id = ?`,
          [cabecera.client_id, cabecera.client_id]
        );
        const totalBeneficiariesWithoutHealthInsurance = rows[0].total_beneficiaries_without_health_insurance;
        const totalBeneficiaries = rows[0].total_beneficiaries;
        const percentage = (totalBeneficiariesWithoutHealthInsurance / totalBeneficiaries * 100).toFixed(2);
        if (isNaN(percentage)) {
          res.json(0);
        } else {
          res.json(percentage);
        }
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});


router.get('/total-beneficiaries-registered-today', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        `select count(user.id) as total 
        from user
        where user.role_id = 5 
        and date(CONVERT_TZ(user.creation_date, '+00:00', 'America/Los_Angeles')) = date(CONVERT_TZ(now(), '+00:00', 'America/Los_Angeles')) 
        ${cabecera.role === 'client' ? 'and user.client_id = ?' : ''}`,
        [cabecera.client_id]
      );
      res.json(rows[0].total);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/total-beneficiaries-recurring-today-scanned', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      // beneficiarios que ya estaban registrados en una fecha distinta a la de hoy y que aparecieron en delivery_beneficiary en la fecha de hoy
      const [rows] = await mysqlConnection.promise().query(
        `select count(distinct user.id) as total
          from user
          inner join delivery_beneficiary as db on user.id = db.receiving_user_id
          where user.role_id = 5 
          and date(CONVERT_TZ(user.creation_date, '+00:00', 'America/Los_Angeles')) != date(CONVERT_TZ(now(), '+00:00', 'America/Los_Angeles')) 
          and date(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')) = date(CONVERT_TZ(now(), '+00:00', 'America/Los_Angeles'))
          and db.approved = 'Y'
          ${cabecera.role === 'client' ? 'and db.client_id = ?' : ''}`,
        [cabecera.client_id]
      );
      res.json(rows[0].total);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/total-beneficiaries-recurring-today-not-scanned', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      // beneficiarios que ya estaban registrados en una fecha distinta a la de hoy y que aparecieron en delivery_beneficiary en la fecha de hoy
      const [rows] = await mysqlConnection.promise().query(
        `select count(distinct user.id) as total
          from user
          inner join delivery_beneficiary as db on user.id = db.receiving_user_id
          where user.role_id = 5 
          and date(CONVERT_TZ(user.creation_date, '+00:00', 'America/Los_Angeles')) != date(CONVERT_TZ(now(), '+00:00', 'America/Los_Angeles')) 
          and date(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')) = date(CONVERT_TZ(now(), '+00:00', 'America/Los_Angeles')) 
          and db.approved = 'N'
          ${cabecera.role === 'client' ? 'and db.client_id = ?' : ''}`,
        [cabecera.client_id]
      );
      res.json(rows[0].total);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});
/*
para que el beneficiario (user.role = 5) sea considerado como beneficiario calificado debe cumplir con los siguientes requisitos:
1. haber respondido todas las preguntas de la encuesta de su client_id que tengan el campo enabled = 'Y' (cruce de tablas user, user_question, question)
2. si la pregunta en la tabla question tiene el campo recurrent = 'Y' entonces el campo creation_date de la tabla user_question debe ser mayor al campo begin_date de la pregunta en la tabla question
*/
// TO-DO
router.get('/total-beneficiaries-qualified', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        `SELECT
          COUNT(DISTINCT user.id) AS total_beneficiaries_qualified
        FROM user
        WHERE user.role_id = 5`
      );
      res.json(rows[0].total_beneficiaries_qualified);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      try {
        // TO-DO por ahora cuenta todos
        const [rows] = await mysqlConnection.promise().query(
          `SELECT COUNT(DISTINCT(user_id)) AS total_beneficiaries_qualified
          FROM client_user
          WHERE client_id = ?`,
          [cabecera.client_id]
        );
        res.json(rows[0].total_beneficiaries_qualified);
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

router.get('/total-clients', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        `SELECT
          COUNT(DISTINCT user.id) AS total_clients
        FROM user
        WHERE user.role_id = 2`
      );
      res.json(rows[0].total_clients);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/total-enabled-users', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        `SELECT
          COUNT(DISTINCT user.id) AS total_enabled_users
        FROM user
        WHERE user.enabled = 'Y'
        `
      );
      res.json(rows[0].total_enabled_users);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      try {
        const [rows] = await mysqlConnection.promise().query(
          `SELECT
            COUNT(DISTINCT u.id) AS total_enabled_users
            FROM user as u
            WHERE u.enabled = 'Y' AND u.client_id = ? AND u.role_id = 2`,
          [cabecera.client_id]
        );
        res.json(rows[0].total_enabled_users);
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

router.get('/total-tickets-uploaded', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        `SELECT
          COUNT(DISTINCT donation_ticket.id) AS total_tickets_uploaded
        FROM donation_ticket
        WHERE enabled = 'Y'`
      );
      res.json(rows[0].total_tickets_uploaded);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      try {
        const [rows] = await mysqlConnection.promise().query(
          `SELECT
            COUNT(DISTINCT dt.id) AS total_tickets_uploaded
            FROM donation_ticket as dt
            INNER JOIN client_location as cl ON dt.location_id = cl.location_id
            WHERE cl.client_id = ? AND dt.enabled = 'Y'`,
          [cabecera.client_id]
        );
        res.json(rows[0].total_tickets_uploaded);
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

router.get('/total-locations-enabled', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        `SELECT
          COUNT(DISTINCT location.id) AS total_locations_enabled
          FROM location
          WHERE location.enabled = 'Y'`
      );
      res.json(rows[0].total_locations_enabled);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      try {
        const [rows] = await mysqlConnection.promise().query(
          `SELECT
            COUNT(DISTINCT l.id) AS total_locations_enabled
            FROM location as l
            INNER JOIN client_location as cl ON l.id = cl.location_id
            WHERE l.enabled = 'Y' AND cl.client_id = ?`,
          [cabecera.client_id]
        );
        res.json(rows[0].total_locations_enabled);
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

router.get('/total-products-uploaded', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        `SELECT
            COUNT(DISTINCT product.id) AS total_products_uploaded
          FROM product`
      );
      res.json(rows[0].total_products_uploaded);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      try {
        const [rows] = await mysqlConnection.promise().query(
          `SELECT
            COUNT(DISTINCT p.id) AS total_products_uploaded
            FROM product as p
            INNER JOIN product_donation_ticket as pdt ON p.id = pdt.product_id
            INNER JOIN donation_ticket as dt ON pdt.donation_ticket_id = dt.id
            INNER JOIN client_location as cl ON dt.location_id = cl.location_id
            WHERE cl.client_id = ? AND dt.enabled = 'Y'`,
          [cabecera.client_id]
        );
        res.json(rows[0].total_products_uploaded);
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

router.get('/total-delivered', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const [rows] = await mysqlConnection.promise().query(
        `SELECT
            COUNT(db.id) AS total_delivered
          FROM delivery_beneficiary as db
          ${cabecera.role === 'client' ? 'WHERE db.client_id = ?' : ''}`,
        [cabecera.client_id]
      );
      res.json(rows[0].total_delivered);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/map/locations', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    try {
      let enabled = req.query.enabled ? req.query.enabled : null;
      let ids = req.query.ids ? req.query.ids.split(',') : [];
      let query = `SELECT
        ST_X(coordinates) as lng, 
        ST_Y(coordinates) as lat, 
        organization as label
        FROM location
        WHERE 1=1`;

      let params_maps = [];

      if (cabecera.role === 'client') {
        params_maps.push(cabecera.client_id);
        query = `SELECT
          ST_X(location.coordinates) as lng, 
          ST_Y(location.coordinates) as lat, 
          location.organization as label
          FROM location
          INNER JOIN client_location ON location.id = client_location.location_id
          WHERE client_location.client_id = ?`;
      }
      if (enabled) {
        params_maps.push(enabled);
        query += ' AND location.enabled = ?';
      }
      if (ids.length > 0) {
        let placeholders = new Array(ids.length).fill('?').join(',');
        query += ` AND location.id IN (${placeholders})`;
        for (let i = 0; i < ids.length; i++) {
          ids[i] = parseInt(ids[i]);
          params_maps.push(ids[i]);
        }
      }

      const [rows] = await mysqlConnection.promise().query(query, params_maps);
      const locations = rows.map(row => ({
        position: { lat: row.lat, lng: row.lng },
        label: row.label
      }));
      const center = locations.reduce((acc, curr) => ({
        lat: acc.lat + curr.position.lat,
        lng: acc.lng + curr.position.lng
      }), { lat: 0, lng: 0 });
      center.lat /= locations.length;
      center.lng /= locations.length;
      res.json({ center, locations });
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.get('/dashboard/graphic-line/:tabSelected', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'director') {
    try {
      const language = req.query.language || 'en';
      const { tabSelected } = req.params;
      let name = '';
      var rows = [];
      var series = [];
      var isTabSelectedCorrect = false;

      switch (tabSelected) {
        case 'pounds':
          name = 'Pounds delivered';
          if (language === 'es') {
            name = 'Libras entregadas';
          }
          [rows] = await mysqlConnection.promise().query(
            `SELECT
                SUM(total_weight) AS value,
                DATE_FORMAT(date, '%m/%Y') AS name
              FROM donation_ticket
              WHERE enabled = 'Y'
              GROUP BY YEAR(date), MONTH(date)
              ORDER BY date`
          );
          isTabSelectedCorrect = true;
          break;
        case 'locationsWorking':
          name = 'Locations working';
          if (language === 'es') {
            name = 'Ubicaciones trabajando';
          }
          [rows] = await mysqlConnection.promise().query(
            `SELECT
                COUNT(DISTINCT DATE(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')), location_id) AS value,
                DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%Y') AS name
              FROM delivery_beneficiary
              GROUP BY YEAR(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')), MONTH(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))
              ORDER BY CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')`
          );
          isTabSelectedCorrect = true;
          break;
        case 'operations':
          name = 'Days of operation';
          if (language === 'es') {
            name = 'Días de operación';
          }
          [rows] = await mysqlConnection.promise().query(
            `SELECT
                COUNT(DISTINCT DAY(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))) AS value,
                DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%Y') AS name
              FROM delivery_beneficiary
              GROUP BY YEAR(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')), MONTH(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))
              ORDER BY CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')`
          );
          isTabSelectedCorrect = true;
          break;
        case 'beneficiaries':
          name = 'Participants registered';
          if (language === 'es') {
            name = 'Participantes registrados';
          }
          [rows] = await mysqlConnection.promise().query(
            `SELECT
                COUNT(DISTINCT user.id) AS value,
                DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%Y') AS name
              FROM user
              WHERE user.role_id = 5
              GROUP BY YEAR(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')), MONTH(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))
              ORDER BY CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')`
          );
          isTabSelectedCorrect = true;
          break;
        default:
          res.status(400).json('Bad request');
          break;
      }
      if (isTabSelectedCorrect && rows.length > 0) {
        series = rows.map(row => ({
          value: row.value,
          name: row.name
        }));
      }
      res.json({ name, series });
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    if (cabecera.role === 'client') {
      try {
        const language = req.query.language || 'en';
        const { tabSelected } = req.params;
        let name = '';
        var rows = [];
        var series = [];
        var isTabSelectedCorrect = false;
        switch (tabSelected) {
          case 'pounds':
            name = 'Pounds delivered';
            if (language === 'es') {
              name = 'Libras entregadas';
            }
            [rows] = await mysqlConnection.promise().query(
              `SELECT
                  SUM(dt.total_weight) AS value,
                  DATE_FORMAT(CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%Y') AS name
                FROM donation_ticket as dt
                INNER JOIN client_location as cl ON dt.location_id = cl.location_id
                WHERE cl.client_id = ? AND dt.enabled = 'Y'
                GROUP BY YEAR(CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles')), MONTH(CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles'))
                ORDER BY CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles')`,
              [cabecera.client_id]
            );
            isTabSelectedCorrect = true;
            break;
          case 'locationsWorking':
            name = 'Locations working';
            if (language === 'es') {
              name = 'Ubicaciones trabajando';
            }
            [rows] = await mysqlConnection.promise().query(
              `SELECT
                  COUNT(DISTINCT DATE(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')), location_id) AS value,
                  DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%Y') AS name
                FROM delivery_beneficiary
                WHERE client_id = ?
                GROUP BY YEAR(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')), MONTH(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))
                ORDER BY CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')`,
              [cabecera.client_id]
            );
            isTabSelectedCorrect = true;
            break;
          case 'operations':
            name = 'Days of operation';
            if (language === 'es') {
              name = 'Días de operación';
            }
            [rows] = await mysqlConnection.promise().query(
              `SELECT
                  COUNT(DISTINCT DAY(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))) AS value,
                  DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%Y') AS name
                FROM delivery_beneficiary
                WHERE client_id = ?
                GROUP BY YEAR(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')), MONTH(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))
                ORDER BY CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')`,
              [cabecera.client_id]
            );
            isTabSelectedCorrect = true;
            break;
          case 'beneficiaries':
            name = 'Participants with food';
            if (language === 'es') {
              name = 'Participantes con alimento';
            }
            [rows] = await mysqlConnection.promise().query(
              `SELECT
                  COUNT(DISTINCT delivery_beneficiary.receiving_user_id) AS value,
                  DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%Y') AS name
                FROM delivery_beneficiary
                WHERE client_id = ?
                GROUP BY YEAR(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')), MONTH(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))
                ORDER BY CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')`,
              [cabecera.client_id]
            );
            isTabSelectedCorrect = true;
            break;
          default:
            res.status(400).json('Bad request');
            break;
        }
        if (isTabSelectedCorrect && rows.length > 0) {
          series = rows.map(row => ({
            value: row.value,
            name: row.name
          }));
        }
        res.json({ name, series });
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(401).json('Unauthorized');
    }
  }
});

function formatPeriod(period, interval) {
  switch (interval) {
    case 'day':
      // period viene como 'YYYY-MM-DD'
      // Convertir a mm/dd/yyyy
      {
        const [year, month, day] = period.split('-');
        return `${month}/${day}/${year}`;
      }

    case 'month':
      // period viene como 'YYYY-MM'
      // Convertir a mm/yyyy
      {
        const [year, month] = period.split('-');
        return `${month}/${year}`;
      }

    case 'quarter':
      // period viene como 'YYYY-QX'
      // Convertir a QX/YYYY
      // Ej: "2024-Q1" -> "Q1/2024"
      {
        const [yearQuarter, q] = period.split('-Q');
        return `Q${q}/${yearQuarter}`;
      }

    case 'year':
      // period viene como 'YYYY'
      // Se queda igual 'YYYY'
      return period;

    case 'week':
      // period viene como 'YYYY-Wxx'
      // Debemos calcular el inicio de la semana. La semana ISO empieza el lunes.
      // year = YYYY, week = Wxx (xx = número de semana ISO)
      {
        const [yearPart, weekPart] = period.split('-W');
        const year = parseInt(yearPart, 10);
        const week = parseInt(weekPart, 10);
        // Calcular fecha del lunes de esa semana ISO
        // La semana ISO 1 es la que contiene el primer jueves de enero.
        // Para simplificar, usaremos la lógica existente: se creará una fecha a partir de year y (week-1)*7 días.
        const firstMonday = new Date(year, 0, (week - 1) * 7 + 1);
        // Ajuste al lunes: ISO week asume que el primer día es lunes. 
        // Según ISO, el jueves de la primera semana del año es entre 1 y 7 de enero.
        // Para mayor exactitud, calcularemos el lunes usando una técnica más elaborada:
        // Sin embargo, el código original que ordenaba semanas usaba algo similar. 
        // Tomaremos la misma aproximación usada en el código original de sort:
        // original: const dateA = new Date(year, 0, (weekA - 1) * 7);
        // Eso colocaría el domingo de la primera semana. Para lunes sumamos 1 día:
        // Hecho arriba ( +1 ).

        const mm = String(firstMonday.getMonth() + 1).padStart(2, '0');
        const dd = String(firstMonday.getDate()).padStart(2, '0');
        const yyyy = firstMonday.getFullYear();
        return `${mm}/${dd}/${yyyy}`;
      }

    default:
      return period;
  }
}


router.post('/dashboard/graphic-line/:tabSelected', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  const filters = req.body;
  let from_date = filters.from_date || null;
  let to_date = filters.to_date || null;
  const locations = filters.locations || [];
  const providers = filters.providers || [];
  const product_types = filters.product_types || [];
  const stocker_upload = filters.stocker_upload || [];
  const transported_by = filters.transported_by || [];
  const interval = filters.interval || 'month';

  // Convertir a formato ISO (fecha sin hora)
  if (filters.from_date) {
    from_date = new Date(filters.from_date).toISOString().slice(0, 10);
  }
  if (filters.to_date) {
    to_date = new Date(filters.to_date).toISOString().slice(0, 10);
  }

  // Obtener rango de fechas si no se proporcionan
  if (!from_date || !to_date) {
    const [dateRange] = await mysqlConnection.promise().query(
      `SELECT 
        MIN(date) AS min_date, 
        MAX(date) AS max_date 
      FROM donation_ticket 
      WHERE enabled = 'Y'`
    );
    if (!from_date) from_date = dateRange[0].min_date.toISOString().slice(0, 10);
    if (!to_date) to_date = dateRange[0].max_date.toISOString().slice(0, 10);
  }

  // Definir expresiones de período y intervalos de adición
  let dateAddInterval;
  let formatString;
  switch (interval) {
    case 'day':
      dateAddInterval = '1 DAY';
      formatString = '%Y-%m-%d';
      break;
    case 'week':
      dateAddInterval = '1 WEEK';
      formatString = '%x-W%v';
      break;
    case 'month':
      dateAddInterval = '1 MONTH';
      formatString = '%Y-%m';
      break;
    case 'quarter':
      // Para trimestres, usaremos un formato especial con YEAR- Q
      dateAddInterval = '1 QUARTER';
      // Notar: La generación del período para quarters se hará en el CTE
      break;
    case 'year':
      dateAddInterval = '1 YEAR';
      formatString = '%Y';
      break;
    default:
      dateAddInterval = '1 MONTH';
      formatString = '%Y-%m';
      break;
  }

  // Construir condiciones dinámicamente
  let query_from_date = '';
  let query_to_date = '';
  let query_locations = '';
  let query_providers = '';
  let query_product_types = '';
  const params = [];

  if (from_date) {
    query_from_date = 'AND dt.date >= ?';
    params.push(from_date);
  }
  if (to_date) {
    query_to_date = 'AND dt.date < DATE_ADD(?, INTERVAL 1 DAY)';
    params.push(to_date);
  }
  if (locations.length > 0) {
    query_locations = 'AND dt.location_id IN (' + locations.map(() => '?').join(',') + ')';
    params.push(...locations);
  }
  if (providers.length > 0) {
    query_providers = 'AND dt.provider_id IN (' + providers.map(() => '?').join(',') + ')';
    params.push(...providers);
  }
  var query_stocker_upload = '';
  if (stocker_upload.length > 0) {
    query_stocker_upload = 'AND sl.user_id IN (' + stocker_upload.join() + ')';
  }
  var query_transported_by = '';
  if (transported_by.length > 0) {
    query_transported_by = 'AND dt.transported_by_id IN (' + transported_by.join() + ')';
  }
  if (product_types.length > 0) {
    // Se filtra por product_types a través de product_donation_ticket y product
    // Al igual que en el código original
    query_product_types = `
      AND dt.id IN (
        SELECT pdt.donation_ticket_id
        FROM product_donation_ticket as pdt
        INNER JOIN product as p ON pdt.product_id = p.id
        WHERE p.product_type_id IN (${product_types.map(() => '?').join(',')})
      )`;
    params.push(...product_types);
  }

  if (cabecera.role === 'client') {
    // Filtrado adicional para client
    query_product_types += `
      AND dt.location_id IN (
        SELECT location_id 
        FROM client_location 
        WHERE client_id = ?
      )
    `;
    params.push(cabecera.client_id);
  }

  const language = req.query.language || 'en';
  const { tabSelected } = req.params;
  let name = '';
  let rows = [];
  let series = [];
  let isTabSelectedCorrect = false;

  if ((cabecera.role === 'admin' || cabecera.role === 'director') || (cabecera.role === 'client')) {
    try {
      switch (tabSelected) {
        case 'pounds-filters':
          name = (language === 'es') ? 'Libras entregadas' : 'Pounds delivered';

          // Construimos el CTE según el intervalo
          let query;
          let cteParams;
          if (interval === 'quarter') {
            // Para quarters necesitamos un CTE similar al del primer endpoint
            cteParams = [from_date, from_date, from_date, to_date];
            query = `
              WITH RECURSIVE date_ranges AS (
                SELECT 
                  CONCAT(YEAR(?), '-Q', QUARTER(?)) AS period, 
                  ? AS date
                UNION ALL
                SELECT 
                  CONCAT(YEAR(DATE_ADD(date, INTERVAL ${dateAddInterval})), '-Q', QUARTER(DATE_ADD(date, INTERVAL ${dateAddInterval}))) AS period,
                  DATE_ADD(date, INTERVAL ${dateAddInterval}) 
                FROM date_ranges
                WHERE DATE_ADD(date, INTERVAL ${dateAddInterval}) <= ?
              )
              SELECT 
                COALESCE(SUM(dt.total_weight), 0) AS value,
                date_ranges.period AS name
              FROM date_ranges
              LEFT JOIN donation_ticket as dt ON 
                CONCAT(YEAR(dt.date), '-Q', QUARTER(dt.date)) = date_ranges.period
              LEFT JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id AND sl.operation_id = 5
              WHERE dt.enabled = 'Y'
              ${query_from_date}
              ${query_to_date}
              ${query_locations}
              ${query_providers}
              ${query_product_types}
              ${query_stocker_upload}
              ${query_transported_by}
              GROUP BY date_ranges.period
              ORDER BY date_ranges.period
            `;
          } else {
            // Para day, week, month, year se usa el formatString
            cteParams = [from_date, from_date, to_date];
            query = `
              WITH RECURSIVE date_ranges AS (
                SELECT 
                  DATE_FORMAT(?, '${formatString}') AS period, 
                  ? AS date
                UNION ALL
                SELECT 
                  DATE_FORMAT(DATE_ADD(date, INTERVAL ${dateAddInterval}), '${formatString}') AS period,
                  DATE_ADD(date, INTERVAL ${dateAddInterval}) 
                FROM date_ranges
                WHERE DATE_ADD(date, INTERVAL ${dateAddInterval}) <= ?
              )
              SELECT 
                COALESCE(SUM(dt.total_weight), 0) AS value,
                date_ranges.period AS name
              FROM date_ranges
              LEFT JOIN donation_ticket as dt ON 
                DATE_FORMAT(dt.date, '${formatString}') = date_ranges.period
              LEFT JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id AND sl.operation_id = 5
              WHERE dt.enabled = 'Y'
              ${query_from_date}
              ${query_to_date}
              ${query_locations}
              ${query_providers}
              ${query_product_types}
              ${query_stocker_upload}
              ${query_transported_by}
              GROUP BY date_ranges.period
              ORDER BY date_ranges.period
            `;
          }

          const finalParams = cteParams.concat(params);
          [rows] = await mysqlConnection.promise().query(query, finalParams);
          isTabSelectedCorrect = true;
          break;

        default:
          return res.status(400).json('Bad request');
      }

      if (isTabSelectedCorrect && rows.length > 0) {
        // Mapeamos las filas a la misma estructura que antes
        series = rows.map(row => ({
          value: row.value,
          name: formatPeriod(row.name, interval) // formatear aquí directamente
        }));
      }

      res.json({ name, series });

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }

  } else {
    // Si el rol no es admin/director/cliente
    res.status(401).json('Unauthorized');
  }
});


router.post('/message', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'delivery' || cabecera.role === 'stocker' || cabecera.role === 'beneficiary' || cabecera.role === 'opsmanager' || cabecera.role === 'director' || cabecera.role === 'auditor') {
    try {
      const user_id = cabecera.id;
      const message = req.body.message || null;

      if (message) {
        const [rows] = await mysqlConnection.promise().query(
          'insert into message(user_id,name) values(? , ?)',
          [user_id, message]
        );
        if (rows.affectedRows > 0) {
          res.json('Message sent successfully');
        } else {
          res.status(500).json('Could not send message');
        }
      } else {
        res.status(400).json('Bad request');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('Unauthorized');
  }
});

router.put('/settings/password', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'delivery' || cabecera.role === 'stocker' || cabecera.role === 'beneficiary' || cabecera.role === 'opsmanager' || cabecera.role === 'director' || cabecera.role === 'auditor') {
    try {
      const user_id = cabecera.id;
      const { actual_password, new_password } = req.body;

      if (actual_password && new_password) {
        const [rows] = await mysqlConnection.promise().query(
          'select password from user where id = ?', [user_id]
        );

        if (rows.length > 0) {
          const passwordCorrect = await bcryptjs.compare(actual_password, rows[0].password);
          if (passwordCorrect) {
            let passwordHash = await bcryptjs.hash(new_password, 8);
            const [rows2] = await mysqlConnection.promise().query(
              'update user set password = ? where id = ?', [passwordHash, user_id]
            );
            if (rows2.affectedRows > 0) {
              res.json('Password updated successfully');
            } else {
              res.status(500).json('Could not update password');
            }
          } else {
            res.status(401).json('Unauthorized');
          }
        } else {
          res.status(500).json('Could not update password');
        }
      } else {
        res.status(400).json('Bad request');
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
});

router.post('/metrics/health/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      var query_locations_db3 = '';
      if (locations.length > 0) {
        query_locations = 'AND (db.location_id IN (' + locations.join() + ') OR u.first_location_id IN (' + locations.join() + ')) ';
        query_locations_db3 = 'AND db3.location_id IN (' + locations.join() + ')';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND u.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND u.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + zipcode;
      }

      let toDate = new Date(to_date);
      toDate.setDate(toDate.getDate() + 1); // Añade un día a la fecha final

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
                u.id as user_id,
                u.username,
                u.email,
                u.firstname,
                u.lastname,
                DATE_FORMAT(u.date_of_birth, '%m/%d/%Y') AS date_of_birth,
                TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) AS age,
                u.phone,
                u.zipcode,
                u.household_size,
                g.name AS gender,
                eth.name AS ethnicity,
                u.other_ethnicity,
                loc.community_city AS last_location_visited,
                (SELECT GROUP_CONCAT(DISTINCT loc_visited.community_city) 
                        FROM delivery_beneficiary AS db_visited 
                        LEFT JOIN location AS loc_visited ON db_visited.location_id = loc_visited.id
                        WHERE db_visited.receiving_user_id = u.id) AS locations_visited,
                COUNT(db.receiving_user_id) AS delivery_count,
                SUM(IF(db.receiving_user_id IS NOT NULL AND db.delivering_user_id IS NULL, 1, 0)) AS delivery_count_not_scanned,
                SUM(IF(db.receiving_user_id IS NOT NULL AND db.delivering_user_id IS NOT NULL, 1, 0)) AS delivery_count_scanned,
                (SELECT COUNT(*) 
                        FROM delivery_beneficiary db2 
                        WHERE db2.receiving_user_id = u.id 
                        AND CONVERT_TZ(db2.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                        AND CONVERT_TZ(db2.creation_date, '+00:00', 'America/Los_Angeles') < ?) AS delivery_count_between_dates,
                (SELECT COUNT(*) 
                        FROM delivery_beneficiary db2 
                        WHERE db2.receiving_user_id = u.id 
                        AND db2.delivering_user_id IS NULL
                        AND CONVERT_TZ(db2.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                        AND CONVERT_TZ(db2.creation_date, '+00:00', 'America/Los_Angeles') < ?) AS delivery_count_between_dates_not_scanned,
                (SELECT COUNT(*) 
                        FROM delivery_beneficiary db2 
                        WHERE db2.receiving_user_id = u.id 
                        AND db2.delivering_user_id IS NOT NULL
                        AND CONVERT_TZ(db2.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                        AND CONVERT_TZ(db2.creation_date, '+00:00', 'America/Los_Angeles') < ?) AS delivery_count_between_dates_scanned,
                DATE_FORMAT(CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS registration_date,
                DATE_FORMAT(CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS registration_time,
                q.id AS question_id,
                at.id AS answer_type_id,
                q.name AS question,
                a.name AS answer,
                uq.answer_text AS answer_text,
                uq.answer_number AS answer_number
        FROM user u
        ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
        INNER JOIN gender AS g ON u.gender_id = g.id
        INNER JOIN ethnicity AS eth ON u.ethnicity_id = eth.id
        LEFT JOIN location AS loc ON u.location_id = loc.id
        CROSS JOIN question AS q
        LEFT JOIN answer_type as at ON q.answer_type_id = at.id
        LEFT JOIN user_question AS uq ON u.id = uq.user_id AND uq.question_id = q.id
        LEFT JOIN user_question_answer AS uqa ON uq.id = uqa.user_question_id
        LEFT JOIN answer as a ON a.id = uqa.answer_id and a.question_id = q.id
        LEFT JOIN delivery_beneficiary AS db ON u.id = db.receiving_user_id
        WHERE u.role_id = 5 AND q.enabled = 'Y' 
        AND (CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? 
        OR u.id IN (SELECT db3.receiving_user_id FROM delivery_beneficiary db3 
                     WHERE CONVERT_TZ(db3.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? ${query_locations_db3}))
        ${cabecera.role === 'client' ? 'AND EXISTS (SELECT 1 FROM question_location ql INNER JOIN client_location cl ON ql.location_id = cl.location_id WHERE ql.question_id = q.id AND cl.client_id = cu.client_id AND ql.enabled = \'Y\')' : ''}
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        ${cabecera.role === 'client' ? 'and cu.client_id = ?' : ''}
        GROUP BY u.id, q.id, a.id
        ORDER BY u.id, q.id, a.id`,
        [from_date, toDate, from_date, toDate, from_date, toDate, from_date, toDate, from_date, toDate, cabecera.client_id]
      );
      // agregar a headers las preguntas de la encuesta, iterar el array rows y agregar el campo question hasta que se vuelva a repetir el question_id 
      var question_id_array = [];
      if (rows.length > 0) {
        for (let i = 0; i < rows.length; i++) {
          const row = rows[i];
          // si el id de la pregunta no esta en el question_id_array, agregarlo
          const id_repetido = question_id_array.some(obj => obj.question_id === row.question_id);
          if (!id_repetido) {
            question_id_array.push({ question_id: row.question_id, question: row.question });
          }
        }
      }

      /* iterar el array rows y agregar los campos username, email, firstname, lastname, date_of_birth, phone, zipcode, household_size, gender, ethnicity, other_ethnicity, location, registration_date, registration_time
      y que cada pregunta sea una columna, si el question_id se repite entonces agregar el campo answer a la columna correspondiente agregando al final del campo texto separando el valor por coma, si no se repite entonces agregar el campo answer a la columna correspondiente y agregar el objeto a rows_filtered
      */
      var rows_filtered = [];
      var row_filtered = {};
      for (let i = 0; i < rows.length; i++) {

        if (!row_filtered["username"]) {
          row_filtered["user_id"] = rows[i].user_id;
          row_filtered["username"] = rows[i].username;
          row_filtered["email"] = rows[i].email;
          row_filtered["firstname"] = rows[i].firstname;
          row_filtered["lastname"] = rows[i].lastname;
          row_filtered["date_of_birth"] = rows[i].date_of_birth;
          row_filtered["age"] = rows[i].age;
          row_filtered["phone"] = rows[i].phone;
          row_filtered["zipcode"] = rows[i].zipcode;
          row_filtered["household_size"] = rows[i].household_size;
          row_filtered["gender"] = rows[i].gender;
          row_filtered["ethnicity"] = rows[i].ethnicity;
          row_filtered["other_ethnicity"] = rows[i].other_ethnicity;
          row_filtered["last_location_visited"] = rows[i].last_location_visited;
          row_filtered["locations_visited"] = rows[i].locations_visited;
          row_filtered["delivery_count"] = rows[i].delivery_count;
          row_filtered["delivery_count_scanned"] = rows[i].delivery_count_scanned;
          row_filtered["delivery_count_not_scanned"] = rows[i].delivery_count_not_scanned;
          row_filtered["delivery_count_between_dates"] = rows[i].delivery_count_between_dates;
          row_filtered["delivery_count_between_dates_scanned"] = rows[i].delivery_count_between_dates_scanned;
          row_filtered["delivery_count_between_dates_not_scanned"] = rows[i].delivery_count_between_dates_not_scanned;
          row_filtered["registration_date"] = rows[i].registration_date;
          row_filtered["registration_time"] = rows[i].registration_time;
        }
        if (!row_filtered[rows[i].question_id]) {

          switch (rows[i].answer_type_id) {
            case 1:
              row_filtered[rows[i].question_id] = rows[i].answer_text;
              break;
            case 2:
              row_filtered[rows[i].question_id] = rows[i].answer_number;
              break;
            case 3:
              row_filtered[rows[i].question_id] = rows[i].answer;
              break;
            case 4:
              row_filtered[rows[i].question_id] = rows[i].answer;
              break;
            default:
              break;
          }
        } else {
          // es un answer_type_id = 4, agregar el campo answer al final del campo texto separando el valor por coma
          row_filtered[rows[i].question_id] = row_filtered[rows[i].question_id] + ', ' + rows[i].answer;
        }
        if (i < rows.length - 1) {
          if (rows[i].username !== rows[i + 1].username) {
            rows_filtered.push(row_filtered);
            row_filtered = {};
          }
        } else {
          rows_filtered.push(row_filtered);
          row_filtered = {};
        }
      }
      // iterar el array headers y convertirlo en un array de objetos con id y title para csvWriter
      var headers_array = [
        { id: 'user_id', title: 'User ID' },
        { id: 'username', title: 'Username' },
        { id: 'email', title: 'Email' },
        { id: 'firstname', title: 'Firstname' },
        { id: 'lastname', title: 'Lastname' },
        { id: 'date_of_birth', title: 'Date of birth' },
        { id: 'age', title: 'Age' },
        { id: 'phone', title: 'Phone' },
        { id: 'zipcode', title: 'Zipcode' },
        { id: 'household_size', title: 'Household size' },
        { id: 'gender', title: 'Gender' },
        { id: 'ethnicity', title: 'Ethnicity' },
        { id: 'other_ethnicity', title: 'Other ethnicity' },
        { id: 'last_location_visited', title: 'Last location visited' },
        { id: 'locations_visited', title: 'Locations visited' },
        { id: 'delivery_count', title: 'Delivery Count' },
        { id: 'delivery_count_scanned', title: 'D.C. scanned' },
        { id: 'delivery_count_not_scanned', title: 'D.C. not scanned' },
        { id: 'delivery_count_between_dates', title: 'D.C. between dates' },
        { id: 'delivery_count_between_dates_scanned', title: 'D.C. between dates scanned' },
        { id: 'delivery_count_between_dates_not_scanned', title: 'D.C. between dates not scanned' },
        { id: 'registration_date', title: 'Registration date' },
        { id: 'registration_time', title: 'Registration time' }
      ];

      for (let i = 0; i < question_id_array.length; i++) {
        const question_id = question_id_array[i].question_id;
        const question = question_id_array[i].question;
        headers_array.push({ id: question_id, title: question });
      }

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows_filtered);

      res.setHeader('Content-disposition', 'attachment; filename=health-metrics.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/user/system-user/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND (u.first_location_id IN (' + locations.join() + ') OR u.id IN (SELECT DISTINCT(db.delivering_user_id) FROM delivery_beneficiary db WHERE db.location_id IN (' + locations.join() + ')))';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND u.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND u.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + zipcode;
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT u.id,
                u.username,
                u.firstname,
                u.lastname,
                u.document,
                DATE_FORMAT(u.date_of_birth, '%m/%d/%Y') AS date_of_birth,
                u.email,
                u.phone,
                u.zipcode,
                u.address,
                g.name as gender,
                r.name as role,
                loc.community_city AS last_location,
                u.reset_password,
                u.enabled,
        DATE_FORMAT(CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(u.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(u.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM user as u
        INNER JOIN role as r ON u.role_id = r.id
        LEFT JOIN gender as g ON u.gender_id = g.id
        LEFT JOIN location AS loc ON u.location_id = loc.id
        WHERE u.enabled = 'Y' AND u.role_id <> 2 AND u.role_id <> 5 AND CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') >= ? AND CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        ORDER BY u.id`,
        [from_date, to_date]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'username', title: 'Username' },
        { id: 'firstname', title: 'Firstname' },
        { id: 'lastname', title: 'Lastname' },
        { id: 'document', title: 'Document' },
        { id: 'date_of_birth', title: 'Date of birth' },
        { id: 'email', title: 'Email' },
        { id: 'phone', title: 'Phone' },
        { id: 'zipcode', title: 'Zipcode' },
        { id: 'address', title: 'Address' },
        { id: 'gender', title: 'Gender' },
        { id: 'role', title: 'Role' },
        { id: 'last_location', title: 'Last location' },
        { id: 'reset_password', title: 'Reset password' },
        { id: 'enabled', title: 'Enabled' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=system-users-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/user/client/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND cl.location_id IN (' + locations.join() + ')';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND u.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND u.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + zipcode;
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT u.id,
                u.username,
                u.firstname,
                u.lastname,
                u.document,
                DATE_FORMAT(u.date_of_birth, '%m/%d/%Y') AS date_of_birth,
                u.email,
                u.phone,
                u.zipcode,
                u.address,
                g.name as gender,
                u.reset_password,
                c.name as client_name,
                c.short_name as client_short_name,
                u.enabled,
        DATE_FORMAT(CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(u.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(u.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM user as u
        LEFT JOIN gender as g ON u.gender_id = g.id
        INNER JOIN client as c ON u.client_id = c.id
        LEFT JOIN client_location as cl ON c.id = cl.client_id
        WHERE u.role_id = 2 AND CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') >= ? AND CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        ${cabecera.role === 'client' ? ' AND u.client_id = ?' : ''}
        GROUP BY u.id
        ORDER BY u.id`,
        [from_date, to_date, cabecera.client_id]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'username', title: 'Username' },
        { id: 'firstname', title: 'Firstname' },
        { id: 'lastname', title: 'Lastname' },
        { id: 'document', title: 'Document' },
        { id: 'date_of_birth', title: 'Date of birth' },
        { id: 'email', title: 'Email' },
        { id: 'phone', title: 'Phone' },
        { id: 'zipcode', title: 'Zipcode' },
        { id: 'address', title: 'Address' },
        { id: 'gender', title: 'Gender' },
        { id: 'reset_password', title: 'Reset password' },
        { id: 'client_name', title: 'Client name' },
        { id: 'client_short_name', title: 'Client short name' },
        { id: 'enabled', title: 'Enabled' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=client-users-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/client/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(c.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(c.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND cl.location_id IN (' + locations.join() + ')';
      }

      let clientIds = [];

      const [rows] = await mysqlConnection.promise().query(
        `SELECT DISTINCT c.id
          FROM client as c
          LEFT JOIN client_location as cl ON c.id = cl.client_id
          WHERE 1=1 ${query_locations}`
      );

      clientIds = rows.map(row => row.id);

      const [rows2] = await mysqlConnection.promise().query(
        `SELECT c.id,
                c.name,
                c.short_name,
                GROUP_CONCAT(DISTINCT l.community_city SEPARATOR ', ') as locations,
                c.email,
                c.phone,
                c.address,
                c.webpage,
                c.enabled,
        DATE_FORMAT(CONVERT_TZ(c.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(c.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(c.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(c.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM client as c
        LEFT JOIN client_location as cl ON c.id = cl.client_id
        LEFT JOIN location as l ON cl.location_id = l.id
        WHERE c.id IN (${clientIds.join()}) AND CONVERT_TZ(c.creation_date, '+00:00', 'America/Los_Angeles') >= ? AND CONVERT_TZ(c.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
        GROUP BY c.id
        ORDER BY c.id`,
        [from_date, to_date]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'name', title: 'Name' },
        { id: 'short_name', title: 'Short name' },
        { id: 'locations', title: 'Locations' },
        { id: 'email', title: 'Email' },
        { id: 'phone', title: 'Phone' },
        { id: 'address', title: 'Address' },
        { id: 'webpage', title: 'Webpage' },
        { id: 'enabled', title: 'Enabled' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows2);

      res.setHeader('Content-disposition', 'attachment; filename=clients-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/delivered/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND db.location_id IN (' + locations.join() + ')';
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT db.id, 
        db.delivering_user_id, 
        u1.username as delivery_username, 
        db.receiving_user_id, 
        u2.username as beneficiary_username, 
        u2.firstname as beneficiary_firstname, 
        u2.lastname as beneficiary_lastname, 
        db.location_id, 
        l.community_city, 
        db.approved, 
        DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time
        FROM delivery_beneficiary as db
        INNER JOIN location as l ON db.location_id = l.id
        INNER JOIN user as u2 ON db.receiving_user_id = u2.id
        LEFT JOIN user as u1 ON db.delivering_user_id = u1.id
        WHERE 1=1
        ${query_from_date}
        ${query_to_date}
        ${query_locations}
        ${cabecera.role === 'client' ? ' AND db.client_id = ?' : ''}
        ORDER BY db.id`,
        [from_date, to_date, cabecera.client_id]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'delivering_user_id', title: 'Delivering user ID' },
        { id: 'delivery_username', title: 'Delivery username' },
        { id: 'receiving_user_id', title: 'Receiving user ID' },
        { id: 'beneficiary_username', title: 'Beneficiary username' },
        { id: 'beneficiary_firstname', title: 'Beneficiary firstname' },
        { id: 'beneficiary_lastname', title: 'Beneficiary lastname' },
        { id: 'location_id', title: 'Location ID' },
        { id: 'community_city', title: 'Community city' },
        { id: 'approved', title: 'Approved' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=delivery-summary.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.get('/view/worker/username/:idWorker', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    try {
      const { idWorker } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT u.username
          FROM user as u
          WHERE u.id = ?`,
        [idWorker]
      );

      if (rows.length > 0) {

        res.json(rows[0].username);
      } else {
        res.status(404).json('worker no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.post('/view/worker/table/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    try {
      const language = req.query.language || 'en';
      const idUser = req.params.id;

      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      from_date = from_date.split('T')[0];
      to_date = to_date.split('T')[0];

      const locations = filters.locations || [];
      const workers = filters.workers || [];

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND db.location_id IN (' + locations.join() + ')';
      }
      var query_workers = '';
      if (workers.length > 0) {
        query_workers = 'AND db.delivering_user_id IN (' + workers.join() + ')';
      } else {
        query_workers = 'AND db.delivering_user_id = ' + idUser;
      }

      const [table_rows_worker] = await mysqlConnection.promise().query(
        `SELECT
          db.id,
          db.receiving_user_id,
          user.username as username,
          location.community_city as location,
          DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date
        FROM delivery_beneficiary as db
        INNER JOIN user ON db.receiving_user_id = user.id
        INNER JOIN location ON db.location_id = location.id
        WHERE 1=1
        ${query_from_date}
        ${query_to_date}
        ${query_locations}
        ${query_workers}
        ORDER BY db.id`,
        []
      );

      if (table_rows_worker.length > 0) {
        res.status(200).json(table_rows_worker);
      } else {
        res.status(200).json([]);
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/table/ethnicity/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(e.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(e.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT e.id,
                e.name,
                e.name_es,
                e.enabled,
        DATE_FORMAT(CONVERT_TZ(e.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(e.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(e.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(e.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM ethnicity as e
        WHERE CONVERT_TZ(e.creation_date, '+00:00', 'America/Los_Angeles') >= ? AND CONVERT_TZ(e.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
        ORDER BY e.id`,
        [from_date, to_date]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'name', title: 'Name' },
        { id: 'name_es', title: 'Spanish name' },
        { id: 'enabled', title: 'Enabled' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=ethnicities-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/gender/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(g.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(g.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT g.id,
                g.name,
                g.name_es,
                g.enabled,
        DATE_FORMAT(CONVERT_TZ(g.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(g.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(g.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(g.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM gender as g
        WHERE CONVERT_TZ(g.creation_date, '+00:00', 'America/Los_Angeles') >= ? AND CONVERT_TZ(g.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
        ORDER BY g.id`,
        [from_date, to_date]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'name', title: 'Name' },
        { id: 'name_es', title: 'Spanish name' },
        { id: 'enabled', title: 'Enabled' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=genders-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/delivered-by/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT db.id,
                db.name,
                db.enabled,
        DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(db.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(db.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM delivered_by as db
        WHERE CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') >= ? AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
        ORDER BY db.id`,
        [from_date, to_date]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'name', title: 'Name' },
        { id: 'enabled', title: 'Enabled' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=delivered-by-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/transported-by/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(tb.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(tb.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT tb.id,
                tb.name,
                tb.enabled,
        DATE_FORMAT(CONVERT_TZ(tb.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(tb.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(tb.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(tb.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM transported_by as tb
        WHERE CONVERT_TZ(tb.creation_date, '+00:00', 'America/Los_Angeles') >= ? AND CONVERT_TZ(tb.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
        ORDER BY tb.id`,
        [from_date, to_date]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'name', title: 'Name' },
        { id: 'enabled', title: 'Enabled' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=transported-by-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/location/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(l.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(l.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT l.id,
                l.organization,
                l.community_city,
                GROUP_CONCAT(DISTINCT client.short_name SEPARATOR ', ') as partner,
                l.address,
                CONCAT(ST_Y(l.coordinates), ', ', ST_X(l.coordinates)) as coordinates, 
                l.enabled,
        DATE_FORMAT(CONVERT_TZ(l.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(l.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(l.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(l.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM location as l
        LEFT JOIN client_location ON l.id = client_location.location_id
        LEFT JOIN client ON client_location.client_id = client.id
        WHERE CONVERT_TZ(l.creation_date, '+00:00', 'America/Los_Angeles') >= ? AND CONVERT_TZ(l.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
        ${cabecera.role === 'client' ? ' AND client_location.client_id = ?' : ''}
        GROUP BY l.id`,
        [from_date, to_date, cabecera.client_id]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'organization', title: 'Organization' },
        { id: 'community_city', title: 'Community city' },
        { id: 'partner', title: 'Partner' },
        { id: 'address', title: 'Address' },
        { id: 'coordinates', title: 'Coordinates' },
        { id: 'enabled', title: 'Enabled' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=locations-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/product/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const providers = filters.providers || [];
      const product_types = filters.product_types || [];

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        if (cabecera.role === 'admin') {
          query_from_date = 'AND CONVERT_TZ(p.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
        } else {
          query_from_date = 'AND dt.date >= \'' + from_date + '\'';
        }
      }
      var query_to_date = '';
      if (filters.to_date) {
        if (cabecera.role === 'admin') {
          query_to_date = 'AND CONVERT_TZ(p.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
        } else {
          query_to_date = 'AND dt.date < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
        }
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND dt.location_id IN (' + locations.join() + ')';
      }
      var query_providers = '';
      if (providers.length > 0) {
        query_providers = 'AND dt.provider_id IN (' + providers.join() + ')';
      }
      var query_product_types = '';
      if (product_types.length > 0) {
        query_product_types = 'AND p.product_type_id IN (' + product_types.join() + ')';
      }
      const [rows] = await mysqlConnection.promise().query(
        `SELECT p.id,
          p.name,
          pt.name as product_type_name,
          pt.name_es as product_type_name_es,
          IFNULL(SUM(product_donation_ticket.quantity), 0) as total_quantity,
          ${cabecera.role === 'admin' || cabecera.role === 'opsmanager' ? `DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,` : `DATE_FORMAT(CONVERT_TZ(min(dt.creation_date), '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,`}
          ${cabecera.role === 'admin' || cabecera.role === 'opsmanager' ? `DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,` : `DATE_FORMAT(CONVERT_TZ(min(dt.creation_date), '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,`}  
          ${cabecera.role === 'admin' || cabecera.role === 'opsmanager' ? `DATE_FORMAT(CONVERT_TZ(p.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,` : `DATE_FORMAT(CONVERT_TZ(min(dt.modification_date), '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,`}
          ${cabecera.role === 'admin' || cabecera.role === 'opsmanager' ? `DATE_FORMAT(CONVERT_TZ(p.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time` : `DATE_FORMAT(CONVERT_TZ(min(dt.modification_date), '+00:00', 'America/Los_Angeles'), '%T') AS modification_time`}
        FROM product as p
        INNER JOIN product_type as pt ON pt.id = p.product_type_id
        ${cabecera.role === 'admin' || cabecera.role === 'opsmanager' ? 'LEFT JOIN product_donation_ticket ON p.id = product_donation_ticket.product_id LEFT JOIN donation_ticket as dt ON product_donation_ticket.donation_ticket_id = dt.id LEFT JOIN client_location ON dt.location_id = client_location.location_id' : 'INNER JOIN product_donation_ticket ON p.id = product_donation_ticket.product_id INNER JOIN donation_ticket as dt ON product_donation_ticket.donation_ticket_id = dt.id INNER JOIN client_location ON dt.location_id = client_location.location_id'}
        WHERE 1=1
        ${query_from_date}
        ${query_to_date}
        ${query_locations}
        ${query_providers}
        ${query_product_types}
        ${cabecera.role === 'client' ? ' AND client_location.client_id = ?' : ''}
        GROUP BY p.id`,
        [cabecera.client_id]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'name', title: 'Name' },
        { id: 'product_type_name', title: 'Food type' },
        { id: 'product_type_name_es', title: 'Spanish food type' },
        { id: 'total_quantity', title: 'Total quantity' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=foods-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/product-type/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(pt.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(pt.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT pt.id,
                pt.name,
                pt.name_es,
        DATE_FORMAT(CONVERT_TZ(pt.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(pt.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(pt.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(pt.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM product_type as pt
        WHERE 1=1
        ${query_from_date}
        ${query_to_date}`
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'name', title: 'Name' },
        { id: 'name_es', title: 'Spanish name' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=food-types-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/table/provider/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(p.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(p.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND dt.location_id IN (' + locations.join() + ')';
      }

      let providerIds = [];

      const [rows] = await mysqlConnection.promise().query(
        `SELECT DISTINCT p.id
          FROM provider as p
          LEFT JOIN donation_ticket as dt ON p.id = dt.provider_id
          LEFT JOIN location as l ON dt.location_id = l.id
          WHERE 1=1 ${query_locations}`
      );

      providerIds = rows.map(row => row.id);

      const [rows2] = await mysqlConnection.promise().query(
        `SELECT p.id,
                p.name,
                GROUP_CONCAT(DISTINCT l.community_city SEPARATOR ', ') as locations,
        DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
        DATE_FORMAT(CONVERT_TZ(p.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS modification_date,
                        DATE_FORMAT(CONVERT_TZ(p.modification_date, '+00:00', 'America/Los_Angeles'), '%T') AS modification_time
        FROM provider as p
        LEFT JOIN donation_ticket as dt ON p.id = dt.provider_id
        LEFT JOIN location as l ON dt.location_id = l.id
        LEFT JOIN client_location ON dt.location_id = client_location.location_id
        WHERE p.id IN (${providerIds.join()})
        ${query_from_date}
        ${query_to_date}
        ${cabecera.role === 'client' ? ' AND client_location.client_id = ?' : ''}
        GROUP BY p.id
        ORDER BY p.id
        `,
        [cabecera.client_id]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'name', title: 'Name' },
        { id: 'locations', title: 'Locations' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'modification_date', title: 'Modification date' },
        { id: 'modification_time', title: 'Modification time' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows2);

      res.setHeader('Content-disposition', 'attachment; filename=providers-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);


/*
Generar CSV con las siguientes columnas: locacion_id, community_city, fecha de reparticion,
count_beneficiaries_creation_date: count de beneficiarios que se registraron ese dia en esa localidad y retiraron comida en esa localidad (con db.creation_date = u.creation_date), 
count_beneficiaries_same_location: count beneficiarios que retiraron comida en esa fecha y localidad (tabla beneficiary_delivery) y ya han retirado en esa misma localidad y no en otra, 
count_beneficiaries_same_and_other_location: count de beneficiarios que retiraron comida de esa fecha y localidad y han ido a esa localidad y a otra localidad, 
count_beneficiaries_first_time: count de beneficiarios que retiraron comida de esa fecha y localidad y es la primera vez que van a esa localidad (anteriormente fueron a otras).
count_beneficiaries_already_registered_first_time: count de beneficiarios que ya estaban registrados pero es la primera vez que van a una localidad, no fueron a otra localidad antes.
total_beneficiaries: count de beneficiarios que retiraron comida de esa fecha y localidad.
tabla: delivery_beneficiary
campos: receiving_user_id (beneficiary), location_id, creation_date
tabla: location
campos: id, community_city
tabla: user
campos: id, creation_date
*/
router.post('/table/delivered/beneficiary-summary/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      // count_beneficiaries_creation_date
      query1 = `SELECT loc.id as location_id,
                        loc.community_city,
                        DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        SUM(IF(
                          NOT EXISTS (
                            SELECT 1
                            FROM delivery_beneficiary db1
                            WHERE db1.receiving_user_id = db.receiving_user_id
                              AND CONVERT_TZ(db1.creation_date, '+00:00', 'America/Los_Angeles') < CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')
                          ) AND DATE(db.creation_date) = DATE(u.creation_date), 1, 0)) AS count_beneficiaries_creation_date
                  FROM delivery_beneficiary as db
                      INNER JOIN location as loc ON db.location_id = loc.id
                      INNER JOIN user as u ON db.receiving_user_id = u.id
                  WHERE CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                      AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
                    ${cabecera.role === 'client' ? ' AND db.client_id = ?' : ''}
                  GROUP BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')
                  ORDER BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')`;

      //  count_beneficiaries_same_location
      query2 = `SELECT loc.id as location_id,
                        loc.community_city,
                        DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        COUNT(DISTINCT IF(
                          NOT EXISTS (
                            SELECT 1
                            FROM delivery_beneficiary db2
                            WHERE db2.receiving_user_id = db.receiving_user_id
                              AND db2.location_id != db.location_id
                              AND CONVERT_TZ(db2.creation_date, '+00:00', 'America/Los_Angeles') < CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')
                          ) AND EXISTS (
                            SELECT 1
                            FROM delivery_beneficiary db3
                            WHERE db3.receiving_user_id = db.receiving_user_id
                              AND db3.location_id = db.location_id
                              AND CONVERT_TZ(db3.creation_date, '+00:00', 'America/Los_Angeles') < CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')
                          ) AND DATE(db.creation_date) > DATE(u.creation_date), db.receiving_user_id, NULL)) AS count_beneficiaries_same_location
                FROM delivery_beneficiary as db
                      INNER JOIN location as loc ON db.location_id = loc.id
                      INNER JOIN user as u ON db.receiving_user_id = u.id
                WHERE CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                      AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
                      ${cabecera.role === 'client' ? ' AND db.client_id = ?' : ''}
                GROUP BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')
                ORDER BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')`;

      // count_beneficiaries_same_and_other_location
      query3 = `SELECT loc.id as location_id,
                      loc.community_city,
                      DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                      SUM(IF(EXISTS (
                        SELECT 1
                        FROM delivery_beneficiary db1
                        WHERE db1.receiving_user_id = db.receiving_user_id
                          AND CONVERT_TZ(db1.creation_date, '+00:00', 'America/Los_Angeles') < CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')
                        GROUP BY db1.receiving_user_id
                        HAVING COUNT(DISTINCT db1.location_id) > 1
                      ), 1, 0)) AS count_beneficiaries_same_and_other_location
              FROM delivery_beneficiary as db
                  INNER JOIN location as loc ON db.location_id = loc.id
              WHERE CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                  AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
                  ${cabecera.role === 'client' ? ' AND db.client_id = ?' : ''}
              GROUP BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')
              ORDER BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')`;

      // count_beneficiaries_first_time
      query4 = `SELECT loc.id as location_id,
                      loc.community_city,
                      DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                      SUM(IF(
                        NOT EXISTS (
                          SELECT 1
                          FROM delivery_beneficiary db1
                          WHERE db1.receiving_user_id = db.receiving_user_id
                            AND db1.location_id = db.location_id
                            AND CONVERT_TZ(db1.creation_date, '+00:00', 'America/Los_Angeles') < CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')
                        ) AND EXISTS (
                          SELECT 1
                          FROM delivery_beneficiary db2
                          WHERE db2.receiving_user_id = db.receiving_user_id
                            AND db2.location_id != db.location_id
                            AND CONVERT_TZ(db2.creation_date, '+00:00', 'America/Los_Angeles') < CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')
                        ), 1, 0)) AS count_beneficiaries_first_time
                FROM delivery_beneficiary as db
                    INNER JOIN location as loc ON db.location_id = loc.id
                WHERE CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                    AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
                    ${cabecera.role === 'client' ? ' AND db.client_id = ?' : ''}
                GROUP BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')
                ORDER BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')`;

      // count_beneficiaries_already_registered_first_time
      query5 = `SELECT loc.id as location_id,
                      loc.community_city,
                      DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                      SUM(IF(
                        NOT EXISTS (
                          SELECT 1
                          FROM delivery_beneficiary db1
                          WHERE db1.receiving_user_id = db.receiving_user_id
                            AND CONVERT_TZ(db1.creation_date, '+00:00', 'America/Los_Angeles') < CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')
                        ) AND DATE(db.creation_date) > DATE(u.creation_date), 1, 0)) AS count_beneficiaries_already_registered_first_time
                FROM delivery_beneficiary as db
                    INNER JOIN location as loc ON db.location_id = loc.id
                    INNER JOIN user as u ON db.receiving_user_id = u.id
                WHERE CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                    AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
                    ${cabecera.role === 'client' ? ' AND db.client_id = ?' : ''}
                GROUP BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')
                ORDER BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')`;

      // total_beneficiaries
      query6 = `SELECT loc.id as location_id,
                    loc.community_city,
                    DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                    COUNT(DISTINCT db.receiving_user_id) AS total_beneficiaries
          FROM delivery_beneficiary as db
          INNER JOIN location as loc ON db.location_id = loc.id
          WHERE CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
            AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
            ${cabecera.role === 'client' ? ' AND db.client_id = ?' : ''}
          GROUP BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')
          ORDER BY loc.id, DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y')`;

      const funcionesParalelas = [
        mysqlConnection.promise().query(query1, [from_date, to_date, cabecera.client_id]),
        mysqlConnection.promise().query(query2, [from_date, to_date, cabecera.client_id]),
        mysqlConnection.promise().query(query3, [from_date, to_date, cabecera.client_id]),
        mysqlConnection.promise().query(query4, [from_date, to_date, cabecera.client_id]),
        mysqlConnection.promise().query(query5, [from_date, to_date, cabecera.client_id]),
        mysqlConnection.promise().query(query6, [from_date, to_date, cabecera.client_id])
      ];

      const [
        [count_beneficiaries_creation_date],
        [count_beneficiaries_same_location],
        [count_beneficiaries_same_and_other_location],
        [count_beneficiaries_first_time],
        [count_beneficiaries_already_registered_first_time],
        [total_beneficiaries]
      ] = await Promise.all(funcionesParalelas);

      // unir los 6 arrays en uno solo con los campos location_id, community_city, creation_date, count_beneficiaries_creation_date, count_beneficiaries_same_location, count_beneficiaries_same_and_other_location, count_beneficiaries_first_time, donde location_id y creation_date son iguales
      var rows = [];
      for (let i = 0; i < count_beneficiaries_creation_date.length; i++) {
        const row = count_beneficiaries_creation_date[i];
        const row2 = count_beneficiaries_same_location[i];
        const row3 = count_beneficiaries_same_and_other_location[i];
        const row4 = count_beneficiaries_first_time[i];
        const row5 = count_beneficiaries_already_registered_first_time[i];
        const row6 = total_beneficiaries[i];
        rows.push({
          location_id: row.location_id,
          community_city: row.community_city,
          creation_date: row.creation_date,
          count_beneficiaries_creation_date: row.count_beneficiaries_creation_date,
          count_beneficiaries_same_location: row2.count_beneficiaries_same_location,
          count_beneficiaries_same_and_other_location: row3.count_beneficiaries_same_and_other_location,
          count_beneficiaries_first_time: row4.count_beneficiaries_first_time,
          count_beneficiaries_already_registered_first_time: row5.count_beneficiaries_already_registered_first_time,
          total_beneficiaries: row6.total_beneficiaries
        });
      }

      var headers_array = [
        { id: 'location_id', title: 'Location ID' },
        { id: 'community_city', title: 'Community city' },
        { id: 'count_beneficiaries_creation_date', title: 'Beneficiaries who registered in that location and scanned QR' },
        { id: 'count_beneficiaries_same_location', title: 'Beneficiaries who always go to the same location' },
        { id: 'count_beneficiaries_same_and_other_location', title: 'Beneficiaries who have already gone to the location and have gone to others' },
        { id: 'count_beneficiaries_first_time', title: 'Beneficiaries who are going for the first time but have already gone to another location' },
        { id: 'count_beneficiaries_already_registered_first_time', title: 'Beneficiaries who are going for the first time and have not gone to another location (already registered)' },
        { id: 'total_beneficiaries', title: 'Total beneficiaries' },
        { id: 'creation_date', title: 'Date' },
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=beneficiary-summary.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/table/ticket/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const providers = filters.providers || [];
      const delivered_by = filters.delivered_by || [];
      const transported_by = filters.transported_by || [];
      const stocker_upload = filters.stocker_upload || [];
      const language = req.query.language || 'en';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }
      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND dt.date >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND dt.date < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND dt.location_id IN (' + locations.join() + ')';
      }
      var query_providers = '';
      if (providers.length > 0) {
        query_providers = 'AND dt.provider_id IN (' + providers.join() + ')';
      }
      var query_delivered_by = '';
      if (delivered_by.length > 0) {
        query_delivered_by = 'AND dt.delivered_by IN (' + delivered_by.join() + ')';
      }
      var query_transported_by = '';
      if (transported_by.length > 0) {
        query_transported_by = 'AND dt.transported_by_id IN (' + transported_by.join() + ')';
      }
      var query_stocker_upload = '';
      if (stocker_upload.length > 0) {
        query_stocker_upload = 'AND sl.user_id IN (' + stocker_upload.join() + ')';
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT dt.id,
                dt.donation_id,
                dt.total_weight,
                p.id as provider_id,
                p.name as provider,
                loc.community_city as location,
                DATE_FORMAT(dt.date, '%m/%d/%Y') as date,
                db.name as delivered_by,
                tb.name as transported_by,
                as1.name as audit_status,
                u.id as created_by_id,
                u.username as created_by_username,
                DATE_FORMAT(CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                DATE_FORMAT(CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time,
                product.id as product_id,
                product.name as product,
                pt.name as product_type,
                pdt.quantity as quantity
        FROM donation_ticket as dt
        LEFT JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id AND sl.operation_id = 5
        LEFT JOIN delivered_by as db ON dt.delivered_by = db.id
        LEFT JOIN transported_by as tb ON dt.transported_by_id = tb.id
        LEFT JOIN provider as p ON dt.provider_id = p.id
        LEFT JOIN audit_status as as1 ON dt.audit_status_id = as1.id
        LEFT JOIN location as loc ON dt.location_id = loc.id
        ${cabecera.role === 'client' ? 'LEFT JOIN client_location cl ON dt.location_id = cl.location_id' : ''}
        LEFT JOIN user as u ON sl.user_id = u.id
        LEFT JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
        LEFT JOIN product as product ON pdt.product_id = product.id
        LEFT JOIN product_type as pt ON product.product_type_id = pt.id
        WHERE dt.enabled = 'Y'
        ${query_from_date}
        ${query_to_date}
        ${query_locations}
        ${query_providers}
        ${query_delivered_by}
        ${query_transported_by}
        ${query_stocker_upload}
        ${cabecera.role === 'client' ? ' AND cl.client_id = ?' : ''}
        ORDER BY dt.date, dt.id`,
        [from_date, to_date, cabecera.client_id]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'donation_id', title: 'Donation ID' },
        { id: 'total_weight', title: 'Total weight' },
        { id: 'provider_id', title: 'Provider ID' },
        { id: 'provider', title: 'Provider' },
        { id: 'location', title: 'Location' },
        { id: 'date', title: 'Date' },
        { id: 'delivered_by', title: 'Delivered by' },
        { id: 'transported_by', title: 'Transported by' },
        { id: 'audit_status', title: 'Audit status' },
        { id: 'created_by_id', title: 'Created by ID' },
        { id: 'created_by_username', title: 'Created by username' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
        { id: 'product_id', title: 'Product ID' },
        { id: 'product', title: 'Product' },
        { id: 'product_type', title: 'Product type' },
        { id: 'quantity', title: 'Quantity' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      // res.setHeader('Content-disposition', 'attachment; filename=tickets-table.csv');
      // res.setHeader('Content-type', 'text/csv; charset=utf-8');
      // res.send(csvData);

      // Generar el segundo CSV
      const headersArrayWithoutProduct = headers_array.filter(header => !['product_id', 'product', 'product_type', 'quantity'].includes(header.id));
      const csvStringifierWithoutProduct = createCsvStringifier({
        header: headersArrayWithoutProduct,
        fieldDelimiter: ';'
      });
      const uniqueTickets = new Set();
      const uniqueRows = rows.filter(row => {
        if (!uniqueTickets.has(row.id)) {
          uniqueTickets.add(row.id);
          return true;
        }
        return false;
      });
      let csvDataWithoutProduct = csvStringifierWithoutProduct.getHeaderString();
      csvDataWithoutProduct += csvStringifierWithoutProduct.stringifyRecords(uniqueRows);

      // Crear un archivo ZIP
      const zip = new JSZip();
      zip.file("tickets-with-food.csv", csvData);
      zip.file("tickets.csv", csvDataWithoutProduct);

      // Establecer encabezados antes de enviar el cuerpo de la respuesta
      res.setHeader('Content-disposition', 'attachment; filename=tickets.zip');
      res.setHeader('Content-type', 'application/zip');

      zip.generateNodeStream({ type: 'nodebuffer', streamFiles: true })
        .pipe(res)
        .on('finish', function () {
          // No es necesario llamar a res.end() aquí, ya que .pipe() manejará el fin del stream.
          // También, asegúrate de no establecer ningún encabezado o intentar modificar la respuesta después de este punto.
        });

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);
// TO-DO que hacer con las preguntas que no son multiple choice
const moment = require('moment-timezone');
const e = require('express');

router.post('/metrics/health/questions', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const filters = req.body;
      const language = req.query.language || 'en';

      // Manejo de fechas y zonas horarias
      const timeZone = 'America/Los_Angeles';
      const from_date = filters.from_date ? moment.tz(filters.from_date, timeZone).utc().format('YYYY-MM-DD HH:mm:ss') : '1970-01-01 00:00:00';
      const to_date = filters.to_date ? moment.tz(filters.to_date, timeZone).utc().endOf('day').format('YYYY-MM-DD HH:mm:ss') : '2100-01-01 23:59:59';

      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;
      const register_form = filters.register_form || null;

      // Calcular rangos de fechas de nacimiento para edades
      const today = moment.tz(timeZone).startOf('day');
      const minBirthDate = today.clone().subtract(max_age, 'years').format('YYYY-MM-DD');
      const maxBirthDate = today.clone().subtract(min_age, 'years').format('YYYY-MM-DD');

      // Construir cláusulas dinámicas para filtros
      let whereClauses = [];
      let params = [];

      whereClauses.push(`u.role_id = 5`);

      // Filtro de fechas
      whereClauses.push(`(u.creation_date BETWEEN ? AND ? OR db.creation_date BETWEEN ? AND ?)`);
      params.push(from_date, to_date, from_date, to_date);

      // Filtro de ubicaciones
      if (locations.length > 0) {
        whereClauses.push(`(db.location_id IN (${locations.map(() => '?').join(',')}) OR u.first_location_id IN (${locations.map(() => '?').join(',')}))`);
        params.push(...locations, ...locations);
      }

      // Filtro de género
      if (genders.length > 0) {
        whereClauses.push(`u.gender_id IN (${genders.map(() => '?').join(',')})`);
        params.push(...genders);
      }

      // Filtro de etnia
      if (ethnicities.length > 0) {
        whereClauses.push(`u.ethnicity_id IN (${ethnicities.map(() => '?').join(',')})`);
        params.push(...ethnicities);
      }

      // Filtro de edad
      if (filters.min_age || filters.max_age) {
        whereClauses.push(`u.date_of_birth BETWEEN ? AND ?`);
        params.push(minBirthDate, maxBirthDate);
      }

      // Filtro de código postal
      if (zipcode) {
        whereClauses.push(`u.zipcode = ?`);
        params.push(zipcode);
      }

      // Filtro de formulario de registro
      if (filters.register_form) {
        const conditions = [];
        for (const [question_id, content] of Object.entries(register_form)) {
          if (Array.isArray(content)) {
            if (content.length > 0) {
              // Manejar arreglos no vacíos
              conditions.push(`u.id IN (
                  SELECT uq.user_id FROM user_question uq
                  INNER JOIN user_question_answer uqa ON uq.id = uqa.user_question_id
                  WHERE uq.question_id = ? AND uqa.answer_id IN (${content.map(() => '?').join(',')})
                )`);
              params.push(question_id, ...content);
            }
            // Si el arreglo está vacío, no agregar ninguna condición
          } else if (content) {
            // Manejar valores únicos no nulos/definidos
            conditions.push(`u.id IN (
                SELECT uq.user_id FROM user_question uq
                INNER JOIN user_question_answer uqa ON uq.id = uqa.user_question_id
                WHERE uq.question_id = ? AND uqa.answer_id = ?
              )`);
            params.push(question_id, content);
          }
          // Si content es falsy (e.g., null, undefined, vacío), no agregar ninguna condición
        }
        if (conditions.length > 0) {
          whereClauses.push(conditions.join(' AND '));
        }
      }

      // Filtro específico para clientes
      if (cabecera.role === 'client') {
        whereClauses.push(`cu.client_id = ?`);
        params.push(cabecera.client_id);
      }

      // Construir la consulta SQL
      const query = `
        SELECT u.id AS user_id,
               q.id AS question_id,
               at.id AS answer_type_id,
               ${language === 'en' ? 'q.name' : 'q.name_es'} AS question,
               a.id AS answer_id,
               ${language === 'en' ? 'a.name' : 'a.name_es'} AS answer,
               uq.answer_text AS answer_text,
               uq.answer_number AS answer_number
        FROM user u
        ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
        INNER JOIN question q ON q.enabled = 'Y' AND q.answer_type_id IN (3, 4)
        LEFT JOIN answer_type at ON q.answer_type_id = at.id
        LEFT JOIN user_question uq ON u.id = uq.user_id AND uq.question_id = q.id
        LEFT JOIN user_question_answer uqa ON uq.id = uqa.user_question_id
        LEFT JOIN answer a ON a.id = uqa.answer_id AND a.question_id = q.id
        LEFT JOIN delivery_beneficiary db ON u.id = db.receiving_user_id
        WHERE ${whereClauses.join(' AND ')}
        GROUP BY u.id, q.id, a.id
        ORDER BY q.id, a.id, u.id
      `;

      const [rows] = await mysqlConnection.promise().query(query, params);

      // Procesamiento de resultados
      const questionsMap = {};

      for (const row of rows) {
        if (!questionsMap[row.question_id]) {
          questionsMap[row.question_id] = {
            question_id: row.question_id,
            question: row.question,
            answers: {}
          };
        }

        const question = questionsMap[row.question_id];

        if (row.answer_id) {
          if (!question.answers[row.answer_id]) {
            question.answers[row.answer_id] = {
              answer_id: row.answer_id,
              answer: row.answer,
              total: 0
            };
          }
          question.answers[row.answer_id].total += 1;
        }
      }

      // Obtener todas las posibles respuestas para cada pregunta
      const [answerRows] = await mysqlConnection.promise().query(`
        SELECT q.id AS question_id, 
               a.id AS answer_id, 
               ${language === 'en' ? 'a.name' : 'a.name_es'} AS answer
        FROM question q
        JOIN answer a ON q.id = a.question_id
        WHERE q.enabled = 'Y' AND q.answer_type_id IN (3, 4)
        ORDER BY q.id, a.id
      `);

      // Asegurarse de que todas las respuestas posibles están incluidas
      for (const row of answerRows) {
        if (!questionsMap[row.question_id]) {
          questionsMap[row.question_id] = {
            question_id: row.question_id,
            question: row.question,
            answers: {}
          };
        }

        const question = questionsMap[row.question_id];

        if (!question.answers[row.answer_id]) {
          question.answers[row.answer_id] = {
            answer_id: row.answer_id,
            answer: row.answer,
            total: 0
          };
        }
      }

      // Convertir el mapa en una lista
      const questions = Object.values(questionsMap).map(question => ({
        question_id: question.question_id,
        question: question.question,
        answers: Object.values(question.answers)
      }));

      res.json(questions);
    } catch (err) {
      console.error(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Forbidden');
  }
});

router.post('/metrics/demographic/gender', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND (db.location_id IN (' + locations.join() + ') OR u.first_location_id IN (' + locations.join() + ')) ';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND u.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND u.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + zipcode;
      }

      let toDate = new Date(to_date);
      toDate.setDate(toDate.getDate() + 1); // Añade un día a la fecha final

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
        ${language === 'en' ? 'g.name' : 'g.name_es'} AS name,
        COUNT(DISTINCT(u.id)) AS total
        FROM user u
        ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
        INNER JOIN gender AS g ON u.gender_id = g.id
        LEFT JOIN delivery_beneficiary AS db ON u.id = db.receiving_user_id
        WHERE u.role_id = 5 AND u.enabled = 'Y' 
        AND (CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? 
        OR u.id IN (SELECT db3.receiving_user_id FROM delivery_beneficiary db3 
                     WHERE CONVERT_TZ(db3.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ?))
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        ${cabecera.role === 'client' ? 'and cu.client_id = ?' : ''}
        GROUP BY g.name`,
        [from_date, toDate, from_date, toDate, cabecera.client_id]
      );

      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/metrics/demographic/ethnicity', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND (db.location_id IN (' + locations.join() + ') OR u.first_location_id IN (' + locations.join() + ')) ';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND u.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND u.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + zipcode;
      }

      let toDate = new Date(to_date);
      toDate.setDate(toDate.getDate() + 1); // Añade un día a la fecha final

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
        ${language === 'en' ? 'e.name' : 'e.name_es'} AS name,
        COUNT(DISTINCT(u.id)) AS total
        FROM user u
        ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
        INNER JOIN ethnicity AS e ON u.ethnicity_id = e.id
        LEFT JOIN delivery_beneficiary AS db ON u.id = db.receiving_user_id
        WHERE u.role_id = 5 AND u.enabled = 'Y' 
        AND (CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? 
        OR u.id IN (SELECT db3.receiving_user_id FROM delivery_beneficiary db3 
                     WHERE CONVERT_TZ(db3.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ?))
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        ${cabecera.role === 'client' ? 'and cu.client_id = ?' : ''}
        GROUP BY e.name`,
        [from_date, toDate, from_date, toDate, cabecera.client_id]
      );

      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/metrics/demographic/household', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND (db.location_id IN (' + locations.join() + ') OR u.first_location_id IN (' + locations.join() + ')) ';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND u.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND u.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + zipcode;
      }

      let toDate = new Date(to_date);
      toDate.setDate(toDate.getDate() + 1); // Añade un día a la fecha final

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
        u.household_size AS name,
        COUNT(DISTINCT(u.id)) AS total
        FROM user u
        ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
        LEFT JOIN delivery_beneficiary AS db ON u.id = db.receiving_user_id
        WHERE u.role_id = 5 AND u.enabled = 'Y' 
       AND (CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? 
        OR u.id IN (SELECT db3.receiving_user_id FROM delivery_beneficiary db3 
                     WHERE CONVERT_TZ(db3.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ?))
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        ${cabecera.role === 'client' ? 'and cu.client_id = ?' : ''}
        GROUP BY u.household_size
        ORDER BY u.household_size`,
        [from_date, toDate, from_date, toDate, cabecera.client_id]
      );

      // Calcular el promedio
      let sum = 0;
      let count = 0;
      for (const row of rows) {
        sum += row.name * row.total;
        count += row.total;
      }
      const average = Number((sum / count).toFixed(2));

      // Calcular la mediana
      rows.sort((a, b) => a.name - b.name);
      let median;
      let accumulatedCount = 0;
      for (const row of rows) {
        accumulatedCount += row.total;
        if (accumulatedCount >= count / 2) {
          median = row.name;
          break;
        }
      }

      // Convertir los números a cadenas
      for (const row of rows) {
        row.name = String(row.name);
      }
      res.json({ average: average, median: median, data: rows });
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/metrics/demographic/age', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND (db.location_id IN (' + locations.join() + ') OR u.first_location_id IN (' + locations.join() + ')) ';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND u.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND u.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + zipcode;
      }

      let toDate = new Date(to_date);
      toDate.setDate(toDate.getDate() + 1); // Añade un día a la fecha final

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
        TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) AS name,
        COUNT(DISTINCT(u.id)) AS total
        FROM user u
        ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
        LEFT JOIN delivery_beneficiary AS db ON u.id = db.receiving_user_id
        WHERE u.role_id = 5 AND u.enabled = 'Y' 
        AND (CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? 
        OR u.id IN (SELECT db3.receiving_user_id FROM delivery_beneficiary db3 
                     WHERE CONVERT_TZ(db3.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ?))
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        ${cabecera.role === 'client' ? 'and cu.client_id = ?' : ''}
        GROUP BY name
        ORDER BY name`,
        [from_date, toDate, from_date, toDate, cabecera.client_id]
      );

      // Calcular el promedio
      let sum = 0;
      let count = 0;
      for (const row of rows) {
        sum += row.name * row.total;
        count += row.total;
      }
      const average = Number((sum / count).toFixed(2));

      // Calcular la mediana
      let median;
      let accumulatedCount = 0;
      for (const row of rows) {
        accumulatedCount += row.total;
        if (accumulatedCount >= count / 2) {
          median = row.name;
          break;
        }
      }

      // Convertir los números a cadenas
      for (const row of rows) {
        row.name = String(row.name);
      }

      res.json({ average: average, median: median, data: rows });
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/metrics/volunteer/gender', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND v.location_id IN (' + locations.join() + ')) ';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND v.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND v.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND v.zipcode = ' + zipcode;
      }

      let toDate = new Date(to_date);
      toDate.setDate(toDate.getDate() + 1); // Añade un día a la fecha final

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
        ${language === 'en' ? 'g.name' : 'g.name_es'} AS name,
        COUNT(DISTINCT(v.id)) AS total
        FROM volunteer as v
        INNER JOIN gender AS g ON v.gender_id = g.id
        WHERE CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? 
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        GROUP BY g.name`,
        [from_date, toDate]
      );

      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/metrics/volunteer/ethnicity', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND v.location_id IN (' + locations.join() + ')) ';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND v.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND v.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND v.zipcode = ' + zipcode;
      }

      let toDate = new Date(to_date);
      toDate.setDate(toDate.getDate() + 1); // Añade un día a la fecha final

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
        ${language === 'en' ? 'e.name' : 'e.name_es'} AS name,
        COUNT(DISTINCT(v.id)) AS total
        FROM volunteer as v
        INNER JOIN ethnicity AS e ON v.ethnicity_id = e.id
        WHERE CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? 
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        GROUP BY e.name`,
        [from_date, toDate]
      );

      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/metrics/volunteer/location', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND v.location_id IN (' + locations.join() + ')) ';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND v.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND v.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND v.zipcode = ' + zipcode;
      }

      let toDate = new Date(to_date);
      toDate.setDate(toDate.getDate() + 1); // Añade un día a la fecha final

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
        l.community_city AS name,
        COUNT(DISTINCT(v.id)) AS total
        FROM volunteer AS v
        INNER JOIN location AS l ON v.location_id = l.id
        WHERE CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? 
        
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        GROUP BY l.community_city
        ORDER BY l.community_city`,
        [from_date, toDate]
      );

      // Calcular el promedio
      let sum = 0;
      let count = 0;
      for (const row of rows) {
        sum += row.name * row.total;
        count += row.total;
      }
      const average = Number((sum / count).toFixed(2));

      // Calcular la mediana
      rows.sort((a, b) => a.name - b.name);
      let median;
      let accumulatedCount = 0;
      for (const row of rows) {
        accumulatedCount += row.total;
        if (accumulatedCount >= count / 2) {
          median = row.name;
          break;
        }
      }

      // Convertir los números a cadenas
      for (const row of rows) {
        row.name = String(row.name);
      }
      res.json({ average: average, median: median, total: count, data: rows });
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/metrics/volunteer/age', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND v.location_id IN (' + locations.join() + ')) ';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND v.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND v.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND v.zipcode = ' + zipcode;
      }

      let toDate = new Date(to_date);
      toDate.setDate(toDate.getDate() + 1); // Añade un día a la fecha final

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
        TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) AS name,
        COUNT(DISTINCT(v.id)) AS total
        FROM volunteer as v
        WHERE CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles') BETWEEN ? AND ? 
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        GROUP BY name
        ORDER BY name`,
        [from_date, toDate]
      );

      // Calcular el promedio
      let sum = 0;
      let count = 0;
      for (const row of rows) {
        sum += row.name * row.total;
        count += row.total;
      }
      const average = Number((sum / count).toFixed(2));

      // Calcular la mediana
      let median;
      let accumulatedCount = 0;
      for (const row of rows) {
        accumulatedCount += row.total;
        if (accumulatedCount >= count / 2) {
          median = row.name;
          break;
        }
      }

      // Convertir los números a cadenas
      for (const row of rows) {
        row.name = String(row.name);
      }

      res.json({ average: average, median: median, data: rows });
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/metrics/participant/register', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      // const language = req.query.language || 'en'; // Not used in this specific query's results

      // Location filter for 'new' users (checks u.first_location_id)
      // and for the new type of 'recurring' users (checks u.first_location_id)
      var query_locations_new_user_first_location = '';
      if (locations.length > 0) {
        query_locations_new_user_first_location = `AND u.first_location_id IN (${locations.map(Number).join(',')}) `;
      }

      // Location filter for 'recurring' users (checks db_range.location_id for deliveries within the date range)
      var query_locations_recurring_delivery = '';
      if (locations.length > 0) {
        query_locations_recurring_delivery = `AND db_range.location_id IN (${locations.map(Number).join(',')})`;
      }
      
      // Location filter for original 'recurring' logic (checks db_prev_original.location_id for deliveries prior to current one)
      let original_recurring_location_condition_sql = '';
      if (locations.length > 0) {
        original_recurring_location_condition_sql = `AND db_prev_original.location_id IN (${locations.map(Number).join(',')})`;
      }

      var query_genders = '';
      if (genders.length > 0) {
        query_genders = `AND u.gender_id IN (${genders.map(Number).join(',')})`;
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = `AND u.ethnicity_id IN (${ethnicities.map(Number).join(',')})`;
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ${Number(min_age)}`;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ${Number(max_age)}`;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + mysqlConnection.escape(zipcode);
      }

      let params_metrics_participant = [];
      let clientCondition = '';

      if (cabecera.role === 'client') {
        clientCondition = 'AND cu.client_id = ?';
      }

      // Params for TOTAL subquery
      if (cabecera.role === 'client') {
        params_metrics_participant.push(cabecera.client_id);
      }

      // Params for NEW subquery
      params_metrics_participant.push(from_date); // For u.creation_date >= ?
      params_metrics_participant.push(to_date);   // For u.creation_date < DATE_ADD(?, INTERVAL 1 DAY)
      if (cabecera.role === 'client') {
        params_metrics_participant.push(cabecera.client_id);
      }

      // Params for RECURRING subquery
      // For db_range.creation_date range:
      params_metrics_participant.push(from_date); // For db_range.creation_date >= ?
      params_metrics_participant.push(to_date);   // For db_range.creation_date < DATE_ADD(?, INTERVAL 1 DAY)
      // For the OR (...) part:
      // Params for the new type of recurring:
      params_metrics_participant.push(from_date); // For u.creation_date < ?
      params_metrics_participant.push(from_date); // For db_no_past.creation_date < ?
      
      if (cabecera.role === 'client') {
        params_metrics_participant.push(cabecera.client_id);
      }

      const sqlQuery = `
        SELECT
          (SELECT COUNT(DISTINCT u.id)
              FROM user u
              ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
              WHERE u.role_id = 5
                AND u.enabled = 'Y' ${clientCondition}
          ) AS total,
          (SELECT COUNT(DISTINCT u.id)
              FROM user u
              ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
              WHERE u.role_id = 5
                AND u.enabled = 'Y'
                AND CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                AND CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
                ${clientCondition}
                ${query_locations_new_user_first_location}
                ${query_genders}
                ${query_ethnicities}
                ${query_min_age}
                ${query_max_age}
                ${query_zipcode}
          ) AS new,
          (SELECT COUNT(DISTINCT db_range.receiving_user_id)
              FROM delivery_beneficiary db_range
              INNER JOIN user u ON db_range.receiving_user_id = u.id
              ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
              WHERE 
                CONVERT_TZ(db_range.creation_date, '+00:00', 'America/Los_Angeles') >= ? 
                AND CONVERT_TZ(db_range.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
                AND u.role_id = 5 AND u.enabled = 'Y'
                ${clientCondition}
                ${query_locations_recurring_delivery}
                ${query_genders}
                ${query_ethnicities}
                ${query_min_age}
                ${query_max_age}
                ${query_zipcode}
                AND (
                    -- Original recurring: had a delivery prior to this specific db_range delivery (respecting location filter for that prior delivery)
                    EXISTS (
                        SELECT 1
                        FROM delivery_beneficiary db_prev_original
                        WHERE db_prev_original.receiving_user_id = u.id
                          AND CONVERT_TZ(db_prev_original.creation_date, '+00:00', 'America/Los_Angeles') < CONVERT_TZ(db_range.creation_date, '+00:00', 'America/Los_Angeles')
                          ${original_recurring_location_condition_sql}
                    )
                    OR
                    -- New type of recurring: registered before from_date, first_loc matches (if loc filter), AND no deliveries ANYWHERE before from_date
                    (
                        CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') < ? 
                        ${query_locations_new_user_first_location} 
                        AND NOT EXISTS (
                            SELECT 1
                            FROM delivery_beneficiary db_no_past
                            WHERE db_no_past.receiving_user_id = u.id
                              AND CONVERT_TZ(db_no_past.creation_date, '+00:00', 'America/Los_Angeles') < ? 
                        )
                    )
                )
          ) AS recurring
        LIMIT 1`;

      const [rows] = await mysqlConnection.promise().query(sqlQuery, params_metrics_participant);

      if (rows[0]) {
        res.json({ total: rows[0].total, new: rows[0].new, recurring: rows[0].recurring });
      } else {
        res.json({ total: 0, new: 0, recurring: 0 });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
});

router.post('/metrics/participant/email', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND ( (db.location_id IN (' + locations.join() + ') AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\' AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY) ) OR u.first_location_id IN (' + locations.join() + ') ) ';
        // 
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND u.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND u.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + zipcode;
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
          IF(u.email IS NULL, ${language === 'en' ? "'No'" : "'No'"}, ${language === 'en' ? "'Yes'" : "'Si'"}) AS name,
          COUNT(DISTINCT(u.id)) AS total
          FROM user u
          ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
          
          WHERE u.id IN (SELECT DISTINCT u2.id 
                          FROM user u2
                          LEFT JOIN delivery_beneficiary AS db ON u2.id = db.receiving_user_id
                          WHERE u2.role_id = 5 AND u2.enabled = 'Y' 
                          ${query_from_date}
                          ${query_to_date}
                          ${query_locations}
                          ${query_genders}
                          ${query_ethnicities}
                          ${query_min_age}
                          ${query_max_age}
                          ${query_zipcode}
                        )
          ${cabecera.role === 'client' ? 'and cu.client_id = ?' : ''}
          GROUP BY name`,
        [cabecera.client_id]
      );

      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/metrics/participant/phone', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(u.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND ( (db.location_id IN (' + locations.join() + ') AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\' AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY) ) OR u.first_location_id IN (' + locations.join() + ')) ';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND u.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND u.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND u.zipcode = ' + zipcode;
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
          IF(u.phone IS NULL, ${language === 'en' ? "'No'" : "'No'"}, ${language === 'en' ? "'Yes'" : "'Si'"}) AS name,
          COUNT(DISTINCT(u.id)) AS total
          FROM user u
          ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
          
          WHERE u.id IN (SELECT DISTINCT u2.id 
                          FROM user u2
                          LEFT JOIN delivery_beneficiary AS db ON u2.id = db.receiving_user_id
                          WHERE u2.role_id = 5 AND u2.enabled = 'Y' 
                          ${query_from_date}
                          ${query_to_date}
                          ${query_locations}
                          ${query_genders}
                          ${query_ethnicities}
                          ${query_min_age}
                          ${query_max_age}
                          ${query_zipcode}
                        )
          ${cabecera.role === 'client' ? 'and cu.client_id = ?' : ''}
          GROUP BY name`,
        [cabecera.client_id]
      );

      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/metrics/product/reach', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director' || cabecera.role === 'auditor') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const providers = filters.providers || [];
      const stocker_upload = filters.stocker_upload || [];
      const transported_by = filters.transported_by || [];
      const product_types = filters.product_types || [];

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      var query_from_date_product = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
        query_from_date_product = 'AND dt.date >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      var query_to_date_product = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
        query_to_date_product = 'AND dt.date < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      var query_locations_product = '';
      if (locations.length > 0) {
        query_locations = 'AND db.location_id IN (' + locations.join() + ')';
        query_locations_product = 'AND dt.location_id IN (' + locations.join() + ')';
      }
      var query_providers = '';
      if (providers.length > 0) {
        query_providers = 'AND dt.provider_id IN (' + providers.join() + ')';
      }
      var query_product_types = '';
      if (product_types.length > 0) {
        query_product_types = 'AND p.product_type_id IN (' + product_types.join() + ')';
      }
      var query_stocker_upload = '';
      if (stocker_upload.length > 0) {
        query_stocker_upload = 'AND sl.user_id IN (' + stocker_upload.join() + ')';
      }
      var query_transported_by = '';
      if (transported_by.length > 0) {
        query_transported_by = 'AND dt.transported_by_id IN (' + transported_by.join() + ')';
      }

      const [rows_reach] = await mysqlConnection.promise().query(
        `SELECT 
          SUM(u.household_size) AS reach
          FROM (
            SELECT DISTINCT u.id, u.household_size
            FROM delivery_beneficiary as db
            INNER JOIN user as u ON db.receiving_user_id = u.id
            ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
            WHERE u.role_id = 5 AND u.enabled = 'Y' 
            ${query_from_date}
            ${query_to_date}
            ${query_locations}
            ${cabecera.role === 'client' ? 'and cu.client_id = ?' : ''}
          ) as u`,
        [cabecera.client_id]
      );

      // Modified query based on whether product_types filter is provided
      let poundsDeliveredQuery;
      if (product_types.length > 0) {
        // When product_types is specified, use pdt.quantity (existing behavior)
        poundsDeliveredQuery = `
          SELECT 
            SUM(pdt.quantity) AS poundsDelivered
            FROM donation_ticket as dt
            INNER JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id and sl.operation_id = 5
            INNER JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
            INNER JOIN product as p ON pdt.product_id = p.id
            ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
            WHERE dt.enabled = 'Y'
            ${query_from_date_product}
            ${query_to_date_product}
            ${query_locations_product}
            ${query_providers}
            ${query_product_types}
            ${query_stocker_upload}
            ${query_transported_by}
            ${cabecera.role === 'client' ? 'and cl.client_id = ?' : ''}
          `;
      } else {
        // When product_types is not specified, use dt.total_weight
        poundsDeliveredQuery = `
          SELECT 
            SUM(dt.total_weight) AS poundsDelivered
            FROM donation_ticket as dt
            INNER JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id and sl.operation_id = 5
            ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
            WHERE dt.enabled = 'Y'
            ${query_from_date_product}
            ${query_to_date_product}
            ${query_locations_product}
            ${query_providers}
            ${query_stocker_upload}
            ${query_transported_by}
            ${cabecera.role === 'client' ? 'and cl.client_id = ?' : ''}
          `;
      }

      const [rows_poundsDelivered] = await mysqlConnection.promise().query(
        poundsDeliveredQuery,
        [cabecera.client_id]
      );

      rows_reach_total = rows_reach[0] ? rows_reach[0].reach : 0;
      rows_poundsDelivered_total = rows_poundsDelivered[0] ? rows_poundsDelivered[0].poundsDelivered : 0;

      res.json({ reach: rows_reach_total, poundsDelivered: rows_poundsDelivered_total });

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Unauthorized');
  }
}
);

router.post('/view/worker/scannedQR/:idUser', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    try {
      const { idUser } = req.params;
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      from_date = from_date.split('T')[0];
      to_date = to_date.split('T')[0];
      const locations = filters.locations || [];
      const workers = filters.workers || [];

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND location_id IN (' + locations.join() + ')';
      }
      var query_workers = '';
      if (workers.length > 0) {
        query_workers = 'AND delivering_user_id IN (' + workers.join() + ')';
      } else {
        if (idUser != '0') {
          query_workers = 'AND delivering_user_id = ' + idUser;
        }
      }
      // Consulta para "New"
      const [newRows] = await mysqlConnection.promise().query(
        `SELECT 
          ${language === 'en' ? '"New"' : 'Nuevos'} AS name,
          COUNT(DISTINCT receiving_user_id) AS total
          FROM delivery_beneficiary
          WHERE approved = 'Y'
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_workers}
          AND receiving_user_id NOT IN (
            SELECT receiving_user_id
            FROM delivery_beneficiary
            WHERE approved = 'Y'
            AND creation_date < CONVERT_TZ(?, '+00:00', 'America/Los_Angeles')
          )`,
        [from_date]
      );

      // Consulta para "Recurring"
      const [recurringRows] = await mysqlConnection.promise().query(
        `SELECT 
          ${language === 'en' ? '"Recurring"' : 'Recurrentes'} AS name,
          COUNT(DISTINCT receiving_user_id) AS total
          FROM delivery_beneficiary
          WHERE approved = 'Y'
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_workers}
          AND receiving_user_id IN (
            SELECT receiving_user_id
            FROM delivery_beneficiary
            WHERE approved = 'Y'
            AND creation_date < CONVERT_TZ(?, '+00:00', 'America/Los_Angeles')
          )`,
        [from_date]
      );

      const result = [
        newRows[0],
        recurringRows[0]
      ];

      res.json(result);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Forbidden');
  }
});

router.post('/view/worker/scanHistory/:idUser', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    try {
      const { idUser } = req.params;
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const workers = filters.workers || [];

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND location_id IN (' + locations.join() + ')';
      }
      var query_workers = '';
      if (workers.length > 0) {
        query_workers = 'AND delivering_user_id IN (' + workers.join() + ')';
      } else {
        if (idUser != '0') {
          query_workers = 'AND delivering_user_id = ' + idUser;
        }
      }
      // Consulta para "New" agrupada por día
      const [newRows] = await mysqlConnection.promise().query(
        `SELECT 
          DATE(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')) AS name,
          COUNT(DISTINCT receiving_user_id) AS value
          FROM delivery_beneficiary AS db1
          WHERE approved = 'Y'
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_workers}
          AND NOT EXISTS (
            SELECT 1
            FROM delivery_beneficiary AS db2
            WHERE db2.receiving_user_id = db1.receiving_user_id
            AND db2.approved = 'Y'
            AND db2.creation_date < db1.creation_date
          )
          GROUP BY DATE(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))`,
        []
      );

      // Consulta para "Recurring" agrupada por día
      const [recurringRows] = await mysqlConnection.promise().query(
        `SELECT 
          DATE(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')) AS name,
          COUNT(DISTINCT receiving_user_id) AS value
          FROM delivery_beneficiary AS db1
          WHERE approved = 'Y'
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_workers}
          AND EXISTS (
            SELECT 1
            FROM delivery_beneficiary AS db2
            WHERE db2.receiving_user_id = db1.receiving_user_id
            AND db2.approved = 'Y'
            AND db2.creation_date < db1.creation_date
          )
          GROUP BY DATE(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'))`,
        []
      );

      // Obtener los días únicos de ambos conjuntos de resultados
      const uniqueDays = new Set([
        ...newRows.map(row => row.name),
        ...recurringRows.map(row => row.name)
      ]);

      // Crear un objeto para cada conjunto de resultados
      const newMap = {};
      newRows.forEach(row => {
        newMap[row.name] = row.value;
      });

      const recurringMap = {};
      recurringRows.forEach(row => {
        recurringMap[row.name] = row.value;
      });

      // Construir las series finales
      const series_new = [];
      const series_recurring = [];

      uniqueDays.forEach(day => {
        series_new.push({
          name: day,
          value: newMap[day] || 0
        });
        series_recurring.push({
          name: day,
          value: recurringMap[day] || 0
        });
      });

      // Ordenar las series por fecha
      series_new.sort((a, b) => new Date(a.name) - new Date(b.name));
      series_recurring.sort((a, b) => new Date(a.name) - new Date(b.name));

      const result = [
        { name: language === 'en' ? 'New' : 'Nuevos', series: series_new },
        { name: language === 'en' ? 'Recurring' : 'Recurrentes', series: series_recurring }
      ];

      res.json(result);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(403).json('Forbidden');
  }
});

router.post('/metrics/participant/register_history', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (
    cabecera.role === 'admin' ||
    cabecera.role === 'client' ||
    cabecera.role === 'director' ||
    cabecera.role === 'auditor'
  ) {
    try {
      const filters = req.body;
      let from_date = filters.from_date || null;
      let to_date = filters.to_date || null;
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;
      const interval = filters.interval || 'month';
      const language = req.query.language || 'en';

      const laTimeZone = "'America/Los_Angeles'";
      const utcTimeZone = "'+00:00'";

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      } else {
        const [dateRange] = await mysqlConnection
          .promise()
          .query(
            `SELECT 
              MIN(CONVERT_TZ(creation_date, ${utcTimeZone}, ${laTimeZone})) AS min_date
            FROM (
              SELECT creation_date FROM user WHERE enabled = 'Y' AND role_id = 5
              UNION ALL
              SELECT creation_date FROM delivery_beneficiary
            ) AS combined_dates`
          );
        from_date = dateRange[0].min_date ? new Date(dateRange[0].min_date).toISOString().slice(0, 10) : '1970-01-01';
      }

      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      } else {
        const [dateRange] = await mysqlConnection
          .promise()
          .query(
            `SELECT 
              MAX(CONVERT_TZ(creation_date, ${utcTimeZone}, ${laTimeZone})) AS max_date
            FROM (
              SELECT creation_date FROM user WHERE enabled = 'Y' AND role_id = 5
              UNION ALL
              SELECT creation_date FROM delivery_beneficiary
            ) AS combined_dates`
          );
        to_date = dateRange[0].max_date ? new Date(dateRange[0].max_date).toISOString().slice(0, 10) : new Date().toISOString().slice(0,10);
      }

      const isValidDate = (date) => /^\d{4}-\d{2}-\d{2}$/.test(date);
      if (!isValidDate(from_date) || !isValidDate(to_date)) {
        return res.status(400).send('Invalid date format.');
      }
      
      const from_date_param_original = from_date;
      const to_date_obj_for_exclusive = new Date(to_date);
      to_date_obj_for_exclusive.setDate(to_date_obj_for_exclusive.getDate() + 1);
      const to_date_exclusive_param = to_date_obj_for_exclusive.toISOString().slice(0, 10);

      let periodExpressionUser;
      let periodExpressionDelivery;
      switch (interval) {
        case 'day':
          periodExpressionUser = `DATE_FORMAT(CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone}), '%Y-%m-%d')`;
          periodExpressionDelivery = `DATE_FORMAT(CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone}), '%Y-%m-%d')`;
          break;
        case 'week':
          periodExpressionUser = `DATE_FORMAT(CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone}), '%x-W%v')`;
          periodExpressionDelivery = `DATE_FORMAT(CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone}), '%x-W%v')`;
          break;
        case 'month':
          periodExpressionUser = `DATE_FORMAT(CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone}), '%Y-%m')`;
          periodExpressionDelivery = `DATE_FORMAT(CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone}), '%Y-%m')`;
          break;
        case 'quarter':
          periodExpressionUser = `CONCAT(YEAR(CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone})), '-Q', QUARTER(CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone})))`;
          periodExpressionDelivery = `CONCAT(YEAR(CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone})), '-Q', QUARTER(CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone})))`;
          break;
        case 'year':
          periodExpressionUser = `DATE_FORMAT(CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone}), '%Y')`;
          periodExpressionDelivery = `DATE_FORMAT(CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone}), '%Y')`;
          break;
        default:
          periodExpressionUser = `DATE_FORMAT(CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone}), '%Y-%m')`;
          periodExpressionDelivery = `DATE_FORMAT(CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone}), '%Y-%m')`;
          break;
      }

      const periods = generatePeriods(from_date, to_date, interval); // generatePeriods should use LA dates

      let clientConditionSql = '';
      const clientParams = [];
      if (cabecera.role === 'client') {
        clientConditionSql = 'AND cu.client_id = ?';
        clientParams.push(cabecera.client_id);
      }

      const demographicParams = [];
      let demographic_filters_sql = '';
      if (genders.length > 0) {
        demographic_filters_sql += ` AND u.gender_id IN (${genders.map(() => '?').join(',')})`;
        demographicParams.push(...genders.map(Number));
      }
      if (ethnicities.length > 0) {
        demographic_filters_sql += ` AND u.ethnicity_id IN (${ethnicities.map(() => '?').join(',')})`;
        demographicParams.push(...ethnicities.map(Number));
      }
      if (filters.min_age) {
        demographic_filters_sql += ` AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), ${utcTimeZone}, ${laTimeZone}))) >= ?`;
        demographicParams.push(Number(min_age));
      }
      if (filters.max_age) {
        demographic_filters_sql += ` AND TIMESTAMPDIFF(YEAR, u.date_of_birth, DATE(CONVERT_TZ(NOW(), ${utcTimeZone}, ${laTimeZone}))) <= ?`;
        demographicParams.push(Number(max_age));
      }
      if (filters.zipcode) {
        demographic_filters_sql += ' AND u.zipcode = ?';
        demographicParams.push(zipcode);
      }

      let query_locations_new_user_first_location_history = '';
      const location_params_for_first_location = [];
      if (locations.length > 0) {
        query_locations_new_user_first_location_history = `AND u.first_location_id IN (${locations.map(() => '?').join(',')})`;
        location_params_for_first_location.push(...locations.map(Number));
      }

      let query_locations_recurring_delivery_history = '';
      const location_params_for_recurring_delivery = [];
      if (locations.length > 0) {
        query_locations_recurring_delivery_history = `AND db_current.location_id IN (${locations.map(() => '?').join(',')})`;
        location_params_for_recurring_delivery.push(...locations.map(Number));
      }
      
      let original_recurring_location_condition_sql_history = '';
      const location_params_for_original_recurring = [];
      if (locations.length > 0) {
        original_recurring_location_condition_sql_history = `AND db_prev_original.location_id IN (${locations.map(() => '?').join(',')})`;
        location_params_for_original_recurring.push(...locations.map(Number));
      }

      const newUsersParams = [
        from_date_param_original, 
        to_date_exclusive_param,
        ...demographicParams,
        ...clientParams, // clientParams for clientConditionSql
        ...location_params_for_first_location
      ];
      
      const newUsersQuery = `
        SELECT
          ${periodExpressionUser} AS period,
          COUNT(DISTINCT u.id) AS new_users
        FROM user u
        ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
        WHERE u.role_id = 5
          AND u.enabled = 'Y'
          AND CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone}) >= ?
          AND CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone}) < ?
          ${clientConditionSql}
          ${demographic_filters_sql}
          ${query_locations_new_user_first_location_history}
        GROUP BY period
      `;
      
      const recurringUsersParams = [
        from_date_param_original,
        to_date_exclusive_param,
        ...demographicParams,
        ...clientParams, // For clientConditionSql on u
        ...location_params_for_recurring_delivery, // For query_locations_recurring_delivery_history
        // Params for the AND ( (EXISTS) OR (NEW_TYPE_RECURRING) ) block
        ...location_params_for_original_recurring, // For original_recurring_location_condition_sql_history
        from_date_param_original, // For u.creation_date < ? in NEW_TYPE_RECURRING
        ...location_params_for_first_location, // For query_locations_new_user_first_location_history in NEW_TYPE_RECURRING
        from_date_param_original  // For db_no_past.creation_date < ? in NEW_TYPE_RECURRING
      ];

      const recurringUsersQuery = `
        SELECT
          ${periodExpressionDelivery} AS period,
          COUNT(DISTINCT db_current.receiving_user_id) AS recurring_users
        FROM delivery_beneficiary db_current
        INNER JOIN user u ON db_current.receiving_user_id = u.id
        ${cabecera.role === 'client' ? 'INNER JOIN client_user cu ON u.id = cu.user_id' : ''}
        WHERE 
          CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone}) >= ? 
          AND CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone}) < ?
          AND u.role_id = 5 AND u.enabled = 'Y'
          ${clientConditionSql}
          ${demographic_filters_sql}
          ${query_locations_recurring_delivery_history}
          AND (
              EXISTS (
                  SELECT 1
                  FROM delivery_beneficiary db_prev_original
                  WHERE db_prev_original.receiving_user_id = u.id
                    AND CONVERT_TZ(db_prev_original.creation_date, ${utcTimeZone}, ${laTimeZone}) < CONVERT_TZ(db_current.creation_date, ${utcTimeZone}, ${laTimeZone})
                    ${original_recurring_location_condition_sql_history}
              )
              OR
              (
                  CONVERT_TZ(u.creation_date, ${utcTimeZone}, ${laTimeZone}) < ? 
                  ${query_locations_new_user_first_location_history} 
                  AND NOT EXISTS (
                      SELECT 1
                      FROM delivery_beneficiary db_no_past
                      WHERE db_no_past.receiving_user_id = u.id
                        AND CONVERT_TZ(db_no_past.creation_date, ${utcTimeZone}, ${laTimeZone}) < ? 
                  )
              )
          )
        GROUP BY period
      `;

      const [newUsersRows] = await mysqlConnection.promise().query(newUsersQuery, newUsersParams);
      const [recurringUsersRows] = await mysqlConnection.promise().query(recurringUsersQuery, recurringUsersParams);

      const periodsMap = new Map();
      periods.forEach(period => {
        periodsMap.set(period, { new_users: 0, recurring_users: 0 });
      });

      newUsersRows.forEach(row => {
        if (periodsMap.has(row.period)) {
          periodsMap.get(row.period).new_users = Number(row.new_users);
        }
      });

      recurringUsersRows.forEach(row => {
        if (periodsMap.has(row.period)) {
          periodsMap.get(row.period).recurring_users = Number(row.recurring_users);
        }
      });

      const categories = Array.from(periodsMap.keys());
      const newUsersData = categories.map(period => periodsMap.get(period).new_users);
      const recurringUsersData = categories.map(period => periodsMap.get(period).recurring_users);
      
      const formattedCategories = categories.map(c => formatPeriod(c, interval, language));


      const series = [
        { name: language === 'en' ? 'New' : 'Nuevos', data: newUsersData },
        { name: language === 'en' ? 'Recurring' : 'Recurrentes', data: recurringUsersData },
      ];

      res.json({ series, categories: formattedCategories });
    } catch (error) {
      console.error("Error in /metrics/participant/register_history:", error);
      res.status(500).json({ message: 'Internal server error', error: error.message });
    }
  } else {
    res.status(403).json('Forbidden');
  }
});

router.post('/metrics/participant/location_new_recurring', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (
    cabecera.role === 'admin' ||
    cabecera.role === 'client' ||
    cabecera.role === 'director' ||
    cabecera.role === 'auditor'
  ) {
    try {
      const filters = req.body;
      let from_date = filters.from_date || null;
      let to_date = filters.to_date || null;
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;
      const language = req.query.language || 'en';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      } else {
        // Si no se proporciona, obtener la fecha mínima de la base de datos
        const [dateRange] = await mysqlConnection
          .promise()
          .query(
            `SELECT 
              MIN(creation_date) AS min_date
            FROM (
              SELECT creation_date FROM user WHERE enabled = 'Y'
              UNION ALL
              SELECT creation_date FROM delivery_beneficiary
            ) AS combined_dates`
          );
        from_date = dateRange[0].min_date ? dateRange[0].min_date.toISOString().slice(0, 10) : '1970-01-01';
      }

      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      } else {
        // Si no se proporciona, obtener la fecha máxima de la base de datos
        const [dateRange] = await mysqlConnection
          .promise()
          .query(
            `SELECT 
              MAX(creation_date) AS max_date
            FROM (
              SELECT creation_date FROM user WHERE enabled = 'Y'
              UNION ALL
              SELECT creation_date FROM delivery_beneficiary
            ) AS combined_dates`
          );
        to_date = dateRange[0].max_date ? dateRange[0].max_date.toISOString().slice(0, 10) : new Date().toISOString().slice(0, 10);
      }

      // Validar las fechas para evitar inyección SQL
      const isValidDate = (date) => /^\d{4}-\d{2}-\d{2}$/.test(date);
      if (!isValidDate(from_date) || !isValidDate(to_date)) {
        return res.status(400).send('Invalid date format.');
      }

      // --- Parameterized Filters ---
      const paramsNew = [];
      const paramsRecurring = [];
      let query_conditions_new = ''; // Conditions applied to user table for 'new'
      let query_conditions_recurring = ''; // Conditions applied to user table for 'recurring'
      let query_join_client_user = '';
      let location_condition_new = ''; // Location condition for 'new' query
      let location_condition_recurring = ''; // Location condition for 'recurring' query
      const locationParams = [];

      if (genders.length > 0) {
        const genderPlaceholders = genders.map(() => '?').join(',');
        query_conditions_new += ` AND u.gender_id IN (${genderPlaceholders})`;
        query_conditions_recurring += ` AND u.gender_id IN (${genderPlaceholders})`;
        paramsNew.push(...genders);
        paramsRecurring.push(...genders);
      }
      if (ethnicities.length > 0) {
        const ethnicityPlaceholders = ethnicities.map(() => '?').join(',');
        query_conditions_new += ` AND u.ethnicity_id IN (${ethnicityPlaceholders})`;
        query_conditions_recurring += ` AND u.ethnicity_id IN (${ethnicityPlaceholders})`;
        paramsNew.push(...ethnicities);
        paramsRecurring.push(...ethnicities);
      }
      if (filters.min_age) {
        query_conditions_new += ` AND TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) >= ?`;
        query_conditions_recurring += ` AND TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) >= ?`;
        paramsNew.push(min_age);
        paramsRecurring.push(min_age);
      }
      if (filters.max_age) {
        query_conditions_new += ` AND TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) <= ?`;
        query_conditions_recurring += ` AND TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) <= ?`;
        paramsNew.push(max_age);
        paramsRecurring.push(max_age);
      }
      if (filters.zipcode) {
        query_conditions_new += ' AND u.zipcode = ?';
        query_conditions_recurring += ' AND u.zipcode = ?';
        paramsNew.push(zipcode);
        paramsRecurring.push(zipcode);
      }
      if (cabecera.role === 'client') {
        query_join_client_user = 'INNER JOIN client_user cu ON u.id = cu.user_id';
        query_conditions_new += ' AND cu.client_id = ?';
        query_conditions_recurring += ' AND cu.client_id = ?';
        paramsNew.push(cabecera.client_id);
        paramsRecurring.push(cabecera.client_id);
      }

      if (locations.length > 0) {
        const locationPlaceholders = locations.map(() => '?').join(',');
        // Location for NEW: Check first_location OR delivery location within period
        location_condition_new = ` AND (u.first_location_id IN (${locationPlaceholders}) OR db.location_id IN (${locationPlaceholders}))`;
        // Location for RECURRING: Check ONLY delivery location within period
        location_condition_recurring = ` AND db.location_id IN (${locationPlaceholders})`;
        locationParams.push(...locations); // Add location params once
      }
      // --- End Parameterized Filters ---

      // Adjust dates for queries
      const fromDateUTC = from_date + ' 00:00:00';
      let toDateObj = new Date(to_date);
      toDateObj.setDate(toDateObj.getDate() + 1); // Add day for exclusive end date
      const toDateUTCExclusive = toDateObj.toISOString().slice(0, 10) + ' 00:00:00'; // Use 00:00:00 of next day

      // Get relevant locations
      let locationQuery = '';
      let locationQueryParams = [];
      if (locations.length > 0) {
        locationQuery = 'WHERE l.id IN (' + locations.map(() => '?').join(',') + ')';
        locationQueryParams = [...locations];
      } else {
        // If no locations specified, get all locations associated with deliveries or users in the date range potentially?
        // For simplicity, let's get all locations if none are specified. Adjust if needed.
        locationQuery = '';
        locationQueryParams = [];
      }
      const [locationsRows] = await mysqlConnection.promise().query(
        `SELECT l.id, l.community_city AS name
         FROM location l
         ${locationQuery}
         ORDER BY l.community_city`,
        locationQueryParams
      );
      if (locationsRows.length === 0 && locations.length > 0) { // Check if specific locations were requested but none found
        return res.json({ series: [], categories: [] });
      }

      // Query for NEW users
      const newUsersQuery = `
        SELECT
          COALESCE(u.first_location_id, db.location_id) AS location_id,
          COUNT(DISTINCT u.id) AS new_count
        FROM user u
        LEFT JOIN delivery_beneficiary db ON u.id = db.receiving_user_id
            AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') >= ? /* Date filter for join */
            AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') < ?  /* Date filter for join */
        ${query_join_client_user}
        WHERE u.role_id = 5
          AND u.enabled = 'Y'
          AND CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') >= ?
          AND CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') < ?
          ${query_conditions_new}
          ${location_condition_new} /* Apply parameterized location condition */
        GROUP BY location_id
      `;
      // Params: db_date_from, db_date_to, user_date_from, user_date_to, ...demographic/client params, ...location params (potentially twice)
      const newUsersParams = [fromDateUTC, toDateUTCExclusive, fromDateUTC, toDateUTCExclusive, ...paramsNew, ...locationParams, ...(locations.length > 0 ? locationParams : [])]; // Add location params again if needed by the OR condition

      // Query for RECURRING users
      const recurringUsersQuery = `
        SELECT
          db.location_id AS location_id,
          COUNT(DISTINCT db.receiving_user_id) AS recurring_count
        FROM delivery_beneficiary db
        INNER JOIN user u ON db.receiving_user_id = u.id
        ${query_join_client_user}
        WHERE CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') >= ?
          AND CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles') < ?
          AND u.role_id = 5 AND u.enabled = 'Y'
          ${query_conditions_recurring}
          ${location_condition_recurring} /* Apply parameterized location condition for db.location_id */
          AND (
            -- Condition 1: User had a previous delivery to the current one (classic recurring)
            EXISTS (
              SELECT 1
              FROM delivery_beneficiary db_prev
              WHERE db_prev.receiving_user_id = u.id
                AND CONVERT_TZ(db_prev.creation_date, '+00:00', 'America/Los_Angeles') < CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles')
                ${locations.length > 0 ? `AND db_prev.location_id IN (${locations.map(() => '?').join(',')})` : ''}
            )
            OR
            -- Condition 2: User registered before the period, first_location_id matches filter (if any), and no deliveries before the period
            (
              CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles') < ?
              ${locations.length > 0 ? `AND u.first_location_id IN (${locations.map(() => '?').join(',')})` : ''}
              AND NOT EXISTS (
                SELECT 1
                FROM delivery_beneficiary db_past
                WHERE db_past.receiving_user_id = u.id
                  AND CONVERT_TZ(db_past.creation_date, '+00:00', 'America/Los_Angeles') < ?
              )
            )
          )
        GROUP BY db.location_id
      `;
      // Params:
      // 1. db.creation_date >= fromDateUTC
      // 2. db.creation_date < toDateUTCExclusive
      // 3. ...paramsRecurring (for query_conditions_recurring)
      // 4. ...locationParams (for location_condition_recurring on db.location_id)
      // For the AND ( (...) OR (...) ) block:
      // 5. ...locationParams (for EXISTS db_prev.location_id IN (...)) - if locations.length > 0
      // 6. fromDateUTC (for u.creation_date < ? in OR)
      // 7. ...locationParams (for u.first_location_id IN (...)) - if locations.length > 0
      // 8. fromDateUTC (for NOT EXISTS db_past.creation_date < ?)
      const recurringUsersParams = [
        fromDateUTC,
        toDateUTCExclusive,
        ...paramsRecurring,
        ...(locations.length > 0 ? locationParams : []), // For main db.location_id filter
        // Params for the new AND block
        ...(locations.length > 0 ? locationParams : []), // For EXISTS db_prev.location_id
        fromDateUTC, // For u.creation_date < ?
        ...(locations.length > 0 ? locationParams : []), // For u.first_location_id
        fromDateUTC  // For NOT EXISTS db_past.creation_date < ?
      ];
      // Execute queries
      const [newUsersRows] = await mysqlConnection.promise().query(newUsersQuery, newUsersParams);
      const [recurringUsersRows] = await mysqlConnection.promise().query(recurringUsersQuery, recurringUsersParams);

      // --- Processing results (keep existing logic) ---
      const locationsMap = new Map();
      // Use all locations if none specified, otherwise use filtered list
      const relevantLocations = locations.length > 0 ? locationsRows : await mysqlConnection.promise().query(`SELECT id, community_city AS name FROM location ORDER BY community_city`).then(([rows]) => rows);

      relevantLocations.forEach(location => {
        locationsMap.set(location.id, {
          id: location.id,
          name: location.name,
          new_users: 0,
          recurring_users: 0
        });
      });

      newUsersRows.forEach(row => {
        if (row.location_id && locationsMap.has(row.location_id)) { // Check if location_id is not null
          locationsMap.get(row.location_id).new_users = row.new_count;
        }
      });

      recurringUsersRows.forEach(row => {
        if (row.location_id && locationsMap.has(row.location_id)) { // Check if location_id is not null
          locationsMap.get(row.location_id).recurring_users = row.recurring_count;
        }
      });

      // Preparar los datos para la respuesta
      const locationData = Array.from(locationsMap.values());
      locationData.sort((a, b) => a.name.localeCompare(b.name)); // Sort alphabetically by name
      const categories = locationData.map(location => location.name);
      const newUsersData = locationData.map(location => location.new_users);
      const recurringUsersData = locationData.map(location => location.recurring_users);

      const series = [
        { name: language === 'en' ? 'New' : 'Nuevos', data: newUsersData },
        { name: language === 'en' ? 'Recurring' : 'Recurrentes', data: recurringUsersData },
      ];

      res.json({ series, categories });
    } catch (error) {
      console.log(error);
      res.status(500).send(error.message);
    }
  } else {
    res.status(403).send('Forbidden');
  }
});

// Funciones auxiliares
function generatePeriods(startDate, endDate, interval) {
  const periods = [];
  let current = new Date(new Date(startDate + 'T00:00:00.000Z').toLocaleString("en-US", {timeZone: "America/Los_Angeles"}));
  const end = new Date(new Date(endDate + 'T00:00:00.000Z').toLocaleString("en-US", {timeZone: "America/Los_Angeles"}));

  while (current <= end) {
    let period;
    const year = current.getFullYear();
    const month = current.getMonth(); // 0-11
    const day = current.getDate();

    switch (interval) {
      case 'day':
        period = `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
        current.setDate(current.getDate() + 1);
        break;
      case 'week':
        // This needs to match MySQL's %x-W%v format for the LA timezone.
        // Moment.js or a similar library would be robust here.
        // Simplified version, might not perfectly match MySQL's week definition across all edge cases.
        const tempDateForWeek = new Date(current.valueOf());
        tempDateForWeek.setDate(tempDateForWeek.getDate() - (tempDateForWeek.getDay() + 6) % 7); // Monday of the week
        const weekYear = tempDateForWeek.getFullYear();
        const firstDayOfYear = new Date(weekYear, 0, 1);
        const pastDaysOfYear = (tempDateForWeek - firstDayOfYear) / 86400000;
        const weekNumber = String(Math.ceil((pastDaysOfYear + firstDayOfYear.getDay() + 1) / 7)).padStart(2,'0');
        period = `${weekYear}-W${weekNumber}`; // Approximation
        current.setDate(current.getDate() + 7);
        break;
      case 'month':
        period = `${year}-${String(month + 1).padStart(2, '0')}`;
        current.setMonth(current.getMonth() + 1);
        break;
      case 'quarter':
        const quarter = Math.floor(month / 3) + 1;
        period = `${year}-Q${quarter}`;
        current.setMonth(current.getMonth() + 3);
        break;
      case 'year':
        period = `${year}`;
        current.setFullYear(current.getFullYear() + 1);
        break;
      default: // Default to month
        period = `${year}-${String(month + 1).padStart(2, '0')}`;
        current.setMonth(current.getMonth() + 1);
        break;
    }
    periods.push(period);
  }
  return periods;
}

router.post('/metrics/product/total_pounds', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (['admin', 'client', 'director', 'auditor'].includes(cabecera.role)) {
    try {
      const filters = req.body;
      let from_date = filters.from_date || null;
      let to_date = filters.to_date || null;
      const locations = filters.locations || [];
      const providers = filters.providers || [];
      const product_types = filters.product_types || [];
      const stocker_upload = filters.stocker_upload || [];
      const transported_by = filters.transported_by || [];
      const interval = filters.interval || 'month';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      // Obtener rango de fechas si no se proporcionan
      if (!from_date || !to_date) {
        const [dateRange] = await mysqlConnection.promise().query(
          `SELECT 
            MIN(date) AS min_date, 
            MAX(date) AS max_date 
          FROM donation_ticket 
          WHERE enabled = 'Y'`
        );
        if (!from_date) from_date = dateRange[0].min_date.toISOString().slice(0, 10);
        if (!to_date) to_date = dateRange[0].max_date.toISOString().slice(0, 10);
      }

      // Definir expresiones de período y intervalos de adición
      let dateAddInterval;
      let periodExpression;
      switch (interval) {
        case 'day':
          dateAddInterval = '1 DAY';
          periodExpression = "DATE_FORMAT(dt.date, '%Y-%m-%d')";
          break;
        case 'week':
          dateAddInterval = '1 WEEK';
          periodExpression = "DATE_FORMAT(dt.date, '%x-W%v')";
          break;
        case 'month':
          dateAddInterval = '1 MONTH';
          periodExpression = "DATE_FORMAT(dt.date, '%Y-%m')";
          break;
        case 'quarter':
          // Para trimestres, usamos CONCAT para incluir el número del trimestre
          dateAddInterval = '1 QUARTER';
          periodExpression = "CONCAT(YEAR(dt.date), '-Q', QUARTER(dt.date))";
          break;
        case 'year':
          dateAddInterval = '1 YEAR';
          periodExpression = "DATE_FORMAT(dt.date, '%Y')";
          break;
        default:
          dateAddInterval = '1 MONTH';
          periodExpression = "DATE_FORMAT(dt.date, '%Y-%m')";
          break;
      }

      // Construir condiciones y parámetros de la consulta
      let query_from_date = '';
      let query_to_date = '';
      let query_locations = '';
      let query_providers = '';
      let query_product_types = '';
      const params = [];

      if (from_date) {
        query_from_date = 'AND dt.date >= ?';
        params.push(from_date);
      }
      if (to_date) {
        query_to_date = 'AND dt.date < DATE_ADD(?, INTERVAL 1 DAY)';
        params.push(to_date);
      }
      if (locations.length > 0) {
        query_locations = 'AND dt.location_id IN (' + locations.map(() => '?').join(',') + ')';
        params.push(...locations);
      }
      if (providers.length > 0) {
        query_providers = 'AND dt.provider_id IN (' + providers.map(() => '?').join(',') + ')';
        params.push(...providers);
      }

      let useProductFilter = product_types.length > 0;

      if (useProductFilter) {
        query_product_types = 'AND p.product_type_id IN (' + product_types.map(() => '?').join(',') + ')';
        params.push(...product_types);
      }

      if (cabecera.role === 'client') {
        if (useProductFilter) {
          query_product_types += ' AND cl.client_id = ?';
        } else {
          query_product_types = ' AND cl.client_id = ?';
        }
        params.push(cabecera.client_id);
      }

      var query_stocker_upload = '';
      if (stocker_upload.length > 0) {
        query_stocker_upload = 'AND sl.user_id IN (' + stocker_upload.join() + ')';
      }
      var query_transported_by = '';
      if (transported_by.length > 0) {
        query_transported_by = 'AND dt.transported_by_id IN (' + transported_by.join() + ')';
      }

      // Construir la consulta SQL con el CTE
      let query;
      let cteParams;

      // Define the data selection - use total_weight when no product types are specified
      const dataSelection = useProductFilter ?
        "COALESCE(SUM(pdt.quantity), 0) AS data" :
        "COALESCE(SUM(dt.total_weight), 0) AS data";

      // Define product joins only when needed
      const productJoins = useProductFilter ?
        `LEFT JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
         LEFT JOIN product as p ON pdt.product_id = p.id
         LEFT JOIN product_type as pt ON p.product_type_id = pt.id` :
        '';

      if (interval === 'quarter') {
        // Para 'quarter', necesitamos cuatro parámetros en el CTE
        cteParams = [from_date, from_date, from_date, to_date];
        query = `
          WITH RECURSIVE date_ranges AS (
            SELECT 
              CONCAT(YEAR(?), '-Q', QUARTER(?)) AS period, 
              ? AS date
            UNION ALL
            SELECT 
              CONCAT(YEAR(DATE_ADD(date, INTERVAL ${dateAddInterval})), '-Q', QUARTER(DATE_ADD(date, INTERVAL ${dateAddInterval}))) AS period,
              DATE_ADD(date, INTERVAL ${dateAddInterval}) 
            FROM date_ranges
            WHERE DATE_ADD(date, INTERVAL ${dateAddInterval}) <= ?
          )
          SELECT 
            pr.name AS name,
            ${dataSelection},
            date_ranges.period AS period
          FROM date_ranges
          LEFT JOIN donation_ticket as dt ON 
            CONCAT(YEAR(dt.date), '-Q', QUARTER(dt.date)) = date_ranges.period
          LEFT JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id and sl.operation_id = 5
          LEFT JOIN provider as pr ON dt.provider_id = pr.id
          ${productJoins}
          ${cabecera.role === 'client' ? 'LEFT JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
          WHERE dt.enabled = 'Y'
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_providers}
          ${query_product_types}
          ${query_stocker_upload}
          ${query_transported_by}
          GROUP BY name, period
        `;
      } else {
        // Para otros intervalos, necesitamos tres parámetros en el CTE
        cteParams = [from_date, from_date, to_date];
        const formatString = interval === 'day' ? '%Y-%m-%d' :
          interval === 'week' ? '%x-W%v' :
            interval === 'month' ? '%Y-%m' :
              interval === 'year' ? '%Y' : '%Y-%m';

        query = `
          WITH RECURSIVE date_ranges AS (
            SELECT 
              DATE_FORMAT(?, '${formatString}') AS period, 
              ? AS date
            UNION ALL
            SELECT 
              DATE_FORMAT(DATE_ADD(date, INTERVAL ${dateAddInterval}), '${formatString}') AS period,
              DATE_ADD(date, INTERVAL ${dateAddInterval}) 
            FROM date_ranges
            WHERE DATE_ADD(date, INTERVAL ${dateAddInterval}) <= ?
          )
          SELECT 
            pr.name AS name,
            ${dataSelection},
            date_ranges.period AS period
          FROM date_ranges
          LEFT JOIN donation_ticket as dt ON 
            DATE_FORMAT(dt.date, '${formatString}') = date_ranges.period
          LEFT JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id and sl.operation_id = 5
          LEFT JOIN provider as pr ON dt.provider_id = pr.id
          ${productJoins}
          ${cabecera.role === 'client' ? 'LEFT JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
          WHERE dt.enabled = 'Y'
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_providers}
          ${query_product_types}
          ${query_stocker_upload}
          ${query_transported_by}
          GROUP BY name, period
        `;
      }

      // Combinar los parámetros del CTE con los demás parámetros
      const finalParams = cteParams.concat(params);

      const [rows] = await mysqlConnection.promise().query(query, finalParams);

      // Transformar las filas al formato deseado
      const categories = [...new Set(rows.map(row => row.period))].sort((a, b) => {
        if (interval === 'week') {
          const [yearA, weekA] = a.split('-W').map(Number);
          const [yearB, weekB] = b.split('-W').map(Number);
          const dateA = new Date(yearA, 0, (weekA - 1) * 7);
          const dateB = new Date(yearB, 0, (weekB - 1) * 7);
          return dateA - dateB;
        } else if (interval === 'quarter') {
          const [yearA, quarterA] = a.split('-Q').map(Number);
          const [yearB, quarterB] = b.split('-Q').map(Number);
          const dateA = new Date(yearA, (quarterA - 1) * 3);
          const dateB = new Date(yearB, (quarterB - 1) * 3);
          return dateA - dateB;
        } else {
          return new Date(a) - new Date(b);
        }
      });

      // Después del sort, formatear las categorías
      const formattedCategories = categories.map(c => formatPeriod(c, interval));

      const providersMap = new Map();

      // Inicializar providersMap con todos los proveedores y todos los periodos con datos en 0
      rows.forEach(row => {
        if (!providersMap.has(row.name)) {
          providersMap.set(row.name, Array(categories.length).fill(0));
        }
      });

      // Rellenar providersMap con datos reales
      rows.forEach(row => {
        const index = categories.indexOf(row.period);
        if (index !== -1) {
          providersMap.get(row.name)[index] = row.data;
        }
      });

      const series = Array.from(providersMap, ([name, data]) => ({ name, data }));

      const result = {
        series,
        categories: formattedCategories // usar las categorías formateadas
      };

      res.json(result);

    } catch (error) {
      console.log(error);
      res.status(500).send(error.message);
    }
  } else {
    res.status(403).send('Forbidden');
  }
});

router.post('/metrics/product/number_of_trips', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (['admin', 'client', 'director', 'auditor'].includes(cabecera.role)) {
    try {
      const filters = req.body;
      let from_date = filters.from_date || null;
      let to_date = filters.to_date || null;
      const locations = filters.locations || [];
      const providers = filters.providers || [];
      const product_types = filters.product_types || [];
      const stocker_upload = filters.stocker_upload || [];
      const transported_by = filters.transported_by || [];
      const interval = filters.interval || 'month';

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      // Obtener rango de fechas si no se proporcionan
      if (!from_date || !to_date) {
        const [dateRange] = await mysqlConnection.promise().query(
          `SELECT 
            MIN(date) AS min_date, 
            MAX(date) AS max_date 
          FROM donation_ticket 
          WHERE enabled = 'Y'`
        );
        if (!from_date) from_date = dateRange[0].min_date.toISOString().slice(0, 10);
        if (!to_date) to_date = dateRange[0].max_date.toISOString().slice(0, 10);
      }

      // Definir expresiones de período y intervalos de adición
      let dateAddInterval;
      let periodExpression;
      switch (interval) {
        case 'day':
          dateAddInterval = '1 DAY';
          periodExpression = "DATE_FORMAT(dt.date, '%Y-%m-%d')";
          break;
        case 'week':
          dateAddInterval = '1 WEEK';
          periodExpression = "DATE_FORMAT(dt.date, '%x-W%v')";
          break;
        case 'month':
          dateAddInterval = '1 MONTH';
          periodExpression = "DATE_FORMAT(dt.date, '%Y-%m')";
          break;
        case 'quarter':
          // Para trimestres, usamos CONCAT para incluir el número del trimestre
          dateAddInterval = '1 QUARTER';
          periodExpression = "CONCAT(YEAR(dt.date), '-Q', QUARTER(dt.date))";
          break;
        case 'year':
          dateAddInterval = '1 YEAR';
          periodExpression = "DATE_FORMAT(dt.date, '%Y')";
          break;
        default:
          dateAddInterval = '1 MONTH';
          periodExpression = "DATE_FORMAT(dt.date, '%Y-%m')";
          break;
      }

      // Construir condiciones y parámetros de la consulta
      let query_from_date = '';
      let query_to_date = '';
      let query_locations = '';
      let query_providers = '';
      let query_product_types = '';
      const params = [];

      if (from_date) {
        query_from_date = 'AND dt.date >= ?';
        params.push(from_date);
      }
      if (to_date) {
        query_to_date = 'AND dt.date < DATE_ADD(?, INTERVAL 1 DAY)';
        params.push(to_date);
      }
      if (locations.length > 0) {
        query_locations = 'AND dt.location_id IN (' + locations.map(() => '?').join(',') + ')';
        params.push(...locations);
      }
      if (providers.length > 0) {
        query_providers = 'AND dt.provider_id IN (' + providers.map(() => '?').join(',') + ')';
        params.push(...providers);
      }
      if (product_types.length > 0) {
        query_product_types = 'AND p.product_type_id IN (' + product_types.map(() => '?').join(',') + ')';
        params.push(...product_types);
      }
      if (cabecera.role === 'client') {
        query_product_types += ' AND cl.client_id = ?';
        params.push(cabecera.client_id);
      }
      var query_stocker_upload = '';
      if (stocker_upload.length > 0) {
        query_stocker_upload = 'AND sl.user_id IN (' + stocker_upload.join() + ')';
      }
      var query_transported_by = '';
      if (transported_by.length > 0) {
        query_transported_by = 'AND dt.transported_by_id IN (' + transported_by.join() + ')';
      }


      // Construir la consulta SQL con el CTE
      let query;
      let cteParams;
      if (interval === 'quarter') {
        // Para 'quarter', necesitamos cuatro parámetros en el CTE
        cteParams = [from_date, from_date, from_date, to_date];
        query = `
          WITH RECURSIVE date_ranges AS (
            SELECT 
              CONCAT(YEAR(?), '-Q', QUARTER(?)) AS period, 
              ? AS date
            UNION ALL
            SELECT 
              CONCAT(YEAR(DATE_ADD(date, INTERVAL ${dateAddInterval})), '-Q', QUARTER(DATE_ADD(date, INTERVAL ${dateAddInterval}))) AS period,
              DATE_ADD(date, INTERVAL ${dateAddInterval}) 
            FROM date_ranges
            WHERE DATE_ADD(date, INTERVAL ${dateAddInterval}) <= ?
          )
          SELECT 
            tb.name AS name,
            COALESCE(COUNT(DISTINCT dt.id), 0) AS data,
            date_ranges.period AS period
          FROM date_ranges
          LEFT JOIN donation_ticket as dt ON 
            CONCAT(YEAR(dt.date), '-Q', QUARTER(dt.date)) = date_ranges.period
          LEFT JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id
          LEFT JOIN transported_by as tb ON dt.transported_by_id = tb.id
          LEFT JOIN provider as pr ON dt.provider_id = pr.id
          LEFT JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
          LEFT JOIN product as p ON pdt.product_id = p.id
          LEFT JOIN product_type as pt ON p.product_type_id = pt.id
          ${cabecera.role === 'client' ? 'LEFT JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
          WHERE dt.enabled = 'Y' and tb.enabled = 'Y' and sl.operation_id = 5
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_providers}
          ${query_product_types}
          ${query_stocker_upload}
          ${query_transported_by}
          GROUP BY name, period
        `;
      } else {
        // Para otros intervalos, necesitamos tres parámetros en el CTE
        cteParams = [from_date, from_date, to_date];
        const formatString = interval === 'day' ? '%Y-%m-%d' :
          interval === 'week' ? '%x-W%v' :
            interval === 'month' ? '%Y-%m' :
              interval === 'year' ? '%Y' : '%Y-%m';

        query = `
          WITH RECURSIVE date_ranges AS (
            SELECT 
              DATE_FORMAT(?, '${formatString}') AS period, 
              ? AS date
            UNION ALL
            SELECT 
              DATE_FORMAT(DATE_ADD(date, INTERVAL ${dateAddInterval}), '${formatString}') AS period,
              DATE_ADD(date, INTERVAL ${dateAddInterval}) 
            FROM date_ranges
            WHERE DATE_ADD(date, INTERVAL ${dateAddInterval}) <= ?
          )
          SELECT 
            tb.name AS name,
            COALESCE(COUNT(DISTINCT dt.id), 0) AS data,
            date_ranges.period AS period
          FROM date_ranges
          LEFT JOIN donation_ticket as dt ON 
            DATE_FORMAT(dt.date, '${formatString}') = date_ranges.period
          LEFT JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id
          LEFT JOIN transported_by as tb ON dt.transported_by_id = tb.id
          LEFT JOIN provider as pr ON dt.provider_id = pr.id
          LEFT JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
          LEFT JOIN product as p ON pdt.product_id = p.id
          LEFT JOIN product_type as pt ON p.product_type_id = pt.id
          ${cabecera.role === 'client' ? 'LEFT JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
          WHERE dt.enabled = 'Y' and tb.enabled = 'Y' and sl.operation_id = 5
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_providers}
          ${query_product_types}
          ${query_stocker_upload}
          ${query_transported_by}
          GROUP BY name, period
        `;
      }

      // Combinar los parámetros del CTE con los demás parámetros
      const finalParams = cteParams.concat(params);

      const [rows] = await mysqlConnection.promise().query(query, finalParams);

      // Transformar las filas al formato deseado
      const categories = [...new Set(rows.map(row => row.period))].sort((a, b) => {
        if (interval === 'week') {
          const [yearA, weekA] = a.split('-W').map(Number);
          const [yearB, weekB] = b.split('-W').map(Number);
          const dateA = new Date(yearA, 0, (weekA - 1) * 7);
          const dateB = new Date(yearB, 0, (weekB - 1) * 7);
          return dateA - dateB;
        } else if (interval === 'quarter') {
          const [yearA, quarterA] = a.split('-Q').map(Number);
          const [yearB, quarterB] = b.split('-Q').map(Number);
          const dateA = new Date(yearA, (quarterA - 1) * 3);
          const dateB = new Date(yearB, (quarterB - 1) * 3);
          return dateA - dateB;
        } else {
          return new Date(a) - new Date(b);
        }
      });

      // Después del sort, formatear las categorías
      const formattedCategories = categories.map(c => formatPeriod(c, interval));

      const providersMap = new Map();

      // Inicializar providersMap con todos los proveedores y todos los periodos con datos en 0
      rows.forEach(row => {
        if (!providersMap.has(row.name)) {
          providersMap.set(row.name, Array(categories.length).fill(0));
        }
      });

      // Rellenar providersMap con datos reales
      rows.forEach(row => {
        const index = categories.indexOf(row.period);
        if (index !== -1) {
          providersMap.get(row.name)[index] = row.data;
        }
      });

      const series = Array.from(providersMap, ([name, data]) => ({ name, data }));

      const result = {
        series,
        categories: formattedCategories // usar las categorías formateadas
      };

      res.json(result);

    } catch (error) {
      console.log(error);
      res.status(500).send(error.message);
    }
  } else {
    res.status(403).send('Forbidden');
  }
});

router.post('/metrics/product/kind_of_product', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director' || cabecera.role === 'auditor') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const providers = filters.providers || [];
      const product_types = filters.product_types || [];
      const stocker_upload = filters.stocker_upload || [];
      const transported_by = filters.transported_by || [];

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND dt.date >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND dt.date < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND dt.location_id IN (' + locations.join() + ')';
      }
      var query_providers = '';
      if (providers.length > 0) {
        query_providers = 'AND dt.provider_id IN (' + providers.join() + ')';
      }
      var query_product_types = '';
      if (product_types.length > 0) {
        query_product_types = 'AND p.product_type_id IN (' + product_types.join() + ')';
      }
      var query_stocker_upload = '';
      if (stocker_upload.length > 0) {
        query_stocker_upload = 'AND sl.user_id IN (' + stocker_upload.join() + ')';
      }
      var query_transported_by = '';
      if (transported_by.length > 0) {
        query_transported_by = 'AND dt.transported_by_id IN (' + transported_by.join() + ')';
      }


      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
          ${language === 'en' ? 'pt.name' : 'pt.name_es'} AS name,
          SUM(pdt.quantity) AS total
          FROM donation_ticket as dt
          INNER JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id and sl.operation_id = 5
          INNER JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
          INNER JOIN product as p ON pdt.product_id = p.id
          INNER JOIN product_type as pt ON p.product_type_id = pt.id
          ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
          WHERE dt.enabled = 'Y'
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_providers}
          ${query_product_types}
          ${query_stocker_upload}
          ${query_transported_by}
          ${cabecera.role === 'client' ? 'and cl.client_id = ?' : ''}
          GROUP BY name`,
        [cabecera.client_id]
      );

      res.json(rows);
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/metrics/product/pounds_per_location', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director' || cabecera.role === 'auditor') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const providers = filters.providers || [];
      const product_types = filters.product_types || [];
      const stocker_upload = filters.stocker_upload || [];
      const transported_by = filters.transported_by || [];

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND dt.date >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND dt.date < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND dt.location_id IN (' + locations.join() + ')';
      }
      var query_providers = '';
      if (providers.length > 0) {
        query_providers = 'AND dt.provider_id IN (' + providers.join() + ')';
      }
      var query_product_types = '';
      if (product_types.length > 0) {
        query_product_types = 'AND p.product_type_id IN (' + product_types.join() + ')';
      }
      var query_stocker_upload = '';
      if (stocker_upload.length > 0) {
        query_stocker_upload = 'AND sl.user_id IN (' + stocker_upload.join() + ')';
      }
      var query_transported_by = '';
      if (transported_by.length > 0) {
        query_transported_by = 'AND dt.transported_by_id IN (' + transported_by.join() + ')';
      }

      // Select the appropriate query based on whether product_types filter is provided
      let query;
      if (product_types.length > 0) {
        // Use specific product types query (sum by product quantity)
        query = `SELECT 
          l.community_city AS name,
          SUM(pdt.quantity) AS total
          FROM donation_ticket as dt
          INNER JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id and sl.operation_id = 5
          INNER JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
          INNER JOIN product as p ON pdt.product_id = p.id
          INNER JOIN location as l ON dt.location_id = l.id
          WHERE dt.enabled = 'Y'
          ${cabecera.role === 'client' ? 'and dt.location_id IN (SELECT location_id FROM client_location WHERE client_id = ?)' : ''}
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_providers}
          ${query_product_types}
          ${query_stocker_upload}
          ${query_transported_by}
          GROUP BY l.id
          ORDER BY total desc`;
      } else {
        // Use total weight query (sum by ticket total weight)
        query = `SELECT 
          l.community_city AS name,
          SUM(dt.total_weight) AS total
          FROM donation_ticket as dt
          INNER JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id and sl.operation_id = 5
          INNER JOIN location as l ON dt.location_id = l.id
          WHERE dt.enabled = 'Y'
          ${cabecera.role === 'client' ? 'and dt.location_id IN (SELECT location_id FROM client_location WHERE client_id = ?)' : ''}
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_providers}
          ${query_stocker_upload}
          ${query_transported_by}
          GROUP BY l.id
          ORDER BY total desc`;
      }

      const [rows] = await mysqlConnection.promise().query(query, [cabecera.client_id]);

      // Si no hay datos, devolver un objeto vacío
      if (rows.length === 0) {
        res.json({ average: 0, median: 0, data: [] });
        return;
      }

      // Calcular el promedio
      let sum = 0;
      let count = 0;
      for (const row of rows) {
        sum += row.total;
        count++;
      }
      const average = Number((sum / count).toFixed(2));

      // Calcular la mediana
      let median;
      let sortedRows = [...rows].sort((a, b) => a.total - b.total);
      if (sortedRows.length % 2 === 0) {
        median = (sortedRows[sortedRows.length / 2 - 1].total + sortedRows[sortedRows.length / 2].total) / 2;
      } else {
        median = sortedRows[Math.floor(sortedRows.length / 2)].total;
      }

      // Convertir los números a cadenas
      for (const row of rows) {
        row.name = String(row.name);
      }

      res.json({ average: average, median: median, data: rows });
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.post('/metrics/product/pounds_per_product', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'director' || cabecera.role === 'auditor') {
    try {
      var page = req.query.page ? Number(req.query.page) : 1;
      if (page < 1) {
        page = 1;
      }
      var resultsPerPage = 10;
      var start = (page - 1) * resultsPerPage;

      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const providers = filters.providers || [];
      const product_types = filters.product_types || [];
      const stocker_upload = filters.stocker_upload || [];
      const transported_by = filters.transported_by || [];

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      const language = req.query.language || 'en';

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND dt.date >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND dt.date < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND dt.location_id IN (' + locations.join() + ')';
      }
      var query_providers = '';
      if (providers.length > 0) {
        query_providers = 'AND dt.provider_id IN (' + providers.join() + ')';
      }
      var query_product_types = '';
      if (product_types.length > 0) {
        query_product_types = 'AND p.product_type_id IN (' + product_types.join() + ')';
      }
      var query_stocker_upload = '';
      if (stocker_upload.length > 0) {
        query_stocker_upload = 'AND sl.user_id IN (' + stocker_upload.join() + ')';
      }
      var query_transported_by = '';
      if (transported_by.length > 0) {
        query_transported_by = 'AND dt.transported_by_id IN (' + transported_by.join() + ')';
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
        p.name AS name,
        SUM(pdt.quantity) AS total
        FROM donation_ticket as dt
        INNER JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id and sl.operation_id = 5
        INNER JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
        INNER JOIN product as p ON pdt.product_id = p.id
        ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
        WHERE dt.enabled = 'Y'
        ${query_from_date}
        ${query_to_date}
        ${query_locations}
        ${query_providers}
        ${query_product_types}
        ${query_stocker_upload}
        ${query_transported_by}
        ${cabecera.role === 'client' ? 'and cl.client_id = ?' : ''}
        GROUP BY name
        ORDER BY total DESC`,
        [cabecera.client_id]
      );

      // Si no hay datos, devolver un objeto vacío
      if (rows.length === 0) {
        res.json({ average: 0, median: 0, totalItems: 0, page: page - 1, data: [] });
        return;
      }

      // Calcular el promedio
      let sum = 0;
      let count = 0;
      for (const row of rows) {
        sum += row.total;
        count++;
      }
      const average = Number((sum / count).toFixed(2));

      // Calcular la mediana
      let median;
      let sortedRows = [...rows].sort((a, b) => a.total - b.total);
      if (sortedRows.length % 2 === 0) {
        median = (sortedRows[sortedRows.length / 2 - 1].total + sortedRows[sortedRows.length / 2].total) / 2;
      } else {
        median = sortedRows[Math.floor(sortedRows.length / 2)].total;
      }

      // Convertir los números a cadenas
      for (const row of rows) {
        row.name = String(row.name);
      }

      const totalItems = rows.length;
      const data = rows.slice(start, start + resultsPerPage);

      res.json({ average: average, median: median, totalItems: totalItems, page: page - 1, data: data });
    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);

router.get('/table/notification', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  let buscar = req.query.search;
  let queryBuscar = '';

  if (cabecera.role === 'admin') {

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;

    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `WHERE (message.id like '${buscar}' or message.user_id like '${buscar}' or user.username like '${buscar}' or message.name like '${buscar}' or DATE_FORMAT(CONVERT_TZ(message.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `SELECT
      message.id,
      message.user_id,
      user.username as user_name,
      message.name as message,
      DATE_FORMAT(CONVERT_TZ(message.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date
      FROM message
      INNER JOIN user ON message.user_id = user.id
      ${queryBuscar}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`

      const [rows] = await mysqlConnection.promise().query(
        query
        , [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
        SELECT COUNT(*) as count
        FROM message
        INNER JOIN user ON message.user_id = user.id
        ${queryBuscar}
      `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});


router.post('/table/volunteer', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';
    const locations = filters.locations || [];
    const genders = filters.genders || [];
    const ethnicities = filters.ethnicities || [];
    const min_age = filters.min_age || 0;
    const max_age = filters.max_age || 150;
    const zipcode = filters.zipcode || null;
    const language = req.query.language || 'en';

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }
    var query_locations = '';
    if (locations.length > 0) {
      query_locations = 'AND v.location_id IN (' + locations.join() + ')';
    }
    var query_genders = '';
    if (genders.length > 0) {
      query_genders = 'AND v.gender_id IN (' + genders.join() + ')';
    }
    var query_ethnicities = '';
    if (ethnicities.length > 0) {
      query_ethnicities = 'AND v.ethnicity_id IN (' + ethnicities.join() + ')';
    }
    var query_min_age = '';
    if (filters.min_age) {
      query_min_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
    }
    var query_max_age = '';
    if (filters.max_age) {
      query_max_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
    }
    var query_zipcode = '';
    if (filters.zipcode) {
      query_zipcode = 'AND v.zipcode = ' + zipcode;
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;

    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (v.id like '${buscar}' or v.email like '${buscar}' or v.firstname like '${buscar}' or v.lastname like '${buscar}' or l.community_city like '${buscar}' or g.name like '${buscar}' or e.name like '${buscar}' or g.name_es like '${buscar}' or e.name_es like '${buscar}' or DATE_FORMAT(CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `SELECT
      v.id,
      v.email,
      v.firstname,
      v.lastname,
      l.community_city as location,
      ${language === 'en' ? 'g.name' : 'g.name_es'} as gender,
      ${language === 'en' ? 'e.name' : 'e.name_es'} as ethnicity,
      DATE_FORMAT(CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date
      FROM volunteer as v
      INNER JOIN location as l ON v.location_id = l.id
      INNER JOIN gender as g ON v.gender_id = g.id
      INNER JOIN ethnicity as e ON v.ethnicity_id = e.id
      WHERE 1=1 
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ${query_locations}
      ${query_genders}
      ${query_ethnicities}
      ${query_min_age}
      ${query_max_age}
      ${query_zipcode}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`

      const [rows] = await mysqlConnection.promise().query(
        query
        , [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(*) as count
          FROM volunteer as v
          INNER JOIN location as l ON v.location_id = l.id
          INNER JOIN gender as g ON v.gender_id = g.id
          INNER JOIN ethnicity as e ON v.ethnicity_id = e.id
          WHERE 1=1
          ${queryBuscar}
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_genders}
          ${query_ethnicities}
          ${query_min_age}
          ${query_max_age}
          ${query_zipcode}
        `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/volunteer/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {
      const filters = req.body;
      let from_date = filters.from_date || '1970-01-01';
      let to_date = filters.to_date || '2100-01-01';
      const locations = filters.locations || [];
      const genders = filters.genders || [];
      const ethnicities = filters.ethnicities || [];
      const min_age = filters.min_age || 0;
      const max_age = filters.max_age || 150;
      const zipcode = filters.zipcode || null;

      // Convertir a formato ISO y obtener solo la fecha
      if (filters.from_date) {
        from_date = new Date(filters.from_date).toISOString().slice(0, 10);
      }
      if (filters.to_date) {
        to_date = new Date(filters.to_date).toISOString().slice(0, 10);
      }

      var query_from_date = '';
      if (filters.from_date) {
        query_from_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
      }
      var query_to_date = '';
      if (filters.to_date) {
        query_to_date = 'AND CONVERT_TZ(v.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
      }
      var query_locations = '';
      if (locations.length > 0) {
        query_locations = 'AND (v.location_id IN (' + locations.join() + ') )';
      }
      var query_genders = '';
      if (genders.length > 0) {
        query_genders = 'AND v.gender_id IN (' + genders.join() + ')';
      }
      var query_ethnicities = '';
      if (ethnicities.length > 0) {
        query_ethnicities = 'AND v.ethnicity_id IN (' + ethnicities.join() + ')';
      }
      var query_min_age = '';
      if (filters.min_age) {
        query_min_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) >= ` + min_age;
      }
      var query_max_age = '';
      if (filters.max_age) {
        query_max_age = `AND TIMESTAMPDIFF(YEAR, v.date_of_birth, DATE(CONVERT_TZ(NOW(), '+00:00', 'America/Los_Angeles'))) <= ` + max_age;
      }
      var query_zipcode = '';
      if (filters.zipcode) {
        query_zipcode = 'AND v.zipcode = ' + zipcode;
      }

      const [rows] = await mysqlConnection.promise().query(
        `SELECT v.id,
                v.firstname,
                v.lastname,
                DATE_FORMAT(v.date_of_birth, '%m/%d/%Y') AS date_of_birth,
                v.email,
                v.phone,
                v.zipcode,
                g.name as gender,
                e.name as ethnicity,
                v.other_ethnicity,
                l.community_city as location,
        DATE_FORMAT(CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') AS creation_date,
                        DATE_FORMAT(CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles'), '%T') AS creation_time
        FROM volunteer as v
        INNER JOIN ethnicity as e ON v.ethnicity_id = e.id
        INNER JOIN gender as g ON v.gender_id = g.id
        INNER JOIN location as l ON v.location_id = l.id
        WHERE CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles') >= ? AND CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles') < DATE_ADD(?, INTERVAL 1 DAY)
        ${query_locations}
        ${query_genders}
        ${query_ethnicities}
        ${query_min_age}
        ${query_max_age}
        ${query_zipcode}
        ORDER BY v.id`,
        [from_date, to_date]
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'firstname', title: 'Firstname' },
        { id: 'lastname', title: 'Lastname' },
        { id: 'date_of_birth', title: 'Date of birth' },
        { id: 'email', title: 'Email' },
        { id: 'phone', title: 'Phone' },
        { id: 'zipcode', title: 'Zipcode' },
        { id: 'gender', title: 'Gender' },
        { id: 'ethnicity', title: 'Ethnicity' },
        { id: 'other_ethnicity', title: 'Other ethnicity' },
        { id: 'location', title: 'Location' },
        { id: 'creation_date', title: 'Creation date' },
        { id: 'creation_time', title: 'Creation time' },
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=participants-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  }
}
);


router.post('/table/delivered', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';
    const locations = filters.locations || [];

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }
    var query_locations = '';
    if (locations.length > 0) {
      query_locations = 'AND db.location_id IN (' + locations.join() + ')';
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;

    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = ` AND (db.id like '${buscar}' or db.delivering_user_id like '${buscar}' or user_delivery.username like '${buscar}' or db.receiving_user_id like '${buscar}' or user_beneficiary.username like '${buscar}' or db.location_id like '${buscar}' or location.community_city like '${buscar}' or db.approved like '${buscar}' or DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `SELECT
      db.id,
      db.delivering_user_id,
      user_delivery.username as delivery_username,
      db.receiving_user_id,
      user_beneficiary.username as beneficiary_username,
      db.location_id,
      location.community_city,
      db.approved,
      DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date
      FROM delivery_beneficiary as db
      INNER JOIN location ON db.location_id = location.id
      INNER JOIN user as user_beneficiary ON db.receiving_user_id = user_beneficiary.id
      LEFT JOIN user as user_delivery ON db.delivering_user_id = user_delivery.id
      WHERE 1=1
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ${query_locations}
      ${cabecera.role === 'client' ? 'AND db.client_id = ' + cabecera.client_id : ''}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`

      const [rows] = await mysqlConnection.promise().query(
        query
        , [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
        SELECT COUNT(DISTINCT db.id) as count
        FROM delivery_beneficiary as db
        INNER JOIN location ON db.location_id = location.id
        INNER JOIN user as user_beneficiary ON db.receiving_user_id = user_beneficiary.id
        LEFT JOIN user as user_delivery ON db.delivering_user_id = user_delivery.id
        WHERE 1=1
        ${queryBuscar}
        ${query_from_date}
        ${query_to_date}
        ${query_locations}
        ${cabecera.role === 'client' ? 'AND db.client_id = ' + cabecera.client_id : ''}
      `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/ticket', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'director' || cabecera.role === 'stocker' || cabecera.role === 'auditor') {
    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';
    const locations = filters.locations || [];
    const providers = filters.providers || [];
    const delivered_by = filters.delivered_by || [];
    const transported_by = filters.transported_by || [];
    const stocker_upload = filters.stocker_upload || [];
    const language = req.query.language || 'en';

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }
    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND dt.date >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND dt.date < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }
    var query_locations = '';
    if (locations.length > 0) {
      query_locations = 'AND dt.location_id IN (' + locations.join() + ')';
    }
    var query_providers = '';
    if (providers.length > 0) {
      query_providers = 'AND dt.provider_id IN (' + providers.join() + ')';
    }
    var query_delivered_by = '';
    if (delivered_by.length > 0) {
      query_delivered_by = 'AND dt.delivered_by IN (' + delivered_by.join() + ')';
    }
    var query_transported_by = '';
    if (transported_by.length > 0) {
      query_transported_by = 'AND dt.transported_by_id IN (' + transported_by.join() + ')';
    }
    var query_stocker_upload = '';
    if (stocker_upload.length > 0) {
      query_stocker_upload = 'AND sl.user_id IN (' + stocker_upload.join() + ')';
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'date';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';

    var queryOrderBy = `${orderBy} ${orderType}`;

    if (orderBy === 'date') {
      queryOrderBy = `dt.date ${orderType}, dt.id desc`;
    }

    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = ` AND (dt.id like '${buscar}' or dt.donation_id like '${buscar}' or dt.total_weight like '${buscar}' or provider.name like '${buscar}' or location.community_city like '${buscar}' or DATE_FORMAT(dt.date, '%m/%d/%Y') like '${buscar}' or db.name like '${buscar}' or DATE_FORMAT(CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `SELECT
      dt.id,
      dt.donation_id,
      dt.total_weight,
      provider.name as provider,
      location.community_city as location,
      DATE_FORMAT(dt.date, '%m/%d/%Y') as date,
      db.name as delivered_by,
      tb.name as transported_by,
      ${language === 'en' ? 'as1.name' : 'as1.name_es'} as audit_status,
      COUNT(DISTINCT pdt.product_id) AS products,
      DATE_FORMAT(CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date
      FROM donation_ticket as dt
      INNER JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id AND sl.operation_id = 5
      INNER JOIN delivered_by as db ON dt.delivered_by = db.id
      INNER JOIN transported_by as tb ON dt.transported_by_id = tb.id
      INNER JOIN provider ON dt.provider_id = provider.id
      INNER JOIN audit_status as as1 ON dt.audit_status_id = as1.id
      INNER JOIN location ON dt.location_id = location.id
      ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON location.id = cl.location_id' : ''}
      LEFT JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
      WHERE dt.enabled = 'Y'
      ${cabecera.role === 'client' ? ' AND cl.client_id = ' + cabecera.client_id : ''}
      ${cabecera.role === 'stocker' ? ' AND dt.id IN (SELECT donation_ticket_id FROM stocker_log WHERE operation_id = 5 AND user_id = ' + cabecera.id + ')' : ''}
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ${query_locations}
      ${query_providers}
      ${query_delivered_by}
      ${query_transported_by}
      ${query_stocker_upload}
      GROUP BY dt.id
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`

      const [rows] = await mysqlConnection.promise().query(
        query
        , [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
        SELECT COUNT(DISTINCT dt.id) as count
        FROM donation_ticket as dt
        INNER JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id AND sl.operation_id = 5
        INNER JOIN delivered_by as db ON dt.delivered_by = db.id
        INNER JOIN transported_by as tb ON dt.transported_by_id = tb.id
        INNER JOIN provider ON dt.provider_id = provider.id
        INNER JOIN audit_status as as1 ON dt.audit_status_id = as1.id
        INNER JOIN location ON dt.location_id = location.id
        ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON location.id = cl.location_id' : ''}
        LEFT JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
        WHERE dt.enabled = 'Y'
        ${cabecera.role === 'client' ? ' AND cl.client_id = ' + cabecera.client_id : ''}
        ${cabecera.role === 'stocker' ? ' AND dt.id IN (SELECT donation_ticket_id FROM stocker_log WHERE operation_id = 5 AND user_id = ' + cabecera.id + ')' : ''}
        ${queryBuscar}
        ${query_from_date}
        ${query_to_date}
        ${query_locations}
        ${query_providers}
        ${query_delivered_by}
        ${query_transported_by}
        ${query_stocker_upload}
      `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.delete('/ticket/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    const id = req.params.id;
    try {
      // update del campo ENABLED en donation_ticket por 'N'
      const [rows] = await mysqlConnection.promise().query(
        `UPDATE donation_ticket
        SET enabled = 'N'
        WHERE id = ?`,
        [id]
      );
      res.json('Ticket eliminado');
    } catch (error) {
      console.log(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/product', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    const language = req.query.language || 'en';

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';
    const locations = filters.locations || [];
    const providers = filters.providers || [];
    const product_types = filters.product_types || [];

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(p.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(p.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }
    var query_locations = '';
    if (locations.length > 0) {
      query_locations = 'AND dt.location_id IN (' + locations.join() + ')';
    }
    var query_providers = '';
    if (providers.length > 0) {
      query_providers = 'AND dt.provider_id IN (' + providers.join() + ')';
    }
    var query_product_types = '';
    if (product_types.length > 0) {
      query_product_types = 'AND p.product_type_id IN (' + product_types.join() + ')';
    }

    let buscar = req.query.search;
    let queryBuscar = '';
    let queryBuscarCount = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;


    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (id like '${buscar}' or name like '${buscar}' or product_type like '${buscar}' or value_usd like '${buscar}' or total_quantity like '${buscar}' or DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
      queryBuscarCount = `AND (p.id like '${buscar}' or p.name like '${buscar}' or pt.name like '${buscar}' or pt.name_es like '${buscar}' or p.value_usd like '${buscar}' or DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `
      SELECT * FROM (
        SELECT
          p.id,
          p.name,
          ${language === 'en' ? 'pt.name' : 'pt.name_es'} AS product_type,
          p.value_usd,
          DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date,
          IFNULL(SUM(pdt.quantity), 0) as total_quantity
        FROM product as p
        INNER JOIN product_type as pt ON p.product_type_id = pt.id
        LEFT JOIN product_donation_ticket as pdt ON p.id = pdt.product_id
        LEFT JOIN donation_ticket as dt ON pdt.donation_ticket_id = dt.id
        ${cabecera.role === 'client' ? 'LEFT JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
        WHERE 1=1
        ${query_from_date}
        ${query_to_date}
        ${query_locations}
        ${query_providers}
        ${query_product_types}
        ${cabecera.role === 'client' ? 'AND cl.client_id = ' + cabecera.client_id : ''}
        GROUP BY p.id
      ) as subquery
      WHERE 1=1 
      ${queryBuscar}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`;

      const [rows] = await mysqlConnection.promise().query(query, [start, resultsPerPage]);
      if (rows.length > 0) {
        let countRows;
        if (cabecera.role === 'admin') {
          [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(DISTINCT p.id) as count
          FROM product as p
          INNER JOIN product_type as pt ON p.product_type_id = pt.id
          LEFT JOIN product_donation_ticket as pdt ON p.id = pdt.product_id
          LEFT JOIN donation_ticket as dt ON pdt.donation_ticket_id = dt.id
          WHERE 1=1 
          ${queryBuscarCount}
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_providers}
          ${query_product_types}
        `);
        } else {
          // client
          [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(DISTINCT p.id) as count
          FROM product as p
          INNER JOIN product_type as pt ON p.product_type_id = pt.id
          LEFT JOIN product_donation_ticket as pdt ON p.id = pdt.product_id
          LEFT JOIN donation_ticket as dt ON pdt.donation_ticket_id = dt.id 
          LEFT JOIN client_location as cl ON dt.location_id = cl.location_id
          WHERE cl.client_id = ?
          ${queryBuscarCount}
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          ${query_providers}
          ${query_product_types}
        `, [cabecera.client_id])
        }

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/product-type', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    const language = req.query.language || 'en';

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(pt.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(pt.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;


    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (id like '${buscar}' or name like '${buscar}' or name_es like '${buscar}' or DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}' or DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `
      SELECT
        id,
        ${language === 'en' ? 'name' : 'name_es'} AS name,
        DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date,
        DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as modification_date
      FROM product_type as pt
      WHERE 1=1 
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`;

      const [rows] = await mysqlConnection.promise().query(query, [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(*) as count
          FROM product_type as pt
          WHERE 1=1 
          ${queryBuscar}
          ${query_from_date}
          ${query_to_date}
        `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/worker/download-csv', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    const language = req.query.language || 'en';

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';
    const locations = filters.locations || [];
    const workers = filters.workers || [];

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(dl.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(dl.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }
    var query_locations = '';
    if (locations.length > 0) {
      query_locations = 'AND dl.location_id IN (' + locations.join() + ')';
    }
    var query_workers = '';
    if (workers.length > 0) {
      query_workers = 'AND dl.user_id IN (' + workers.join() + ')';
    }

    try {
      const [rows] = await mysqlConnection.promise().query(`
      SELECT
        dl.id,
        dl.user_id,
        u.username,
        u.firstname,
        u.lastname,
        l.community_city,
        DATE_FORMAT(CONVERT_TZ(dl.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as onboarding_date,
        DATE_FORMAT(CONVERT_TZ(dl.offboarding_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as offboarding_date
      FROM delivery_log as dl
      INNER JOIN user as u ON dl.user_id = u.id
      LEFT JOIN location as l ON dl.location_id = l.id
      WHERE u.enabled = 'Y' and dl.operation_id = 3 
      ${query_from_date}
      ${query_to_date}
      ${query_locations}
      ${query_workers}
      ORDER BY dl.id`
      );

      var headers_array = [
        { id: 'id', title: 'ID' },
        { id: 'user_id', title: 'User ID' },
        { id: 'username', title: 'Username' },
        { id: 'firstname', title: 'First Name' },
        { id: 'lastname', title: 'Last Name' },
        { id: 'community_city', title: 'Location' },
        { id: 'onboarding_date', title: 'Onboarding Date' },
        { id: 'offboarding_date', title: 'Offboarding Date' }
      ];

      const csvStringifier = createCsvStringifier({
        header: headers_array,
        fieldDelimiter: ';'
      });

      let csvData = csvStringifier.getHeaderString();
      csvData += csvStringifier.stringifyRecords(rows);

      res.setHeader('Content-disposition', 'attachment; filename=workers-table.csv');
      res.setHeader('Content-type', 'text/csv; charset=utf-8');
      res.send(csvData);

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/worker', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    const language = req.query.language || 'en';

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';
    const locations = filters.locations || [];
    const workers = filters.workers || [];

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(dl.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(dl.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }
    var query_locations = '';
    if (locations.length > 0) {
      query_locations = 'AND dl.location_id IN (' + locations.join() + ')';
    }
    var query_workers = '';
    if (workers.length > 0) {
      query_workers = 'AND dl.user_id IN (' + workers.join() + ')';
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';

    if (orderBy === 'id') {
      orderBy = 'first_onboarding_id';
    }

    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;

    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (subquery.first_onboarding_id like '${buscar}' or subquery.user_id like '${buscar}' or subquery.username like '${buscar}' or subquery.firstname like '${buscar}' or subquery.lastname like '${buscar}' or subquery.community_city like '${buscar}' or subquery.onboarding_date like '${buscar}' or subquery.offboarding_date like '${buscar}')`;
    }

    try {
      const query = `
      SELECT * FROM (
        SELECT
          dl.user_id,
          u.username,
          u.firstname,
          u.lastname,
          l.community_city,
          DATE_FORMAT(MIN(CONVERT_TZ(dl.creation_date, '+00:00', 'America/Los_Angeles')), '%m/%d/%Y %T') as onboarding_date,
          DATE_FORMAT(MAX(CONVERT_TZ(dl.offboarding_date, '+00:00', 'America/Los_Angeles')), '%m/%d/%Y %T') as offboarding_date,
          (SELECT id FROM delivery_log WHERE user_id = dl.user_id AND DATE(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')) = DATE(CONVERT_TZ(dl.creation_date, '+00:00', 'America/Los_Angeles')) ORDER BY creation_date ASC LIMIT 1) as first_onboarding_id
        FROM delivery_log as dl
        INNER JOIN user as u ON dl.user_id = u.id
        LEFT JOIN location as l ON dl.location_id = l.id
        WHERE u.enabled = 'Y' and dl.operation_id = 3 
        ${query_from_date}
        ${query_to_date}
        ${query_locations}
        ${query_workers}
        GROUP BY dl.user_id, DATE(CONVERT_TZ(dl.creation_date, '+00:00', 'America/Los_Angeles'))
      ) as subquery
      WHERE 1=1
      ${queryBuscar}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`;

      const [rows] = await mysqlConnection.promise().query(query, [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(*) as count
          FROM (
            SELECT 
              dl.user_id,
              u.username,
              u.firstname,
              u.lastname,
              l.community_city,
              DATE_FORMAT(MIN(CONVERT_TZ(dl.creation_date, '+00:00', 'America/Los_Angeles')), '%m/%d/%Y %T') as onboarding_date,
              DATE_FORMAT(MAX(CONVERT_TZ(dl.offboarding_date, '+00:00', 'America/Los_Angeles')), '%m/%d/%Y %T') as offboarding_date,
              (SELECT id FROM delivery_log WHERE user_id = dl.user_id AND DATE(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles')) = DATE(CONVERT_TZ(dl.creation_date, '+00:00', 'America/Los_Angeles')) ORDER BY creation_date ASC LIMIT 1) as first_onboarding_id
            FROM delivery_log as dl
            INNER JOIN user as u ON dl.user_id = u.id
            LEFT JOIN location as l ON dl.location_id = l.id
            WHERE u.enabled = 'Y' and dl.operation_id = 3 
            ${query_from_date}
            ${query_to_date}
            ${query_locations}
            ${query_workers}
            GROUP BY dl.user_id, DATE(CONVERT_TZ(dl.creation_date, '+00:00', 'America/Los_Angeles'))
          ) as subquery
          WHERE 1=1
          ${queryBuscar}
        `);
        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/delivered-by', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(db.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;


    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (id like '${buscar}' or name like '${buscar}' or enabled like '${buscar}' or DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}' or DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `
      SELECT
        id,
        name,
        enabled,
        DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date,
        DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as modification_date
      FROM delivered_by as db
      WHERE 1=1 
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`;

      const [rows] = await mysqlConnection.promise().query(query, [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(*) as count
          FROM delivered_by as db
          WHERE 1=1 
          ${queryBuscar}
          ${query_from_date}
          ${query_to_date}
        `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/transported-by', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(tb.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(tb.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;


    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (id like '${buscar}' or name like '${buscar}' or enabled like '${buscar}' or DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}' or DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `
      SELECT
        id,
        name,
        enabled,
        DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date,
        DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as modification_date
      FROM transported_by as tb
      WHERE 1=1 
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`;

      const [rows] = await mysqlConnection.promise().query(query, [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(*) as count
          FROM transported_by as tb
          WHERE 1=1 
          ${queryBuscar}
          ${query_from_date}
          ${query_to_date}
        `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/gender', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    const language = req.query.language || 'en';

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(g.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(g.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;


    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (id like '${buscar}' or name like '${buscar}' or name_es like '${buscar}' or enabled like '${buscar}' or DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}' or DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `
      SELECT
        id,
        ${language === 'en' ? 'name' : 'name_es'} AS name,
        enabled,
        DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date,
        DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as modification_date
      FROM gender as g
      WHERE 1=1 
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`;

      const [rows] = await mysqlConnection.promise().query(query, [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(*) as count
          FROM gender as g
          WHERE 1=1 
          ${queryBuscar}
          ${query_from_date}
          ${query_to_date}
        `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/ethnicity', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    const language = req.query.language || 'en';

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(e.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(e.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }
    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;


    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (id like '${buscar}' or name like '${buscar}' or name_es like '${buscar}' or enabled like '${buscar}' or DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}' or DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `
      SELECT
        id,
        ${language === 'en' ? 'name' : 'name_es'} AS name,
        enabled,
        DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date,
        DATE_FORMAT(CONVERT_TZ(modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as modification_date
      FROM ethnicity as e
      WHERE 1=1 
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`;

      const [rows] = await mysqlConnection.promise().query(query, [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(*) as count
          FROM ethnicity as e
          WHERE 1=1 
          ${queryBuscar}
          ${query_from_date}
          ${query_to_date}
        `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/provider', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';
    const locations = filters.locations || [];

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(p.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(p.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }
    var query_locations = '';
    if (locations.length > 0) {
      query_locations = 'AND dt.location_id IN (' + locations.join() + ')';
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;


    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (p.id like '${buscar}' or p.name like '${buscar}' or DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}' or DATE_FORMAT(CONVERT_TZ(p.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `
      SELECT
        p.id,
        p.name,
        DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date,
        DATE_FORMAT(CONVERT_TZ(p.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as modification_date
      FROM provider as p
      WHERE 1=1 
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ${query_locations}
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`;

      const [rows] = await mysqlConnection.promise().query(query, [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(*) as count
          FROM provider as p
          WHERE 1=1 
          ${queryBuscar}
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
        `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/client', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    const language = req.query.language || 'en';

    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';
    const locations = filters.locations || [];

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(c.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(c.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }
    var query_locations = '';
    if (locations.length > 0) {
      query_locations = 'AND cl.location_id IN (' + locations.join() + ')';
    }

    let buscar = req.query.search;
    let queryBuscar = '';

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;


    if (buscar) {
      buscar = '%' + buscar + '%';
      queryBuscar = `AND (c.id like '${buscar}' or c.name like '${buscar}' or c.short_name like '${buscar}' or c.enabled like '${buscar}' or DATE_FORMAT(CONVERT_TZ(c.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}' or DATE_FORMAT(CONVERT_TZ(c.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') like '${buscar}')`;
    }

    try {
      const query = `
      SELECT
        c.id,
        c.name,
        c.short_name,
        c.enabled,
        DATE_FORMAT(CONVERT_TZ(c.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date,
        DATE_FORMAT(CONVERT_TZ(c.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as modification_date
      FROM client as c
      LEFT JOIN client_location as cl ON c.id = cl.client_id
      WHERE 1=1 
      ${queryBuscar}
      ${query_from_date}
      ${query_to_date}
      ${query_locations}
      GROUP BY c.id
      ORDER BY ${queryOrderBy}
      LIMIT ?, ?`;

      const [rows] = await mysqlConnection.promise().query(query, [start, resultsPerPage]);
      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
          SELECT COUNT(*) as count
          FROM client as c
          LEFT JOIN client_location as cl ON c.id = cl.client_id
          WHERE 1=1 
          ${queryBuscar}
          ${query_from_date}
          ${query_to_date}
          ${query_locations}
          GROUP BY c.id
        `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.post('/table/location', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    const filters = req.body;
    let from_date = filters.from_date || '1970-01-01';
    let to_date = filters.to_date || '2100-01-01';

    // Convertir a formato ISO y obtener solo la fecha
    if (filters.from_date) {
      from_date = new Date(filters.from_date).toISOString().slice(0, 10);
    }
    if (filters.to_date) {
      to_date = new Date(filters.to_date).toISOString().slice(0, 10);
    }

    var query_from_date = '';
    if (filters.from_date) {
      query_from_date = 'AND CONVERT_TZ(l.creation_date, \'+00:00\', \'America/Los_Angeles\') >= \'' + from_date + '\'';
    }
    var query_to_date = '';
    if (filters.to_date) {
      query_to_date = 'AND CONVERT_TZ(l.creation_date, \'+00:00\', \'America/Los_Angeles\') < DATE_ADD(\'' + to_date + '\', INTERVAL 1 DAY)';
    }

    let buscar = req.query.search;

    var page = req.query.page ? Number(req.query.page) : 1;

    if (page < 1) {
      page = 1;
    }
    var resultsPerPage = 10;
    var start = (page - 1) * resultsPerPage;

    var orderBy = req.query.orderBy ? req.query.orderBy : 'id';
    var orderType = ['asc', 'desc'].includes(req.query.orderType) ? req.query.orderType : 'desc';
    var queryOrderBy = `${orderBy} ${orderType}`;
    let havingClause = '';
    if (buscar) {
      buscar = '%' + buscar + '%';
      havingClause = `HAVING (l.id like '${buscar}' or l.organization like '${buscar}' or l.community_city like '${buscar}' or partner like '${buscar}' or l.address like '${buscar}' or l.enabled like '${buscar}' or creation_date like '${buscar}')`;
    }

    try {
      const query = `SELECT
        l.id,
        l.organization,
        l.community_city,
        GROUP_CONCAT(DISTINCT client.short_name SEPARATOR ', ') as partner,
        l.address,
        l.enabled,
        DATE_FORMAT(CONVERT_TZ(l.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date
        FROM location as l
        LEFT JOIN client_location ON l.id = client_location.location_id
        LEFT JOIN client ON client_location.client_id = client.id
        WHERE 1=1 
        ${query_from_date}
        ${query_to_date}
        ${cabecera.role === 'client' ? 'AND client_location.client_id = ' + cabecera.client_id : ''}
        GROUP BY l.id
        ${havingClause}
        ORDER BY ${queryOrderBy}
        LIMIT ?, ?`

      const [rows] = await mysqlConnection.promise().query(
        query
        , [start, resultsPerPage]);

      if (rows.length > 0) {
        const [countRows] = await mysqlConnection.promise().query(`
        SELECT COUNT(*) as count
        FROM (
          SELECT
          l.id,
          l.organization,
          l.community_city,
          GROUP_CONCAT(DISTINCT client.short_name SEPARATOR ', ') as partner,
          l.address,
          l.enabled,
          DATE_FORMAT(CONVERT_TZ(l.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date
          FROM location as l
          LEFT JOIN client_location ON l.id = client_location.location_id
          LEFT JOIN client ON client_location.client_id = client.id
          WHERE 1=1 
          ${query_from_date}
          ${query_to_date}
          ${cabecera.role === 'client' ? 'AND client_location.client_id = ' + cabecera.client_id : ''}
          GROUP BY l.id
          ${havingClause}
        ) as subquery
      `);

        const numOfResults = countRows[0].count;
        const numOfPages = Math.ceil(numOfResults / resultsPerPage);

        res.json({ results: rows, numOfPages: numOfPages, totalItems: numOfResults, page: page - 1, orderBy: orderBy, orderType: orderType });
      } else {
        res.json({ results: rows, numOfPages: 0, totalItems: 0, page: page - 1, orderBy: orderBy, orderType: orderType });
      }

    } catch (error) {
      console.log(error);
      logger.error(error);
      res.status(500).json('Error interno');
    }
  } else {
    res.status(401).json('No autorizado');
  }
});

router.get('/view/user/:idUser', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {
      const { idUser } = req.params;
      const language = req.query.language || 'en';

      const [rows] = await mysqlConnection.promise().query(
        `SELECT 
            u.id,
            u.username,
            u.email,
            u.firstname,
            u.lastname,
            c.name as client_name,
            DATE_FORMAT(u.date_of_birth, '%m/%d/%Y') AS date_of_birth,
            l.community_city as last_location_community_city,
            r.name as role_name,
            u.reset_password,
            u.enabled,
            DATE_FORMAT(CONVERT_TZ(u.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS modification_date,
            DATE_FORMAT(CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
            ${language === 'en' ? 'e.name' : 'e.name_es'} as ethnicity_name,
            u.other_ethnicity,
            ${language === 'en' ? 'g.name' : 'g.name_es'} as gender_name,
            u.phone,
            u.zipcode,
            u.household_size
          FROM user as u
          INNER JOIN role as r ON u.role_id = r.id
          ${cabecera.role === 'client' ? 'LEFT JOIN client_user as cu ON u.id = cu.user_id' : ''}
          LEFT JOIN client as c ON u.client_id = c.id
          LEFT JOIN location as l ON u.location_id = l.id
          LEFT JOIN ethnicity as e ON u.ethnicity_id = e.id
          LEFT JOIN gender as g ON u.gender_id = g.id
          WHERE u.id = ?
          ${cabecera.role === 'client' ? ' AND (cu.client_id = ? or u.client_id = ?)' : ''}`,
        [idUser, cabecera.client_id, cabecera.client_id]
      );
      const [rows_emails] = await mysqlConnection.promise().query(
        `select email
        from user_email_report
        where user_id = ?
        `,
        [idUser]
      );

      if (rows.length > 0) {
        var user = {};

        user["id"] = rows[0].id;
        user["username"] = rows[0].username;
        user["email"] = rows[0].email;
        user["firstname"] = rows[0].firstname;
        user["lastname"] = rows[0].lastname;
        user["client_name"] = rows[0].client_name;
        user["date_of_birth"] = rows[0].date_of_birth;
        user["last_location_community_city"] = rows[0].last_location_community_city;
        user["role_name"] = rows[0].role_name;
        user["reset_password"] = rows[0].reset_password;
        user["enabled"] = rows[0].enabled;
        user["modification_date"] = rows[0].modification_date;
        user["creation_date"] = rows[0].creation_date;
        user["role_name"] = rows[0].role_name;
        user["ethnicity_name"] = rows[0].ethnicity_name;
        user["other_ethnicity"] = rows[0].other_ethnicity;
        user["gender_name"] = rows[0].gender_name;
        user["phone"] = rows[0].phone;
        user["zipcode"] = rows[0].zipcode;
        user["household_size"] = rows[0].household_size;
        user["emails_for_reporting"] = rows_emails;


        switch (user["role_name"]) {

          case 'beneficiary':
            if (language === 'en') {
              user["table_header"] = ['ID', 'Question', 'Answer', 'Creation date'];
            } else {
              user["table_header"] = ['ID', 'Pregunta', 'Respuesta', 'Fecha de creación'];
            }

            user["table_rows"] = [[]];

            const [table_rows_beneficiary] = await mysqlConnection.promise().query(
              `SELECT 
                      q.id AS question_id,
                      at.id AS answer_type_id,
                      ${language === 'en' ? 'q.name' : 'q.name_es'} as question,
                      ${language === 'en' ? 'a.name' : 'a.name_es'} as answer,
                      uq.answer_text AS answer_text,
                      uq.answer_number AS answer_number,
                      DATE_FORMAT(CONVERT_TZ(uq.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y') as creation_date
              FROM user u
              CROSS JOIN question AS q
              LEFT JOIN answer_type as at ON q.answer_type_id = at.id
              LEFT JOIN user_question AS uq ON u.id = uq.user_id AND uq.question_id = q.id
              LEFT JOIN user_question_answer AS uqa ON uq.id = uqa.user_question_id
              LEFT JOIN answer as a ON a.id = uqa.answer_id and a.question_id = q.id
              WHERE u.role_id = 5 AND u.id = ?
              GROUP BY q.id, a.id
              ORDER BY q.id, a.id`,
              [idUser]
            );

            let result = [];
            let map = {};

            // Agrupar las respuestas por pregunta
            table_rows_beneficiary.forEach(row => {
              if (!map[row.question_id]) {
                map[row.question_id] = {
                  question_id: row.question_id,
                  question: row.question,
                  answers: [],
                  creation_date: row.creation_date
                };
                result.push(map[row.question_id]);
              }

              let answer;
              switch (row.answer_type_id) {
                case 1:
                  answer = row.answer_text;
                  break;
                case 2:
                  answer = row.answer_number;
                  break;
                case 3:
                  answer = row.answer;
                  break;
                case 4:
                  answer = row.answer;
                  break;
              }

              if (row.answer_type_id === 4 && map[row.question_id].answers.length > 0) {
                map[row.question_id].answers[map[row.question_id].answers.length - 1] += ', ' + answer;
              } else {
                map[row.question_id].answers.push(answer);
              }
            });

            // Convertir las respuestas a cadenas
            result.forEach(item => {
              item.answers = item.answers.join(', ');
            });

            user["table_rows"] = result.map(row => {
              return [
                row.question_id,
                row.question,
                row.answers,
                row.creation_date
              ];
            });

            break;

          case 'delivery':
            if (language === 'en') {
              user["table_header"] = ['ID', 'Beneficiary user ID', 'Username', 'Location', 'Creation date', 'View delivered'];
            } else {
              user["table_header"] = ['ID', 'ID de beneficiario', 'Nombre de usuario', 'Ubicación', 'Fecha de creación', 'Ver entrega'];
            }
            user["table_rows"] = [[]];
            const [table_rows_delivery] = await mysqlConnection.promise().query(
              `SELECT
                db.id,
                db.receiving_user_id,
                user.username as username,
                location.community_city as location,
                DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date
              FROM delivery_beneficiary as db
              INNER JOIN user ON db.receiving_user_id = user.id
              INNER JOIN location ON db.location_id = location.id
              WHERE db.delivering_user_id = ?`,
              [idUser]
            );
            user["table_rows"] = table_rows_delivery.map(row => {
              return [
                row.id,
                row.receiving_user_id,
                row.username,
                row.location,
                row.creation_date
              ];
            });
            break;

          case 'stocker':
            if (language === 'en') {
              user["table_header"] = ['ID', 'Donation ID', 'Provider', 'Location', 'Date', 'Creation date', 'View ticket'];
            } else {
              user["table_header"] = ['ID', 'ID de donación', 'Proveedor', 'Ubicación', 'Fecha', 'Fecha de creación', 'Ver ticket'];
            }
            user["table_rows"] = [[]];
            const [table_rows_stocker] = await mysqlConnection.promise().query(
              `SELECT
                dt.id,
                dt.donation_id,
                provider.name as provider,
                location.community_city as location,
                DATE_FORMAT(dt.date, '%m/%d/%Y') as date,
                DATE_FORMAT(CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date
              FROM donation_ticket as dt
              INNER JOIN provider ON dt.provider_id = provider.id
              INNER JOIN location ON dt.location_id = location.id
              INNER JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id AND sl.operation_id = 5
              WHERE sl.user_id = ? AND dt.enabled = 'Y'`,
              [idUser]
            );
            user["table_rows"] = table_rows_stocker.map(row => {
              return [
                row.id,
                row.donation_id,
                row.provider,
                row.location,
                row.date,
                row.creation_date
              ];
            });
            break;

          default:
            user["table_header"] = [];
            user["table_rows"] = [[]];
        }

        res.json(user);
      } else {
        res.status(404).json('user no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/location/:idLocation', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    try {
      const { idLocation } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT l.id,
            l.organization,
            l.community_city,
            GROUP_CONCAT(DISTINCT client.short_name SEPARATOR ', ') as partner,
            l.address,
            l.enabled,
            CONCAT(ST_Y(l.coordinates), ', ', ST_X(l.coordinates)) as coordinates, 
            DATE_FORMAT(CONVERT_TZ(l.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date
          FROM location as l
          LEFT JOIN client_location ON l.id = client_location.location_id
          LEFT JOIN client ON client_location.client_id = client.id
          WHERE l.id = ?
          ${cabecera.role === 'client' ? ' AND client_location.client_id = ?' : ''}
          GROUP BY l.id`,
        [idLocation, cabecera.client_id]
      );

      if (rows.length > 0) {
        var location = {};

        location["id"] = rows[0].id;
        location["organization"] = rows[0].organization;
        location["community_city"] = rows[0].community_city;
        location["partner"] = rows[0].partner;
        location["address"] = rows[0].address;
        location["enabled"] = rows[0].enabled;
        location["coordinates"] = rows[0].coordinates; // coordenadas: latitud, longitud como google maps
        location["creation_date"] = rows[0].creation_date;

        res.json(location);
      } else {
        res.status(404).json('location no encontrada');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/notification/:idNotification', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { idNotification } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT m.id,
            m.user_id,
            u.username as user_name, 
          u.email user_email,
          m.name as message,
          DATE_FORMAT(CONVERT_TZ(m.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
          (SELECT JSON_ARRAYAGG(JSON_OBJECT('notification_id', m2.id, 'user_id', u2.id, 'message', m2.name, 'creation_date', DATE_FORMAT(CONVERT_TZ(m2.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T'))) 
          FROM message as m2
          INNER JOIN user as u2 ON m2.user_id = u2.id
          WHERE m2.user_id = m.user_id
          ) as notifications
          FROM message as m
          INNER JOIN user as u ON m.user_id = u.id
          WHERE m.id = ?`,
        [idNotification]
      );

      if (rows.length > 0) {
        var notification = {};

        notification["id"] = rows[0].id;
        notification["user_id"] = rows[0].user_id;
        notification["user_name"] = rows[0].user_name;
        notification["user_email"] = rows[0].user_email;
        notification["message"] = rows[0].message;
        notification["creation_date"] = rows[0].creation_date;
        notification["notifications"] = rows[0].notifications;
        notification["notifications"].sort((a, b) => new Date(b.creation_date) - new Date(a.creation_date));

        res.json(notification);
      } else {
        res.status(404).json('notification no encontrada');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/delivered/:idDelivered', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {
      const { idDelivered } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT db.id,
            db.delivering_user_id,
            user_delivery.username as delivery_username, 
          db.receiving_user_id, 
          user_beneficiary.username as beneficiary_username, 
          db.location_id, 
          l.community_city, 
          db.approved, 
          DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date
          FROM delivery_beneficiary as db
          INNER JOIN location as l ON db.location_id = l.id
          INNER JOIN user as user_beneficiary ON db.receiving_user_id = user_beneficiary.id
          LEFT JOIN user as user_delivery ON db.delivering_user_id = user_delivery.id
          WHERE db.id = ?
          ${cabecera.role === 'client' ? ' AND db.client_id = ?' : ''}`,
        [idDelivered, cabecera.client_id]
      );


      if (rows.length > 0) {
        // buscar historial de entregas del beneficiario
        const [rows_history] = await mysqlConnection.promise().query(`
        SELECT db.id as delivered_id, 
          u.username as delivery_username,
          db.receiving_user_id as receiving_user_id, 
          l.community_city, 
          db.approved, 
          DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') as creation_date 
          FROM delivery_beneficiary as db
          INNER JOIN location as l ON db.location_id = l.id
          ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON db.location_id = cl.location_id' : ''}
          LEFT JOIN user as u ON db.delivering_user_id = u.id
          WHERE db.receiving_user_id = ?
          ${cabecera.role === 'client' ? 'AND cl.client_id = ?' : ''}
        `, [rows[0].receiving_user_id, cabecera.client_id]);

        var delivered = {};

        delivered["id"] = rows[0].id;
        delivered["delivering_user_id"] = rows[0].delivering_user_id;
        delivered["delivery_username"] = rows[0].delivery_username;
        delivered["receiving_user_id"] = rows[0].receiving_user_id;
        delivered["beneficiary_username"] = rows[0].beneficiary_username;
        delivered["location_id"] = rows[0].location_id;
        delivered["community_city"] = rows[0].community_city;
        delivered["approved"] = rows[0].approved;
        delivered["creation_date"] = rows[0].creation_date;
        delivered["deliveries"] = rows_history;

        res.json(delivered);
      } else {
        res.status(404).json('delivered no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/client/:idClient', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { idClient } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT c.id,
          c.name,
          c.short_name,
          c.email,
          c.phone,
          c.address,
          c.webpage,
          c.enabled,
          DATE_FORMAT(CONVERT_TZ(c.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
          DATE_FORMAT(CONVERT_TZ(c.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS modification_date,
          l.id as location_id,
          l.community_city,
          l.enabled as location_enabled,
          DATE_FORMAT(CONVERT_TZ(l.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS location_creation_date
        FROM client as c
        LEFT JOIN client_location as cl ON c.id = cl.client_id
        LEFT JOIN location as l ON cl.location_id = l.id
        WHERE c.id = ?`,
        [idClient]
      );
      const [rows_emails] = await mysqlConnection.promise().query(
        `select email
        from client_email
        where client_id = ?
        `,
        [idClient]
      );

      if (rows.length > 0) {

        // create object with client data and field 'locations' with array of locations
        var client = {};
        var locations = [];

        client["id"] = rows[0].id;
        client["name"] = rows[0].name;
        client["short_name"] = rows[0].short_name;
        client["email"] = rows[0].email;
        client["phone"] = rows[0].phone;
        client["address"] = rows[0].address;
        client["webpage"] = rows[0].webpage;
        client["enabled"] = rows[0].enabled;
        client["creation_date"] = rows[0].creation_date;
        client["modification_date"] = rows[0].modification_date;

        for (let i = 0; i < rows.length; i++) {
          if (rows[i].location_id) {
            locations.push({ location_id: rows[i].location_id, community_city: rows[i].community_city, enabled: rows[i].location_enabled, creation_date: rows[i].location_creation_date });
          }
        }

        client["locations"] = locations;

        client["emails_for_reporting"] = rows_emails;

        res.json(client);
      } else {
        res.status(404).json('Client no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/provider/:idProvider', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client') {
    try {
      const { idProvider } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT p.id,
          p.name,
          DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
          DATE_FORMAT(CONVERT_TZ(p.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS modification_date,
          t.id as ticket_id,
          t.donation_id as ticket_donation_id,
          IFNULL(SUM(pdt.quantity), 0) as quantity,
          DATE_FORMAT(CONVERT_TZ(t.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS ticket_creation_date
        FROM provider as p
        LEFT JOIN donation_ticket as t ON p.id = t.provider_id
        LEFT JOIN product_donation_ticket as pdt ON t.id = pdt.donation_ticket_id
        ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON t.location_id = cl.location_id' : ''}
        WHERE p.id = ? and t.enabled = 'Y'
        ${cabecera.role === 'client' ? ' AND cl.client_id = ?' : ''}
        GROUP BY t.id
        ORDER BY t.donation_id DESC`,
        [idProvider, cabecera.client_id]
      );

      if (rows.length > 0) {

        // create object with provider data and field 'tickets' with array of tickets
        var provider = {};
        var tickets = [];
        var total_quantity = 0;

        provider["id"] = rows[0].id;
        provider["name"] = rows[0].name;
        provider["creation_date"] = rows[0].creation_date;
        provider["modification_date"] = rows[0].modification_date;

        for (let i = 0; i < rows.length; i++) {
          if (rows[i].ticket_id) {
            total_quantity += rows[i].quantity;
            tickets.push({ ticket_id: rows[i].ticket_id, donation_id: rows[i].ticket_donation_id, quantity: rows[i].quantity, creation_date: rows[i].ticket_creation_date });
          }
        }

        provider["total_quantity"] = total_quantity;
        provider["tickets"] = tickets;

        res.json(provider);
      } else {
        res.status(404).json('Provider no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/product/:idProduct', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'director') {
    try {
      const { idProduct } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT p.id,
          p.name,
          pt.name as product_type,
          pdt.quantity,
          p.value_usd,
          DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
          DATE_FORMAT(CONVERT_TZ(p.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS modification_date,
          t.id as ticket_id,
          t.donation_id as ticket_donation_id,
          DATE_FORMAT(CONVERT_TZ(t.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS ticket_creation_date
        FROM product as p
        INNER JOIN product_type as pt ON p.product_type_id = pt.id
        LEFT JOIN product_donation_ticket as pdt ON p.id = pdt.product_id
        LEFT JOIN donation_ticket as t ON pdt.donation_ticket_id = t.id
        ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON t.location_id = cl.location_id' : ''}
        WHERE p.id = ? and t.enabled = 'Y'
        ${cabecera.role === 'client' ? ' AND cl.client_id = ?' : ''}
        ORDER BY t.donation_id DESC`,
        [idProduct, cabecera.client_id]
      );

      if (rows.length > 0) {

        // create object with product data and field 'tickets' with array of tickets
        var product = {};
        var tickets = [];
        var total_quantity = 0;

        product["id"] = rows[0].id;
        product["name"] = rows[0].name;
        product["product_type"] = rows[0].product_type;
        product["value_usd"] = rows[0].value_usd;
        product["creation_date"] = rows[0].creation_date;
        product["modification_date"] = rows[0].modification_date;

        for (let i = 0; i < rows.length; i++) {
          if (rows[i].ticket_id) {
            total_quantity += rows[i].quantity;
            tickets.push({ ticket_id: rows[i].ticket_id, donation_id: rows[i].ticket_donation_id, quantity: rows[i].quantity, creation_date: rows[i].ticket_creation_date });
          }
        }

        product["total_quantity"] = total_quantity;
        product["tickets"] = tickets;

        res.json(product);
      } else {
        res.status(404).json('Product no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/product-type/:idProductType', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { idProductType } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT pt.id,
          pt.name,
          pt.name_es,
          DATE_FORMAT(CONVERT_TZ(pt.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
          DATE_FORMAT(CONVERT_TZ(pt.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS modification_date,
          p.id as product_id,
          p.name as product_name,
          IFNULL(SUM(pdt.quantity), 0) as total_quantity,
          DATE_FORMAT(CONVERT_TZ(p.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS product_creation_date
        FROM product_type as pt
        INNER JOIN product as p ON pt.id = p.product_type_id
        LEFT JOIN product_donation_ticket as pdt ON p.id = pdt.product_id
        WHERE pt.id = ?
        GROUP BY p.id
        ORDER BY p.id DESC`,
        [idProductType]
      );

      if (rows.length > 0) {

        // create object with product type data and field 'products' with array of products
        var product_type = {};
        var products = [];

        product_type["id"] = rows[0].id;
        product_type["name"] = rows[0].name;
        product_type["name_es"] = rows[0].name_es;
        product_type["creation_date"] = rows[0].creation_date;
        product_type["modification_date"] = rows[0].modification_date;

        for (let i = 0; i < rows.length; i++) {
          if (rows[i].product_id) {
            products.push({ product_id: rows[i].product_id, name: rows[i].product_name, total_quantity: rows[i].total_quantity, creation_date: rows[i].product_creation_date });
          }
        }

        product_type["products"] = products;

        res.json(product_type);
      } else {
        res.status(404).json('Product type no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/delivered-by/:idDeliveredBy', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { idDeliveredBy } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT db.id,
          db.name,
          DATE_FORMAT(CONVERT_TZ(db.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
          DATE_FORMAT(CONVERT_TZ(db.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS modification_date,
          t.id as ticket_id,
          t.donation_id,
          DATE_FORMAT(t.date, '%m/%d/%Y') as date,
          DATE_FORMAT(CONVERT_TZ(t.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS ticket_creation_date
        FROM delivered_by as db
        LEFT JOIN donation_ticket as t ON db.id = t.delivered_by
        WHERE db.id = ? and t.enabled = 'Y'
        ORDER BY t.date DESC`,
        [idDeliveredBy]
      );

      if (rows.length > 0) {

        // create object with delivered by data and field 'tickets' with array of tickets
        var delivered_by = {};
        var tickets = [];

        delivered_by["id"] = rows[0].id;
        delivered_by["name"] = rows[0].name;
        delivered_by["name_es"] = rows[0].name_es;
        delivered_by["creation_date"] = rows[0].creation_date;
        delivered_by["modification_date"] = rows[0].modification_date;

        for (let i = 0; i < rows.length; i++) {
          if (rows[i].ticket_id) {
            tickets.push({ ticket_id: rows[i].ticket_id, donation_id: rows[i].donation_id, date: rows[i].date, creation_date: rows[i].ticket_creation_date });
          }
        }

        delivered_by["tickets"] = tickets;

        res.json(delivered_by);
      } else {
        res.status(404).json('Delivered by no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/transported-by/:idTransportedBy', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { idTransportedBy } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT tb.id,
          tb.name,
          DATE_FORMAT(CONVERT_TZ(tb.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
          DATE_FORMAT(CONVERT_TZ(tb.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS modification_date,
          t.id as ticket_id,
          t.donation_id,
          DATE_FORMAT(t.date, '%m/%d/%Y') as date,
          DATE_FORMAT(CONVERT_TZ(t.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS ticket_creation_date
        FROM transported_by as tb
        LEFT JOIN donation_ticket as t ON tb.id = t.transported_by_id
        WHERE tb.id = ? and t.enabled = 'Y'
        ORDER BY t.date DESC`,
        [idTransportedBy]
      );

      if (rows.length > 0) {

        // create object with transported by data and field 'tickets' with array of tickets
        var transported_by = {};
        var tickets = [];

        transported_by["id"] = rows[0].id;
        transported_by["name"] = rows[0].name;
        transported_by["name_es"] = rows[0].name_es;
        transported_by["creation_date"] = rows[0].creation_date;
        transported_by["modification_date"] = rows[0].modification_date;

        for (let i = 0; i < rows.length; i++) {
          if (rows[i].ticket_id) {
            tickets.push({ ticket_id: rows[i].ticket_id, donation_id: rows[i].donation_id, date: rows[i].date, creation_date: rows[i].ticket_creation_date });
          }
        }

        transported_by["tickets"] = tickets;

        res.json(transported_by);
      } else {
        res.status(404).json('Transported by no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/gender/:idGender', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { idGender } = req.params;

      const [rows] = await mysqlConnection.promise().query(
        `SELECT g.id,
          g.name,
          g.name_es,
          DATE_FORMAT(CONVERT_TZ(g.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
          DATE_FORMAT(CONVERT_TZ(g.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS modification_date,
          u.id as beneficiary_id,
          u.username,
          DATE_FORMAT(CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS beneficiary_creation_date
        FROM gender as g
        LEFT JOIN user as u ON g.id = u.gender_id
        WHERE (g.id = ? and u.role_id = 5) or (g.id = ? and u.role_id IS NULL)
        ORDER BY u.id DESC`,
        [idGender, idGender]
      );

      if (rows.length > 0) {

        // create object with gender data and field 'beneficiaries' with array of beneficiaries
        var gender = {};
        var beneficiaries = [];

        gender["id"] = rows[0].id;
        gender["name"] = rows[0].name;
        gender["name_es"] = rows[0].name_es;
        gender["creation_date"] = rows[0].creation_date;
        gender["modification_date"] = rows[0].modification_date;

        for (let i = 0; i < rows.length; i++) {
          if (rows[i].beneficiary_id) {
            beneficiaries.push({ beneficiary_id: rows[i].beneficiary_id, username: rows[i].username, creation_date: rows[i].beneficiary_creation_date });
          }
        }

        gender["beneficiaries"] = beneficiaries;

        res.json(gender);
      } else {
        res.status(404).json('Gender no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/ethnicity/:idEthnicity', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { idEthnicity } = req.params;
      const [rows] = await mysqlConnection.promise().query(
        `SELECT e.id,
          e.name,
          e.name_es,
          DATE_FORMAT(CONVERT_TZ(e.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
          DATE_FORMAT(CONVERT_TZ(e.modification_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS modification_date,
          u.id as beneficiary_id,
          u.username,
          DATE_FORMAT(CONVERT_TZ(u.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS beneficiary_creation_date
        FROM ethnicity as e
        LEFT JOIN user as u ON e.id = u.ethnicity_id
        WHERE (e.id = ? and u.role_id = 5) or (e.id = ? and u.role_id IS NULL)
        ORDER BY u.id DESC`,
        [idEthnicity, idEthnicity]
      );

      if (rows.length > 0) {

        // create object with ethnicity data and field 'beneficiaries' with array of beneficiaries
        var ethnicity = {};
        var beneficiaries = [];

        ethnicity["id"] = rows[0].id;
        ethnicity["name"] = rows[0].name;
        ethnicity["name_es"] = rows[0].name_es;
        ethnicity["creation_date"] = rows[0].creation_date;
        ethnicity["modification_date"] = rows[0].modification_date;

        for (let i = 0; i < rows.length; i++) {
          if (rows[i].beneficiary_id) {
            beneficiaries.push({ beneficiary_id: rows[i].beneficiary_id, username: rows[i].username, creation_date: rows[i].beneficiary_creation_date });
          }
        }

        ethnicity["beneficiaries"] = beneficiaries;

        res.json(ethnicity);
      } else {
        res.status(404).json('Ethnicity no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/ticket/:idTicket', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'director' || cabecera.role === 'stocker' || cabecera.role === 'auditor') {
    try {
      const { idTicket } = req.params;
      const language = req.query.language || 'en';

      const [rows] = await mysqlConnection.promise().query(
        `SELECT dt.id,
                dt.donation_id,
                dt.total_weight,
                p.name as provider,
                loc.community_city as location,
                DATE_FORMAT(dt.date, '%m/%d/%Y') as date,
                db.name as delivered_by,
                tb.name as transported_by,
                ${language === 'en' ? 'as1.name' : 'as1.name_es'} as audit_status,
                u.id as created_by_id,
                u.username as created_by_username,
                DATE_FORMAT(CONVERT_TZ(dt.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date,
                product.id as product_id,
                product.name as product,
                pdt.quantity as quantity
        FROM donation_ticket as dt
        INNER JOIN delivered_by as db ON dt.delivered_by = db.id
        INNER JOIN transported_by as tb ON dt.transported_by_id = tb.id
        INNER JOIN provider as p ON dt.provider_id = p.id
        INNER JOIN audit_status as as1 ON dt.audit_status_id = as1.id
        INNER JOIN location as loc ON dt.location_id = loc.id
        ${cabecera.role === 'client' ? 'INNER JOIN client_location as cl ON dt.location_id = cl.location_id' : ''}
        LEFT JOIN stocker_log as sl ON dt.id = sl.donation_ticket_id AND sl.operation_id = 5
        LEFT JOIN user as u ON sl.user_id = u.id
        LEFT JOIN product_donation_ticket as pdt ON dt.id = pdt.donation_ticket_id
        LEFT JOIN product as product ON pdt.product_id = product.id
        WHERE dt.id = ? AND dt.enabled = 'Y'
        ${cabecera.role === 'client' ? ' AND cl.client_id = ?' : ''}`,
        [idTicket, cabecera.client_id]
      );

      if (rows.length > 0) {

        // create object with ticket data and field 'products' with array of products
        var ticket = {};
        var products = [];
        ticket["id"] = rows[0].id;
        ticket["donation_id"] = rows[0].donation_id;
        ticket["total_weight"] = rows[0].total_weight;
        ticket["provider"] = rows[0].provider;
        ticket["location"] = rows[0].location;
        ticket["date"] = rows[0].date;
        ticket["delivered_by"] = rows[0].delivered_by;
        ticket["transported_by"] = rows[0].transported_by;
        ticket["audit_status"] = rows[0].audit_status;
        ticket["created_by_id"] = rows[0].created_by_id;
        ticket["created_by_username"] = rows[0].created_by_username;
        ticket["creation_date"] = rows[0].creation_date;

        if (rows[0].product_id) {
          for (let i = 0; i < rows.length; i++) {
            products.push({ product_id: rows[i].product_id, product: rows[i].product, quantity: rows[i].quantity });
          }
        }
        ticket["products"] = products;

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
          [idTicket]
        );

        ticket["notes"] = rows_notes;

        res.json(ticket);
      } else {
        res.status(404).json('Ticket no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/ticket/images/:idTicket', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const { idTicket } = req.params;

  if (cabecera.role === 'admin' || cabecera.role === 'client' || cabecera.role === 'opsmanager' || cabecera.role === 'director' || cabecera.role === 'stocker' || cabecera.role === 'auditor') {

    const [rows] = await mysqlConnection.promise().query(`
                          select id, file, DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date
                          from donation_ticket_image \
                          where donation_ticket_id = ?`, [idTicket]);

    if (rows.length > 0) {
      for (let i = 0; i < rows.length; i++) {
        getObjectParams = {
          Bucket: bucketName,
          Key: rows[i].file
        };
        command = new GetObjectCommand(getObjectParams);
        url = await getSignedUrl(s3, command, { expiresIn: 3600 });
        rows[i].file = url;
      }
    }

    res.json(rows);

  } else {
    res.status(401).json('No autorizado');
  }
})

router.get('/view/volunteer/:idVolunteer', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  if (cabecera.role === 'admin') {
    try {
      const { idVolunteer } = req.params;
      const language = req.query.language || 'en';

      const [rows] = await mysqlConnection.promise().query(
        `SELECT v.id,
          v.email,
          v.firstname,
          v.lastname,
          DATE_FORMAT(v.date_of_birth, '%m/%d/%Y') AS date_of_birth,
          v.phone,
          v.zipcode,
          l.community_city,
          ${language === 'en' ? 'g.name' : 'g.name_es'} AS gender,
          ${language === 'en' ? 'e.name' : 'e.name_es'} AS ethnicity,
          v.other_ethnicity,
          DATE_FORMAT(CONVERT_TZ(v.creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date
        FROM volunteer as v
        INNER JOIN location as l ON v.location_id = l.id
        INNER JOIN gender as g ON v.gender_id = g.id
        INNER JOIN ethnicity as e ON v.ethnicity_id = e.id
        WHERE v.id = ?`,
        [idVolunteer]
      );

      if (rows.length > 0) {
        res.json(rows[0]);
      } else {
        res.status(404).json('Gender no encontrado');
      }

    } catch (err) {
      console.log(err);
      res.status(500).json('Internal server error');
    }
  } else {
    res.status(401).json('No autorizado');
  }
}
);

router.get('/view/volunteer/images/:idVolunteer', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);
  const { idVolunteer } = req.params;

  if (cabecera.role === 'admin') {

    const [rows] = await mysqlConnection.promise().query(`
                          select id, file, DATE_FORMAT(CONVERT_TZ(creation_date, '+00:00', 'America/Los_Angeles'), '%m/%d/%Y %T') AS creation_date
                          from volunteer_signature \
                          where volunteer_id = ?`, [idVolunteer]);

    if (rows.length > 0) {
      for (let i = 0; i < rows.length; i++) {
        getObjectParams = {
          Bucket: bucketName,
          Key: rows[i].file
        };
        command = new GetObjectCommand(getObjectParams);
        url = await getSignedUrl(s3, command, { expiresIn: 3600 });
        rows[i].file = url;
      }
    }

    res.json(rows);

  } else {
    res.status(401).json('No autorizado');
  }
})

router.put('/enable-disable/:id', verifyToken, async (req, res) => {
  const cabecera = JSON.parse(req.data.data);

  if (cabecera.role === 'admin') {
    const { id } = req.params;
    const { table, enabled } = req.body;

    if (id && table && enabled) {
      try {
        const [rows] = await mysqlConnection.promise().query(
          `update ${table} set enabled = ? where id = ?`,
          [enabled, id]
        );
        if (rows.affectedRows > 0) {
          res.json('Registro actualizado correctamente');
        } else {
          res.status(500).json('No se pudo actualizar el registro');
        }
      } catch (err) {
        console.log(err);
        res.status(500).json('Internal server error');
      }
    } else {
      res.status(400).json('Faltan datos');
    }
  } else {
    res.status(401).send();
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

function verifyTokenOptional(req, res, next) {

  if (!req.headers.authorization) {
    next();
  } else {
    const token = req.headers.authorization.substr(7);
    if (token && token !== '' && token !== 'null') {
      jwt.verify(token, process.env.JWT_SECRET, (error, authData) => {
        if (error) {
          res.status(403).json('Error en el token');
        } else {
          req.data = authData;
          next();
        }
      });
    } else {
      next();
    }
  }
}

module.exports = router;