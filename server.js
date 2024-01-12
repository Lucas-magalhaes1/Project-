const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '1234',
  database: 'usuariosdb',
});

connection.connect((err) => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados:', err.message);
  } else {
    console.log('Conexão ao banco de dados estabelecida!');
  }
});

const app = express();
const PORT = 3000; // Defina a porta que seu servidor irá ouvir

// Configurar o middleware para receber dados JSON
app.use(express.json());

// Rota para o registro de um novo usuário
app.post('/register', (req, res) => {
  const { nome, email, senha } = req.body;

  // Verificar se o e-mail ou senha já existem no banco de dados
  connection.query(
    'SELECT * FROM usuarios WHERE email = ? OR senha = ?',
    [email, senha],
    (err, results) => {
      if (err) {
        console.error('Erro ao verificar dados no banco de dados:', err);
        return res.status(500).json({ message: 'Erro ao verificar dados no banco de dados' });
      }

      if (results.length > 0) {
        // E-mail ou senha já estão em uso
        return res.status(409).json({ message: 'E-mail ou senha já estão em uso' });
      }

      // Criptografar a senha antes de armazená-la no banco de dados
      bcrypt.hash(senha, 10, (hashErr, hash) => {
        if (hashErr) {
          console.error('Erro ao criptografar a senha:', hashErr);
          return res.status(500).json({ message: 'Erro ao registrar usuário' });
        }

        // Inserir o novo usuário no banco de dados
        connection.query(
          'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
          [nome, email, hash], // Use a senha criptografada
          (insertErr) => {
            if (insertErr) {
              console.error('Erro ao inserir o usuário no banco de dados:', insertErr);
              return res.status(500).json({ message: 'Erro ao registrar usuário' });
            }

            // Registro bem-sucedido
            return res.status(201).json({ message: 'Usuário registrado com sucesso' });
          }
        );
      });
    }
  );
});

// Rota para autenticar o login do usuário
app.post('/login', (req, res) => {
  const { email, senha } = req.body;

  // Buscar o usuário no banco de dados pelo e-mail
  connection.query(
    'SELECT * FROM usuarios WHERE email = ?',
    [email],
    (err, results) => {
      if (err) {
        console.error('Erro ao verificar dados no banco de dados:', err);
        return res.status(500).json({ message: 'Erro ao verificar dados no banco de dados' });
      }

      if (results.length === 0) {
        // Usuário não encontrado
        return res.status(401).json({ message: 'Credenciais inválidas' });
      }

      // Comparar a senha fornecida com a senha armazenada no banco de dados
      bcrypt.compare(senha, results[0].senha, (compareErr, match) => {
        if (compareErr || !match) {
          // Senha incorreta
          return res.status(401).json({ message: 'Credenciais inválidas' });
        }

        // Login bem-sucedido
        return res.status(200).json({ message: 'Login bem-sucedido' });
      });
    }
  );
});

// Iniciar o servidor na porta especificada
app.listen(PORT, () => {
  console.log(`Servidor iniciado na porta ${PORT}`);
});

document.addEventListener('DOMContentLoaded', () => {
  // Obtenha o nome do usuário (você pode receber essa informação do backend)
  const userName = "admin"; // Altere "admin" para o nome de usuário real obtido do backend

  // Verifique se o nome do usuário é "admin" (usuário com permissões avançadas)
  if (userName === "admin") {
    // Exiba as opções adicionais para usuários com permissões avançadas
    const adminOptions = document.getElementById("admin-options");
    adminOptions.style.display = "block";
  }

  // Exiba as opções limitadas para todos os usuários
  const limitedOptions = document.getElementById("limited-options");
  limitedOptions.style.display = "block";
});
