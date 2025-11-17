const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const bcrypt = require('bcrypt');

router.post('/register', async (req, res) => {
  const { email, password, nom, prenom } = req.body;

  // 1. Validation
  if (!email || !password) {
    return res.status(400).json({ error: 'email et password sont obligatoires' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // 2. Vérifier si email existe
    const checkUser = await client.query(
      'SELECT id FROM utilisateurs WHERE email = $1',
      [email]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email déjà utilisé' });
    }

    // 3. Hasher le mot de passe
    const passwordHash = await bcrypt.hash(password, 10);

    // 4. Insérer l'utilisateur
    const result = await client.query(
      `INSERT INTO utilisateurs (email, password_hash, nom, prenom)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, nom, prenom, date_creation`,
      [email, passwordHash, nom, prenom]
    );

    const newUser = result.rows[0];

    // 5. Assigner le rôle "user"
    await client.query(
      `INSERT INTO utilisateurs_roles (utilisateur_id, role_id)
       VALUES ($1, (SELECT id FROM roles WHERE nom = 'user'))`,
      [newUser.id]
    );

    // 6. Commit
    await client.query('COMMIT');

    // 7. Retourner l'utilisateur sans mot de passe
    res.status(201).json({
      message: 'Utilisateur créé avec succès',
      user: newUser
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erreur création utilisateur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  } finally {
    client.release();
  }
});

module.exports = router;

const pool = require('../database/db');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // 1. Récupérer l'utilisateur
    const userResult = await client.query(
      `SELECT id, email, password_hash, nom, prenom, actif
       FROM utilisateurs
       WHERE email = $1`,
      [email]
    );

    if (userResult.rows.length === 0) {
      // 6. Logger l'échec
      await client.query(
        `INSERT INTO logs_connexion (email, succes, message)
         VALUES ($1, false, 'Utilisateur inexistant')`,
        [email]
      );

      await client.query('COMMIT');
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    const user = userResult.rows[0];

    // 2. Vérifier si actif
    if (!user.actif) {
      await client.query(
        `INSERT INTO logs_connexion (email, succes, message)
         VALUES ($1, false, 'Compte inactif')`,
        [email]
      );
      await client.query('COMMIT');
      return res.status(403).json({ error: 'Compte désactivé' });
    }

    // 3. Vérifier le mot de passe
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      await client.query(
        `INSERT INTO logs_connexion (email, succes, message)
         VALUES ($1, false, 'Mot de passe incorrect')`,
        [email]
      );
      await client.query('COMMIT');
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    // 4. Générer token
    const token = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    // 5. Créer une session
    await client.query(
      `INSERT INTO sessions (utilisateur_id, token, expire_le)
       VALUES ($1, $2, $3)`,
      [user.id, token, expiresAt]
    );

    // 6. Logger succès
    await client.query(
      `INSERT INTO logs_connexion (email, succes, message)
       VALUES ($1, true, 'Connexion réussie')`,
      [email]
    );

    await client.query('COMMIT');

    // 7. Retourner token + infos utilisateur
    res.json({
      message: 'Connexion réussie',
      token: token,
      user: {
        id: user.id,
        email: user.email,
        nom: user.nom,
        prenom: user.prenom
      },
      expiresAt: expiresAt
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erreur login:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  } finally {
    client.release();
  }
});

module.exports = router;

const { requireAuth } = require('../middleware/auth');

// GET /api/auth/profile
router.get('/profile', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id; // défini par le middleware requireAuth
    const result = await pool.query(
      `SELECT u.id, u.email, u.nom, u.prenom, u.date_creation,
              array_agg(r.nom) AS roles
       FROM utilisateurs u
       LEFT JOIN utilisateurs_roles ur ON u.id = ur.utilisateur_id
       LEFT JOIN roles r ON ur.role_id = r.id
       WHERE u.id = $1
       GROUP BY u.id`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Erreur profil:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/auth/logout
router.post('/logout', requireAuth, async (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(400).json({ error: 'Token manquant' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // 1. Désactiver la session
    await client.query(
      `UPDATE sessions
       SET actif = false
       WHERE token = $1`,
      [token]
    );

    // 2. Logger la déconnexion dans logs_connexion
    await client.query(
      `INSERT INTO logs_connexion (utilisateur_id, action, date)
       VALUES (
         (SELECT utilisateur_id FROM sessions WHERE token = $1),
         'logout',
         NOW()
       )`,
      [token]
    );

    await client.query('COMMIT');

    res.json({ message: 'Déconnexion réussie' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erreur logout:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  } finally {
    client.release();
  }
});

// GET /api/auth/logs
router.get('/logs', requireAuth, async (req, res) => {
  const userId = req.user.id; // défini par requireAuth

  try {
    const result = await pool.query(
      `SELECT *
       FROM logs_connexion
       WHERE utilisateur_id = $1
       ORDER BY date_heure DESC
       LIMIT 50`,
      [userId]
    );

    res.json({ logs: result.rows });
  } catch (error) {
    console.error('Erreur logs:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});