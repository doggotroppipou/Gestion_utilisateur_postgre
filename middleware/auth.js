const pool = require('../database/db');

async function requireAuth(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'Token manquant' });
  }

  try {
    // Vérifier que le token est valide, non expiré, et que l'utilisateur est actif
    const result = await pool.query(
      `SELECT 
         u.id, u.email, u.nom, u.prenom, u.actif
       FROM sessions s
       JOIN utilisateurs u ON u.id = s.utilisateur_id
       WHERE s.token = $1
       AND s.expire_le > NOW()
       AND u.actif = true`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Token invalide ou expiré' });
    }

    // Attache l'utilisateur au req
    req.user = result.rows[0];

    next();
  } catch (error) {
    console.error('Erreur middleware auth:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
}

module.exports = { requireAuth };