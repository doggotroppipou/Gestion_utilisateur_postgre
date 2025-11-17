DROP TABLE IF EXISTS logs_connexion;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS utilisateur_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS utilisateurs;

CREATE TABLE utilisateurs (
    id SERIAL PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL CHECK (email LIKE '%@%.%'), 
    password_hash TEXT UNIQUE NOT NULL,
    nom VARCHAR(100),
    prenom VARCHAR(100), 
    actif BOOLEAN DEFAULT TRUE,
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_modification TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_utilisateurs_email ON utilisateurs(email);
CREATE INDEX idx_utilisateurs_actif ON utilisateurs(actif);

CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(50) UNIQUE NOT NULL,
    ressource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    UNIQUE (ressource, action)
);

CREATE TABLE role_permissions (
    role_id INT,
    permission_id INT,
    date_attribution TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE TABLE utilisateur_roles (
    utilisateur_id INT,
    role_id INT,
    date_attribution TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (utilisateur_id, role_id),
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    utilisateur_id INT,
    token VARCHAR(255) UNIQUE NOT NULL,
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_expiration TIMESTAMP,
    actif BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id) ON DELETE CASCADE
);

CREATE TABLE logs_connexion (
    id SERIAL PRIMARY KEY,
    utilisateur_id INT,
    email_tentative VARCHAR(100),
    date_heure TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    adresse_ip VARCHAR(50),
    user_agent TEXT,
    succes BOOLEAN,
    message TEXT,
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id) ON DELETE CASCADE
);

INSERT INTO roles (nom, description) VALUES
 ('admin', 'Administrateur avec tous les droits'),
 ('moderator', 'Modérateur de contenu'),
 ('user', 'Utilisateur standard');

INSERT INTO permissions (nom, ressource, action, description) VALUES
 ('read_users', 'users', 'read', 'Lire les utilisateurs'),
 ('write_users', 'users', 'write', 'Créer/modifier des utilisateurs'),
 ('delete_users', 'users', 'delete', 'Supprimer des utilisateurs'),
 ('read_posts', 'posts', 'read', 'Lire les posts'),
 ('write_posts', 'posts', 'write', 'Créer/modifier des posts'),
 ('delete_posts', 'posts', 'delete', 'Supprimer des posts');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.nom = 'admin';

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.nom = 'moderator' AND p.nom IN ('read_users', 'read_posts', 'write_posts', 'delete_posts');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.nom = 'user' AND p.nom IN ('read_users', 'read_posts', 'write_posts');

CREATE OR REPLACE FUNCTION utilisateur_a_permission(
 p_utilisateur_id INT,
 p_ressource VARCHAR,
 p_action VARCHAR
)
RETURNS BOOLEAN AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM utilisateurs WHERE id = p_utilisateur_id AND actif = TRUE) THEN
        RETURN FALSE;
    END IF;
    RETURN EXISTS (
        SELECT 1
        FROM utilisateur_roles ur
        JOIN role_permissions rp ON ur.role_id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.utilisateur_id = p_utilisateur_id
          AND p.ressource = p_ressource
          AND p.action = p_action
    );
END;
$$ LANGUAGE plpgsql;

SELECT
 u.*,
 array_agg(r.nom) AS roles
FROM utilisateurs u
JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
JOIN roles r ON ur.role_id = r.id
WHERE u.id = 1
GROUP BY u.id;

SELECT DISTINCT
 u.id AS utilisateur_id,
 u.email,
 p.nom AS permission,
 p.ressource,
 p.action
FROM utilisateurs u
JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
JOIN role_permissions rp ON ur.role_id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id
WHERE u.id = 1
ORDER BY p.ressource, p.action;


SELECT
 r.nom AS role,
 COUNT(ur.utilisateur_id) AS nombre_utilisateurs
FROM roles r
LEFT JOIN utilisateur_roles ur ON r.id = ur.role_id
GROUP BY r.id, r.nom
ORDER BY nombre_utilisateurs DESC;


SELECT
 u.id,
 u.email,
 array_agg(r.nom) AS roles
FROM utilisateurs u
JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
JOIN roles r ON ur.role_id = r.id
WHERE r.nom IN ('admin', 'moderator')
GROUP BY u.id, u.email
HAVING COUNT(DISTINCT r.nom) = 2


SELECT
 DATE(date_heure) AS jour,
 COUNT(*) AS tentatives_echouees
FROM logs_connexion
WHERE succes = false
 AND date_heure >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY DATE(date_heure)
ORDER BY jour DESC;

CREATE OR REPLACE FUNCTION est_token_valide(p_token VARCHAR)
RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1
    FROM sessions s
    INNER JOIN utilisateurs u ON s.utilisateur_id = u.id
    WHERE s.token = p_token
      AND s.actif = true
      AND s.date_expiration > CURRENT_TIMESTAMP
      AND u.actif = true
  );
END;
$$ LANGUAGE plpgsql;

