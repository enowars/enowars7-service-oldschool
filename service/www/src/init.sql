CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username STRING NOT NULL UNIQUE,
	password STRING NOT NULL,
	name STRING NOT NULL  DEFAULT "",
	is_admin INTEGER NOT NULL DEFAULT 0,
	flag INTEGER DEFAULT NULL
);

-- CREATE TABLE IF NOT EXISTS courses (
-- 	uid INTEGER SECONDARY KEY,
-- 	file STRING NOT NULL,
-- 	dir STRING NOT NULL,
-- 	creat INTEGER NOT NULL,
-- 	UNIQUE(uid, file) ON CONFLICT ABORT,
-- 	FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
-- );

INSERT OR IGNORE INTO users (id, username, password, name, is_admin, flag)
	VALUES (1, "user", "$2y$10$Pj60GRAnLmqvkZ/CcQfs1OEQjoLzSgZdmc173EzkjJf.xGlbiJ/4u", "", 0, "flag{this_is_a_flag}");
-- TODO: remove admin user!
INSERT OR IGNORE INTO users (id, username, password, name, is_admin, flag)
	VALUES (1, "admin", "$2y$10$b9wVsbbrhmodmnonbRMSkOClFqL1an0iXjc5RgGUhmSStO3RNxKj.", "", 1, "flag{this_is_a_flag_admin}");
