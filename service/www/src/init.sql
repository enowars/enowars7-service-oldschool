CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username STRING NOT NULL UNIQUE,
	name STRING NOT NULL  DEFAULT "",
	password STRING NOT NULL,
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

INSERT OR IGNORE INTO users (id, username, password, is_admin, flag)
	VALUES (1, "user", "user", 0, "flag{this_is_a_flag}");
