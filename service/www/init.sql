CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username STRING NOT NULL UNIQUE,
	password STRING NOT NULL,
	name STRING NOT NULL DEFAULT "",
	about_me STRING,
	is_admin INTEGER NOT NULL DEFAULT 0,
	flag INTEGER DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS courses (
	id INTEGER PRIMARY KEY,
	title STRING NOT NULL,
	course_data STRING NOT NULL,
	created_by INTEGER NOT NULL,
	is_private INTEGER NOT NULL DEFAULT 0
);

INSERT
	OR IGNORE INTO users (id, username, password, name, is_admin, flag)
VALUES
	(
		1,
		"user",
		"$2y$10$Pj60GRAnLmqvkZ/CcQfs1OEQjoLzSgZdmc173EzkjJf.xGlbiJ/4u",
		"",
		0,
		"flag{this_is_a_flag}"
	);

-- TODO: remove admin user!
INSERT
	OR IGNORE INTO users (id, username, password, name, is_admin, flag)
VALUES
	(
		2,
		"admin",
		"$2y$10$b9wVsbbrhmodmnonbRMSkOClFqL1an0iXjc5RgGUhmSStO3RNxKj.",
		"",
		1,
		"flag{this_is_a_flag_admin}"
	);

INSERT
	OR IGNORE INTO users (id, username, password, name, is_admin, flag)
VALUES
	(
		3,
		"mike",
		"$2y$10$Pj60GRAnLmqvkZ/CcQfs1OEQjoLzSgZdmc173EzkjJf.xGlbiJ/4u",
		"",
		0,
		"flag{this_is_a_flag_mike}"
	);

INSERT
	OR IGNORE INTO courses (id, title, course_data, created_by, is_private)
VALUES
	(
		1,
		"Introduction to Web Security",
		"<?xml version='1.0' encoding='UTF-8'?><data><course><name>WEB 101</name><description>Learn the basics of web security and common vulnerabilities, including XSS, CSRF, and SQL injection.</description></course></data>",
		1,
		0
	);