CREATE TABLE IF NOT EXISTS users (
	id INTEGER AUTO_INCREMENT PRIMARY KEY,
	username VARCHAR(255) NOT NULL UNIQUE,
	password VARCHAR(255) NOT NULL,
	name VARCHAR(255) NOT NULL DEFAULT "",
	about_me TEXT,
	is_admin INTEGER NOT NULL DEFAULT 0,
	flag VARCHAR(255) DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS courses (
	id INTEGER AUTO_INCREMENT PRIMARY KEY,
	title VARCHAR(255) NOT NULL,
	course_data TEXT NOT NULL,
	created_by INTEGER NOT NULL,
	is_private INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS grades (
	id INTEGER AUTO_INCREMENT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	filename TEXT NOT NULL
);

INSERT INTO
	users (id, username, password, name, is_admin, flag)
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
INSERT INTO
	users (id, username, password, name, is_admin, flag)
VALUES
	(
		2,
		"admin",
		"$2y$10$b9wVsbbrhmodmnonbRMSkOClFqL1an0iXjc5RgGUhmSStO3RNxKj.",
		"",
		1,
		"flag{this_is_a_flag_admin}"
	);

INSERT INTO
	users (id, username, password, name, is_admin, flag)
VALUES
	(
		3,
		"mike",
		"$2y$10$Pj60GRAnLmqvkZ/CcQfs1OEQjoLzSgZdmc173EzkjJf.xGlbiJ/4u",
		"",
		0,
		"flag{this_is_a_flag_mike}"
	);

INSERT INTO
	courses (id, title, course_data, created_by, is_private)
VALUES
	(
		1,
		"Introduction to Web Security",
		"<?xml version='1.0' encoding='UTF-8'?><data><course><name>WEB 101</name><description>Learn the basics of web security and common vulnerabilities, including XSS, CSRF, and SQL injection.</description></course></data>",
		1,
		0
	);