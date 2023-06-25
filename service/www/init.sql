CREATE TABLE IF NOT EXISTS courses (
	id INTEGER AUTO_INCREMENT PRIMARY KEY,
	title VARCHAR(255) NOT NULL,
	course_data TEXT NOT NULL,
	created_by INTEGER NOT NULL,
	is_private INTEGER NOT NULL DEFAULT 0,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
	id INTEGER AUTO_INCREMENT PRIMARY KEY,
	username VARCHAR(255) NOT NULL UNIQUE,
	password VARCHAR(255) NOT NULL,
	name VARCHAR(255) NOT NULL DEFAULT "",
	about_me TEXT,
	admin_of INTEGER DEFAULT NULL,
	flag VARCHAR(255) DEFAULT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (admin_of) REFERENCES courses(id)
);

CREATE TABLE IF NOT EXISTS course_enrollments (
    id INTEGER AUTO_INCREMENT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(course_id) REFERENCES courses(id)
);

CREATE TABLE IF NOT EXISTS grades (
	id INTEGER AUTO_INCREMENT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	filename TEXT NOT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO
	users (id, username, password, name, flag)
VALUES
	(
		1,
		"user",
		"$2y$10$Pj60GRAnLmqvkZ/CcQfs1OEQjoLzSgZdmc173EzkjJf.xGlbiJ/4u",
		"",
		"FLAG{this_is_also_just_test_flag!}"
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