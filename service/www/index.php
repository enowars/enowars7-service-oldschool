<?php
require_once 'vendor/autoload.php';
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL & ~E_NOTICE);

use Twig\Extension\SandboxExtension;
use Twig\Sandbox\SecurityPolicy;

$loader = new \Twig\Loader\FilesystemLoader('.');
$twig = new \Twig\Environment($loader);
$parsedown = new Parsedown();

$config = loadConfig('config/config.ini');

$xmlMode = $config['xml']['mode'];
$allowedTags = explode(',', $config['sandbox']['allowed_tags']);
$allowedFilters = explode(',', $config['sandbox']['allowed_filters']);
$allowedMethods = explode(',', $config['sandbox']['allowed_methods']);
$allowedProperties = explode(',', $config['sandbox']['allowed_properties']);
$allowedFunctions = explode(',', $config['sandbox']['allowed_functions']);

$sandbox = new SandboxExtension(
    new SecurityPolicy(
        $allowedTags,
        $allowedFilters,
        $allowedMethods,
        $allowedProperties,
        $allowedFunctions
    )
);
$twig->addExtension($sandbox);
$twig->getExtension(SandboxExtension::class)->enableSandbox();

$filter = new \Twig\TwigFilter('markdown', function ($string) use ($twig, $parsedown) {
    try {
        $html = $parsedown->text($string);
        $template = $twig->createTemplate($html);
        return $template->render([]);
    } catch (\Exception $e) {
        error_log('Error rendering markdown: ' . $e->getMessage());
        return 'Error rendering markdown. Please check your input.';
    }
});

$twig->addFilter($filter);


session_start();

$action = $_GET['action'] ?? 'home';



function loadConfig($filePath)
{
    $config = parse_ini_file($filePath, true);
    if (!$config) {
        throw new Exception("Failed to load configuration.");
    }
    return $config;
}

function getDbConnection()
{
    static $dbh = null;
    if ($dbh === null) {
        try {
            $dbh = new PDO('mysql:host=db;dbname=oldschool', 'oldschool', 'oldschoolpassword');
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            error_log("Database connection established.");
        } catch (PDOException $e) {
            error_log("Error connecting to the database: " . $e->getMessage());
            throw $e;
        }
    }
    return $dbh;
}

function updateProfile($userId, $profileData)
{
    $dbh = getDbConnection();
    $sql = 'UPDATE users SET ';
    $params = [];
    $first = true;

    foreach ($profileData as $key => $value) {
        if (!$first) {
            $sql .= ', ';
        } else {
            $first = false;
        }
        $sql .= $key . ' = :' . $key;
        $params[':' . $key] = $value;
    }

    $sql .= ' WHERE id = :userId';
    $params[':userId'] = $userId;
    if (isset($params[':password']) && $params[':password'] != '') {
        $params[':password'] = password_hash($params[':password'], PASSWORD_DEFAULT);
    }

    $stmt = $dbh->prepare($sql);
    $stmt->execute($params);
}

function getAllCourses()
{
    $dbh = getDbConnection();
    $stmt = $dbh->prepare("SELECT * FROM courses");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function addCourse($title, $description, $user_id)
{
    $dbh = getDbConnection();
    $stmt = $dbh->prepare("INSERT INTO courses (title, description, user_id) VALUES (:title, :description, :user_id)");
    $stmt->bindParam(':title', $title);
    $stmt->bindParam(':description', $description);
    $stmt->bindParam(':user_id', $user_id);
    $stmt->execute();
}



switch ($action) {
    case 'home':
        echo $twig->render('templates/home.twig', ['user' => $_SESSION['user'] ?? null]);
        break;

    case 'login':
        if (isset($_SESSION['user'])) {
            header('Location: index.php');
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $username = $_POST['username'];
            $password = $_POST['password'];

            $dbh = getDbConnection();
            $stmt = $dbh->prepare('SELECT * FROM users WHERE username = :username');
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password'])) {
                $_SESSION['user'] = $user;
                header('Location: index.php');
                exit;
            } else {
                $message = 'Invalid username or password.';
            }
        }

        echo $twig->render('templates/login.twig', ['message' => $message ?? null]);
        break;

    case 'logout':
        if (isset($_SESSION['user'])) {
            unset($_SESSION['user']);
        }
        header('Location: index.php?action=login');
        exit;

    case 'register':
        if (isset($_SESSION['user'])) {
            header('Location: index.php');
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $username = $_POST['username'];
            $password = $_POST['password'];
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            $dbh = getDbConnection();
            try {
                $stmt = $dbh->prepare('INSERT INTO users (username, password, flag) VALUES (:username, :password, "")');
                $stmt->bindParam(':username', $username);
                $stmt->bindParam(':password', $hashedPassword);
                $stmt->execute();

                $stmt = $dbh->prepare('SELECT * FROM users WHERE username = :username');
                $stmt->bindParam(':username', $username);
                $stmt->execute();
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                $_SESSION['user'] = $user;
                header('Location: index.php');
                exit;

            } catch (PDOException $e) {
                $message = "Username already exists.";
            }
        }

        echo $twig->render('templates/register.twig', ['message' => $message ?? null]);
        break;

    case 'profile':
        if (!isset($_SESSION['user'])) {
            header('Location: index.php?action=login');
            exit;
        }

        $profile_user = $_SESSION['user'];
        $profile_user_id = $_GET['id'] ?? null;
        $dbh = getDbConnection();

        if (isset($profile_user_id)) {
            $stmt = $dbh->prepare("SELECT * FROM users WHERE id = :id");
            $stmt->bindParam(":id", $profile_user_id, PDO::PARAM_INT);
            $stmt->execute();
            $profile_user = $stmt->fetch(PDO::FETCH_ASSOC);

            $stmt = $dbh->prepare("SELECT * FROM course_enrollments WHERE course_id IN (SELECT admin_of FROM users WHERE id = :admin_id) AND user_id = :user_id");
            $stmt->bindParam(':admin_id', $_SESSION['user']['id']);
            $stmt->bindParam(':user_id', $profile_user['id']);
            $stmt->execute();

            if ($stmt->rowCount() == 0 && $_SESSION['user']['id'] != $profile_user['id']) {
                header('Location: index.php?action=profile');
                exit;
            }
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST' && $_SESSION['user']['id'] == $profile_user['id']) {
            unset($_POST['id']);
            unset($_POST['submit']);

            try {
                updateProfile($_SESSION['user']['id'], $_POST);
                $stmt = $dbh->prepare("SELECT * FROM users WHERE id = :id");
                $stmt->bindParam(":id", $_SESSION['user']['id'], PDO::PARAM_INT);
                $stmt->execute();
                $_SESSION['user'] = $stmt->fetch(PDO::FETCH_ASSOC);
                $profile_user = $_SESSION['user'];
            } catch (PDOException $e) {
                $message = "Error updating profile..";
            }
        }

        $profile_user['about_me'] = $profile_user['about_me'] ?? "";

        echo $twig->render('templates/profile.twig', ['user' => $profile_user, 'logged_in_user' => $_SESSION['user'], 'message' => $message ?? null]);
        break;

    case 'courses':
        if (!isset($_SESSION['user'])) {
            header('Location: index.php?action=login');
            exit;
        }

        $dbh = getDbConnection();
        $message = null;

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            if (isset($_POST['course_id'])) {
                $course_id = $_POST['course_id'];
                $stmt = $dbh->prepare("INSERT INTO course_enrollments (course_id, user_id) VALUES (:course_id, :user_id)");
                $stmt->bindParam(':course_id', $course_id);
                $stmt->bindParam(':user_id', $_SESSION['user']['id']);
                $stmt->execute();
            } else {
                $title = $_POST['title'];
                $course_data = file_get_contents($_FILES['course_data']['tmp_name']);
                $is_private = isset($_POST['is_private']) ? 1 : 0;

                $dom = new DOMDocument();
                libxml_use_internal_errors(true);

                if ($dom->loadXML($course_data, $xmlMode)) {
                    try {
                        $stmt = $dbh->prepare("INSERT INTO courses (title, course_data, created_by, is_private) VALUES (:title, :course_data, :created_by, :is_private)");
                        $stmt->bindParam(':title', $title);
                        $stmt->bindParam(':course_data', $course_data);
                        $stmt->bindParam(':created_by', $_SESSION['user']['id']);
                        $stmt->bindParam(':is_private', $is_private);
                        $stmt->execute();
                        $course_id = $dbh->lastInsertId();

                        $stmt = $dbh->prepare("UPDATE users SET admin_of = :course_id WHERE id = :user_id");
                        $stmt->bindParam(':course_id', $course_id);
                        $stmt->bindParam(':user_id', $_SESSION['user']['id']);
                        $stmt->execute();
                        $_SESSION['user']['admin_of'] = $course_id;

                        $stmt = $dbh->prepare("INSERT INTO course_enrollments (course_id, user_id) VALUES (:course_id, :user_id)");
                        $stmt->bindParam(':course_id', $course_id);
                        $stmt->bindParam(':user_id', $_SESSION['user']['id']);
                        $stmt->execute();

                        http_response_code(201);
                    } catch (PDOException $e) {
                        $message = "Error adding course.";
                    }
                } else {
                    $message = "Invalid XML. Please make sure your XML is valid";
                    $errors = libxml_get_errors();
                    libxml_clear_errors();
                }
            }
        }

        $stmt = $dbh->prepare("SELECT * FROM courses WHERE is_private = 0 OR created_by = :user_id");
        $stmt->bindParam(':user_id', $_SESSION['user']['id']);
        $stmt->execute();
        $courses = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($courses as &$course) {
            $dom = new DOMDocument();
            $dom->loadXML($course['course_data'], $xmlMode);
            $course_data_element = $dom->getElementsByTagName('data')->item(0);
            $course['course_data'] = $dom->saveXML($course_data_element);

            $stmt = $dbh->prepare("SELECT user_id FROM course_enrollments WHERE course_id = :course_id");
            $stmt->bindParam(':course_id', $course['id']);
            $stmt->execute();
            $course['users'] = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);

            if (in_array($_SESSION['user']['id'], $course['users'])) {
                $course['user_enrolled'] = true;
            } else {
                $course['user_enrolled'] = false;
            }

            if ($_SESSION['user']['admin_of'] == $course['id']) {
                $stmt = $dbh->prepare("SELECT users.* FROM users JOIN course_enrollments ON users.id = course_enrollments.user_id WHERE course_enrollments.course_id = :course_id");
                $stmt->bindParam(':course_id', $course['id']);
                $stmt->execute();
                $course['enrolled_users'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }
        }

        echo $twig->render('templates/courses.twig', ['courses' => $courses, 'user' => $_SESSION['user'], 'message' => $message, 'enrolled_users' => $enrolled_users]);
        break;

    case 'join_course':
        if (!isset($_SESSION['user'])) {
            header('Location: index.php?action=login');
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $course_id = $_POST['course_id'];
            $dbh = getDbConnection();

            $stmt = $dbh->prepare("SELECT * FROM courses WHERE id = :course_id");
            $stmt->bindParam(':course_id', $course_id);
            $stmt->execute();
            $course = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($course['is_private'] == 1 && $_SESSION['user']['id'] != $course['created_by']) {
                header('Location: index.php?action=courses&message=You+cannot+join+a+private+course.');
                exit;
            }

            try {
                $stmt = $dbh->prepare("INSERT INTO course_enrollments (course_id, user_id) VALUES (:course_id, :user_id)");
                $stmt->bindParam(':course_id', $course_id);
                $stmt->bindParam(':user_id', $_SESSION['user']['id']);
                $stmt->execute();
                header('Location: index.php?action=courses');
                exit;
            } catch (PDOException $e) {
                $message = "Error joining course.";
            }
        }

        header('Location: index.php?action=courses');
        break;

    case 'grades':
        if (!isset($_SESSION['user'])) {
            header('Location: index.php?action=login');
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST' && $_SESSION['user']) {
            if (isset($_FILES['grades']) && $_FILES['grades']['error'] == 0) {
                try {
                    $filename = $_SESSION['user']['id'] . "_" . md5($_FILES['grades']['name'] . uniqid() . mt_rand());
                    $destination = "grades/" . $filename;
                    move_uploaded_file($_FILES['grades']['tmp_name'], $destination);

                    $dbh = getDbConnection();
                    $stmt = $dbh->prepare("INSERT INTO grades (user_id, filename) VALUES (:user_id, :filename)");
                    $stmt->bindParam(':user_id', $_SESSION['user']['id']);
                    $stmt->bindParam(':filename', $filename);
                    $stmt->execute();
                    http_response_code(201);
                } catch (PDOException $e) {
                    $message = "Error adding grades.";
                }
            }
        }

        $dbh = getDbConnection();
        $stmt = $dbh->prepare("SELECT * FROM grades WHERE user_id = :user_id");
        $stmt->bindParam(':user_id', $_SESSION['user']['id']);
        $stmt->execute();
        $grades = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($grades as &$grade) {
            $filename = "grades/" . $grade['filename'];
            $grade['content'] = file_exists($filename) ? file_get_contents($filename) : 'File not found';
        }

        echo $twig->render('templates/grades.twig', ['grades' => $grades, 'user' => $_SESSION['user']]);
        break;

    case 'about':
        echo $twig->render('templates/about.twig', ['user' => $_SESSION['user'] ?? null]);
        break;

    default:
        echo $twig->render('templates/home.twig', ['user' => $_SESSION['user'] ?? null]);

}