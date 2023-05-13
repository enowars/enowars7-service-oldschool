<?php
require_once 'vendor/autoload.php';

$loader = new \Twig\Loader\FilesystemLoader('.');
$twig = new \Twig\Environment($loader);

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

$action = $_GET['action'] ?? 'home';

function getDbConnection()
{
    static $dbh = null;
    if ($dbh === null) {
        try {
            $dbh = new PDO('sqlite:/service/db.sqlite');
            $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Debugging
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
    $params[':password'] = password_hash($params[':password'], PASSWORD_DEFAULT);

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
                $stmt = $dbh->prepare('INSERT INTO users (username, password, is_admin, flag) VALUES (:username, :password, 0, "flag{user_flag}")');
                $stmt->bindParam(':username', $username);
                $stmt->bindParam(':password', $hashedPassword);
                $stmt->execute();

                header('Location: index.php?action=login');
                exit;
            } catch (PDOException $e) {
                $message = "Error: " . $e->getMessage();
            }
        }

        echo $twig->render('templates/register.twig', ['message' => $message ?? null]);
        break;

    case 'all_users':
        if (!isset($_SESSION['user']) || !$_SESSION['user']['is_admin']) {
            header('Location: index.php?action=login');
            exit;
        }

        $dbh = getDbConnection();
        $stmt = $dbh->prepare("SELECT * FROM users");
        $stmt->execute();
        $all_users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo $twig->render('templates/all_users.twig', ['users' => $all_users]);
        break;
        
    case 'profile':
        if (!isset($_SESSION['user'])) {
            header('Location: index.php?action=login');
            exit;
        }

        $profile_user = $_SESSION['user'];
        $profile_user_id = $_GET['id'] ?? null;
        $dbh = getDbConnection();

        if (isset($profile_user_id) && $profile_user['is_admin']) {
            $stmt = $dbh->prepare("SELECT * FROM users WHERE id = :id");
            $stmt->bindParam(":id", $profile_user_id, PDO::PARAM_INT);
            $stmt->execute();
            $profile_user = $stmt->fetch(PDO::FETCH_ASSOC);
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST' && (!isset($profile_user_id) || !$profile_user['is_admin'])) {
            unset($_POST['id']);
            unset($_POST['submit']);

            updateProfile($_SESSION['user']['id'], $_POST);

            $stmt = $dbh->prepare("SELECT * FROM users WHERE id = :id");
            $stmt->bindParam(":id", $_SESSION['user']['id'], PDO::PARAM_INT);
            $stmt->execute();
            $_SESSION['user'] = $stmt->fetch(PDO::FETCH_ASSOC);
            $profile_user = $_SESSION['user'];
        }

        $template = $profile_user['template'];
        if (!$template) {
            $template = '{{ user.username }}';
        }
        $userTemplate = $twig->createTemplate($template);
        echo $twig->render('templates/profile.twig', ['user' => $profile_user, 'logged_in_user' => $_SESSION['user'], 'userTemplate' => $userTemplate]);
        break;


    case 'courses':
        if (!isset($_SESSION['user'])) {
            header('Location: index.php?action=login');
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST' && $_SESSION['user']) {
            $title = $_POST['title'];
            $course_data = file_get_contents($_FILES['course_data']['tmp_name']);

            $dom = new DOMDocument();
            $dom->loadXML($course_data, 2 | 4);

            $dbh = getDbConnection();
            $stmt = $dbh->prepare("INSERT INTO courses (title, course_data) VALUES (:title, :course_data)");
            $stmt->bindParam(':title', $title);
            $stmt->bindParam(':course_data', $course_data);
            $stmt->execute();
        }

        $dbh = getDbConnection();
        $stmt = $dbh->prepare("SELECT * FROM courses");
        $stmt->execute();
        $courses = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($courses as &$course) {
            $dom = new DOMDocument();
            $dom->loadXML($course['course_data'], 2 | 4);
            $course_data_element = $dom->getElementsByTagName('data')->item(0);
            $course['course_data'] = $dom->saveXML($course_data_element);
        }

        echo $twig->render('templates/courses.twig', ['courses' => $courses, 'user' => $_SESSION['user']]);
        break;



    default:
        echo $twig->render('templates/home.twig', ['user' => $_SESSION['user'] ?? null]);

}