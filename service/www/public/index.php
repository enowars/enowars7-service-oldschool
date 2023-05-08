<?php
require_once '../vendor/autoload.php';

$loader = new \Twig\Loader\FilesystemLoader('../templates');
$twig = new \Twig\Environment($loader);

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

// TODO use actual database
$users = [
    [
        'id' => 1,
        'username' => 'admin',
        'password' => 'admin',
        'is_admin' => true,
        'flag' => 'flag{admin_flag}'
    ],
    [
        'id' => 2,
        'username' => 'user',
        'password' => 'user',
        'is_admin' => false,
        'flag' => 'flag{user_flag}'
    ]
];

if (!isset($_SESSION['users'])) {
    $_SESSION['users'] = $users;
} else {
    $users = $_SESSION['users'];
}

$users = $_SESSION['users'];

$action = $_GET['action'] ?? 'home';

if (!isset($_SESSION['courses'])) {
    $_SESSION['courses'] = [];
}

$courses = $_SESSION['courses'];

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

function updateProfile($user_index, $new_data)
{
    global $users;
    $_SESSION['users'][$user_index] = array_merge($users[$user_index], $new_data);
    $users = $_SESSION['users'];
}

switch ($action) {
    case 'home':
        echo $twig->render('home.twig', ['user' => $_SESSION['user'] ?? null]);
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

        echo $twig->render('login.twig', ['message' => $message ?? null]);
        break;

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

        echo $twig->render('register.twig', ['message' => $message ?? null]);
        break;


    case 'all_users':
        if (!isset($_SESSION['user']) || !$_SESSION['user']['is_admin']) {
            header('Location: index.php?action=login');
            exit;
        }

        echo $twig->render('all_users.twig', ['users' => $users]);
        break;

    case 'profile':
        if (!isset($_SESSION['user'])) {
            header('Location: index.php?action=login');
            exit;
        }

        $profile_user = $_SESSION['user'];
        $profile_user_id = $_GET['id'] ?? null;

        if (isset($profile_user_id) && $profile_user['is_admin']) {
            foreach ($users as $key => $user) {
                if ($user['id'] == $profile_user_id) {
                    $profile_user = $user;
                    $_SESSION['viewing_user_key'] = $key;
                    break;
                }
            }
        } else {
            $_SESSION['viewing_user_key'] = array_search($profile_user['id'], array_column($users, 'id'));
        }

        if ($_SERVER['REQUEST_METHOD'] == 'POST' && (!isset($profile_user_id) || !$profile_user['is_admin'])) {
            unset($_POST['id']);
            unset($_POST['submit']);

            updateProfile($_SESSION['viewing_user_key'], $_POST);
            $_SESSION['users'] = $users;
            $_SESSION['user'] = $users[$_SESSION['viewing_user_key']];
            $profile_user = $_SESSION['user'];
        }

        echo $twig->render('profile.twig', ['user' => $profile_user, 'logged_in_user' => $_SESSION['user']]);
        break;

    case 'courses':
        if (!isset($_SESSION['user'])) {
            header('Location: index.php?action=login');
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['xml'])) {
            $xmlFile = $_FILES['xml']['tmp_name'];
            $xmlContent = file_get_contents($xmlFile);

            $dom = new DOMDocument();
            // TODO: make this less obvious
            $dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD);

            $title = $dom->getElementsByTagName('title')->item(0)->nodeValue;
            $description = $dom->getElementsByTagName('description')->item(0)->nodeValue;

            echo $twig->render('view_course.twig', [
                'title' => $title,
                'description' => $description,
            ]);
        } else if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            echo $twig->render('create_course.twig');
        } else {
            echo $twig->render('forbidden.twig');
        }
        break;

    default:
        echo $twig->render('home.twig', ['user' => $_SESSION['user'] ?? null]);

}