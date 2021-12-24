<?php
require_once './config/conn.php';
require_once 'objects/user.php';

$request_method = $_SERVER["REQUEST_METHOD"];
$result = "";
$data = json_decode(file_get_contents("php://input"), true);
$user = new User;
if (!empty($_GET['function'])) {
    $user->initfunc($_GET['function'], $data);
}
switch ($request_method) {
    case 'GET':
        if (!empty($_GET['id']))
            $user->getUser($_GET['id'], $data);
        else
            $user->getAllUser($data);
        break;

    case 'POST':
        $user->createUser($data);
        break;

    case 'PUT':
        $user->updateUser($_GET['id'], $data);
        break;

    case 'DELETE':
        $user->deleteUser($_GET['id'], $data);
        break;
}
