<?php
require_once './config/conn.php';
require_once './config/config.php';
require_once './vendor/autoload.php';

use Firebase\JWT\JWT;

class User
{
    private $conn;
    private $database;
    private $username;
    private $password;
    private $role;
    public function __construct()
    {
        $this->database = new Database;
        $this->conn = $this->database->connect();
    }
    public function initfunc($func, $data)
    {
        if (method_exists($this, $func)) {
            $this->$func($data);
        } else {
            $this->throwError(404, "Function $func tidak ditemukan.");
        }
    }
    private function login($data)
    {
        if (!empty($data['name']) && !empty($data['password'])) {
            $this->username = $data['name'];
            $stmt = $this->conn->prepare("SELECT * FROM " . $this->database->db_table . " WHERE " .
                $this->database->db_table_username . " = :name");
            $stmt->bindParam(":name", $this->username);
            $stmt->execute();
            $result = $stmt->fetchAll();
            $result = $result[0];
            if (!empty($result)) {
                $this->password = $result[$this->database->db_table_password];
                $pass = strcmp($data['password'], $this->password);
                if (!$pass) {
                    $this->role = $result[$this->database->db_table_role];
                    $this->generatetoken($result[$this->database->db_table_id]);
                } else {
                    $this->throwError(404, 'Password salah.');
                }
            } else {
                $this->throwError(404, 'Username tidak didapati.');
            }

            echo json_encode($data);
            exit;
        } else {
            $this->throwError(400, 'Username atau Password kosong.');
        }
    }
    private function generatetoken($id)
    {
        $token = [
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => $this->database->getServername(),
            'data' => [
                'id' => $id,
                'name' => $this->username,
                'role' => $this->role,
            ]
        ];
        $jwt = JWT::encode($token, SECRETE_KEY);
        echo json_encode($jwt);
        exit;
    }
    private function decodetoken($token)
    {
        try {
            $jwt = JWT::decode($token, SECRETE_KEY, ['HS256']);
            if ($jwt->exp < time()) {
                $this->throwError(400, 'Token sudah lewat masa expired.');
            }
            return $jwt->data;
        } catch (\Exception $th) {
            $this->throwError(400, 'Token invalid .');
        }
    }
    public function getUser($id = null, $data)
    {
        if (!empty($data['token'])) {
            $token = $this->decodetoken($data['token']);
            if ($token->role == 'admin' || $token->id == $id) {
                if ($id == null) {
                    $stmt = $this->conn->query("SELECT * FROM " . $this->database->db_table . "");
                    $data = $stmt->fetchAll();
                    if (!empty($data)) {
                        $this->response($data);
                    } else {
                        $this->throwError(400, "Tidak ada konten database");
                    }
                }
                $stmt = $this->conn->prepare("SELECT * FROM " . $this->database->db_table .
                    " WHERE " . $this->database->db_table_id . " = :id");
                $stmt->bindParam(":id", $id);
                $stmt->execute();
                $data = $stmt->fetchAll();
                if (!empty($data)) {
                    $this->response($data);
                } else {
                    $this->throwError(404, "ID tidak didapati");
                }
            } else {
                $this->throwError(403, 'Hanya admin bisa mengakses semua data.');
            }
        } else {
            $this->throwError(400, 'Token belum dimasukkan.');
        }
    }
    public function getAllUser($data)
    {
        if (!empty($data['token'])) {
            $token = $this->decodetoken($data['token']);
            if ($token->role == 'admin') {
                $stmt = $this->conn->query("SELECT * FROM " . $this->database->db_table);
                $result = $stmt->fetchAll();
                echo json_encode($result);
            } else {
                $this->throwError(403, 'Hanya admin bisa mengakses semua data.');
            }
        } else {
            $this->throwError(400, 'Token belum dimasukkan.');
        }
    }
    public function createUser($data)
    {
        if (!empty($data['token'])) {
            $token = $this->decodetoken($data['token']);

            if ($token->role == 'admin') {
                if (!empty($data['name']) && !empty($data['password']) && !empty($data['role'])) {
                    $stmt = $this->conn->prepare("SELECT * FROM " . $this->database->db_table . " WHERE " . $this->database->db_table_username . " = :name");
                    $stmt->bindParam(":name", $data['name']);
                    $stmt->execute();
                    $result = $stmt->fetchAll();
                    if (empty($result)) {
                        $this->username = $data['name'];
                        $this->role = $data['role'];
                        $this->password = $data['password'];
                        $stmt = $this->conn->prepare("INSERT INTO " . $this->database->db_table . " SET " .
                            $this->database->db_table_username . " = :name, " . $this->database->db_table_password . " = :pass, "
                            . $this->database->db_table_role . " = :role");
                        $stmt->bindParam(":name", $this->username);
                        $stmt->bindParam(":pass", $this->password);
                        $stmt->bindParam(":role", $this->role);
                        $stmt->execute();
                        if ($stmt) {
                            $response = [
                                'message' => 'Berhasil membuat user.',

                            ];
                            $this->response($response);
                        } else {
                            $this->throwError(400, "Gagal membuat user.");
                        }
                    } else {
                        $this->throwError(400, "Name sudah ada.");
                    }
                } else {
                    $this->throwError(400, "Username atau password atau role kosong.");
                }
            } else {
                $this->throwError(403, 'Hanya admin yang bisa mengakses.');
            }
        } else {
            $this->throwError(400, 'Token belum dimasukkan.');
        }
    }
    public function updateUser($id, $data)
    {
        if (!empty($data['token'])) {
            $token = $this->decodetoken($data['token']);

            if ($token->role == 'admin' || $token->id == $id) {
                if (!empty($data['name']) && !empty($data['password']) && !empty($id)) {
                    $this->username = $data['name'];
                    $this->password = $data['password'];
                    $stmt = $this->conn->prepare("SELECT * FROM " . $this->database->db_table . " 
            WHERE " . $this->database->db_table_id . " = :id");
                    $stmt->bindParam(":id", $id);
                    $stmt->execute();
                    $result = $stmt->fetchAll();
                    if (!empty($result)) {
                        $stmt = $this->conn->prepare("UPDATE " . $this->database->db_table . " SET " .
                            $this->database->db_table_username . " = :name, " .
                            $this->database->db_table_password . " = :pass WHERE " .

                            $this->database->db_table_id . " = :id");

                        $pass = $this->password;
                        $stmt->bindParam(":name", $this->username);
                        $stmt->bindParam(":pass", $pass);
                        $stmt->bindParam(":id", $id);
                        if ($stmt->execute()) {
                            $response = [
                                'message' => "Berhasil mengupdate user dengan id = $id ",
                            ];
                            $this->response($response);
                        } else {
                            $this->throwError(400, "Gagal update data.");
                        }
                    } else {
                        $this->throwError(404, "User id tidak didapati.");
                    }
                } else {
                    $this->throwError(400, "Parameter id tidak didapati.");
                }
            } else {
                $this->throwError(403, 'Hanya admin yang bisa akses semua id.');
            }
        } else {
            $this->throwError(400, 'Token belum dimasukkan.');
        }
    }
    public function deleteUser($id = null, $data)
    {
        if (!empty($data['token'])) {
            $token = $this->decodetoken($data['token']);
            if ($token->role == 'admin') {
                if (!empty($id)) {
                    $stmt = $this->conn->prepare("DELETE FROM " . $this->database->db_table .
                        " WHERE " . $this->database->db_table_id . " = :id");
                    $stmt->bindParam(":id", $id);
                    if ($stmt->execute()) {
                        $response = [
                            'message' => "Berhasil menghapus user dengan $id ",
                        ];
                        $this->response($response);
                    } else {
                        $this->throwError(400, "Gagal dihapus.");
                    }
                } else {
                    $this->throwError(400, "Parameter id tidak didapat.");
                }
            } else {
                $this->throwError(403, 'Hanya admin yang bisa akses semua id.');
            }
        } else {
            $this->throwError(400, 'Token belum dimasukkan.');
        }
    }
    public function throwError($code, $msg)
    {
        http_response_code($code);
        $message = [
            'status' => $code,
            'message' => $msg
        ];
        echo json_encode($message);
        exit;
    }
    public function response($data)
    {
        http_response_code(200);
        $message = [
            'status' => 200,
            'data' => $data
        ];
        echo json_encode($message);
        exit;
    }
}
