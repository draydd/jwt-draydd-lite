<?php
class Database
{
    private $servername = "localhost";
    private $username = "root";
    private $password = "";
    private $database = "jwt";
    public $db_table = "user";
    public $db_table_username = "name";
    public $db_table_password = "password";
    public $db_table_id = "id";
    public $db_table_role = "role";
    public function connect()
    {
        try {
            $conn = new PDO("mysql:host=$this->servername;dbname=$this->database", $this->username, $this->password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            return $conn;
        } catch (\Exception $e) {
            echo "Database can't connect: " . $e->getMessage();
        }
    }
    public function getServername()
    {
        return $this->servername;
    }
}
