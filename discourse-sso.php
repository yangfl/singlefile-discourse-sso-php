<?php
/*
This is single-file SSO client for Discourse.

# Latest version on Github:
https://github.com/ArseniyShestakov/singlefile-discourse-sso-php
# Discourse How-To about setting SSO provider:
https://meta.discourse.org/t/using-discourse-as-a-sso-provider/32974
# Based off paxmanchris example:
https://gist.github.com/paxmanchris/e93018a3e8fbdfced039
*/
define('SSO_DB_HOST', 'localhost');
define('SSO_DB_USERNAME', '');
define('SSO_DB_PASSWORD', '');
define('SSO_DB_SCHEMA', '');
define('SSO_DB_NONCE', 'sso_login');
define('SSO_DB_TABLE', 'sso_user');

define('SSO_URL_SITE', 'https://'.$_SERVER['HTTP_HOST']);
define('SSO_URL_SCRIPT', '/' . basename(__FILE__));
define('SSO_URL_DISCOURSE', 'https://example.com');
// "sso secret" from Discourse admin panel
// Good way to generate one on Linux: pwgen -syc
define('SSO_SECRET', '<CHANGE_ME>');
// Another secret used for sign local cookie
define('SSO_LOCAL_SECRET', '<CHANGE_ME>');
// Seconds before new nonce expire
define('SSO_TIMEOUT', 120);
// Seconds before SSO authentication expire
define('SSO_EXPIRE', 2592000);
define('SSO_RENEW_EXPIRE', SSO_EXPIRE);
define('SSO_COOKIE', '__discourse_sso');
define('SSO_COOKIE_DOMAIN', $_SERVER['HTTP_HOST']);
define('SSO_COOKIE_SECURE', true);
define('SSO_COOKIE_HTTPONLY', true);

// We'll only redirect to Discrouse if script executed directly
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    $returnto = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : SSO_URL_SITE;

    $DISCOURSE_SSO = new DiscourseSSOClient(true);
    if (isset($_GET['logout'])) {
        $DISCOURSE_SSO->deauthenticate($returnto);
        exit();
    }

    $status = $DISCOURSE_SSO->getAuthentication($returnto);
    if ($status and $status['logged']) {
        header('Location: ' . SSO_URL_SITE);
        exit();
    }

    if (empty($_GET) || !isset($_GET['sso']) || !isset($_GET['sig'])) {
        $DISCOURSE_SSO->authenticate($returnto);
    } else {
        $DISCOURSE_SSO->verify($_GET['sso'], $_GET['sig'], $_GET['returnto']);
    }
}

class DiscourseSSOClient {
    private $db;
    private $sqlNonceStructure = 'CREATE TABLE IF NOT EXISTS `%s` (
        `nonce` text NOT NULL PRIMARY KEY,
        `expire` int NOT NULL,
        `external_id` int NOT NULL DEFAULT 0
    )';
    private $sqlTableStructure = 'CREATE TABLE IF NOT EXISTS `%s` (
        `external_id` int NOT NULL PRIMARY KEY,
        `target_username` text,
        `name` text,
        `username` text,
        `email` text,
        `admin` Tinyint(1) NOT NULL DEFAULT 0,
        `moderator` Tinyint(1) NOT NULL DEFAULT 0,
        `groups` text
    )';

    public function __construct ($createTableIfNotExist = false) {
        $this->db = new SQLite3(SSO_DB_HOST);
        if (!$this->db) {
            exit('Discourse SSO: could not connect to SQLite3 database!');
        }
        if ($createTableIfNotExist)
            $this->createTableIfNotExist();
        if (!mt_rand(0, 99))
            $this->removeExpiredNonces();
    }

    public function getAuthentication ($returnto = SSO_URL_SITE) {
        $nonce = $this->getCookie();
        if (!$nonce) {
            return false;
        }
        $status = $this->getStatus($nonce);
        if ($status and !$status['logged']) {
            $this->authenticate($returnto);
            exit();
        }
        return $status;
    }

    public function authenticate ($returnto = SSO_URL_SITE) {
        $new_nonce = $this->newNonce();
        $nonce = $new_nonce[0];
        $nonceExpire = $new_nonce[1];
        $this->setCookie($nonce, $nonceExpire);
        $payload = base64_encode(http_build_query(array(
            'nonce' => $nonce,
            'return_sso_url' =>
                SSO_URL_SITE . SSO_URL_SCRIPT . '?returnto=' . urlencode($returnto),
        )));
        $request = array(
            'sso' => $payload,
            'sig' => hash_hmac('sha256', $payload, SSO_SECRET)
        );
        $url = $this->getUrl($request);
        header('Location: ' . $url);
        echo '<a href=' . $url . '>Sign in with Discourse</a><pre>';
    }

    public function deauthenticate ($returnto = SSO_URL_SITE) {
        $nonce = $this->getCookie();
        if ($nonce) {
            $this->removeNonce($nonce);
        }
        $this->clearCookie();
        header('Location: ' . $returnto);
    }

    private function failedVerify ($reason) {
        header('HTTP/1.1 401 Unauthorized');
        echo $reason;
        exit();
    }

    public function verify ($sso, $signature, $returnto = SSO_URL_SITE) {
        $sso = urldecode($sso);
        if (hash_hmac('sha256', $sso, SSO_SECRET) !== $signature) {
            $this->failedVerify('bad sig');
        }

        $query = [];
        parse_str(base64_decode($sso), $query);
        $query['nonce'] = $this->clear($query['nonce']);

        if (!$this->verifyNonce($query['nonce'])) {
            $this->failedVerify('time expired');
        }

        $cookie_nonce = $this->getCookie();
        if ($cookie_nonce != $query['nonce']) {
            $this->failedVerify('bad cookie');
        }

        $loginExpire = time() + SSO_EXPIRE;
        $this->loginUser($query, $loginExpire);
        $this->setCookie($query['nonce'], $loginExpire + SSO_RENEW_EXPIRE);
        header('Access-Control-Allow-Origin: *');
        header('Location: ' . $returnto);
    }

    public function removeNonce ($nonce) {
        $nonce = $this->db->escapeString($nonce);
        $this->db->query(
            'DELETE FROM ' . SSO_DB_NONCE . ' WHERE nonce = "'.$nonce.'"');
    }

    private function removeExpiredNonces () {
        $this->db->query(
            'DELETE FROM ' . SSO_DB_NONCE . ' WHERE expire < ' . time());
    }

    private function newNonce () {
        $nonce = base64_encode(random_bytes(96));
        $expire = time() + SSO_TIMEOUT;
        $this->db->query(
            'INSERT INTO ' . SSO_DB_NONCE .
            " (`nonce`, `expire`) VALUES ('" . $this->db->escapeString($nonce) .
            "', '".$expire."')");
        return [$nonce, $expire];
    }

    private function verifyNonce ($nonce) {
        $nonce_record = $this->db->query(
            "SELECT * FROM " . SSO_DB_NONCE . " WHERE `nonce` = '" .
            $this->db->escapeString($nonce) . "'"
        )->fetchArray();
        if ($nonce_record) {
            if ($nonce_record['expire'] >= time()) {
                return true;
            }
            $this->removeNonce($nonce);
        }
        return false;
    }

    private function getStatus($nonce) {
        $nonce_record = $this->db->query(
            "SELECT * FROM " . SSO_DB_NONCE . " WHERE `nonce` = '" .
            $this->db->escapeString($nonce) . "'"
        )->fetchArray();
        if ($nonce_record and $nonce_record['external_id']) {
            $logged = $nonce_record['expire'] >= time();
            if (!$logged) {
                $this->removeNonce($nonce);
                $this->clearCookie();
            }
            return [
                'nonce' => $nonce,
                'logged' => $logged,
                'data' => $this->db->query(
                    "SELECT * FROM " . SSO_DB_TABLE .
                    " WHERE `external_id` = '${nonce_record['external_id']}'"
                )->fetchArray()
            ];
        }
        return false;
    }

    private function loginUser ($data, $expire) {
        $this->db->query("UPDATE `" . SSO_DB_NONCE . "` SET
                `external_id` = ${data['external_id']},
                `expire` = $expire
            WHERE `nonce` = '".$this->db->escapeString($data['nonce'])."'");

        $old_data = $this->db->query(
            "SELECT * FROM " . SSO_DB_TABLE .
            " WHERE external_id = ${data['external_id']}")->fetchArray();
        if (!$old_data) {
            $this->db->query(
                'INSERT INTO ' . SSO_DB_TABLE .
                " (`external_id`, `target_username`, `name`,
                `username`, `email`, `admin`, `moderator`, `groups`) VALUES (
                    '${data['external_id']}',
                    '" . $this->db->escapeString($data['username']) . "',
                    '" . $this->db->escapeString($data['name']) . "',
                    '" . $this->db->escapeString($data['username']) . "',
                    '" . $this->db->escapeString($data['email']) . "',
                    '" . (int)$data['admin'] . "',
                    '" . (int)$data['moderator'] . "',
                    '" . $this->db->escapeString($data['groups']) . "'
                )");
        } else {
            if (!$old_data['target_username']) {
                $this->db->query("UPDATE `" . SSO_DB_TABLE . "` SET
                    `target_username` = '" . $this->db->escapeString($data['username']) . "'
                    WHERE `external_id` = ${data['external_id']}");
            }
            $this->db->query("UPDATE `" . SSO_DB_TABLE . "` SET
                `name` = '" . $this->db->escapeString($data['name']) . "',
                `username` = '" . $this->db->escapeString($data['username']) . "',
                `email` = '" . $this->db->escapeString($data['email']) . "',
                `admin` = '" . (int)$data['admin'] . "',
                `moderator` = '" . (int)$data['moderator'] . "'
                WHERE `external_id` = ${data['external_id']}");
        }
    }

    private function setCookie ($value, $expire) {
        setcookie(
            SSO_COOKIE, $value . ',' . $this->signCookie($value), $expire, "/",
            SSO_COOKIE_DOMAIN, SSO_COOKIE_SECURE, SSO_COOKIE_HTTPONLY);
    }

    private function getCookie () {
        if (empty($_COOKIE) || !isset($_COOKIE[SSO_COOKIE]))
            return '';

        $cookie_nonce = explode(',', $_COOKIE[SSO_COOKIE], 2);
        if ($cookie_nonce[1] !== $this->signCookie($cookie_nonce[0])) {
            $this->clearCookie();
            return false;
        }

        return $this->clear($cookie_nonce[0]);
    }

    private function clearCookie () {
        $this->setCookie('', time() - 3600);
    }

    private function getUrl ($request) {
        return SSO_URL_DISCOURSE . '/session/sso_provider?' .
            http_build_query($request);
    }

    private function signCookie ($string) {
        return hash_hmac('sha256', $string, SSO_LOCAL_SECRET);
    }

    private function clear ($string) {
        return preg_replace('[^A-Za-z0-9_]', '', trim($string));
    }

    private function createTableIfNotExist () {
        if (!$this->db->query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='" .
                SSO_DB_NONCE . "'")->fetchArray()) {
            $this->db->query(sprintf($this->sqlNonceStructure, SSO_DB_NONCE));
        }
        if (!$this->db->query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='" .
                SSO_DB_TABLE . "'")->fetchArray()) {
            $this->db->query(sprintf($this->sqlTableStructure, SSO_DB_TABLE));
        }
    }

    public function dropTable () {
        $this->db->query("DROP TABLE IF EXISTS ".SSO_DB_TABLE);
    }
}
