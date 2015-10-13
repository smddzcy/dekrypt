<?php

/**
 * Dekrypt
 * @description A decrypter&decoder with multiple algorithm support
 * @version 1.0
 * @author Samed Duzcay <samedduzcay@gmail.com>
 */

class dekrypt
{

    public $hash;
    public $key = array();
    public $iv = array();

    /**
     * @param string $hash Data to decrypt görünü
     * @param mixed $key Key array|file|string
     * @param mixed $iv IV array|file|string
     */
    public function __construct($hash, $key = '', $iv = '')
    {
        if (is_file(base64_decode($hash)))
            $this->hash = base64_encode(file_get_contents(base64_decode($hash)));
        else
            $this->hash = trim($hash);

        if (is_array($key) || is_object($key))
            $this->key = (array)$key;
        elseif (file_exists($key))
            $this->key = explode("\n", file_get_contents($key)); // Delimiter is new line for key list file
        else
            $this->key[] = trim($key);

        if (is_array($iv) || is_object($iv))
            $this->iv = (array)$iv;
        elseif (file_exists($iv))
            $this->iv = explode("\n", file_get_contents($iv)); // Delimiter is new line for key list file
        else
            $this->iv[] = trim($iv);
    }

    /**
     * @param string $url cURL connection will be established to this URL
     * @return string HTML output
     */
    public function connect($url)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0');
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }

    /**
     * @param string $str String to be checked if it contains any non-ASCII characters
     * @return bool Returns true if string is all in ASCII, false otherwise.
     */
    public function isAscii($str)
    {
        return (preg_match('/[^\x20-\x7f]/', $str)) ? false : true;
    }

    /**
     * Online decrypter for MD5 that uses http://md5cracker.org/ 's *not official* API :)
     * @return bool|string If it can decrypt than returns decrypted data, or returns false
     */
    public function DE_md5()
    {
        $sites = array(
            'md5.net', 'md5cracker.org', 'tmto', 'md5online.net', 'md5.my-addr.com', 'md5decryption.com', 'md5crack', 'authsecu', 'netmd5crack', 'md5pass', 'i337.net'
        );
        foreach ($sites as $site) {
            $result = json_decode($this->connect("http://md5cracker.org/api/api.cracker.php?&database=" . $site . "&hash=" . $this->hash), true);
            if ($result['status'] == 1)
                return $result['result'];
        }
        return false;
    }

    /**
     * Code below guesses the shift count by usage ratio of each character in English alphabet
     *
     * $max = 0;
     * $ratio = array(
     * 6.51, 1.89, 3.06, 5.08, 17.4,
     * 1.66, 3.01, 4.76, 7.55, 0.27,
     * 1.21, 3.44, 2.53, 9.78, 2.51,
     * 0.29, 0.02, 7.00, 7.27, 6.15,
     * 4.35, 0.67, 1.89, 0.03, 0.04, 1.13);
     *
     * $c = $s = array(
     * 0, 0, 0, 0, 0,
     * 0, 0, 0, 0, 0,
     * 0, 0, 0, 0, 0,
     * 0, 0, 0, 0, 0,
     * 0, 0, 0, 0, 0, 0);
     *
     * for ($i = 0; $i < strlen($this->hash); $i++) {
     * $x = (ord($this->hash[$i]) | 32) - 97;
     * if (0 <= $x && $x < 26) {
     * ++$c[$x];
     * }
     * }
     *
     * for ($j = 0; $j < 26; $t++) {
     * for ($i = 0; $i < 26; ++$i) {
     * if ($max < ($s[$j] += 0.01 * $c[$i] * $ratio[($i + $j) % 26])) {
     * $max = $s[$j];
     * }
     * }
     * }
     * $shift = (26 - array_search($max, $s)) % 26;
     *
     */

    /**
     * @param int $shift How many characters are shifted (to the RIGHT)
     * @return string Deciphered data
     */
    public function DE_caesar($shift)
    {
        $ret = "";
        for ($i = 0; $i < strlen($this->hash); $i++) {
            $asc = ord($this->hash[$i]);
            if (97 <= $asc && $asc < 123) { // Lower-case letters
                $ret .= chr(($asc - $shift + 7) % 26 + 97);
            } elseif (65 <= $asc && $asc < 91) { // Upper-case letters
                $ret .= chr(($asc - $shift + 13) % 26 + 65);
            } else { // Anything not [a-zA-Z]
                $ret .= $this->hash[$i];
            }
        }
        return $ret;
    }

    /**
     * ROT13 decode
     * @return string
     */
    public function DE_rot13()
    {
        return str_rot13($this->hash);
    }

    /**
     * Base64 decode
     * @return string
     */
    public function DE_base64()
    {
        return base64_decode($this->hash);
    }

    /**
     * Hex decode (to string)
     * @param string $hash If this is set, it'll be decoded instead of object's hash
     * @return string Decoded data
     */
    public function DE_hex($hash = "")
    {
        if ($hash == "")
            return pack("H*", $this->hash);
        else
            return pack("H*", $hash);
    }

    /**
     * Binary decode (to string)
     * @param string $hash If this is set, it'll be decoded instead of object's hash
     * @return string
     */
    public function DE_bin($hash = "")
    {
        if ($hash == "")
            return $this->DE_hex(dechex(bindec($this->hash)));
        else
            return $this->DE_hex(dechex(bindec($hash)));
    }

    /**
     * Decimal decode (to string)
     * @param string $hash If this is set, it'll be decoded instead of object's hash
     * @return string
     */
    public function DE_dec($hash = "")
    {
        if ($hash == "")
            return $this->DE_hex(dechex($this->hash));
        else
            return $this->DE_hex(dechex($hash));
    }

    /**
     * UU decode
     * @return string
     */
    public function DE_uu()
    {
        return convert_uudecode($this->hash);
    }

    /**
     * Mcrypt function for decrypting hashes
     * @param string $hash Encrypted hash (with base64)
     * @param array $methods Decrypt methods for openssl
     * @param array $key Key
     * @param array $iv Initialization vector
     * @return bool|string If it can decrypt than returns decrypted data, or returns false
     */
    public function DE_mcrypt($hash, $methods, $key, $iv)
    {
        foreach ($key as $k) {
            foreach ($iv as $i) {
                foreach ($methods as $method) {
                    list($m, $mod) = explode(':', $method);
                    if (($res = mcrypt_decrypt($m, trim($k), base64_decode($hash), $mod, (trim($i) == '') ? str_repeat('0', mcrypt_get_iv_size($m, $mod)) : trim($i))) != false) {
                        /*
                         * Check if the result is in ASCII
                         * Otherwise convert it to hex
                         */
                        if ($this->isAscii($res)) {
                            return $res;
                        } else {
                            $hexVal = "Hex value -> ";
                            foreach (str_split($res) as $v) {
                                $hexVal .= strlen(dechex(ord($v))) == 1 ? '0' . dechex(ord($v)) : dechex(ord($v));
                            }
                            return $hexVal;
                        }

                    }
                }
            }
        }
        return false;
    }

    /**
     * AES decrypt (128-192-256 bit)
     * @return bool|string If it can decrypt than returns decrypted data, or returns false
     */
    public function DE_aes()
    {
        switch (strlen($this->DE_base64())) {
            case 16:
                $methods = array(
                    'rijndael-128:cbc', 'rijndael-128:cfb', 'rijndael-128:ecb'
                );
                break;
            case 24:
                $methods = array(
                    'rijndael-192:cbc', 'rijndael-192:cfb', 'rijndael-192:ecb'
                );
                break;
            case 32:
                $methods = array(
                    'rijndael-256:cbc', 'rijndael-256:cfb', 'rijndael-256:ecb'
                );
                break;
            default:
                return false;
        }
        if ($this->key != '' || !empty($this->key))
            return $this->DE_mcrypt($this->hash, $methods, $this->key, $this->iv);
        else
            return false;
    }

    /**
     * Blowfish decrypt
     * @return bool|string If it can decrypt than returns decrypted data, or returns false
     */
    public function DE_blowfish()
    {
        $methods = array(
            'blowfish:cbc', 'blowfish:cfb', 'blowfish:ecb', 'blowfish-compat:cbc', 'blowfish-compat:cfb', 'blowfish-compat:ecb'
        );
        if (($this->key != '' || !empty($this->key) && ($this->iv != '' || !empty($this->iv))))
            return $this->DE_mcrypt($this->hash, $methods, $this->key, $this->iv);
        else
            return false;
    }

    /**
     * DES decrypt
     * @return bool|string If it can decrypt than returns decrypted data, or returns false
     */
    public function DE_des()
    {
        $methods = array(
            'des:cbc', 'des:cfb', 'des:ecb', 'tripledes:cbc', 'tripledes:cfb', 'tripledes:ecb'
        );
        if (($this->key != '' || !empty($this->key) && ($this->iv != '' || !empty($this->iv))))
            return $this->DE_mcrypt($this->hash, $methods, $this->key, $this->iv);
        else
            return false;
    }

    /**
     * RC2 decrypt
     * @return bool|string If it can decrypt than returns decrypted data, or returns false
     */
    public function DE_rc2()
    {
        $methods = array(
            'rc2:cbc', 'rc2:cfb', 'rc2:ecb'
        );
        if (($this->key != '' || !empty($this->key) && ($this->iv != '' || !empty($this->iv))))
            return $this->DE_mcrypt($this->hash, $methods, $this->key, $this->iv);
        else
            return false;
    }

    /**
     * XOR decode with key
     * @return string
     */
    public function DE_xor()
    {
        $ret = array();
        foreach ($this->key as $key) {
            $new = "";
            $key = trim($key);
            while (strlen($key) < strlen($this->DE_base64()))
                $key .= $key;
            foreach (str_split($this->DE_base64()) as $k => $v) {
                $new .= chr(ord($v) ^ ord($key[$k]));
            }
            $ret[] = $new;
        }

        /*
         * Check if the result is in ASCII
         * Otherwise convert it to hex
         */
        foreach ($ret as &$val) {
            if (!$this->isAscii($val)) {
                $hexVal = "Hex value -> ";
                foreach (str_split($val) as $v) {
                    $hexVal .= strlen(dechex(ord($v))) == 1 ? '0' . dechex(ord($v)) : dechex(ord($v));
                }
                $val = $hexVal;
            }
        }
        return implode(' -- ', $ret);
    }

}

error_reporting(E_ERROR);

$nl = PHP_EOL; // I just don't like using \n :)

/**
 * Usage instructions printer
 */
function printUsage()
{
    global $nl;
    echo $nl;
    echo "# Usage: php " . basename(__FILE__) . " [TYPE] [HASH|HASHFILE] [opts]{$nl}{$nl}";
    echo "# Supported encoding types{$nl}  base64 rot13 caesar hex bin decimal uuencode xor{$nl}";
    echo "# Supported encryption types (for online database check){$nl}  md5{$nl}";
    echo "# Supported block cipher types (key and -if available- IV required){$nl}";
    echo "  aes blowfish des rc2{$nl}{$nl}";
    echo "# Options:{$nl}";
    echo "  -b,  add for base64 encoded hashes{$nl}";
    echo "  key::[KEY|KEYFILE],  *required* for block ciphers and xor{$nl}";
    echo "  iv::[IV],  add -if available- for block ciphers, otherwise null bytes will be used {$nl}{$nl}";
    echo "# Notes:{$nl}";
    echo "  Use 'all' for checking all types{$nl}";
    echo "  Key|hash files must be in the same directory as this script{$nl}";
    echo "  Also multiple keys|hashes in those files must be separated by new lines{$nl}";
}

/**
 * Signature printer
 * @param bool $web Adds <br/> to the newlines if it's true
 */
function printSign($web = false)
{
    global $nl;
    if ($web)
        $nl = $nl . "<br/>";
    echo $nl;
    echo '####################################################' . $nl;
    echo '#     ##### #########     #     # ##### ##### #  # #' . $nl;
    echo '#    #     #   #   #     #     #     # #      # #  #' . $nl;
    echo '#   ##### #   #   # ##### ##### ##### #       #    #' . $nl;
    echo '#      # #   #   # #   # #   # #     #       #     #' . $nl;
    echo '# ##### #   #   # ##### ##### ##### #####   #      #' . $nl;
    echo '####################################################' . $nl;
    echo $nl;
    echo '####################################################' . $nl;
    echo '# Dekrypt ##########################################' . $nl;
    echo '####################################################' . $nl;
}

if (isset($argv[0])) { // Check if it's gonna be used from terminal

    if (isset($argv[1]) && $argv[1] != "") {
        $b = false;
        foreach ($argv as $v) { // Loop through argv for options
            if (preg_match("#key::#si", $v))
                $key = explode("::", $v)[1]; // Set key if provided
            if (preg_match("#iv::#si", $v))
                $iv = explode("::", $v)[1]; // Set iv if provided
            if (preg_match("#shift::#si", $v))
                $s = explode("::", $v)[1]; // It is for caesar. Set shifting if provided
            if ($v == '-b' || $v == '--b')
                $b = true;
        }
        $hash = isset($argv[2]) ? (($b == true) ? base64_decode(trim($argv[2])) : trim($argv[2])) : null; // Base64 decode the hash before using if -b parameter is set
        switch ($argv[1]) {
            case "all":
                if (is_null($hash))
                    die("You must specify a hash.");
                $obj = new dekrypt($hash, isset($key) ? $key : null, isset($iv) ? $iv : null);
                for ($i = 1; $i < 26; ++$i)
                    echo "Caesar [shift {$i}]: " . $obj->DE_caesar($i) . $nl;
                echo "Base64: " . $obj->DE_base64() . $nl;
                echo "Rot13: " . $obj->DE_rot13() . $nl;
                echo "Hex: " . $obj->DE_hex() . $nl;
                echo "Binary: " . $obj->DE_bin() . $nl;
                echo "Decimal: " . $obj->DE_dec() . $nl;
                echo "UUencode: " . $obj->DE_uu() . $nl;
                echo ($res = $obj->DE_md5()) ? "MD5: " . $res . $nl : "MD5: " . $nl;
                if (!isset($key) || $key == "") {
                    echo "Xor and block ciphers (AES,DES etc.) requires a key." . $nl;
                } else {
                    $obj = new dekrypt(base64_encode($hash), $key, isset($iv) ? $iv : '');
                    echo "Xor: " . $obj->DE_xor() . $nl;
                    echo "AES: " . $obj->DE_aes() . $nl;
                    echo "Blowfish: " . $obj->DE_blowfish() . $nl;
                    echo "DES: " . $obj->DE_des() . $nl;
                    echo "RC2: " . $obj->DE_rc2() . $nl;
                }
                break;

            case "b64":
            case "base_64":
            case "base64":
                if (is_null($hash))
                    die("You must specify a hash.");
                $obj = new dekrypt($hash);
                echo "Base64: " . $obj->DE_base64();
                break;

            case "r13":
            case "rot13":
                if (is_null($hash))
                    die("You must specify a hash.");
                $obj = new dekrypt($hash);
                echo "Rot13: " . $obj->DE_rot13();
                break;

            case "sezar": // Yazım sorunuyla uğraşmayın :)
            case "cesar":
            case "casar": // Yeah I know.. I do typos a lot.
            case "caesar":
                if (is_null($hash))
                    die("You must specify a hash.");
                $obj = new dekrypt($hash);
                if (isset($s)) {
                    echo "Caesar [shift {$s}]: " . $obj->DE_caesar($s);
                } else {
                    for ($i = 1; $i < 26; ++$i)
                        echo "Caesar [shift {$i}]: " . $obj->DE_caesar($i) . $nl;
                    echo "You can use shift::[SHIFTCOUNT] for specific shifting next time.";
                }
                break;

            case "hex":
                if (is_null($hash))
                    die("You must specify a hash.");
                $obj = new dekrypt($hash);
                echo "Hex: " . $obj->DE_hex();
                break;

            case "bin":
                if (is_null($hash))
                    die("You must specify a hash.");
                $obj = new dekrypt($hash);
                echo "Binary: " . $obj->DE_bin();
                break;

            case "dec":
            case "decimal":
                if (is_null($hash))
                    die("You must specify a hash.");
                $obj = new dekrypt($hash);
                echo "Decimal: " . $obj->DE_dec();
                break;

            case "uu":
            case "uuencode":
            case "uudecode":
                if (is_null($hash))
                    die("You must specify a hash.");
                $obj = new dekrypt($hash);
                echo "UUencode: " . $obj->DE_uu();
                break;

            case "md5":
                if (is_null($hash))
                    die("You must specify a hash.");
                $obj = new dekrypt($hash);
                echo ($res = $obj->DE_md5()) ? "MD5: " . $res : "MD5:";
                break;

            case "xor":
                if (is_null($hash))
                    die("You must specify a hash.");
                if (!isset($key) || $key == "")
                    die("You must specify a key or keyfile for xor.");
                else {
                    $obj = new dekrypt(base64_encode($hash), $key);
                    echo "Xor: " . $obj->DE_xor() . $nl;
                }
                break;

            case "aes":
                if (is_null($hash))
                    die("You must specify a hash.");
                if (!isset($key) || $key == "")
                    die("You must specify a key or keyfile for AES decryption.");
                else {
                    $obj = new dekrypt(base64_encode($hash), $key, isset($iv) ? $iv : '');
                    echo "AES: " . $obj->DE_aes();
                }
                break;

            case "blowfish":
            case "bf":
            case "bfish":
            case "blowf":
                if (is_null($hash))
                    die("You must specify a hash.");
                if (!isset($key) || $key == "")
                    die("You must specify a key or keyfile for Blowfish decryption.");
                else {
                    $obj = new dekrypt(base64_encode($hash), $key, isset($iv) ? $iv : '');
                    echo "Blowfish: " . $obj->DE_blowfish();
                }
                break;

            case "des":
                if (is_null($hash))
                    die("You must specify a hash.");
                if (!isset($key) || $key == "")
                    die("You must specify a key or keyfile for DES decryption.");
                else {
                    $obj = new dekrypt(base64_encode($hash), $key, isset($iv) ? $iv : '');
                    echo "DES: " . $obj->DE_des();
                }
                break;

            case "rc2":
                if (is_null($hash))
                    die("You must specify a hash.");
                if (!isset($key) || $key == "")
                    die("You must specify a key or keyfile for RC2 decryption.");
                else {
                    $obj = new dekrypt(base64_encode($hash), $key, isset($iv) ? $iv : '');
                    echo "RC2: " . $obj->DE_rc2();
                }
                break;

            default:
                echo "{$nl}That's not a valid type .{$nl}";
                printUsage();
                die();
                break;
        }
    } else {
        printSign();
        printUsage();
        die();
    }
} elseif (isset($_SERVER['REQUEST_METHOD'])) {  // Check if it's gonna be used from web
    echo <<<HTML_DOC
<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/html">
<head>
    <meta charset = "utf-8">
    <meta http - equiv = "X-UA-Compatible" content = "IE=edge">
    <meta name = "viewport" content = "width=device-width, initial-scale=1">
    <title>Dekrypt</title>
    <link rel = "stylesheet" href = "http://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
    <!--
    Not necessary for now .
    <script src = "https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js" ></script>
    <script src = "http://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js" ></script>
    -->
</head>
<body>
<div class="container">
    <div class="page-header" style = "margin-top:10%;">
        <h1>No web support.</h1>
    </div>
    <h3>There is no web support yet, use from terminal, thanks .</h3>
    <p class="text-muted">Nefasetle. <a href="https://twitter.com/smddzcy" target=_blank>@smddzcy</a></p>
</div>
</body>
</html>
HTML_DOC;
}
