<?php
/*

GlobalDynamics 2022 (https://globaldynamics.be)
JWT is compatible with (https://jwt.io/) and respect RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519.html)

*/
class token{

    private $timezone;
    private $locale;
    private $method;
    private $iv;
    private $privateKey;
    private $publicKey;
    private $jwt;
    private $domain;
    public $payload;
    private static $NewInstance;
    
    public static function getInstance()
    {
        self::$NewInstance = new token();
        return self::$NewInstance;
    }
    
    public function __construct(){
        if(JWT_TYPE == "SSL"){
            $this->getPublicKey();
            $this->getPrivateKey();
        }else{
            $this->getOpenSSLcipher();
            $this->getOpenSSLiv();
        }
        $this->timeZone = "Europe/Amsterdam";
        $this->locale = "d-m-Y h:i:s";
    }
    
    private function getOpenSSLcipher(){
        $this->method = "AES-256-CBC";
    }
    
    private function getOpenSSLiv(){
        $this->iv = file_get_contents(JWT_DIRECTORY.'SSL_ENCRYPT_IV.php');
    }
    
    private function getPublicKey(){
        if(is_file(JWT_PUBLIC_KEY)){
            $fp=fopen(JWT_PUBLIC_KEY,"r");
            $this->publicKey=fread($fp,8192);
            fclose($fp);
        }else{
            throw new Exception('Public key missing');
        }
    }
    
    private function getPrivateKey(){
        if(is_file(JWT_PRIVATE_KEY)){
            $fp=fopen(JWT_PRIVATE_KEY,"r");
            $this->privateKey=fread($fp,8192);
            fclose($fp);
        }else{
            throw new Exception('Private key missing');
        }
    }
    
    private function setPayloadDev(){
        return array(
            "alg" => "sha256",
            "typ" => "JWT"
        );
    }
    
    public function createToken($payload,$expire){
        if(!is_array($payload)){ throw new Exception('Payload must be array()'); }
        $this->payload["iss"] = DOMAIN_DEFAULT;
        $this->payload["aud"] = ADMIN_DOMAIN;
        $this->payload["iat"] = $this->iat();
        $this->payload["nbf"] = $this->nbf();
        $this->payload["exp"] = $this->expire($expire);
        $this->payload = array_merge($this->payload,$payload);
        if(JWT_TYPE != "JWT"){                
            $plaintext = base64_encode(json_encode($this->setPayloadDev())) . "," . base64_encode(json_encode($this->payload));
            if ($this->checkSize($plaintext)){
                return $this->encode($plaintext);
            }else{
                throw new Exception('Payload too big for RSA Challenge');
            }
        }else{
            return base64_encode(json_encode($this->setPayloadDev())) . "." . base64_encode(json_encode($this->payload)).".".hash_hmac('sha256',base64_encode(json_encode($this->setPayloadDev())) . "." . base64_encode(json_encode($this->payload)),JWT_SECRET);
        }
    }
    
    public function allowedToken($token){
        $jwt = $this->decode($token);
        if(!is_array($jwt)){
            return false;
        }else{
            if(!$this->checkJWTSources($jwt)){ return false; }
            if(!$this->checkJWTtimeout($jwt)){ return false; }
            return $this->cleanJWT($jwt);
        }
    }
    
    private function cleanJWT($jwt){
        unset($jwt["alg"]);
        unset($jwt["typ"]);
        unset($jwt["iss"]);
        unset($jwt["aud"]);
        unset($jwt["iat"]);
        unset($jwt["nbf"]);
        unset($jwt["exp"]);
        return $jwt;
    }
    
    private function checkJWTSources($jwt){
        return ($jwt["iss"] === DOMAIN_DEFAULT && $jwt["aud"] === ADMIN_DOMAIN)?true:false;
    }
    
    private function checkJWTtimeout($jwt){
        return ($this->checkTimeout($jwt["iat"]) && $this->checkTimeout($jwt["nbf"]) && !$this->checkTimeout($jwt["exp"]))?true:false;
    }
    
    private function checkSize($plaintext){
        // SIZE KEY RSA:2048 = 245 Char (2048/8 - 11)
        if(JWT_TYPE == "SSL"){
            return (strlen($plaintext) <= 245)?true:false;
        }else{
            return true;
        }
    }
    
    private function iat(){
        // Issued at
        date_default_timezone_set($this->timeZone);
        $date = new DateTime();
        $date = $date->format($this->locale);
        return $date;
    }
    
    private function nbf(){
        // Not before
        date_default_timezone_set($this->timeZone);
        $date = new DateTime();
        $date = $date->format($this->locale);
        return $date;
    }
    
    private function expire($expire){
        // expire at
        date_default_timezone_set($this->timeZone);
        $date = new DateTime();
        $date->add(new DateInterval($expire));
        $date = $date->format($this->locale);
        return $date;
    }
    
    private function checkTimeout($dateToCompare){
        date_default_timezone_set($this->timeZone);
        $date = new DateTime();
        $dateToCompare = new DateTime($dateToCompare);
        $date = $date->format($this->locale);
        $dateToCompare = $dateToCompare->format($this->locale);
        $difference_in_seconds = strtotime($dateToCompare) - strtotime($date);
        return ($difference_in_seconds <= 0)?true:false;
    }
    
    private function encode($plaintext){
        if(!extension_loaded('openssl')){$this->setExcecuteSSLException();}       
        $jwt = (JWT_TYPE == "SSL")?$this->encodeSSL($plaintext):$jwt = $this->encodePassPhrase($plaintext);
        return $jwt;
    }
    
    private function encodeSSL($plaintext){
        if(!extension_loaded('openssl')){$this->setExcecuteSSLException();}       
        $key_resource = openssl_get_publickey($this->publicKey);
        openssl_public_encrypt($plaintext, $jwt, $key_resource);
        return $jwt;
    }
    
    private function encodePassPhrase($plaintext){
        if(!extension_loaded('openssl')){$this->setExcecuteSSLException();}       
        return openssl_encrypt($plaintext, $this->method, JWT_SECRET, OPENSSL_RAW_DATA, $this->iv);
    }
    
    private function decode($token){
        if(JWT_TYPE != "JWT"){
            $jwt = (JWT_TYPE == "SSL")?$this->decodeSSL($token):$this->decodePassPhrase($token);
            $iwt_base64 = explode(",", $jwt);
            $first_head = json_decode(base64_decode($iwt_base64[0]),true);
            $second_head = json_decode(base64_decode($iwt_base64[1]),true);
            $jwt = array_merge($first_head, $second_head);
        }else{
            $jwt = $this->decodeJWT($token);
        }
        return $jwt;
    }
    
    private function decodeJWT($token){
        $token = explode(".", $token);
        $first_head = $token[0];
        $second_head = $token[1];
        $secret = $token[2];
        $decode = json_decode(base64_decode($first_head),true);
        $secretCompare = hash_hmac($decode["alg"], $first_head . "." . $second_head , JWT_SECRET);
        if($secret === $secretCompare && $decode["typ"] === "JWT"){
            $first_head = json_decode(base64_decode($first_head),true);
            $second_head = json_decode(base64_decode($second_head),true);
            return array_merge($first_head, $second_head);
        }else{
            return false;
        }
    }
    
    private function decodeSSL($token){
        if(!extension_loaded('openssl')){$this->setExcecuteSSLException();}       
        $key_resource= openssl_get_privatekey($this->privateKey);
        openssl_private_decrypt($token,$jwt,$key_resource); 
        return $jwt;
    }
    
    private function decodePassPhrase($token){
        if(!extension_loaded('openssl')){$this->setExcecuteSSLException();}       
        return openssl_decrypt($token, $this->method, JWT_SECRET, OPENSSL_RAW_DATA, $this->iv);
    }
    
    private function setExcecuteSSLException(){
        throw new Exception('This app needs the Open SSL PHP extension.');
        exit;
    }
    
    public static function getEncrypt(){     
        if(!extension_loaded('openssl')){
            throw new Exception('This app needs the Open SSL PHP extension.');
            exit;
        }            
        if(JWT_TYPE == "SSL" && !is_file(JWT_DIRECTORY."jwt.key" && !is_file(JWT_DIRECTORY."jwt.crt"))){
            $cmd = 'openssl req -x509 -newkey rsa:2048 -nodes -keyout '.JWT_DIRECTORY.'jwt.key -out '.JWT_DIRECTORY.'jwt.crt -days 365 -subj "/C='.JWT_COUNTRY_CODE.'/ST='.JWT_STATE.'/L='.JWT_LOCALITY.'/O='.JWT_COMPANY.'/OU='.JWT_YOUR_FUNCTION.'/CN='.JWT_DOMAIN.'"';
            exec($cmd);
        }else{
            $iv = JWT_DIRECTORY.'SSL_ENCRYPT_IV.php';
            if(!is_file($iv)){
                file_put_contents($iv, openssl_random_pseudo_bytes(16));
            }
        }
    }
}
?>