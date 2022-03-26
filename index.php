<?php 
/*

GlobalDynamics 2022 (https://globaldynamics.be)
JWT is compatible with (https://jwt.io/) and respect RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519.html)

*/

// Require config file and token class
require("config.php");
require("token.php");

// IF openSLL is installed and you want create certificats or vector file (SSL or PASSPHRASE methods from config.php)
token::getEncrypt();

// CREATE JWT
$payload = array(
    "id" => 1,
    "rol" => 1,
	// This after is not possible with OpenSSL certificats because varchar > 245
    "fst" => "John",
    "lst" => "Doe",
    "mil" => "john.doe@gmail.com"
);

// Invoke token create with and expire base on ISO 8601 and get your JWT
$jwt = token::getInstance()->createToken($payload,JWT_EXPIRE_ONE_HOUR);
var_dump($jwt);
     
// Invoke token	allowed and give JWT
$allowed = token::getInstance()->allowedToken($jwt);
if(is_array($allowed)){
var_dump($allowed);
}else{
var_dump($allowed);
}
?>