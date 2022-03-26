<?php
/*

GlobalDynamics 2022

Select your method
JWT is compatible with (https://jwt.io/) and respect RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519.html)

This two others, are more securised but require to have OpenSSL installed
SSL protects JWT with openSSL certificates (self-signed or with yours domains) but limit varchar at 245 for RSA-2048 (((2048/8) - 11) - 245)
PASSPHRASE protects JWT with openSSL Encrypt, vector and Secret

*/
define ("DOMAIN_DEFAULT","Your domain"); // Master Domain
define ("ADMIN_DOMAIN", "Your domain api"); // It's the domain who create this JWT

define("JWT_TYPE","JWT");
//define("JWT_TYPE","SSL");
//define("JWT_TYPE","PASSPHRASE");

// SECRET KEY REQUIRE 
define("JWT_SECRET","fda/ugTHQt6/+ya3u4iFXY/ih+NAeKrq0q7Cl0b0YKmIOxK3nUvgyG6MV/eGBZX5NlqaPgiIw7HPy3gSY08RZFR+rHfWzq2/jyfDrD6GOzc4E/FJXGShZECMI8paUl9e6D66t7wQmlWo99fFRA6W8h5i6cU0BkYvFBB1GD9pyUHsjiiQs6knqaN+OS0vIdrsmyjn/xq/aWrOPclykSMM1cGQwBxMSIDSf9yUPBS/FmwiClkiZS1LOU2zKzkInily");

// CHOICE A DELAY FOR JWT EXPIRE - ISO 8601(https://www.php.net/manual/fr/class.dateinterval.php)
define ("JWT_EXPIRE_ONE_HOUR","PT1H");
define ("JWT_EXPIRE_ONE_DAY","P1D");
define ("JWT_EXPIRE_ONE_MONTH","P1M");
define ("JWT_EXPIRE_ONE_YEAR","P1Y");

// CREATE SELF-SIGNED CERTIFICATS
define("JWT_DIRECTORY","cache".DIRECTORY_SEPARATOR."jwt".DIRECTORY_SEPARATOR);
define("JWT_PUBLIC_KEY",JWT_DIRECTORY."jwt.crt"); // public key
define("JWT_PRIVATE_KEY",JWT_DIRECTORY."jwt.key"); // Private key

// INFORMATIONS FOR SELF-SIGNED CERTIFICAT
define("JWT_COUNTRY_CODE","BE");
define("JWT_STATE","Wallonie");
define("JWT_LOCALITY","Liege");
define("JWT_COMPANY","Your company");
define("JWT_YOUR_FUNCTION","IT");
define("JWT_DOMAIN","Your domain");
?>