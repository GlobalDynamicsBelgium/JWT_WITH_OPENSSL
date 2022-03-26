# JWT_WITH_OPENSSL
JWT token solution with three modes

This code response to https://jwt.io/ 
JWT respect the recommandations jwt.io (https://jwt.io/) and use RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519.html)
Delay expire use ISO 8601

$payload["alg"] = encrypt method
$payload["typ"] = "JWT"
$payload["iss"] = Domain default
$payload["aud"] = Domain audiance
$payload["iat"] = Inclued at
$payload["nbf"] = Not available before
$payload["exp"] = expire at

Three methods (select yours in config.php)
jwt (as jwt.io SHA256 or more if you want)
ssl (encrypt from OpenSSL certificats self-signed or yours)
passphrase (encrypt from OpenSSL, vector and your secret)

All explication in index.php
