openssl genpkey -algorithm ed25519 -out test01.pem
openssl req -new -x509 -days 3650 -key test01.pem -out test01.crt

openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:512 -out test02.pem
openssl req -new -x509 -days 3650 -key test02.pem -out test02.crt

openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:1024 -out test03.pem
openssl req -new -x509 -days 3650 -key test03.pem -out test03.crt

openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out test04.pem
openssl req -new -x509 -days 3650 -key test04.pem -out test04.crt

openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:4096 -out test05.pem
openssl req -new -x509 -days 3650 -key test05.pem -out test05.crt

openssl ecparam -list_curves

openssl ecparam -name secp224r1 -genkey -noout -out test06.pem
openssl req -new -x509 -days 3650 -key test06.pem -out test06.crt

openssl ecparam -name secp384r1 -genkey -noout -out test07.pem
openssl req -new -x509 -days 3650 -key test07.pem -out test07.crt

openssl ecparam -name secp521r1 -genkey -noout -out test08.pem
openssl req -new -x509 -days 3650 -key test08.pem -out test08.crt

openssl ecparam -name prime256v1 -genkey -noout -out test09.pem
openssl req -new -x509 -days 3650 -key test09.pem -out test09.crt
