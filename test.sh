#!/bin/bash

echo -e "/user/100 with admin user\n"
curl -s http://localhost:5000/user/100 --user "robin.lequerec@etna-alternance.net:pass" | jq '.'
echo -e "\n/user/100 with non-admin user\n"
curl -s http://localhost:5000/user/100 --user "alfonso.eaton@mail.fr:pass" | jq '.'


curl -s -X POST -H "Content-Type: application/json" -d '{"lastname": "Casheuh",
"firstname": "Johnny2",
"email": "johnny.cash@etna-alternance.inet",
"password": "secure",
"role": "normal"}' http://localhost:5000/users --user "robin.lequerec@etna-alternance.net:pass"

curl -s -X PUT -H "Content-Type: application/json" -d '{"email": "robin.lequerec@etna-alternance.net"}' http://localhost:5000/user/1 --user "robin.lequerec@etna-alternance.net:pass"
