#!/bin/bash

# This script returns a JWT (signed with HMAC-SHA256 algorithm) when 
# a valid userid / password is provided

echo "content-type: text/plain"
echo ""

if [ -z "$HTTP_AUTHORIZATION" ]
then
    echo "status: 401"
    echo "WWW-Authenticate: Basic realm=\"Please provide user id and password\""
    echo
    echo "Please login"
    exit 1
fi

# Extracts userid/password
CRED=$(echo -n $HTTP_AUTHORIZATION | grep -i basic | sed -E 's/.*[Bb][Aa][Ss][Ii][Cc] (.*)/\1/')
if [ -z "$CRED" ]
then
    echo "status: 401"
    echo "WWW-Authenticate: Basic realm=\"Please provide user id and password\""
    echo
    echo "We only accept BASIC authentication"
    exit 1
fi

USERID=$(echo "$CRED" | base64 -d | cut -f 1 -d ':')
PASSWORD=$(echo "$CRED" | base64 -d | cut -f 2 -d ':')
HASHED_PASSWORD=$(echo -n "$PASSWORD" | sha256sum | cut -f 1 -d ' ')

RECORD=$(grep "$USERID" "passwd_salted.txt")

#CHECK IF USERID EXISTS
if [ -z "$RECORD" ]
then
    echo "status: 401"
    echo "WWW-Authenticate: Basic realm=\"Please provide user id and password\""
    echo
    echo "Userid not found"
    exit 1
fi

SALT=$(echo "$RECORD" | cut -f 3 -d '$')

RESULT=$(openssl passwd -1 -salt $SALT $HASHED_PASSWORD)

CREDENTIALS=$(echo "$USERID:$RESULT")

if grep -Fxq "$CREDENTIALS" passwd_salted.txt; then
    echo "status: 200"

   # Normally - we would perform userid/password looking now
    # In this example, we simply put the userid in the claim, along
    # with an expiry date of 1 hour from current time

    # The JWT standard requires us to strip out all the space and n
    # newlines in JSON objects

    HEADER='{"alg":"HS256","typ":"JWT"}'
    PAYLOAD="{\"id\":\"${USERID}\",\"exp\":\"$(( $(date +%s) + 3600 ))\"}"

    # We now have to base64 encode the header and payload 
    # Pay speical attention where we replace some of the standard 
    # base64 characters with URL-safe characters.  This is known
    # as base64url encoding.  We do this so the encoded token
    # can be used embedded in URLs.

    B64_HEADER=$(echo -n "$HEADER" | base64 | tr '+' '-' | tr '/' '_' | tr -d '=')
    B64_PAYLOAD=$(echo -n "$PAYLOAD" | base64 | tr '+' '-' | tr '/' '_' | tr -d '=')

    # We now produce the HMAC-SHA256 signature using a secret
    # Notice how we also need to change the encoding to base64url and 
    # remove the = character
    SIGNATURE=$(echo -n "${B64_HEADER}.${B64_PAYLOAD}" \
        | openssl dgst -sha256 -hmac "here_is_my_secret" -binary \
        | base64 | tr '+' '-' | tr '/' '_' | tr -d '=')

    echo "${B64_HEADER}.${B64_PAYLOAD}.${SIGNATURE}"
else
    echo "status: 401"
    echo "WWW-Authenticate: Basic realm=\"Please provide user id and password\""
    echo
    echo "Please login"
    exit 1
fi
