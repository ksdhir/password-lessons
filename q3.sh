#!/bin/bash

#
# A naive way to break passwords hashed with sha256sum
#

# The pool of passwords comes from the first 100 common passwords
PASSWORD_URL='https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt'
COMMON_PASSWORDS=$(curl -s $PASSWORD_URL | head -n 100)

# prepare rainbow table
for COMMON_PASSWORD in $COMMON_PASSWORDS
do
    echo -n "$COMMON_PASSWORD" | sha256sum | cut -f 1 -d ' '
done > RAINBOW_TABLE.txt


# grep each item  with rainbow table
for IDPASS in $(cat passwd_sha.txt)
do
    ID=$(echo $IDPASS | cut -f 1 -d ':')
    TARGET=$(echo $IDPASS | cut -f 2 -d ':')

    MATCH=$(grep "$TARGET" "RAINBOW_TABLE.txt");

    if [ -n "$MATCH" ]; then
        echo "$ID has the password $MATCH"
    fi
done
