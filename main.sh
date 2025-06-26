#!/bin/bash

# set -x

echo "This is a project that contains two program :-"
echo "1) AES Cipher Tool "
echo "2) Linux Audit Hardening Tool"

echo "Which program would you like to use : (Enter 1 or 2)"

read option

echo "Debug : option = $option"

if [[ "$option" == 1 ]]; then 
    echo "Starting AES Cipher Tool"
    cd "AES Cipher Tool"
    ./run_aes.sh
elif [[ "$option" == 2 ]]; then
    echo "Starting Linux Audit Hardening Tools"
    cd "Linux Audit Hardening Tools"
    ./run_audit.sh
else
    echo "Exit staus confirmed exiting the script"
fi