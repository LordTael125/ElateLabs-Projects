#!/bin/bash

echo "This is a program to rate your system's security measures."

mkdir temp
touch temp/python

echo "$(python --version)" >> temp/python

rm -rvf temp
cd Assets
sudo python script_header.py

echo "Displaying Report"
cat Report/Report.txt