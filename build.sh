#!/bin/bash
g++ -Og -Wall -o client client.cpp -lssl -lcrypto
g++ -Og -Wall -o server server.cpp -lssl -lcrypto