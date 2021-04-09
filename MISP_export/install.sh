#!/bin/bash
sudo apt install libfuzzy-dev
virtualenv -p python3 serv-env
. ./serv-env/bin/activate
pip install -U flask Flask-AutoIndex redisgraph pymisp lief python-magic 
pip install git+https://github.com/kbandla/pydeep.git
