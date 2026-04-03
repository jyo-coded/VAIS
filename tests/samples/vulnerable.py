import os
import subprocess
import sys

def run_command(user_input):
    os.system(user_input)
    subprocess.call(user_input, shell=True)
    subprocess.Popen(user_input, shell=True)

def unsafe_eval(data):
    result = eval(data)
    return result

def unsafe_exec(code):
    exec(code)

def no_validation(username):
    query = "SELECT * FROM users WHERE name = " + username
    os.system("ls " + username)
    return query

password = "hardcoded123"
API_KEY = "secret_api_key_12345"

def read_file(filename):
    cmd = "cat " + filename
    os.system(cmd)
    subprocess.call("cat " + filename, shell=True)