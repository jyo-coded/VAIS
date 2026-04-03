import os
import subprocess
import pickle
import sys

def vulnerable_function_1(user_input):
    # Rule 1: eval() / exec()
    eval(user_input)
    exec(user_input)
    eval("print(" + user_input + ")")
    exec("import os; os.system('" + user_input + "')")

def vulnerable_function_2(user_data):
    # Rule 2: Unsafe Deserialization
    pickle.loads(user_data)
    pickle.load(open(user_data, 'rb'))
    import pickle as pkl
    pkl.loads(user_data)

def vulnerable_function_3(cmd):
    # Rule 3: subprocess shell=True
    subprocess.call(cmd, shell=True)
    subprocess.Popen(cmd, shell=True)
    subprocess.run(cmd, shell = True)
    subprocess.getoutput(cmd)

def vulnerable_function_4(cmd):
    # Rule 4: os.system()
    os.system(cmd)
    os.popen(cmd)
    os.system("ping " + cmd)
    os.popen("ls " + cmd)

def vulnerable_function_5(filename):
    # Rule 5: Path Traversal via open()
    f = open(filename, 'r')
    data = f.read()
    f.close()
    
    with open(sys.argv[1] + filename) as file:
        pass

def vulnerable_function_6():
    # Rule 6: Hardcoded Secrets
    password = "SuperSecretPassword123!"
    api_key = "AIzaSyD..._something_secret"
    secret = "my_secret_token"
    aws_secret_key = "AKIAIOSFODNN7EXAMPLE"
    auth_token = "abcd1234efgh5678"

if __name__ == "__main__":
    vulnerable_function_1(sys.argv[1])
    vulnerable_function_2(sys.argv[1].encode())
    vulnerable_function_3(sys.argv[1])
    vulnerable_function_4(sys.argv[1])
    vulnerable_function_5(sys.argv[1])
    vulnerable_function_6()