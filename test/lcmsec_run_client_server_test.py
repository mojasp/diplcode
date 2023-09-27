#!/usr/bin/env python
import os
import sys
import subprocess
import time

channels = ["TEST_ECHO",
 "test_lcmtest_primitives_t",
 "test_lcmtest_primitives_list_t",
 "test_lcmtest_node_t",
 "test_lcmtest_multidim_array_t",
 "test_lcmtest2_cross_package_t",
"TEST_ECHO_REPLY",
"test_lcmtest_primitives_t_reply",
"test_lcmtest_primitives_list_t_reply",
"test_lcmtest_node_t_reply",
"test_lcmtest_multidim_array_t_reply",
"test_lcmtest2_cross_package_t_reply" ]

def lcmsec_gen_certificates():

    cert_chain_folder = "test_chain"
    if os.path.exists(cert_chain_folder):
        return

    os.makedirs(cert_chain_folder)
#number of certificates to generate
    num_players = 2;

#capabilities that each certificate has
    mcasturl = "239.255.76.67:7667"

    #generate root ca
    root_ca = cert_chain_folder + "/root_ca.crt"
    root_key = cert_chain_folder + "/root_ca.key"

    command = ['step-cli', 'certificate', 'create', '--no-password', '--insecure' , '--profile', 'root-ca', 'root' ,root_ca , root_key]
    subprocess.call(command)

    for i in range(1, num_players+1):
        ca_file = cert_chain_folder +"/"+ str(i) + ".crt"
        key_file = cert_chain_folder+ "/"+ str(i) + ".key"

        group_urn = "urn:lcmsec:gkexchg_g:"+mcasturl+":"+str(i)

        command = ['step-cli', 'certificate', 'create', "player_"+str(i), ca_file, key_file, '--san', group_urn]
        for channel in channels: 
            command.append("--san")
            command.append("urn:lcmsec:gkexchg:"+mcasturl+":"+channel+":" + str(i))

        for s in ['--profile', 'leaf', '--ca' ,root_ca , '--ca-key' , root_key , '--no-password', '--insecure' ]:
            command.append(s)

        print(command)

        subprocess.call(command)

        command = ['openssl', 'pkcs8', '-topk8', '-in', key_file , '-out',  key_file + ".pem", "-nocrypt"] # format in a way that botan can understand
        subprocess.call(command, stdin=subprocess.PIPE)
        
        command = ['mv',  key_file+".pem", key_file] #rename to .key extension
        subprocess.call(command)

    os.system("chmod +r " + cert_chain_folder +"/*")

def main(server, *client):
    print("HELLO LCMSEC TESTRUNNER")
    lcmsec_gen_certificates()

    # Start the test server
    print("Starting test server")
    server_proc = subprocess.Popen(server)

    # Kludge. Wait for server to start.
    time.sleep(1)

    # Run the client tests while the test server is running
    print("Starting test client")
    test_result = subprocess.call(client)

    # Stop the test server
    print("Stopping test server")
    server_proc.terminate()
    server_status = server_proc.wait()
    print("Test server stopped")

    # Report
    return test_result

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
