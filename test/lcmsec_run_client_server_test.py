#!/usr/bin/env python
import os
import sys
import subprocess
import time

cycle_test_channel = "test_lcmsec_cycle"
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
"test_lcmtest2_cross_package_t_reply",
cycle_test_channel
]


def lcmsec_gen_certificates():
    cert_chain_folder = "test_chain"
    if os.path.exists(cert_chain_folder):
        return

    os.makedirs(cert_chain_folder)

    #capabilities that each certificate has
    mcasturl = "239.255.76.67:7667"

    #generate root ca
    root_ca = cert_chain_folder + "/root_ca.crt"
    root_key = cert_chain_folder + "/root_ca.key"

    command = ['step-cli', 'certificate', 'create', '--no-password', '--insecure' , '--profile', 'root-ca', 'root' ,root_ca , root_key]
    subprocess.call(command)

    for i in range(1, 3):
        ca_file = cert_chain_folder +"/"+ str(i) + ".crt"
        key_file = cert_chain_folder+ "/"+ str(i) + ".key"

        group_urn = "urn:lcmsec:gkexchg_g:"+mcasturl+":"+str(i)

        command = ['step-cli', 'certificate', 'create', "player_"+str(i), ca_file, key_file, '--san', group_urn]
        for channel in channels: 
            command.append("--san")
            command.append("urn:lcmsec:gkexchg:"+mcasturl+":"+channel+":" + str(i))

        for s in ['--profile', 'leaf', '--ca' ,root_ca , '--ca-key' , root_key , '--no-password', '--insecure' ]:
            command.append(s)
        subprocess.call(command)

        command = ['openssl', 'pkcs8', '-topk8', '-in', key_file , '-out',  key_file + ".pem", "-nocrypt"] # format in a way that botan can understand
        subprocess.call(command, stdin=subprocess.PIPE)
        
        command = ['mv',  key_file+".pem", key_file] #rename to .key extension
        subprocess.call(command)

    for i in range(3, 9):
        ca_file = cert_chain_folder +"/"+ str(i) + ".crt"
        key_file = cert_chain_folder+ "/"+ str(i) + ".key"

        group_urn = "urn:lcmsec:gkexchg_g:"+mcasturl+":"+str(i)

        command = ['step-cli', 'certificate', 'create', "player_"+str(i), ca_file, key_file, '--san', group_urn]
        command.append("--san")
        command.append("urn:lcmsec:gkexchg:"+mcasturl+":"+cycle_test_channel+":" + str(i))

        for s in ['--profile', 'leaf', '--ca' ,root_ca , '--ca-key' , root_key , '--no-password', '--insecure' ]:
            command.append(s)

        subprocess.call(command)

        command = ['openssl', 'pkcs8', '-topk8', '-in', key_file , '-out',  key_file + ".pem", "-nocrypt"] # format in a way that botan can understand
        subprocess.call(command, stdin=subprocess.PIPE)
        
        command = ['mv',  key_file+".pem", key_file] #rename to .key extension
        subprocess.call(command)

    os.system("chmod +r " + cert_chain_folder +"/*")

def main(server, *client):
    lcmsec_gen_certificates()

    print("LCMSEC TEST HELLO")
    server_procs = []
    # Start the test servers
    for i in range(2, 9):
        # Start both the server for client/server and roundtrip cycle tests
        print("Starting test server with id " + str(i))
        p = subprocess.Popen([server, str(i)])
        server_procs.append(p)

    # Kludge. Wait for servers to start.
    time.sleep(1)

    # Run the client tests while the test server is running
    print("Starting test client")
    test_result = subprocess.call(client)

    # Stop the test server
    for p in server_procs:
        p.terminate()

    # Report
    return test_result

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
