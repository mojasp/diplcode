# This script will generate a PKI with certificates that can be used with LCMsec.
# Adapt to your liking. In this version, 10 nodes will be created, each of which will have the permission to send on group 239.255.76.67:7667 and "channel1"
# All certificates will be placed in a newly-created "test_chain" directory
# requires step-cli and openssl command line utilites


# Essentially, this script is a wrapper around the following commands:

# This is an example on how to create a certificate which provides "alice" with the permission to send on receive on "channel1" and "channel2" of multicastgroup 239.255.76.67 and port 7667:
# ```bash
#     step-cli certificate create alice alice.crt alice.key --san urn:lcmsec:gkexchg:239.255.76.67:7667:channel1:4 --san urn:lcmsec:gkexchg:239.255.76.67:7667:channel2:4 --san urn:lcmsec:gkexchg_g:239.255.76.67:7667:4   --profile leaf --ca ./root_ca.crt --ca-key ./root_ca.key
#     # format in a way that botan can understand
#     openssl pkcs8 -topk8 -in alice.key -out alice.pem
#     mv alice.pem alice.key
# ```


import subprocess

#foldername -needs to exist prior to using this script
cert_chain_folder = "test_chain"

#number of certificates to generate
num_players = 10;

#capabilities that each certificate has
mcasturl = "239.255.76.67:7667"
channel = "channel1"

def main():
    #generate root ca
    root_ca = cert_chain_folder + "/root_ca.crt"
    root_key = cert_chain_folder + "/root_ca.key"

    command = ['step-cli', 'certificate', 'create', '--no-password', '--insecure' , '--profile', 'root-ca', 'root' ,root_ca , root_key]
    p = subprocess.Popen(command)
    p.wait()

    for i in range(1, num_players+1):
        ca_file = cert_chain_folder +"/"+ str(i) + ".crt"
        key_file = cert_chain_folder+ "/"+ str(i) + ".key"

        ch_urn = "urn:lcmsec:gkexchg:"+mcasturl+":"+channel+":"+str(i)
        group_urn = "urn:lcmsec:gkexchg_g:"+mcasturl+":"+str(i)

        command = ['step-cli', 'certificate', 'create', "player_"+str(i), ca_file, key_file, '--san', ch_urn, '--san', group_urn\
            ,'--profile', 'leaf', '--ca' ,root_ca , '--ca-key' , root_key , '--no-password', '--insecure' ]

        p = subprocess.Popen(command)
        p.wait()

        command = ['openssl', 'pkcs8', '-topk8', '-in', key_file , '-out',  key_file + ".pem", "-nocrypt"] # format in a way that botan can understand
        p = subprocess.Popen(command, stdin=subprocess.PIPE)
        p.wait()
        
        command = ['mv',  key_file+".pem", key_file] #rename to .key extension
        subprocess.Popen(command)

if __name__ == '__main__':
    main()
