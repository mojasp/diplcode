import subprocess
import os

#assumes that the csvexport-binary is available in the path
tracy_csvexport_bin = "csvexport-release"
tracy_capture_bin = "capture-release"

def start_instance(uid):
    if(uid == 1):
        #Special case: this is tracy listener
        os.environ["LD_PRELOAD"] = "../../tracy_build/lcm/liblcm.so"

    cmd = ["./demo_instance", "test_instances/"+str(uid)+".toml"]
    subprocess.Popen(cmd)

def run_test(players):
    tracy_filename = "tracy_" + str(players) + "_players.tracy"
    csv_filename = "tracy_" + str(players) + "_players.csv"
    capture_cmd = [tracy_capture_bin, "-o", tracy_filename, "-s", "5", "-f"]
    p_capture = subprocess.Popen(capture_cmd)

    for i in range(1, players+1):
        start_instance(i)

    p_capture.wait()
    convert_command = [tracy_csvexport_bin, tracy_filename]

    with open(csv_filename, 'w') as f:
        subprocess.Popen(convert_command,  stdout=f)

def main():
    run_test(5)

if __name__ == '__main__':
    main()

