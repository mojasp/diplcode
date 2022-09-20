SOURCE_DIR=$(cd "$(dirname "$0")" && pwd)
BUILD_DIR="$SOURCE_DIR"/../../build

{ LD_LIBRARY_PATH="$BUILD_DIR"/lcm ./demo_instance ./instances/alice.toml & } &>/dev/null 
{ LD_LIBRARY_PATH="$BUILD_DIR"/lcm ./demo_instance ./instances/bob.toml & } &>/dev/null 
{ LD_LIBRARY_PATH="$BUILD_DIR"/lcm ./demo_instance ./instances/charlie.toml & } &>/dev/null 
LD_LIBRARY_PATH="$BUILD_DIR"/lcm ./demo_instance ./instances/daniel.toml
