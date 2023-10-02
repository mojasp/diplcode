// file: listener.cpp
//
// LCM example program.
//
// compile with:
//  $ gcc -o listener listener.cpp -llcm
//
// On a system with pkg-config, you can also use:
//  $ gcc -o listener listener.cpp `pkg-config --cflags --libs lcm`

#include <stdio.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <lcm/lcm-cpp.hpp>
#include <list>
#include <optional>
#include <stdexcept>
#include <thread>

#include "exlcm/example_t.hpp"
#include "tomlplusplus/toml.hpp"
using namespace std::chrono_literals;

constexpr std::chrono::duration sender_delay(2s);

class Handler {
  private:
    bool print_received_msg{true};

  public:
    ~Handler() {}
    Handler(bool print_received_msg) : print_received_msg(print_received_msg) {}
    void handleMessage(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                       const exlcm::example_t *msg)
    {
        if (print_received_msg) {
            int i;
            printf("Received message on channel \"%s\":\n", chan.c_str());
            printf("  timestamp   = %lld\n", (long long) msg->timestamp);
            printf("  position    = (%f, %f, %f)\n", msg->position[0], msg->position[1],
                   msg->position[2]);
            printf("  orientation = (%f, %f, %f, %f)\n", msg->orientation[0], msg->orientation[1],
                   msg->orientation[2], msg->orientation[3]);
            printf("  ranges:");
            int16_t expected = 0;
            for (i = 0; i < msg->num_ranges; i++) {
                assert(expected++ == msg->ranges[i]);
                //    printf(" %d\n", msg->ranges[i]);
            }
            printf("\n");
            printf("  name        = '%s'\n", msg->name.c_str());
            printf("  enabled     = %d\n", msg->enabled);
            printf("\n");
        }
    }
};

void send_on_channel(std::string channel, lcm::LCM &lcm);

Handler handlerObject(true);
static std::string instance_name;
std::vector<std::function<void(void)>> sendfunctions;
std::vector<std::chrono::high_resolution_clock::time_point> last_send;

void send_on_channel(std::string channel, lcm::LCM &lcm,
                     std::chrono::high_resolution_clock::time_point &last_send)
{
    if (std::chrono::high_resolution_clock::now() - last_send >= sender_delay) {
        exlcm::example_t my_data;
        my_data.timestamp = 0;

        my_data.position[0] = 1;
        my_data.position[1] = 2;
        my_data.position[2] = 3;

        my_data.orientation[0] = 1;
        my_data.orientation[1] = 0;
        my_data.orientation[2] = 0;
        my_data.orientation[3] = 0;

// #define SEND_FRAGMENTED
#ifdef SEND_FRAGMENTED
        my_data.num_ranges = 40000;
#else
        my_data.num_ranges = 16;
#endif
        my_data.ranges.resize(my_data.num_ranges);
        for (int i = 0; i < my_data.num_ranges; i++)
            my_data.ranges[i] = i;

        my_data.name = instance_name;
        my_data.enabled = true;

        lcm.publish(channel, &my_data);
        last_send = std::chrono::high_resolution_clock::now();
    }
}

void setup_channel(toml::table &channel_config, lcm::LCM &lcm)
{
    auto channelname = channel_config["channelname"].value<std::string>().value();
    auto send = channel_config["send"].value<bool>().value();
    auto recv = channel_config["receive"].value<bool>().value();

    if (recv) {
        std::cout << instance_name << ": subscribing to channel " << channelname << "\n";
        lcm.subscribe(channelname, &Handler::handleMessage, &handlerObject);
    }

    if (send) {
        std::cout << instance_name << ": starting to send on channel " << channelname << "\n";
        last_send.push_back(
            std::chrono::high_resolution_clock::now() -
            std::chrono::minutes(1));  // initialize to the past so we sent initially
        auto last_send_idx = last_send.size() - 1;
        sendfunctions.push_back(
            [=, &lcm]() { send_on_channel(channelname, lcm, last_send[last_send_idx]); });
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::cerr << "Usage: ./demo_instance <path_to_config_file>\n";
        return 1;
    }
    toml::table config;
    try {
        config = toml::parse_file(argv[1]);
        std::cout << config << "\n";
    } catch (const toml::parse_error &err) {
        std::cerr << "Parsing config file failed failed:\n" << err << "\n";
        return 1;
    }

    try {
        auto groups = config["group"].as_table();
        if (!groups) {
            std::cout << "multicast group URL must be specified \n";
            return 1;
        }
        if (groups->size() != 1) {
            std::cout << "multiple groups not supported atm\n";
            return 1;
        }
        instance_name = config["instance_name"].value<std::string>().value();

        // get and init lcm multicast url
        auto group1key = groups->begin()->first;
        auto &group1 = *(*groups)[group1key].as_table();

        auto multicast_url = group1["multicast_url"];

        // init security parameters
        std::vector<lcm_security_parameters> sec_params;

        std::string algorithm = group1["algorithm"].value<std::string>().value();
        std::string privkey = group1["privkey"].value<std::string>().value();
        std::string cert = group1["cert"].value<std::string>().value();
        std::string root_ca = group1["root_ca"].value<std::string>().value();

        lcm_security_parameters group_params{0};
        group_params.algorithm = algorithm.data();
        group_params.certificate = cert.data();
        group_params.keyfile = privkey.data();
        group_params.root_ca = root_ca.data();
        sec_params.push_back(group_params);

        lcm::LCM lcm(multicast_url.value<std::string>().value(), sec_params.data());
        if (!lcm.good())
            return 1;

        // setup subscriptions
        for (auto &entry : group1) {
            if (entry.second.is_table()) {
                // these are the channels
                auto &channel_config = *entry.second.as_table();

                setup_channel(channel_config, lcm);
            }
        }

        while (true) {
            for (auto &f : sendfunctions) {
                f();
            }
            if (lcm.handleTimeout(100) < 0) {
                std::cerr << "lcm internal error, exiting...\n";
                return 1;
            }
        }
    }
catch (const std::bad_optional_access &err)
{
    std::cerr << "missing configuration: " << err.what() << "\n";

    // threads might have been initialized already, try to shutdown gracefully...
    std::cerr << "joining already dispatched threads... \n";
    return 1;
}
return 0;
}
