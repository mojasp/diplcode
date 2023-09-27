#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <lcm/lcm.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"

static lcm_t *g_lcm = NULL;
static int g_quit = 0;
static int g_lcmtest_primitives_t_count = 0;
static int g_lcmtest_primitives_list_t_count = 0;
static int g_lcmtest_node_t_count = 0;
static int g_lcmtest_multidim_array_t_count = 0;
static int g_lcmtest2_cross_package_t_count = 0;

static void reset_counts()
{
    g_lcmtest_primitives_t_count = 0;
    g_lcmtest_primitives_list_t_count = 0;
    g_lcmtest_node_t_count = 0;
    g_lcmtest_multidim_array_t_count = 0;
    g_lcmtest2_cross_package_t_count = 0;
}

static void lcmtest_primitives_t_handler(const lcm_recv_buf_t *rbuf, const char *channel,
                                         const lcmtest_primitives_t *msg, void *user)
{
    // Reset all counts (maybe)
    if (msg->i64 == 0) {
        reset_counts();
    }

    lcmtest_primitives_t reply;
    fill_lcmtest_primitives_t(g_lcmtest_primitives_t_count + 1, &reply);
    lcmtest_primitives_t_publish(g_lcm, "test_lcmtest_primitives_t_reply", &reply);
    clear_lcmtest_primitives_t(&reply);
    g_lcmtest_primitives_t_count++;
}

static void lcmtest_primitives_list_t_handler(const lcm_recv_buf_t *rbuf, const char *channel,
                                              const lcmtest_primitives_list_t *msg, void *user)
{
    lcmtest_primitives_list_t reply;
    fill_lcmtest_primitives_list_t(g_lcmtest_primitives_list_t_count + 1, &reply);
    lcmtest_primitives_list_t_publish(g_lcm, "test_lcmtest_primitives_list_t_reply", &reply);
    clear_lcmtest_primitives_list_t(&reply);
    g_lcmtest_primitives_list_t_count++;
}

static void lcmtest_node_t_handler(const lcm_recv_buf_t *rbuf, const char *channel,
                                   const lcmtest_node_t *msg, void *user)
{
    lcmtest_node_t reply;
    fill_lcmtest_node_t(g_lcmtest_node_t_count + 1, &reply);
    lcmtest_node_t_publish(g_lcm, "test_lcmtest_node_t_reply", &reply);
    clear_lcmtest_node_t(&reply);
    g_lcmtest_node_t_count++;
}

static void lcmtest_multidim_array_t_handler(const lcm_recv_buf_t *rbuf, const char *channel,
                                             const lcmtest_multidim_array_t *msg, void *user)
{
    lcmtest_multidim_array_t reply;
    fill_lcmtest_multidim_array_t(g_lcmtest_multidim_array_t_count + 1, &reply);
    lcmtest_multidim_array_t_publish(g_lcm, "test_lcmtest_multidim_array_t_reply", &reply);
    clear_lcmtest_multidim_array_t(&reply);
    g_lcmtest_multidim_array_t_count++;
}

static void lcmtest2_cross_package_t_handler(const lcm_recv_buf_t *rbuf, const char *channel,
                                             const lcmtest2_cross_package_t *msg, void *user)
{
    lcmtest2_cross_package_t reply;
    fill_lcmtest2_cross_package_t(g_lcmtest2_cross_package_t_count + 1, &reply);
    lcmtest2_cross_package_t_publish(g_lcm, "test_lcmtest2_cross_package_t_reply", &reply);
    clear_lcmtest2_cross_package_t(&reply);
    g_lcmtest2_cross_package_t_count++;
}

static void echo_handler(const lcm_recv_buf_t *rbuf, const char *channel, void *user)
{
    lcm_publish(g_lcm, "TEST_ECHO_REPLY", rbuf->data, rbuf->data_size);
}

static void quit_handler()
{
    g_quit = 1;
}

static int g_lcmsec_cycle_test_id;
static void lcmsec_cycle_test_handler(const lcm_recv_buf_t *rbuf, const char *channel,
                                      const lcmtest_primitives_t *msg, void *user)
{
    lcmtest_primitives_t reply;
    assert(g_lcmsec_cycle_test_id >= 2);
    assert(g_lcmsec_cycle_test_id <= 9); //server 8 will adress server 9 (nonexistent)
    fprintf(stderr, "server %i got msg with id %i\n", g_lcmsec_cycle_test_id, msg->i8);
    if (g_lcmsec_cycle_test_id == msg->i8) {
        fill_lcmtest_primitives_t(g_lcmsec_cycle_test_id + 1, &reply);
        lcmtest_primitives_t_publish(g_lcm, "test_lcmsec_cycle", &reply);
        clear_lcmtest_primitives_t(&reply);
    }
}

// ============================

int main(int argc, char **argv)
{
    if (!argc) {
        fprintf(stderr, "Please supply an integer as first command line argument");
        exit(EXIT_FAILURE);
    }

    // argv[1] is our id.
    char *endptr;
    g_lcmsec_cycle_test_id = strtol(argv[1], &endptr, 10);
    if (errno != 0) {
        perror("strtol");
        exit(EXIT_FAILURE);
    }
    if (endptr == argv[1]) {
        fprintf(stderr, "Please supply an integer as first command line argument");
        exit(EXIT_FAILURE);
    }
    // client will have id 1, servers 2 to 8
    if (g_lcmsec_cycle_test_id < 2 || g_lcmsec_cycle_test_id > 8) {
        fprintf(stderr, "id out of range");
        exit(EXIT_FAILURE);
    }

    lcm_security_parameters secparams;
    secparams.algorithm = strdup("AES-128/GCM");
    secparams.keyexchange_in_background = 1;
    secparams.keyexchange_url = strdup("udpm://239.255.76.67:7667");

    char cert[100];
    snprintf(cert, sizeof(cert), "%s%s%s", "test_chain/", argv[1], ".crt");
    printf("cert: %s\n", cert);
    secparams.certificate = cert;

    char key[100];
    snprintf(key, sizeof(key), "%s%s%s", "test_chain/", argv[1], ".key");
    printf("key: %s\n", key);
    secparams.keyfile = key;

    secparams.root_ca = strdup("test_chain/root_ca.crt");

    g_lcm = lcm_create_with_security("udpm://239.255.76.67:7667", &secparams);
    if (!g_lcm)
        return 1;

    if (g_lcmsec_cycle_test_id == 2) {
        // server with id 2 will be the server for the server-client test
        lcm_subscribe(g_lcm, "TEST_QUIT", (lcm_msg_handler_t) &quit_handler, NULL);

        lcm_subscribe(g_lcm, "TEST_ECHO", &echo_handler, NULL);

        lcmtest_primitives_t_subscribe(g_lcm, "test_lcmtest_primitives_t",
                                       &lcmtest_primitives_t_handler, NULL);

        lcmtest_primitives_list_t_subscribe(g_lcm, "test_lcmtest_primitives_list_t",
                                            &lcmtest_primitives_list_t_handler, NULL);

        lcmtest_node_t_subscribe(g_lcm, "test_lcmtest_node_t", &lcmtest_node_t_handler, NULL);

        lcmtest_multidim_array_t_subscribe(g_lcm, "test_lcmtest_multidim_array_t",
                                           &lcmtest_multidim_array_t_handler, NULL);

        lcmtest2_cross_package_t_subscribe(g_lcm, "test_lcmtest2_cross_package_t",
                                           &lcmtest2_cross_package_t_handler, NULL);
    }

    // roundtrip-test:
    // We will have 8 participants (with an id). One packet will be send on a round-trip around
    // a cyircle of these participants to ensure that all of them can talk to each other. Of
    // course, they will always be broadcast - The client can check that it received all 19
    // incoming messages.
    lcmtest_primitives_t_subscribe(g_lcm, "test_lcmsec_cycle", &lcmsec_cycle_test_handler, NULL);

    while (lcm_handle(g_lcm) == 0 && !g_quit) {
        // Do nothing
    }

    lcm_destroy(g_lcm);
    return 0;
}
