#include <gtest/gtest.h>
#include <lcm/lcm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "lcmsec_common.h"
#include "lcmtest_primitives_t.h"

#define info(...)             \
    do {                      \
        printf("c_client: "); \
        printf(__VA_ARGS__);  \
        printf("\n");         \
    } while (0)

static lcm_t *g_lcm = NULL;

// ====================================== node_t test
#define MAKE_CLIENT_TEST(type, num_iters)                                                     \
                                                                                              \
    static int g_##type##_response_count = 0;                                                 \
                                                                                              \
    static void type##_handler(const lcm_recv_buf_t *, const char *, const type *msg, void *) \
    {                                                                                         \
        if (!check_##type(msg, g_##type##_response_count + 1)) {                              \
            return;                                                                           \
        }                                                                                     \
        g_##type##_response_count++;                                                          \
    }                                                                                         \
                                                                                              \
    static int do_##type##_test(void)                                                         \
    {                                                                                         \
        type msg;                                                                             \
        type##_subscription_t *subs =                                                         \
            type##_subscribe(g_lcm, "test_" #type "_reply", type##_handler, NULL);            \
        g_##type##_response_count = 0;                                                        \
        int result = 1;                                                                       \
        int iter;                                                                             \
        for (iter = 0; iter < num_iters && result; iter++) {                                  \
            fill_##type(iter, &msg);                                                          \
            type##_publish(g_lcm, "test_" #type, &msg);                                       \
            if (!lcm_handle_timeout(g_lcm, 500)) {                                            \
                info(#type " test: Timeout waiting for reply");                               \
                result = 0;                                                                   \
            } else if (g_##type##_response_count != iter + 1) {                               \
                info(#type " test: failed on iteration %d", iter);                            \
                result = 0;                                                                   \
            }                                                                                 \
            clear_##type(&msg);                                                               \
        }                                                                                     \
        type##_unsubscribe(g_lcm, subs);                                                      \
        return result;                                                                        \
    }

MAKE_CLIENT_TEST(lcmtest2_cross_package_t, 100);
MAKE_CLIENT_TEST(lcmtest_multidim_array_t, 5);
MAKE_CLIENT_TEST(lcmtest_node_t, 7);
MAKE_CLIENT_TEST(lcmtest_primitives_list_t, 100);
MAKE_CLIENT_TEST(lcmtest_primitives_t, 1000);

// ================================= echo test
int g_echo_response_count = 0;
unsigned int g_echo_msg_len = 0;
uint8_t *g_echo_data = NULL;

static void echo_handler(const lcm_recv_buf_t *rbuf, const char *, void *)
{
    if (rbuf->data_size != g_echo_msg_len)
        return;
    if (memcmp(rbuf->data, g_echo_data, rbuf->data_size))
        return;
    g_echo_response_count++;
}

TEST(LCMSEC_C, EchoTest)
{
    srand(time(NULL));

    g_lcm = lcmsec_setup(1);
    ASSERT_TRUE(g_lcm != NULL);

    int maxlen = 10000;
    int minlen = 10;
    g_echo_data = (uint8_t *) malloc(maxlen);
    lcm_subscription_t *subs = lcm_subscribe(g_lcm, "TEST_ECHO_REPLY", echo_handler, NULL);
    g_echo_response_count = 0;

    int iter;
    for (iter = 0; iter < 100; iter++) {
        g_echo_msg_len = rand() % (maxlen - minlen) + minlen;
        unsigned int i;
        for (i = 0; i < g_echo_msg_len; i++)
            g_echo_data[i] = rand() % 256;

        lcm_publish(g_lcm, "TEST_ECHO", g_echo_data, g_echo_msg_len);

        ASSERT_GT(lcm_handle_timeout(g_lcm, 500), 0);
        ASSERT_EQ(g_echo_response_count, iter + 1);

        if (g_echo_response_count != iter + 1) {
            info("echo test failed to receive response on iteration %d", iter);
            lcm_unsubscribe(g_lcm, subs);
            free(g_echo_data);
            return;
        }
    }

    lcm_unsubscribe(g_lcm, subs);
    free(g_echo_data);
}

// Typed tests
TEST(LCMSEC_C, primitives_t)
{
    ASSERT_TRUE(g_lcm != NULL);
    EXPECT_EQ(1, do_lcmtest_primitives_t_test());
}

TEST(LCMSEC_C, primitives_list_t)
{
    ASSERT_TRUE(g_lcm != NULL);
    EXPECT_EQ(1, do_lcmtest_primitives_list_t_test());
}

TEST(LCMSEC_C, node_t)
{
    ASSERT_TRUE(g_lcm != NULL);
    EXPECT_EQ(1, do_lcmtest_node_t_test());
}

TEST(LCMSEC_C, multidim_array_t)
{
    ASSERT_TRUE(g_lcm != NULL);
    EXPECT_EQ(1, do_lcmtest_multidim_array_t_test());
}

TEST(LCMSEC_C, cross_package)
{
    ASSERT_TRUE(g_lcm != NULL);
    EXPECT_EQ(1, do_lcmtest2_cross_package_t_test());
}

static int g_lcmsec_cycle_test_got_messages [9];

static void lcmsec_cycle_test_handler(const lcm_recv_buf_t *, const char *, const lcmtest_primitives_t *msg, void *userdata)
{                                                                                         \
    int *g_lcmsec_cycle_test_fail= (int*)userdata;
    int id = msg->i8;

    if (id < 1 || id > 9){
        *g_lcmsec_cycle_test_fail = 1;
        fprintf(stderr,"lcmsec_cycle_test: id out of bounds");
        return;
    }

    //all fields should be the same
    if(!check_lcmtest_primitives_t(msg, id)){
        fprintf(stderr,"lcmsec_cycle_test: message ill-formed"); 
        *g_lcmsec_cycle_test_fail = 1;
    }

    //sender of the message has the previous id
    g_lcmsec_cycle_test_got_messages[id - 1] = 1;
}

TEST(LCMSEC_C, lcmsec_cycle_test)
{
    ASSERT_TRUE(g_lcm != NULL);

    for (int i = 1; i <= 8; i++) {
        g_lcmsec_cycle_test_got_messages[i] = 0;
    }
    int g_lcmsec_cycle_test_fail = 0;

    lcmtest_primitives_t msg;

    //we are id 1; first recipient will be server 2
    fill_lcmtest_primitives_t(2, &msg);

    lcmtest_primitives_t_subscription_t *subs = lcmtest_primitives_t_subscribe(g_lcm, "test_lcmsec_cycle", lcmsec_cycle_test_handler, &g_lcmsec_cycle_test_fail);

    lcmtest_primitives_t_publish(g_lcm, "test_lcmsec_cycle", &msg);

    //we expect to see a total of 8 messages (including the one we published ourselves)
    for (int i = 1; i <= 8 ; i++) {
        info("lcmsec_cycle_test: handle it %i", i);                               \
        if (!lcm_handle_timeout(g_lcm, 800)) {                                            \
            info("lcmsec_cycle_test: Timeout waiting for reply for i=%i", i);                               \
            g_lcmsec_cycle_test_fail = 1;
        }
    }

    //Check that we indeed got all the messages (we need to check later since order is not defined)
    info("message 1: %i", g_lcmsec_cycle_test_got_messages[1]);
    for (int i = 2; i <= 8; i++) {
        info("message %i: %i", i, g_lcmsec_cycle_test_got_messages[i]);
        EXPECT_EQ(g_lcmsec_cycle_test_got_messages[i], 1); 
    }

    EXPECT_EQ(g_lcmsec_cycle_test_fail, 0);

    lcmtest_primitives_t_unsubscribe(g_lcm, subs);
    lcm_destroy(g_lcm);
}

TEST(LCMSEC_C, API_default_algorithm_test){
    lcm_security_parameters secparams={0};

    char key[100];
    char cert[100];

    snprintf(cert, sizeof(cert), "%s%d%s", "test_chain/", 1, ".crt");
    printf("cert: %s\n", cert);
    secparams.certificate = cert;
    snprintf(key, sizeof(key), "%s%d%s", "test_chain/", 1, ".key");
    printf("key: %s\n", key);
    secparams.keyfile = key;

    secparams.algorithm = NULL; //should default to aesgcm and work

    secparams.root_ca = strdup("test_chain/root_ca.crt");

    lcm_t* lcm = lcm_create_with_security("udpm://239.255.76.67:7667", &secparams);
    ASSERT_TRUE(lcm != NULL);

    lcm_destroy(lcm);
}
