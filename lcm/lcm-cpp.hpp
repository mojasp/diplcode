#ifndef __lcm_cpp_hpp__
#define __lcm_cpp_hpp__

#ifndef LCM_CXX_11_ENABLED
#if __cplusplus >= 201103L
#define LCM_CXX_11_ENABLED 1
#else
#define LCM_CXX_11_ENABLED 0
#endif
#endif

#include <cstdio> /* needed for FILE* */
#include <string>
#include <vector>
#include "lcm.h"

#if LCM_CXX_11_ENABLED
#include <functional>
#endif

namespace lcm {
/**
 * @defgroup LcmCpp C++ API Reference
 *
 * THe %LCM C++ API provides classes and data structures for communicating with
 * other %LCM clients, as well as reading and writing %LCM log files.  It is a
 * pure header wrapper around the C API, and has the same linking requirements
 * as the C API.
 *
 * @{
 */

class Subscription;

struct ReceiveBuffer;

/**
 * @brief Core communications class for the C++ API.
 *
 * @headerfile lcm/lcm-cpp.hpp
 */
class LCM {
  public:
    /**
     * @brief Constructor.
     *
     * Initializes the LCM instance and connects it to the specified LCM
     * network.  See the documentation on lcm_create() in the C API for
     * details on how lcm_url is formatted.
     *
     * @sa lcm_create()
     */
    inline LCM(std::string lcm_url = "", lcm_security_parameters *sec_params = nullptr);

    /**
     * @brief Constructor.
     *
     * Initializes the c++ LCM instance from an existing C instance.
     *
     * @sa lcm_create()
     */
    inline LCM(lcm_t *lcm_in);

    /**
     * @brief Destructor.
     *
     * Disconnects from the LCM network, and destroys all outstanding
     * Subscription objects.
     */
    inline ~LCM();

    /**
     * @brief Checks if initialization succeeded during object
     * construction.
     *
     * @return true if initialization succeeded and the instance appears
     * ready for communication, false if not.
     */
    inline bool good() const;

    /**
     * @brief Publishes a raw data message.
     *
     * @param channel the channel to publish the message on.
     * @param data data buffer containing the message to publish
     * @param datalen length of the message, in bytes.
     *
     * @return 0 on success, -1 on failure.
     */
    inline int publish(const std::string &channel, const void *data, unsigned int datalen);

    /**
     * @brief Publishes a message with automatic message encoding.
     *
     * This template method is designed for use with C++ classes generated
     * by lcm-gen.
     *
     * @param channel the channel to publish the message on.
     * @param msg the message to publish.
     *
     * @return 0 on success, -1 on failure.
     */
    template <class MessageType>
    inline int publish(const std::string &channel, const MessageType *msg);

    /**
     * @brief Returns a file descriptor or socket that can be used with
     * @c select(), @c poll(), or other event loops for asynchronous
     * notification of incoming messages.
     *
     * This method is useful when integrating LCM into another event loop,
     * such as the Qt event loop (via QSocketNotifier), the GLib event loop
     * (via GIOChannel), a custom @c select() @c - or @c poll() @c -based event loop, or any other
     * event loop that supports file descriptors.
     *
     * @todo link to example code.
     *
     * @return a non-negative file descriptor on success, or -1 if something
     * is wrong.
     * @sa lcm_get_fileno()
     */
    inline int getFileno();

    /**
     * @brief Waits for and dispatches messages.
     *
     * @return 0 on success, -1 if something went wrong.
     * @sa lcm_handle()
     */
    inline int handle();

    /**
     * @brief Waits for and dispatches messages, with a timeout.
     *
     * New in LCM 1.1.0.
     *
     * @return >0 if a message was handled, 0 if the function timed out,
     * and <0 if an error occured.
     * @sa lcm_handle_timeout()
     */
    inline int handleTimeout(int timeout_millis);

    /**
     * @brief Subscribes a callback method of an object to a channel, with
     * automatic message decoding.
     *
     * This method is designed for use with C++ classes generated by
     * @c lcm-gen @c .
     *
     * The callback method will be invoked on the object when a message
     * arrives on the specified channel.  Prior to method invocation, LCM
     * will attempt to automatically decode the message to the specified
     * message type @c MessageType @c , which should be a class generated
     * by @c lcm-gen @c .  If message
     * decoding fails, the callback method is not invoked and an error
     * message is printed to stderr.
     *
     * The callback method is invoked during calls to LCM::handle().
     * Callback methods are invoked by the same thread that invokes
     * LCM::handle(), in the order that they were subscribed.
     *
     * For example:
     *
     * \code
     * #include <exlcm/example_t.lcm>
     * #include <lcm/lcm-cpp.hpp>
     *
     * class MyMessageHandler {
     *   void onMessage(const lcm::ReceiveBuffer* rbuf, const std::string& channel,
     *           const exlcm::example_t* msg) {
     *      // do something with the message
     *   }
     * };
     *
     * int main(int argc, char** argv) {
     *   lcm::LCM lcm;
     *   MyMessageHandler handler;
     *   lcm.subscribe("CHANNEL", &MyMessageHandler::onMessage, &handler);
     *   while(true)
     *     lcm.handle();
     *   return 0;
     * }
     * \endcode
     *
     * @param channel The channel to subscribe to.  This is treated as a
     * regular expression implicitly surrounded by '^' and '$'.
     * @param handlerMethod A class method pointer identifying the callback
     * method.
     * @param handler A class instance that the callback method will be
     * invoked on.
     *
     * @return a Subscription object that can be used to adjust the
     * subscription and unsubscribe.  The Subscription object is managed by
     * the LCM class, and is automatically destroyed when its LCM instance
     * is destroyed.
     */
    template <class MessageType, class MessageHandlerClass>
    Subscription *subscribe(const std::string &channel,
                            void (MessageHandlerClass::*handlerMethod)(const ReceiveBuffer *rbuf,
                                                                       const std::string &channel,
                                                                       const MessageType *msg),
                            MessageHandlerClass *handler);

    /**
     * @brief Subscribe a callback method of an object to a channel,
     * without automatic message decoding.
     *
     * This method is designed for use when automatic message decoding is
     * not desired.
     *
     * The callback method will be invoked on the object when a message
     * arrives on the specified channel.  Callback methods are invoked
     * during calls to LCM::handle(), by the same thread that calls
     * LCM::handle().  Callbacks are invoked in the order that they were
     * subscribed.
     *
     * For example:
     *
     * \code
     * #include <lcm/lcm-cpp.hpp>
     *
     * class MyMessageHandler {
     *   void onMessage(const lcm::ReceiveBuffer* rbuf, const std::string& channel) {
     *      // do something with the message.  Raw message bytes are
     *      // accessible via rbuf->data
     *   }
     * };
     *
     * int main(int argc, char** argv) {
     *   lcm::LCM lcm;
     *   MyMessageHandler handler;
     *   lcm.subscribe("CHANNEL", &MyMessageHandler::onMessage, &handler);
     *   while(true)
     *     lcm.handle();
     *   return 0;
     * }
     * \endcode
     *
     * @param channel The channel to subscribe to.  This is treated as a
     * regular expression implicitly surrounded by '^' and '$'.
     * @param handlerMethod A class method pointer identifying the callback
     * method.
     * @param handler A class instance that the callback method will be
     * invoked on.
     *
     * @return a Subscription object that can be used to adjust the
     * subscription and unsubscribe.  The Subscription object is managed by
     * the LCM class, and is automatically destroyed when its LCM instance
     * is destroyed.
     */
    template <class MessageHandlerClass>
    Subscription *subscribe(const std::string &channel,
                            void (MessageHandlerClass::*handlerMethod)(const ReceiveBuffer *rbuf,
                                                                       const std::string &channel),
                            MessageHandlerClass *handler);

    /**
     * @brief Subscribe a function callback to a channel, with automatic
     * message decoding.
     *
     * This method is designed for use with static member functions and
     * C-style functions.
     *
     * The callback function will be invoked on the object when a message
     * arrives on the specified channel.  Prior to callback invocation, LCM
     * will attempt to automatically decode the message to the specified
     * message type @c MessageType @c , which should be a class generated
     * by @c lcm-gen @c .  If message decoding fails, the callback function
     * is not invoked and an error message is printed to stderr.
     *
     * The callback function is invoked during calls to LCM::handle().
     * Callbacks are invoked by the same thread that invokes
     * LCM::handle(), in the order that they were subscribed.
     *
     * For example:
     *
     * \code
     * #include <lcm/lcm-cpp.hpp>
     *
     * class State {
     * public:
     *   lcm::LCM lcm;
     *   int usefulVariable;
     * };
     *
     * void onMessage(const lcm::ReceiveBuffer* rbuf, const std::string& channel, const MessageType*
     * msg, State* state) {
     *   // do something with the message.
     * }
     *
     * int main(int argc, char** argv) {
     *   State* state = new State;
     *   state->lcm.subscribe("CHANNEL", onMessage, state);
     *   while(true)
     *     state->lcm.handle();
     *   delete state;
     *   return 0;
     * }
     * \endcode
     *
     * @param channel The channel to subscribe to.  This is treated as a
     * regular expression implicitly surrounded by '^' and '$'.
     * @param handler A function pointer identifying the callback
     * function.
     * @param context A context variable that will be passed to the
     * callback function.  This can be used to pass state or other
     * information to the callback function.  If not needed, then @c
     * ContextClass @c can be set to void*, and this argument set to NULL.
     *
     * @return a Subscription object that can be used to adjust the
     * subscription and unsubscribe.  The Subscription object is managed by
     * the LCM class, and is automatically destroyed when its LCM instance
     * is destroyed.
     */
    template <class MessageType, class ContextClass>
    Subscription *subscribeFunction(const std::string &channel,
                                    void (*handler)(const ReceiveBuffer *rbuf,
                                                    const std::string &channel,
                                                    const MessageType *msg, ContextClass context),
                                    ContextClass context);

    /**
     * @brief Subscribe a function callback to a channel, without automatic
     * message decoding.
     *
     * This method is designed for use when automatic message decoding is
     * not desired.
     *
     * For example:
     *
     * \code
     * #include <lcm/lcm-cpp.hpp>
     *
     * void onMessage(const lcm::ReceiveBuffer* rbuf, const std::string& channel, void*) {
     *   // do something with the message.  Raw message bytes are
     *   // accessible via rbuf->data
     * }
     *
     * int main(int argc, char** argv) {
     *   LCM::lcm lcm;
     *   lcm.subscribe("CHANNEL", onMessage, NULL);
     *   while(true)
     *     lcm.handle();
     *   return 0;
     * }
     * \endcode
     *
     * @param channel The channel to subscribe to.  This is treated as a
     * regular expression implicitly surrounded by '^' and '$'.
     * @param handler A function pointer identifying the callback
     * function.
     * @param context A context variable that will be passed to the
     * callback function.  This can be used to pass state or other
     * information to the callback function.  If not needed, then @c
     * ContextClass @c can be set to void*, and this argument set to NULL.
     *
     * @return a Subscription object that can be used to adjust the
     * subscription and unsubscribe.  The Subscription object is managed by
     * the LCM class, and is automatically destroyed when its LCM instance
     * is destroyed.
     */
    template <class ContextClass>
    Subscription *subscribeFunction(const std::string &channel,
                                    void (*handler)(const ReceiveBuffer *rbuf,
                                                    const std::string &channel,
                                                    ContextClass context),
                                    ContextClass context);

#if LCM_CXX_11_ENABLED
    /**
     * Type alias for the handler function type.
     */
    template <class MessageType>
    using HandlerFunction = std::function<void(const ReceiveBuffer *rbuf,
                                               const std::string &channel, const MessageType *msg)>;
    /**
     * @brief Subscribes a callback function to a channel, with
     * automatic message decoding.
     *
     * This method is designed for use with C++ classes generated by
     * @c lcm-gen @c .
     *
     * The callback function will be invoked on the object when a message
     * arrives on the specified channel.  Prior to method invocation, LCM
     * will attempt to automatically decode the message to the specified
     * message type @c MessageType @c , which should be a class generated
     * by @c lcm-gen @c .  If message
     * decoding fails, the callback function is not invoked and an error
     * message is printed to stderr.
     *
     * The callback function is invoked during calls to LCM::handle().
     * Callback methods are invoked by the same thread that invokes
     * LCM::handle(), in the order that they were subscribed.
     *
     * For example:
     *
     * \code
     * #include <exlcm/example_t.lcm>
     * #include <lcm/lcm-cpp.hpp>
     *
     * int main(int argc, char** argv) {
     *   lcm::LCM lcm;
     *   lcm::LCM::HandlerFunction<exlcm::example_t> func;
     *   func = [](const lcm::ReceiveBuffer* rbuf, const std::string& channel,
     *             const exlcm::example_t* msg) {
     *       // do something with the message
     *   }
     *   lcm.subscribe("CHANNEL", func);
     *   while(true)
     *     lcm.handle();
     *   return 0;
     * }
     * \endcode
     *
     * @param channel The channel to subscribe to.  This is treated as a
     * regular expression implicitly surrounded by '^' and '$'.
     * @param handler A handler function, for example a lambda.
     *
     * @return a Subscription object that can be used to adjust the
     * subscription and unsubscribe.  The Subscription object is managed by
     * the LCM class, and is automatically destroyed when its LCM instance
     * is destroyed.
     */
    template <class MessageType>
    Subscription *subscribe(const std::string &channel, HandlerFunction<MessageType> handler);
#endif

    /**
     * @brief Unsubscribes a message handler.
     *
     * After unsubscription, the callback registered by the original call
     * to subscribe() or subscribeFunction() will no longer be invoked when
     * messages are received.
     * The Subscription object is destroyed by this method.
     *
     * @param subscription a Subscription object previously returned by a
     * call to subscribe() or subscribeFunction().
     *
     * @return 0 on success, -1 if @p subscription is not a valid
     * subscription.
     */
    inline int unsubscribe(Subscription *subscription);

    /**
     * @brief retrives the lcm_t C data structure wrapped by this class.
     *
     * This method should be used carefully and sparingly.  An example use
     * case would be extending the subscription mechanism to Boost
     * Function objects.
     *
     * @return the lcm_t instance wrapped by this object.
     *
     * @sa lcm_t
     */
    inline lcm_t *getUnderlyingLCM();

  private:
    lcm_t *lcm;
    bool owns_lcm;

    std::vector<Subscription *> subscriptions;
};

/**
 * @brief Stores the raw bytes and timestamp of a received message.
 *
 * @headerfile lcm/lcm-cpp.hpp
 */
struct ReceiveBuffer {
    /**
     * Message payload data, represented as a raw byte buffer.
     */
    void *data;
    /**
     * Length of message payload, in bytes.
     */
    uint32_t data_size;
    /**
     * Timestamp identifying when the message was received.  Specified in
     * microseconds since the UNIX epoch.
     */
    int64_t recv_utime;
};

/**
 * @brief Represents a channel subscription, and can be used to unsubscribe
 * and set options.
 *
 * This class is not meant to be instantiated by the user, and instead is
 * constructed and returned by a call to LCM::subscribe() or
 * LCM::subscribeFunction().
 *
 * To unsubscribe, pass the instance to LCM::unsubscribe().  Once unsubscribed,
 * the object is destroyed and can not be used anymore.
 *
 * @headerfile lcm/lcm-cpp.hpp
 */
class Subscription {
  public:
    virtual ~Subscription() {}
    /**
     * @brief Adjusts the maximum number of received messages that can be
     * queued up for this subscription.
     *
     * @param num_messages the maximum queue size, in messages.  The
     * default is 30.
     *
     * Setting this to a low number may reduce
     * overall latency at the expense of dropping more messages.
     * Conversely, setting this to a high number may drop fewer messages at
     * the expense of increased latency.  A value of 0 indicates no limit,
     * and should be used very carefully.
     *
     */
    inline int setQueueCapacity(int num_messages);

    /**
     * @brief Query the current number of unhandled messages queued up for
     * this subscription.
     */
    inline int getQueueSize() const;

    friend class LCM;

  protected:
    Subscription() { channel_buf.reserve(LCM_MAX_CHANNEL_NAME_LENGTH); };

    /**
     * The underlying lcm_subscription_t object wrapped by this
     * subscription.
     */
    lcm_subscription_t *c_subs;

    // A "workspace" string that is overwritten with the channel name during
    // message handling. This string serves to eliminate a heap allocation that
    // would otherwise occur and which could preclude use in real-time
    // applications.
    std::string channel_buf;
};

/**
 * @brief Represents a single event (message) in a log file.
 *
 *
 *
 * This struct is the C++ counterpart for lcm_eventlog_event_t.
 *
 * @sa lcm_eventlog_event_t
 *
 * @headerfile lcm/lcm-cpp.hpp
 */
struct LogEvent {
    /**
     * Monotically increasing counter identifying the event number.  This field
     * is managed by LCM, and there should be no need to ever set it manually.
     */
    int64_t eventnum;
    /**
     * Timestamp identifying when the event was received.  Represented in
     * microseconds since the UNIX epoch.
     */
    int64_t timestamp;
    /**
     * The LCM channel on which the message was received.
     */
    std::string channel;
    /**
     * The length of the message payload, in bytes
     */
    int32_t datalen;
    /**
     * The message payload.
     */
    void *data;
};

/**
 * @brief Read and write %LCM log files.
 *
 * This class is the C++ counterpart for lcm_eventlog_t.
 *
 * @sa lcm_eventlog_t
 *
 * @headerfile lcm/lcm-cpp.hpp
 */
class LogFile {
  public:
    /**
     * Constructor.  Opens the specified log file for reading or writing.
     * @param path the file to open
     * @param mode "r" (read mode) or "w" (write mode)
     *
     * @sa lcm_eventlog_create()
     */
    inline LogFile(const std::string &path, const std::string &mode);

    /**
     * Destructor.  Closes the log file.
     */
    inline ~LogFile();

    /**
     * @return true if the log file is ready for reading/writing.
     */
    inline bool good() const;

    /**
     * Reads the next event in the log file.  Valid in read mode only.
     *
     * The LogFile class manages the memory of the read event.  The
     * returned event is valid until the next call to this method.
     *
     * @return the next event, or NULL if the end of the log file has been
     * reached.
     */
    inline const LogEvent *readNextEvent();

    /**
     * Seek close to the specified timestamp in the log file.  Valid
     * in read mode only.
     *
     * @param timestamp the desired seek point in the log file.
     *
     * @return 0 on success, -1 on error.
     * @sa lcm_eventlog_seek_to_timestamp()
     */
    inline int seekToTimestamp(int64_t timestamp);

    /**
     * Writes an event to the log file.  Valid in write mode only.
     *
     * @param event the event to write.  The timestamp, channel, datalen,
     * and data fields should be filled in.  The eventnum field will be
     * automatically filled in.
     *
     * @return 0 on success, -1 on error.
     * @sa lcm_eventlog_write_event()
     */
    inline int writeEvent(LogEvent *event);

    /**
     * @brief retrives the underlying FILE* wrapped by this class.
     *
     * This method should be used carefully and sparingly.
     * An example use-case is borrowing to tweak the behavior of the I/O.
     * Calls of interest include fflush(), fileno(), setvbuf(), etc
     * It is a bad idea to attempt reading or writing on the raw FILE*
     *
     * @return the FILE* wrapped by this object.
     */
    inline FILE *getFilePtr();

  private:
    LogEvent curEvent;
    lcm_eventlog_t *eventlog;
    lcm_eventlog_event_t *last_event;
};

/**
 * @}
 */

#define __lcm_cpp_impl_ok__
#include "lcm-cpp-impl.hpp"
#undef __lcm_cpp_impl_ok__
}

#endif
