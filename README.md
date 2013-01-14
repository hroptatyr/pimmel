pimmel
======

pimmel is a simple pub-sub messaging library, much like [0mq][1] or
[nanomsg][2], without all the transports they support and without the
reliability promise.

pimmel uses udp6 multicast to span ad-hoc topologies (on `ff0x::134`)
and uses zmtp (0mq's wire protocol) to propagate messages.

+ github page: <https://github.com/hroptatyr/pimmel>
+ downloads: <https://bitbucket.org/hroptatyr/pimmel/downloads>

shell clients
-------------
There's 2 little shell clients aboard at the moment.

    pimmel-wait "/test"

which will instantiate a subscription to the channel `/test` and block.

Then, somewhere else, issue

    pimmel-noti "/test" "successful"

which publishes the message `successful` to the channel `/test`, and,
if present, wake any subscribers up.

C API
-----
Quite similar to the shell clients is the C API, at its highest level at
least:

    /* for the waiter */
    int s = pmml_socket(PMML_FL_SUB);

    pmml_sub(s, "/test");
    while (pselect|poll|epoll(s, ...)) {
            struct pmml_chnmsg_s msg[1];

            if (pmml_wait(s, msg) < 0) {
                    /* not for us, could also mean socket error */
                    continue;
            }
            fwrite(msg->msg, 1, msg->msz, stdout);
            break;
    }
    /* unsubscribe from all channels */
    pmml_uns(s, NULL);
    pmml_close(s);

where `pselect`, `poll`, or `epoll` guts have been omitted for clarity.

The publisher part is similarly simple:

    /* for the notifier */
    int s = pmml_socket(PMML_FL_PUB);

    pmml_noti(s, &(struct pmml_chnmsg_s){
                    .chan = "/test",
                    .msg = "SUCCESS",
            });
    pmml_close(s);


  [1]: https://github.com/zeromq/libzmq
  [2]: https://github.com/250bpm/nanomsg
