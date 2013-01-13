pimmel
======

pimmel is a simple pub-sub messaging library, much like 0mq[1] or
nanomsg[2], without all the transports they support and without the
reliability promise.

pimmel uses udp6 multicast to span ad-hoc topologies (on `ff0x::134`)
and uses zmtp (0mq's wire protocol) to propagate messages.

shell clients
-------------
There's 2 little shell clients aboard at the moment.

    pimmel-wait "/test"

which will instantiate a subscription to the channel `/test` and block.

Then, somewhere else, issue

    pimmel-noti "/test" "successful"

which publishes the message `successful` to the channel `/test`, and,
if present, wake any subscribers up.


References:
-----------
  [1]: https://github.com/zeromq/libzmq
  [2]: https://github.com/250bpm/nanomsg
