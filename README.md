pimmel
======

[![Build Status](https://secure.travis-ci.org/hroptatyr/pimmel.png?branch=master)](http://travis-ci.org/hroptatyr/pimmel)

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

```c
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
```

where `pselect`, `poll`, or `epoll` guts have been omitted for clarity.

The publisher part is similarly simple:

```c
/* for the notifier */
int s = pmml_socket(PMML_FL_PUB);

pmml_noti(s, &(struct pmml_chnmsg_s){
                .chan = "/test",
                .msg = "SUCCESS",
        });
pmml_close(s);
```

FAQ
---

1. Another messaging library when there's [0mq][1], really?

   First of all, [0mq][1] as it stands isn't stateless, you have to
   carefully set up your toplogy and hard-wire it (or portions of it)
   into your components, well, or use configuration files or whatever.
   pimmel on the other hand works using the magic fingers of
   udp6-multicast, no configuration, no servers, no nothing needed.

   Second, [0mq][1] suffers from what Pieter Hintjens calls the slow
   joiner syndrome: You set up a sub socket on one side and on the other
   side you create a pub socket and immediately blast all your valuable
   banter down the wire.  That pub/sub pair will first do a bit of
   handshaking and is hence not immediately ready for your verbal
   abuse, the first or so message will be dropped.
   Just like in real life really when it might take people by surprise
   when you start citing temperature numbers without the obligatory
   introductory chat about how the weather sucks.  Anyway, pimmel comes
   with no handshaking at this layer, and is ready to take orders right
   after the socket functions return, chances are you won't miss that
   crucial first message.

   Third, [0mq][1] infrastructure is designed to work best for a lengthy
   conversation between two lasting nodes, messages are queued and
   consolidated (much like TCP's Nagle) and sent over reliable sockets
   so questions come before answers and no part of the conversation is
   lost (apart from the first two words or so).  pimmel is designed to
   work best in ad-hoc environments, two nodes casually exist at the
   same time and exchange typically one message.  Messages aren't queued
   but passed onto the wire immediately and neither delivery nor the
   order in which messages are sent or received is guaranteed.

   So to sum it all up [0mq][1] is more like two women meeting up at a
   specific hair salon to have the natter of their lives whereas pimmel
   should be seen as one man mumbling the name of his favourite horse in
   the cubical of a public toilet to fellow bog riders.

2. But [0mq][1] ...

   More buts, there you go then, use [0mq][1] if it serves you better.

3. One datagram per message sounds like a waste

   And it is.  pimmel is designed for the occasional message, much like
   DNS requests.  For a continuous current of messages with the same
   destination (like logging, financial tick data, or measurements from
   your weather station) use something else, [unserding][3] maybe.

  [1]: https://github.com/zeromq/libzmq
  [2]: https://github.com/250bpm/nanomsg
  [3]: https://github.com/hroptatyr/unserding
