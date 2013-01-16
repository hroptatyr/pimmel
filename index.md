---
title: dateutils
layout: default
---

pimmel
======

<div id="rtop" class="sidebar-widget">
  <div class="sidebar-stack">
    <ul>
      <li>
        <script type="text/javascript"
          src="http://www.ohloh.net/p/632570/widgets/project_languages.js">
        </script>
      </li>
    </ul>
  </div>
  <div class="sidebar-stack">
    <ul>
      <li><a href="https://github.com/hroptatyr/pimmel">github page</a></li>
      <li><a href="https://bitbucket.org/hroptatyr/pimmel/downloads/pimmel-0.1.0.tar.xz">latest release (pimmel-0.1.0.tar.xz)</a></li>
    </ul>
  </div>
</div>

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
