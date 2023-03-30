#!/bin/bash

docker run -it --rm -v $(pwd)/cert:/cert --cap-add SYS_NICE --ulimit msgqueue=-1 --sysctl fs.mqueue.msg_max=256 space-quic
