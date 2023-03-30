#!/bin/bash

docker run --rm -v $(pwd)/cert:/cert -v $(pwd)/util:/util --cap-add SYS_NICE --ulimit msgqueue=-1 --sysctl fs.mqueue.msg_max=256 space-quic /bin/bash -c "/util/entrypoint-sat.sh"
