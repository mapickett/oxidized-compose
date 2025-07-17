ARG OXIDIZED_VERSION="0.33.0"

FROM docker.io/oxidized/oxidized:${OXIDIZED_VERSION}

WORKDIR /home/oxidized/.config/oxidized

COPY config .
COPY router.db .