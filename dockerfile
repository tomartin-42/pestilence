FROM ubuntu:24.04

RUN apt update && \
    apt install -y \
	gawk \
        make \
        bash \
        nasm \
        gdb \
        cgdb \
        gcc \
        g++ \
        build-essential \
        btop \
        vim \
        tmux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["/bin/bash"]
