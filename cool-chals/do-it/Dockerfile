FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m lnc
WORKDIR /home/lnc
COPY ./main ./main
COPY flag.txt /home/lnc/flag.txt
RUN chown -R root:lnc /home/lnc && \
    chmod 750 /home/lnc/main
USER lnc
CMD ["socat", "TCP-LISTEN:1337,fork,reuseaddr", "EXEC:./main"]
