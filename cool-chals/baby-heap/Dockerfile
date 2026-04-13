FROM ubuntu:24.04

COPY ./main_patched /srv/app/run
COPY ./libc.so.6 /srv/app/libc.so.6
COPY ./ld-linux-x86-64.so.2 /srv/app/ld-linux-x86-64.so.2
COPY ./entry.sh /srv/app/entry.sh
COPY ./flag.txt /srv/app/flag.txt

RUN chmod 555 /srv/app/run
RUN chmod 444 /srv/app/flag.txt
RUN chmod 555 /srv/app/entry.sh
RUN chmod 555 /srv/app/libc.so.6
RUN chmod 555 /srv/app/ld-linux-x86-64.so.2
RUN ln -sf /srv/app/libc.so.6 /srv/app/libc
RUN ln -sf /srv/app/ld-linux-x86-64.so.2 /srv/app/ld
RUN apt-get update && apt-get install -y socat 

RUN groupadd -g 1001 nonroot && \
    useradd -m -u 1001 -g 1001 -s /bin/bash nonroot && \
    echo 'nonroot ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

USER nonroot

WORKDIR /srv/app

EXPOSE 8081

CMD [ "/srv/app/entry.sh" ]
