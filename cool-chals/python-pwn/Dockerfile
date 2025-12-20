FROM debian:12@sha256:9d11a2b1e25f5c84ae3d454ed51ef64f0cf07cbbc1ec25d689b9b0de7071ea66

RUN apt-get update && apt-get install -y socat python3

RUN addgroup --gid 1001 nonroot && \
    adduser --uid 1001 --gid 1001 --disabled-password --gecos "" nonroot && \
    echo 'nonroot ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

COPY ./chal.py /srv/app/chal.py
COPY ./entry.sh /srv/app/entry.sh
COPY ./flag.txt /srv/app/flag.txt
COPY ./python3.11 /srv/app/python3.11
COPY ./libz.so.1 /srv/app/libz.so.1
COPY ./libm.so.6 /srv/app/libm.so.6
COPY ./libc.so.6 /srv/app/libc.so.6
COPY ./libexpat.so.1 /srv/app/libexpat.so.1
COPY ./ld-linux-x86-64.so.2 /srv/app/ld-linux-x86-64.so.2
COPY ./my_arrays.cpython-311-x86_64-linux-gnu.so /srv/app/my_arrays.cpython-311-x86_64-linux-gnu.so

RUN chmod 444 /srv/app/flag.txt
RUN chmod 444 /srv/app/chal.py
RUN chmod 555 /srv/app/entry.sh
RUN chmod 555 /srv/app/ld-linux-x86-64.so.2
RUN chmod 555 /srv/app/python3.11
RUN chmod 555 /srv/app/libz.so.1
RUN chmod 555 /srv/app/libm.so.6
RUN chmod 555 /srv/app/libc.so.6
RUN chmod 555 /srv/app/libexpat.so.1
RUN chmod 555 /srv/app/my_arrays.cpython-311-x86_64-linux-gnu.so

EXPOSE 1337
USER 1001
WORKDIR /srv/app
CMD [ "/srv/app/entry.sh" ]