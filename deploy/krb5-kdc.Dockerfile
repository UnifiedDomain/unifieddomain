FROM debian:12-slim

ARG KRB5_REALM=UD.INTERNAL
ENV DEBIAN_FRONTEND=noninteractive \
    KRB5_REALM=${KRB5_REALM}

RUN apt-get update \
 && apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server krb5-config krb5-user ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY deploy/krb5-kdc-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 88/udp 88/tcp 749/tcp
ENTRYPOINT ["/entrypoint.sh"]
CMD ["kadmind","-nofork"]
