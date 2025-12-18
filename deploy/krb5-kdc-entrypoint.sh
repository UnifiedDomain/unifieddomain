#!/bin/sh
set -e

REALM="${KRB5_REALM:-${REALM:-UD.INTERNAL}}"
ADMIN_PASS="${KRB5_ADMIN_PASSWORD:-${KADMIN_PASS:-changeit}}"

cat >/etc/krb5.conf <<EOF
[libdefaults]
 default_realm = ${REALM}
 dns_lookup_kdc = false
 dns_lookup_realm = false

[realms]
 ${REALM} = {
  kdc = localhost
  admin_server = localhost
 }
EOF

cat >/etc/krb5kdc/kadm5.acl <<EOF
*/admin@${REALM} *
EOF

if [ ! -f /var/lib/krb5kdc/principal ]; then
  kdb5_util create -s -P "${ADMIN_PASS}"
  kadmin.local -q "addprinc -pw ${ADMIN_PASS} admin/admin"
fi

/usr/sbin/krb5kdc
exec "$@"
