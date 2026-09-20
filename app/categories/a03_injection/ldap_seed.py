from ldap3 import BASE

from app.categories.a03_injection import ldap_client


def seed_ldap_data():
    """Idempotently seeds the LDAP directory with two accounts. Checked via
    a BASE-scope existence search on the marker entry (uid=alice) before
    creating anything, so re-running this (e.g. at every app startup) is
    safe and does not error on an already-seeded directory."""
    conn = ldap_client.get_ldap_connection()
    try:
        base_dn = ldap_client.LDAP_BASE_DN
        alice_dn = f"uid=alice,ou=people,{base_dn}"
        exists = conn.search(alice_dn, "(objectClass=*)", BASE)
        if exists and conn.entries:
            return

        conn.add(f"ou=people,{base_dn}", ["organizationalUnit"])

        conn.add(
            alice_dn,
            ["inetOrgPerson", "organizationalPerson", "person", "top"],
            {
                "cn": "Alice Example",
                "sn": "Example",
                "uid": "alice",
                "userPassword": "alice123",
                "mail": "alice@owasp-lab.local",
            },
        )

        conn.add(
            f"uid=root_admin,ou=people,{base_dn}",
            ["inetOrgPerson", "organizationalPerson", "person", "top"],
            {
                "cn": "Root Administrator",
                "sn": "Administrator",
                "uid": "root_admin",
                "userPassword": "sup3r-s3cret-ldap-admin-pw",
                "mail": "root_admin@owasp-lab.local",
                "description": "recovery-code-x7k2p9",
            },
        )
    finally:
        conn.unbind()
