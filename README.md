pgcrypto-kt
===========

This library is a reimplementation of the pgcrypto extension for the PostgreSQL database as documented [here](https://www.postgresql.org/docs/current/pgcrypto.html).

All functions[^1] have been implemented and are automatically tested against
an actual PG server.

The main purpose of this library is to assist migrating from in-database encryption to client-side encryption, e.g. for
improving load distribution of encryption load. The library would also be useful when migrating to a different PostgreSQL-compatible
database server that does not support the pgcrypto extension (e.g. CockroachDB).

[^1]: The XDES crypt algorithm is not supported due to a lack of JVM-based implementations.