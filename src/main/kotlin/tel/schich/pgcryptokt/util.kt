package tel.schich.pgcryptokt

import java.security.SecureRandom


internal val threadLocalSecureRandom = ThreadLocal.withInitial { SecureRandom() }