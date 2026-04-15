# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2022 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import pytest
import os
from lib389.config import Encryption
from lib389.topologies import topology_st as topo
from lib389.utils import ds_is_older
from lib389.nss_ssl import NssSsl
from lib389.config import Config
from lib389._constants import DN_DM, PASSWORD, SECUREPORT_STANDALONE
import subprocess
import logging

log = logging.getLogger(__name__)

pytestmark = pytest.mark.tier1

LDAPSPORT = str(SECUREPORT_STANDALONE)

def test_long_cipher_list(topo):
    """Test a long cipher list, and makre sure it is not truncated

    :id: bc400f54-3966-49c8-b640-abbf4fb2377d
    :setup: Standalone Instance
    :steps:
        1. Set nsSSL3Ciphers to a very long list of ciphers
        2. Ciphers are applied correctly
    :expectedresults:
        1. Success
        2. Success
    """
    ENABLED_CIPHER = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384::AES-GCM::AEAD::256"
    DISABLED_CIPHER = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256::AES-GCM::AEAD::128"
    CIPHER_LIST = (
            "-all,-SSL_CK_RC4_128_WITH_MD5,-SSL_CK_RC4_128_EXPORT40_WITH_MD5,-SSL_CK_RC2_128_CBC_WITH_MD5,"
            "-SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,-SSL_CK_DES_64_CBC_WITH_MD5,-SSL_CK_DES_192_EDE3_CBC_WITH_MD5,"
            "-TLS_RSA_WITH_RC4_128_MD5,-TLS_RSA_WITH_RC4_128_SHA,-TLS_RSA_WITH_3DES_EDE_CBC_SHA,"
            "-TLS_RSA_WITH_DES_CBC_SHA,-SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,-SSL_RSA_FIPS_WITH_DES_CBC_SHA,"
            "-TLS_RSA_EXPORT_WITH_RC4_40_MD5,-TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,-TLS_RSA_WITH_NULL_MD5,"
            "-TLS_RSA_WITH_NULL_SHA,-TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,-SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,"
            "-SSL_FORTEZZA_DMS_WITH_RC4_128_SHA,-SSL_FORTEZZA_DMS_WITH_NULL_SHA,-TLS_DHE_DSS_WITH_DES_CBC_SHA,"
            "-TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,-TLS_DHE_RSA_WITH_DES_CBC_SHA,-TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,"
            "+TLS_RSA_WITH_AES_128_CBC_SHA,-TLS_DHE_DSS_WITH_AES_128_CBC_SHA,-TLS_DHE_RSA_WITH_AES_128_CBC_SHA,"
            "+TLS_RSA_WITH_AES_256_CBC_SHA,-TLS_DHE_DSS_WITH_AES_256_CBC_SHA,-TLS_DHE_RSA_WITH_AES_256_CBC_SHA,"
            "-TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,-TLS_DHE_DSS_WITH_RC4_128_SHA,-TLS_ECDHE_RSA_WITH_RC4_128_SHA,"
            "-TLS_RSA_WITH_NULL_SHA,-TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,-SSL_CK_DES_192_EDE3_CBC_WITH_MD5,"
            "-TLS_RSA_WITH_RC4_128_MD5,-TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,-TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,"
            "-TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,+TLS_AES_128_GCM_SHA256,+TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        )

    topo.standalone.enable_tls()
    enc = Encryption(topo.standalone)
    enc.set('nsSSL3Ciphers', CIPHER_LIST)
    topo.standalone.restart()
    enabled_ciphers = enc.get_attr_vals_utf8('nssslenabledciphers')
    assert ENABLED_CIPHER in enabled_ciphers
    assert DISABLED_CIPHER not in enabled_ciphers


def connectWithOpenssl(topology_st, cipher, expect):
    """
    Connect with the given cipher
    Condition:
    If expect is True, the handshake should be successful.
    If expect is False, the handshake should be refused with
       access log: "Cannot communicate securely with peer:
                   no common encryption algorithm(s)."
    """
    log.info(f'Testing {cipher} -- expect to handshake {"successfully" if expect else "failed"}')

    myurl = f'localhost:{LDAPSPORT}'
    cmdline = ['/usr/bin/openssl', 's_client', '-connect', myurl, '-cipher', cipher]

    strcmdline = " ".join(cmdline)
    log.info(f"Running cmdline: {strcmdline}")

    try:
        proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
    except ValueError:
        log.info(f"{cmdline} failed: {ValueError}")
        proc.kill()

    while True:
        l = proc.stdout.readline()
        if l == b"":
            break
        if b'Cipher is' in l:
            log.info(f"Found: {l}")
            if expect:
                if b'(NONE)' in l:
                    assert False
                else:
                    proc.stdin.close()
                    assert True
            else:
                if b'(NONE)' in l:
                    assert True
                else:
                    proc.stdin.close()
                    assert False


# def test_ciphers_policy_test(topo):
#     topo.standalone.enable_tls()
#     enc = Encryption(topo.standalone)
#     enc.set('nsSSL3Ciphers', b'default')
#     topo.standalone.restart()
#     assert topo.standalone.status()

#     connectWithOpenssl(topo, 'DES-CBC3-SHA', False)


@pytest.fixture(scope='function')
def setup_cipher_test(request, topo):
    topo.standalone.enable_tls()
    topo.standalone.restart()

    #def fin():
    #    topo.standalone.config.set('nsslapd-security', 'off')
    #    topo.standalone.use_ldap_uri()
    #    topo.standalone.restart()
    #request.addfinalizer(fin)


@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', True), 
                         ('AES256-SHA256', True)])
def test_cipher_policy_0(topo, setup_cipher_test, cipher, expect):
    topo.standalone.simple_bind_s(DN_DM, PASSWORD)
    errloglevel = topo.standalone.config.get_attr_val('nsslapd-errorlog-level')
    try:
        topo.standalone.config.set('nsslapd-errorlog-level', '64')
        topo.standalone.encryption.set('allowWeakCipher', 'on')
        topo.standalone.restart()

        connectWithOpenssl(topo, cipher, expect)
    finally:
        topo.standalone.config.set('nsslapd-errorlog-level', errloglevel)
        topo.standalone.encryption.set('allowWeakCipher', 'off')


@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', False), 
                         ('AES256-SHA256', True)])
def test_cipher_policy_1(topo, setup_cipher_test, cipher, expect):
    topo.standalone.simple_bind_s(DN_DM, PASSWORD)
    errloglevel = topo.standalone.config.get_attr_val('nsslapd-errorlog-level')
    try:
        topo.standalone.config.set('nsslapd-errorlog-level', '64')
        topo.standalone.encryption.delete('allowWeakCipher')
        topo.standalone.restart()

        connectWithOpenssl(topo, cipher, expect)
    finally:
        topo.standalone.config.set('nsslapd-errorlog-level', errloglevel)

#FAILS
@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', False), 
                         #('AES256-SHA256', False),
                         ('AES128-SHA', True),
                         ('AES256-SHA', True)])
def test_cipher_policy_2(topo, cipher, expect):
    topo.standalone.simple_bind_s(DN_DM, PASSWORD)

    try:
        topo.standalone.encryption.set('nsSSL3Ciphers', '+TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384')
        topo.standalone.restart()

        connectWithOpenssl(topo, cipher, expect)
    finally:
        topo.standalone.encryption.set('nsSSL3Ciphers', b'default')


#FAILS
@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', False), 
                         ('AES256-SHA256', False)])
def test_cipher_policy_3(topo, setup_cipher_test, cipher, expect):
    topo.standalone.simple_bind_s(DN_DM, PASSWORD)
    try:
        topo.standalone.encryption.set('nsSSL3Ciphers', b'-all')
        topo.standalone.restart(timeout=120, post_open=False)

        connectWithOpenssl(topo, cipher, expect)
    finally:
        topo.standalone.encryption.set('nsSSL3Ciphers', b'default')


@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', False), 
                         ('AES256-SHA256', True)])
def test_cipher_policy_4(topo, setup_cipher_test, cipher, expect):
    topo.standalone.simple_bind_s(DN_DM, PASSWORD)

    try:
        topo.standalone.encryption.delete('nsSSL3Ciphers')
        topo.standalone.restart()

        connectWithOpenssl(topo, cipher, expect)
    finally:
        topo.standalone.encryption.set('nsSSL3Ciphers', b'default')


@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', False), 
                         ('AES256-SHA256', True)])
def test_cipher_policy_5(topo, setup_cipher_test, cipher, expect):
    topo.standalone.simple_bind_s(DN_DM, PASSWORD)

    topo.standalone.encryption.set('nsSSL3Ciphers', b'default')
    topo.standalone.restart()

    connectWithOpenssl(topo, cipher, expect)


@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', False), 
                         #('AES256-SHA256', False),
                         ('AES128-SHA', True)])
def test_cipher_policy_6(topo, setup_cipher_test, cipher, expect):
    topo.standalone.simple_bind_s(DN_DM, PASSWORD)

    try:
        topo.standalone.encryption.set('nsSSL3Ciphers', b'+all,-TLS_RSA_WITH_AES_256_CBC_SHA256')
        topo.standalone.restart()

        connectWithOpenssl(topo, cipher, expect)
    finally:
        topo.standalone.encryption.set('nsSSL3Ciphers', b'default')


@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', False), 
                         #('AES256-SHA256', False)
                         ])
def test_cipher_policy_8(topo, setup_cipher_test, cipher, expect):
    topo.standalone.simple_bind_s(DN_DM, PASSWORD)

    topo.standalone.encryption.set('nsSSL3Ciphers', b'default')
    topo.standalone.encryption.set('allowWeakCipher', 'off')
    topo.standalone.restart()

    connectWithOpenssl(topo, cipher, expect)


@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', True), 
                         ('AES256-SHA256', True)])
def test_cipher_policy_9(topo, setup_cipher_test, cipher, expect):

    topo.standalone.simple_bind_s(DN_DM, PASSWORD)

    try:
        topo.standalone.encryption.set('nsSSL3Ciphers', None)
        topo.standalone.encryption.set('allowWeakCipher', b'on')
        topo.standalone.config.delete('nsslapd-errorlog-level')
        topo.standalone.restart()

        connectWithOpenssl(topo, cipher, expect)
    finally:
        topo.standalone.encryption.set('nsSSL3Ciphers', b'default')
        topo.standalone.encryption.set('allowWeakCipher', b'off')


@pytest.mark.parametrize('cipher, expect',
                         [('DES-CBC3-SHA', False), 
                         ('AES256-SHA256', False)])
def test_cipher_policy_11(topo, setup_cipher_test, cipher, expect):
    topo.standalone.simple_bind_s(DN_DM, PASSWORD)

    try:
        topo.standalone.encryption.set('nsSSL3Ciphers', '+fortezza')
        topo.standalone.restart(timeout=120, post_open=False)

        connectWithOpenssl(topo, cipher, expect)
    finally:
        topo.standalone.encryption.set('nsSSL3Ciphers', b'default')


if __name__ == '__main__':
    # Run isolated
    # -s for DEBUG mode
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main(["-s", CURRENT_FILE])
