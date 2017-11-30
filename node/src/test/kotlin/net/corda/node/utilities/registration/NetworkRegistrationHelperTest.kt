package net.corda.node.utilities.registration

import com.google.common.jimfs.Configuration.unix
import com.google.common.jimfs.Jimfs
import com.nhaarman.mockito_kotlin.any
import com.nhaarman.mockito_kotlin.doReturn
import com.nhaarman.mockito_kotlin.eq
import com.nhaarman.mockito_kotlin.whenever
import net.corda.core.crypto.Crypto
import net.corda.core.crypto.SecureHash
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.cert
import net.corda.core.internal.createDirectories
import net.corda.node.services.config.NodeConfiguration
import net.corda.nodeapi.internal.crypto.X509Utilities
import net.corda.nodeapi.internal.crypto.loadKeyStore
import net.corda.testing.ALICE
import net.corda.testing.rigorousMock
import net.corda.testing.testNodeConfiguration
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NetworkRegistrationHelperTest {
    private val fs = Jimfs.newFileSystem(unix())
    private val requestId = SecureHash.randomSHA256().toString()

    private lateinit var config: NodeConfiguration

    @Before
    fun init() {
        val baseDirectory = fs.getPath("/baseDir").createDirectories()
        config = testNodeConfiguration(baseDirectory = baseDirectory, myLegalName = ALICE.name)
    }

    @After
    fun cleanUp() {
        fs.close()
    }

    @Test
    fun `successful registration`() {
        val legalName = ALICE.name
        val intermediateCaName = CordaX500Name("CORDA_INTERMEDIATE_CA", "R3 Ltd", "London", "GB")
        val rootCaName = CordaX500Name("CORDA_ROOT_CA", "R3 Ltd", "London", "GB")

        val (nodeCaCert, intermediateCaCert, rootCaCert) = listOf(legalName, intermediateCaName, rootCaName).map(this::createCaCert)

        val certService = mockRegistrationResponse(nodeCaCert, intermediateCaCert, rootCaCert)

        config.rootCertFile.parent.createDirectories()
        X509Utilities.saveCertificateAsPEMFile(rootCaCert, config.rootCertFile)

        assertThat(config.nodeKeystore).doesNotExist()
        assertThat(config.sslKeystore).doesNotExist()
        assertThat(config.trustStoreFile).doesNotExist()

        NetworkRegistrationHelper(config, certService).buildKeystore()

        assertThat(config.nodeKeystore).exists()
        assertThat(config.sslKeystore).exists()
        assertThat(config.trustStoreFile).exists()

        val nodeKeystore = loadKeyStore(config.nodeKeystore, config.keyStorePassword)
        val sslKeystore = loadKeyStore(config.sslKeystore, config.keyStorePassword)
        val trustStore = loadKeyStore(config.trustStoreFile, config.trustStorePassword)

        nodeKeystore.run {
            assertTrue(containsAlias(X509Utilities.CORDA_CLIENT_CA))
            assertFalse(containsAlias(X509Utilities.CORDA_INTERMEDIATE_CA))
            assertFalse(containsAlias(X509Utilities.CORDA_ROOT_CA))
            assertFalse(containsAlias(X509Utilities.CORDA_CLIENT_TLS))
            val nodeCaCertChain = getCertificateChain(X509Utilities.CORDA_CLIENT_CA)
            assertThat(nodeCaCertChain).containsExactly(nodeCaCert, intermediateCaCert, rootCaCert)
        }

        sslKeystore.run {
            assertFalse(containsAlias(X509Utilities.CORDA_CLIENT_CA))
            assertFalse(containsAlias(X509Utilities.CORDA_INTERMEDIATE_CA))
            assertFalse(containsAlias(X509Utilities.CORDA_ROOT_CA))
            assertTrue(containsAlias(X509Utilities.CORDA_CLIENT_TLS))
            val nodeTlsCertChain = getCertificateChain(X509Utilities.CORDA_CLIENT_TLS)
            assertThat(nodeTlsCertChain).hasSize(4)
            // The TLS cert has the same subject as the node CA cert
            assertThat(CordaX500Name.build((nodeTlsCertChain[0] as X509Certificate).subjectX500Principal)).isEqualTo(legalName)
            assertThat(nodeTlsCertChain.drop(1)).containsExactly(nodeCaCert, intermediateCaCert, rootCaCert)
        }

        trustStore.run {
            assertFalse(containsAlias(X509Utilities.CORDA_CLIENT_CA))
            assertFalse(containsAlias(X509Utilities.CORDA_INTERMEDIATE_CA))
            assertTrue(containsAlias(X509Utilities.CORDA_ROOT_CA))
            val trustStoreRootCaCert = getCertificate(X509Utilities.CORDA_ROOT_CA)
            assertThat(trustStoreRootCaCert).isEqualTo(rootCaCert)
        }
    }

    @Test
    fun `rootCertFile doesn't exist`() {
        val certService = rigorousMock<NetworkRegistrationService>()

        assertThatThrownBy {
            NetworkRegistrationHelper(config, certService)
        }.hasMessageContaining(config.rootCertFile.toString())
    }

    @Test
    fun `root cert in response doesn't match expected`() {
        val legalName = ALICE.name
        val intermediateCaName = CordaX500Name("CORDA_INTERMEDIATE_CA", "R3 Ltd", "London", "GB")
        val rootCaName = CordaX500Name("CORDA_ROOT_CA", "R3 Ltd", "London", "GB")

        val (nodeCaCert, intermediateCaCert, rootCaCert) = listOf(legalName, intermediateCaName, rootCaName).map(this::createCaCert)

        val certService = mockRegistrationResponse(nodeCaCert, intermediateCaCert, rootCaCert)

        config.rootCertFile.parent.createDirectories()
        X509Utilities.saveCertificateAsPEMFile(createCaCert(rootCaName), config.rootCertFile)

        assertThatThrownBy {
            NetworkRegistrationHelper(config, certService).buildKeystore()
        }.isInstanceOf(WrongRootCertException::class.java)
    }

    private fun createCaCert(name: CordaX500Name): X509Certificate {
        return X509Utilities.createSelfSignedCACertificate(name, Crypto.generateKeyPair(X509Utilities.DEFAULT_TLS_SIGNATURE_SCHEME)).cert
    }

    private fun mockRegistrationResponse(nodeCa: Certificate, intermediateCa: Certificate, rootCa: Certificate): NetworkRegistrationService {
        return rigorousMock<NetworkRegistrationService>().also {
            doReturn(requestId).whenever(it).submitRequest(any())
            doReturn(arrayOf(nodeCa, intermediateCa, rootCa)).whenever(it).retrieveCertificates(eq(requestId))
        }
    }
}
