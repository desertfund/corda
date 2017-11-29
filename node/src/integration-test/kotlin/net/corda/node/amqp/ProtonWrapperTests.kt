package net.corda.node.amqp

import com.google.common.util.concurrent.SettableFuture
import net.corda.core.internal.div
import net.corda.core.utilities.NetworkHostAndPort
import net.corda.node.internal.protonwrapper.messages.MessageStatus
import net.corda.node.internal.protonwrapper.netty.AMQPClient
import net.corda.node.internal.protonwrapper.netty.AMQPServer
import net.corda.node.services.config.configureWithDevSSLCertificate
import net.corda.nodeapi.internal.crypto.loadKeyStore
import net.corda.testing.ALICE
import net.corda.testing.BOB
import net.corda.testing.freePort
import net.corda.testing.testNodeConfiguration
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.IOException
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProtonWrapperTests {
    @Rule
    @JvmField
    val temporaryFolder = TemporaryFolder()

    private val serverPort = freePort()

    @Test
    fun `Simple AMPQ Client to Server`() {
        val amqpServer = createServer()
        amqpServer.use {
            amqpServer.start()
            val receiveSubs = amqpServer.onReceive.subscribe {
                assertEquals(BOB.name.toString(), it.sourceLegalName)
                assertEquals("p2p.inbound", it.topic)
                assertEquals("Test", String(it.payload))
                it.complete(true)
            }
            val amqpClient = createClient()
            amqpClient.use {
                amqpClient.start()
                val connectedSemaphore = SettableFuture.create<Boolean>()
                val clientConnectedSubs = it.onConnected.subscribe { if (it) connectedSemaphore.set(true) else connectedSemaphore.setException(IOException()) }
                assertTrue(connectedSemaphore.get())
                val msg = amqpClient.createMessage("Test".toByteArray(),
                        "p2p.inbound",
                        ALICE.name.toString(),
                        emptyMap())
                amqpClient.write(msg)
                assertEquals(MessageStatus.Acknowledged, msg.onComplete.get())
                clientConnectedSubs.unsubscribe()
            }
            receiveSubs.unsubscribe()
        }
    }

    private fun createClient(): AMQPClient {
        val clientConfig = testNodeConfiguration(
                baseDirectory = temporaryFolder.root.toPath() / "client",
                myLegalName = BOB.name)
        clientConfig.configureWithDevSSLCertificate()

        val clientTruststore = loadKeyStore(clientConfig.trustStoreFile, clientConfig.trustStorePassword)
        val clientKeystore = loadKeyStore(clientConfig.sslKeystore, clientConfig.keyStorePassword)
        val amqpClient = AMQPClient(NetworkHostAndPort("localhost", serverPort), setOf(ALICE.name), clientKeystore, clientConfig.keyStorePassword, clientTruststore)
        return amqpClient
    }

    private fun createServer(): AMQPServer {
        val serverConfig = testNodeConfiguration(
                baseDirectory = temporaryFolder.root.toPath() / "server",
                myLegalName = ALICE.name)
        serverConfig.configureWithDevSSLCertificate()

        val serverTruststore = loadKeyStore(serverConfig.trustStoreFile, serverConfig.trustStorePassword)
        val serverKeystore = loadKeyStore(serverConfig.sslKeystore, serverConfig.keyStorePassword)
        val amqpServer = AMQPServer("0.0.0.0", serverPort, serverKeystore, serverConfig.keyStorePassword, serverTruststore)
        return amqpServer
    }
}