package net.corda.node.services.messaging

import com.google.common.util.concurrent.MoreExecutors
import net.corda.core.identity.CordaX500Name
import net.corda.core.node.NodeInfo
import net.corda.core.utilities.NetworkHostAndPort
import net.corda.node.internal.protonwrapper.messages.MessageStatus
import net.corda.node.internal.protonwrapper.netty.AMQPClient
import net.corda.node.services.config.NodeConfiguration
import net.corda.node.services.messaging.AMQPBridgeManager.AMQPBridge.Companion.getBridgeName
import net.corda.nodeapi.internal.ArtemisMessagingComponent
import net.corda.nodeapi.internal.ArtemisMessagingComponent.Companion.NODE_USER
import net.corda.nodeapi.internal.crypto.loadKeyStore
import org.apache.activemq.artemis.api.core.SimpleString
import org.apache.activemq.artemis.api.core.client.ActiveMQClient.DEFAULT_ACK_BATCH_SIZE
import org.apache.activemq.artemis.api.core.client.ClientConsumer
import org.apache.activemq.artemis.api.core.client.ClientMessage
import org.apache.activemq.artemis.api.core.client.ClientSession
import org.slf4j.LoggerFactory
import rx.Subscription
import java.security.KeyStore
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class AMQPBridgeManager(val config: NodeConfiguration, val p2pAddress: NetworkHostAndPort) : BridgeManager {

    private val lock = ReentrantLock()
    private val bridges = mutableMapOf<String, AMQPBridge>()
    val keyStore = loadKeyStore(config.sslKeystore, config.keyStorePassword)
    val keyStorePrivateKeyPassword: String = config.keyStorePassword
    val trustStore = loadKeyStore(config.trustStoreFile, config.trustStorePassword)
    private var artemis: ArtemisMessagingClient? = null

    private class AMQPBridge(val queueName: String,
                             val target: NetworkHostAndPort,
                             val legalNames: Set<CordaX500Name>,
                             keyStore: KeyStore,
                             keyStorePrivateKeyPassword: String,
                             trustStore: KeyStore,
                             val artemis: ArtemisMessagingClient) {
        companion object {
            fun getBridgeName(queueName: String, hostAndPort: NetworkHostAndPort): String = "$queueName -> $hostAndPort"
        }

        private val log = LoggerFactory.getLogger("$bridgeName:${legalNames.first()}")

        val amqpClient = AMQPClient(target, legalNames, keyStore, keyStorePrivateKeyPassword, trustStore)
        val bridgeName: String get() = getBridgeName(queueName, target)
        private val lock = ReentrantLock() // lock to serialise session level access
        private var session: ClientSession? = null
        private var consumer: ClientConsumer? = null
        private var connectedSubscription: Subscription? = null

        fun start() {
            log.info("Create new AMQP bridge")
            connectedSubscription = amqpClient.onConnected.subscribe({ x -> onSocketConnected(x) })
            amqpClient.start()
        }

        fun stop() {
            log.info("Stopping AMQP bridge")
            lock.withLock {
                synchronized(artemis) {
                    consumer?.close()
                    consumer = null
                    session?.stop()
                    session = null
                }
            }
            amqpClient.stop()
            connectedSubscription?.unsubscribe()
            connectedSubscription = null
        }

        private fun onSocketConnected(connected: Boolean) {
            lock.withLock {
                synchronized(artemis) {
                    if (connected) {
                        log.info("Bridge Connected")
                        val sessionFactory = artemis.started!!.sessionFactory
                        val session = sessionFactory.createSession(NODE_USER, NODE_USER, false, false, false, false, DEFAULT_ACK_BATCH_SIZE)
                        this.session = session
                        val consumer = session.createConsumer(queueName)
                        this.consumer = consumer
                        consumer.setMessageHandler(this@AMQPBridge::clientArtemisMessageHandler)
                        session.start()
                    } else {
                        log.info("Bridge Disconnected")
                        consumer?.close()
                        consumer = null
                        session?.stop()
                        session = null
                    }
                }
            }
        }

        private fun clientArtemisMessageHandler(artemisMessage: ClientMessage) {
            lock.withLock {
                val data = ByteArray(artemisMessage.bodySize).apply { artemisMessage.bodyBuffer.readBytes(this) }
                val properties = HashMap<Any?, Any?>()
                for (key in artemisMessage.propertyNames) {
                    var value = artemisMessage.getObjectProperty(key)
                    if (value is SimpleString) {
                        value = value.toString()
                    }
                    properties[key.toString()] = value
                }
                log.info("Bridged Send to ${legalNames.first()} uuid: ${artemisMessage.getObjectProperty("_AMQ_DUPL_ID")}")
                val sendableMessage = amqpClient.createMessage(data, "p2p.inbound",
                        legalNames.first().toString(),
                        properties)
                sendableMessage.onComplete.addListener(Runnable {
                    log.info("Bridge ACK ${sendableMessage.onComplete.get()}")
                    lock.withLock {
                        if (sendableMessage.onComplete.get() == MessageStatus.Acknowledged) {
                            artemisMessage.acknowledge()
                            session?.commit()
                        } else {
                            session?.rollback(false)
                        }
                    }
                }, MoreExecutors.directExecutor())
                amqpClient.write(sendableMessage)
            }
        }
    }

    private fun gatherAddresses(node: NodeInfo): Sequence<ArtemisMessagingComponent.ArtemisPeerAddress> {
        val address = node.addresses.first()
        return node.legalIdentitiesAndCerts.map { ArtemisMessagingComponent.NodeAddress(it.party.owningKey, address) }.asSequence()
    }

    override fun deployBridge(queueName: String, target: NetworkHostAndPort, legalNames: Set<CordaX500Name>) {
        if (bridgeExists(getBridgeName(queueName, target))) {
            return
        }
        val newBridge = AMQPBridge(queueName, target, legalNames, keyStore, keyStorePrivateKeyPassword, trustStore, artemis!!)
        lock.withLock {
            bridges[newBridge.bridgeName] = newBridge
        }
        newBridge.start()
    }

    override fun destroyBridges(node: NodeInfo) {
        lock.withLock {
            gatherAddresses(node).forEach {
                val bridge = bridges.remove(getBridgeName(it.queueName, it.hostAndPort))
                bridge?.stop()
            }
        }
    }

    override fun bridgeExists(bridgeName: String): Boolean = lock.withLock { bridges.containsKey(bridgeName) }

    override fun start() {
        val artemis = ArtemisMessagingClient(config, p2pAddress)
        this.artemis = artemis
        artemis.start()
    }

    override fun stop() = close()

    override fun close() {
        lock.withLock {
            for (bridge in bridges.values) {
                bridge.stop()
            }
            bridges.clear()
            artemis?.stop()
        }
    }
}