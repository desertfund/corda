package net.corda.node.services.messaging

import net.corda.core.identity.CordaX500Name
import net.corda.core.node.NodeInfo
import net.corda.core.utilities.NetworkHostAndPort
import net.corda.node.services.config.NodeConfiguration
import net.corda.nodeapi.ArtemisTcpTransport
import net.corda.nodeapi.ConnectionDirection
import net.corda.nodeapi.internal.ArtemisMessagingComponent
import net.corda.nodeapi.internal.ArtemisMessagingComponent.Companion.P2P_QUEUE
import net.corda.nodeapi.internal.ArtemisMessagingComponent.Companion.PEER_USER
import org.apache.activemq.artemis.core.config.BridgeConfiguration
import org.apache.activemq.artemis.core.server.ActiveMQServer
import java.time.Duration

class CoreBridgeManager(val config: NodeConfiguration, val activeMQServer: ActiveMQServer) : BridgeManager {
    companion object {
        private fun getBridgeName(queueName: String, hostAndPort: NetworkHostAndPort): String = "$queueName -> $hostAndPort"

        private val ArtemisMessagingComponent.ArtemisPeerAddress.bridgeName: String get() = getBridgeName(queueName, hostAndPort)

    }

    private fun gatherAddresses(node: NodeInfo): Sequence<ArtemisMessagingComponent.ArtemisPeerAddress> {
        val address = node.addresses.first()
        return node.legalIdentitiesAndCerts.map { ArtemisMessagingComponent.NodeAddress(it.party.owningKey, address) }.asSequence()
    }

    /**
     * All nodes are expected to have a public facing address called [ArtemisMessagingComponent.P2P_QUEUE] for receiving
     * messages from other nodes. When we want to send a message to a node we send it to our internal address/queue for it,
     * as defined by ArtemisAddress.queueName. A bridge is then created to forward messages from this queue to the node's
     * P2P address.
     */
    override fun deployBridge(queueName: String, target: NetworkHostAndPort, legalNames: Set<CordaX500Name>) {
        val connectionDirection = ConnectionDirection.Outbound(
                connectorFactoryClassName = VerifyingNettyConnectorFactory::class.java.name,
                expectedCommonNames = legalNames
        )
        val tcpTransport = ArtemisTcpTransport.tcpTransport(connectionDirection, target, config, enableSSL = true)
        tcpTransport.params[ArtemisMessagingServer::class.java.name] = this
        // We intentionally overwrite any previous connector config in case the peer legal name changed
        activeMQServer.configuration.addConnectorConfiguration(target.toString(), tcpTransport)

        activeMQServer.deployBridge(BridgeConfiguration().apply {
            name = getBridgeName(queueName, target)
            this.queueName = queueName
            forwardingAddress = P2P_QUEUE
            staticConnectors = listOf(target.toString())
            confirmationWindowSize = 100000 // a guess
            isUseDuplicateDetection = true // Enable the bridge's automatic deduplication logic
            // We keep trying until the network map deems the node unreachable and tells us it's been removed at which
            // point we destroy the bridge
            retryInterval = config.activeMQServer.bridge.retryIntervalMs
            retryIntervalMultiplier = config.activeMQServer.bridge.retryIntervalMultiplier
            maxRetryInterval = Duration.ofMinutes(config.activeMQServer.bridge.maxRetryIntervalMin).toMillis()
            // As a peer of the target node we must connect to it using the peer user. Actual authentication is done using
            // our TLS certificate.
            user = PEER_USER
            password = PEER_USER
        })
    }

    override fun bridgeExists(bridgeName: String): Boolean = activeMQServer.clusterManager.bridges.containsKey(bridgeName)


    override fun start() {
        // Nothing to do
    }

    override fun stop() {
        // Nothing to do
    }

    override fun close() = stop()

    override fun destroyBridges(node: NodeInfo) {
        gatherAddresses(node).forEach {
            activeMQServer.destroyBridge(it.bridgeName)
        }
    }

}