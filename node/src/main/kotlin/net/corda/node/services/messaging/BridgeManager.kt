package net.corda.node.services.messaging

import net.corda.core.identity.CordaX500Name
import net.corda.core.node.NodeInfo
import net.corda.core.utilities.NetworkHostAndPort

interface BridgeManager : AutoCloseable {
    fun deployBridge(queueName: String, target: NetworkHostAndPort, legalNames: Set<CordaX500Name>)

    fun destroyBridges(node: NodeInfo)

    fun bridgeExists(bridgeName: String): Boolean

    fun start()

    fun stop()
}