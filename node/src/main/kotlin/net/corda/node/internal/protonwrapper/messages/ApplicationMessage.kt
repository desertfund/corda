package net.corda.node.internal.protonwrapper.messages

import net.corda.core.utilities.NetworkHostAndPort

interface ApplicationMessage {
    val payload: ByteArray
    val topic: String
    val destinationLegalName: String
    val destinationLink: NetworkHostAndPort
    val applicationProperties: Map<Any?, Any?>
}