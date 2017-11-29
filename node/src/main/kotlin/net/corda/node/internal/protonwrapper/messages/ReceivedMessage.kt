package net.corda.node.internal.protonwrapper.messages

import net.corda.core.utilities.NetworkHostAndPort

interface ReceivedMessage : ApplicationMessage {
    val sourceLegalName: String
    val sourceLink: NetworkHostAndPort

    fun complete(accepted: Boolean)
}