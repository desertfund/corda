package net.corda.node.internal.protonwrapper.messages.impl

import com.google.common.util.concurrent.ListenableFuture
import com.google.common.util.concurrent.SettableFuture
import io.netty.buffer.ByteBuf
import net.corda.core.utilities.NetworkHostAndPort
import net.corda.node.internal.protonwrapper.messages.MessageStatus
import net.corda.node.internal.protonwrapper.messages.SendableMessage

class SendableMessageImpl(override val payload: ByteArray,
                          override val topic: String,
                          override val destinationLegalName: String,
                          override val destinationLink: NetworkHostAndPort,
                          override val applicationProperties: Map<Any?, Any?>) : SendableMessage {
    var buf: ByteBuf? = null
    @Volatile
    var status: MessageStatus = MessageStatus.Unsent

    private val _onComplete = SettableFuture.create<MessageStatus>()
    override val onComplete: ListenableFuture<MessageStatus> get() = _onComplete

    fun release() {
        buf?.release()
        buf = null
    }

    fun doComplete(status: MessageStatus) {
        this.status = status
        _onComplete.set(status)
    }

    override fun toString(): String = "Sendable ${String(payload)} $topic $status"
}