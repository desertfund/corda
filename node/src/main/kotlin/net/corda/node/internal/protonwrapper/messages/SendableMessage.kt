package net.corda.node.internal.protonwrapper.messages

import com.google.common.util.concurrent.ListenableFuture

interface SendableMessage : ApplicationMessage {
    val onComplete: ListenableFuture<MessageStatus>
}