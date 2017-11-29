package net.corda.node.internal.protonwrapper.messages

enum class MessageStatus {
    Unsent,
    Sent,
    Acknowledged,
    Rejected
}