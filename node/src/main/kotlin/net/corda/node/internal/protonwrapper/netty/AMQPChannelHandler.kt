package net.corda.node.internal.protonwrapper.netty

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import io.netty.channel.socket.SocketChannel
import io.netty.handler.ssl.SslHandler
import io.netty.handler.ssl.SslHandshakeCompletionEvent
import io.netty.util.ReferenceCountUtil
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.toX509CertHolder
import net.corda.node.internal.protonwrapper.engine.EventProcessor
import net.corda.node.internal.protonwrapper.messages.ReceivedMessage
import net.corda.node.internal.protonwrapper.messages.impl.ReceivedMessageImpl
import net.corda.node.internal.protonwrapper.messages.impl.SendableMessageImpl
import org.apache.qpid.proton.engine.ProtonJTransport
import org.apache.qpid.proton.engine.Transport
import org.apache.qpid.proton.engine.impl.ProtocolTracer
import org.apache.qpid.proton.framing.TransportFrame
import org.bouncycastle.cert.X509CertificateHolder
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress


class AMQPChannelHandler(val serverMode: Boolean,
                         val allowedRemoteLegalNames: Set<CordaX500Name>?,
                         val trace: Boolean,
                         val onOpen: (SocketChannel) -> Unit,
                         val onClose: (SocketChannel) -> Unit,
                         val onReceive: (ReceivedMessage) -> Unit) : ChannelDuplexHandler() {
    private val log = LoggerFactory.getLogger(allowedRemoteLegalNames?.firstOrNull()?.toString() ?: "AMQPChannelHandler")
    private lateinit var remoteAddress: InetSocketAddress
    private lateinit var localCert: X509CertificateHolder
    private lateinit var remoteCert: X509CertificateHolder
    private lateinit var eventProcessor: EventProcessor

    override fun channelActive(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        remoteAddress = ch.remoteAddress() as InetSocketAddress
        val localAddress = ch.localAddress() as InetSocketAddress
        log.info("New client connection ${ch.id()} from ${remoteAddress} to ${localAddress}")
    }

    private fun createAMQPEngine(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        eventProcessor = EventProcessor(ch, serverMode, localCert.subject.toString(), remoteCert.subject.toString())
        val connection = eventProcessor.connection
        val transport = connection.transport as ProtonJTransport
        if (trace) {
            transport.protocolTracer = object : ProtocolTracer {
                override fun sentFrame(transportFrame: TransportFrame) {
                    log.info("${transportFrame.body}")
                }

                override fun receivedFrame(transportFrame: TransportFrame) {
                    log.info("${transportFrame.body}")
                }
            }
        }
        ctx.fireChannelActive()
        eventProcessor.processEventsAsync()
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        log.info("Closed client connection ${ch.id()} from ${remoteAddress} to ${ch.localAddress()}")
        onClose(ch as SocketChannel)
        eventProcessor.close()
        ctx.fireChannelInactive()
    }

    override fun userEventTriggered(ctx: ChannelHandlerContext, evt: Any) {
        if (evt is SslHandshakeCompletionEvent) {
            if (evt.isSuccess) {
                val sslHandler = ctx.pipeline().get(SslHandler::class.java)
                localCert = sslHandler.engine().session.localCertificates.first().toX509CertHolder()
                remoteCert = sslHandler.engine().session.peerCertificates.first().toX509CertHolder()
                try {
                    val remoteX500Name = CordaX500Name.parse(remoteCert.subject.toString())
                    require(allowedRemoteLegalNames == null || remoteX500Name in allowedRemoteLegalNames)
                    log.info("handshake completed subject: ${remoteX500Name}")
                } catch (ex: IllegalArgumentException) {
                    log.error("Invalid certificate subject", ex)
                    ctx.close()
                    return
                }
                createAMQPEngine(ctx)
                onOpen(ctx.channel() as SocketChannel)
            } else {
                log.error("Handshake failure $evt")
                ctx.close()
            }
        }
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        try {
            log.info("Received $msg")
            if (msg is ByteBuf) {
                eventProcessor.transportProcessInput(msg)
            }
        } finally {
            ReferenceCountUtil.release(msg)
        }
        eventProcessor.processEventsAsync()
    }

    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        try {
            log.info("Sent $msg")
            when (msg) {
                is SendableMessageImpl -> {
                    val inetAddress = InetSocketAddress(msg.destinationLink.host, msg.destinationLink.port)
                    require(inetAddress == remoteAddress) {
                        "Message for incorrect endpoint"
                    }
                    require(CordaX500Name.parse(msg.destinationLegalName) == CordaX500Name.parse(remoteCert.subject.toString())) {
                        "Message for incorrect legal identity"
                    }
                    log.info("channel write ${msg.applicationProperties["_AMQ_DUPL_ID"]}")
                    eventProcessor.transportWriteMessage(msg)
                }
                is ReceivedMessage -> {
                    onReceive(msg)
                }
                is Transport -> {
                    eventProcessor.transportProcessOutput(ctx)
                }
                is ReceivedMessageImpl.MessageCompleter -> {
                    eventProcessor.complete(msg)
                }
            }
        } finally {
            ReferenceCountUtil.release(msg)
        }

        eventProcessor.processEventsAsync()
    }
}