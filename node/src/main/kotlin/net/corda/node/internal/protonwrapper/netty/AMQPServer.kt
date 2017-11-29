package net.corda.node.internal.protonwrapper.netty

import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LoggingHandler
import io.netty.util.internal.logging.InternalLoggerFactory
import io.netty.util.internal.logging.Slf4JLoggerFactory
import net.corda.core.utilities.NetworkHostAndPort
import net.corda.core.utilities.loggerFor
import net.corda.node.internal.protonwrapper.messages.ReceivedMessage
import net.corda.node.internal.protonwrapper.messages.SendableMessage
import net.corda.node.internal.protonwrapper.messages.impl.SendableMessageImpl
import org.apache.qpid.proton.engine.Delivery
import rx.Observable
import rx.subjects.PublishSubject
import java.net.BindException
import java.net.InetSocketAddress
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.withLock


class AMQPServer(val hostName: String,
                 val port: Int,
                 keyStore: KeyStore,
                 keyStorePrivateKeyPassword: String,
                 trustStore: KeyStore,
                 val trace: Boolean = false) : AutoCloseable {

    companion object {
        init {
            InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE)
        }

        private val log = loggerFor<AMQPServer>()
    }

    private val lock = ReentrantLock()
    @Volatile
    private var stopping: Boolean = false
    private var bossGroup: EventLoopGroup? = null
    private var workerGroup: EventLoopGroup? = null
    private var serverChannel: Channel? = null
    private val clientChannels = ConcurrentHashMap<InetSocketAddress, SocketChannel>()
    private val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    private val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())

    init {
        keyManagerFactory.init(keyStore, keyStorePrivateKeyPassword.toCharArray())
        trustManagerFactory.init(trustStore)
    }

    private class ServerChannelInitializer(val parent: AMQPServer) : ChannelInitializer<SocketChannel>() {
        override fun initChannel(ch: SocketChannel) {
            val pipeline = ch.pipeline()
            val handler = createServerSslHelper(parent.keyManagerFactory, parent.trustManagerFactory)
            pipeline.addLast("sslHandler", handler)
            if (parent.trace) pipeline.addLast("logger", LoggingHandler(LogLevel.INFO))
            pipeline.addLast(AMQPChannelHandler(true,
                    null,
                    parent.trace,
                    {
                        parent.clientChannels.put(it.remoteAddress(), it)
                        parent._onConnection.onNext(ConnectionChange(it.remoteAddress(), true))
                    },
                    {
                        parent.clientChannels.remove(it.remoteAddress())
                        parent._onConnection.onNext(ConnectionChange(it.remoteAddress(), false))
                    },
                    { rcv -> parent._onReceive.onNext(rcv) }))
        }
    }

    fun start() {
        lock.withLock {
            stop()

            bossGroup = NioEventLoopGroup(1)
            workerGroup = NioEventLoopGroup()

            val server = ServerBootstrap()
            server.group(bossGroup, workerGroup).
                    channel(NioServerSocketChannel::class.java).
                    option(ChannelOption.SO_BACKLOG, 100).
                    handler(LoggingHandler(LogLevel.INFO)).
                    childHandler(ServerChannelInitializer(this))

            log.info("Try to bind $port")
            val channelFuture = server.bind(hostName, port).sync() // block/throw here as better to know we failed to claim port than carry on
            if (!channelFuture.isDone || !channelFuture.isSuccess) {
                throw BindException("Failed to bind port $port")
            }
            log.info("Listening on port $port")
            serverChannel = channelFuture.channel()
        }
    }


    fun stop() {
        lock.withLock {
            try {
                stopping = true
                serverChannel?.apply { close() }
                serverChannel = null

                workerGroup?.shutdownGracefully()
                workerGroup?.terminationFuture()?.sync()

                bossGroup?.shutdownGracefully()
                bossGroup?.terminationFuture()?.sync()

                workerGroup = null
                bossGroup = null
            } finally {
                stopping = false
            }
        }
    }

    override fun close() = stop()

    val listening: Boolean
        get() {
            val channel = lock.withLock { serverChannel }
            return channel?.isActive ?: false
        }

    fun createMessage(payload: ByteArray,
                      topic: String,
                      destinationLegalName: String,
                      destinationLink: NetworkHostAndPort,
                      properties: Map<Any?, Any?>): SendableMessage {
        val dest = InetSocketAddress(destinationLink.host, destinationLink.port)
        require(dest in clientChannels.keys) {
            "Destination not available"
        }
        return SendableMessageImpl(payload, topic, destinationLegalName, destinationLink, properties)
    }

    fun write(msg: SendableMessage) {
        val dest = InetSocketAddress(msg.destinationLink.host, msg.destinationLink.port)
        val channel = clientChannels[dest]
        if (channel == null) {
            throw IllegalStateException("Connection to ${msg.destinationLink} not active")
        } else {
            channel.writeAndFlush(msg)
        }
    }

    fun complete(delivery: Delivery, target: InetSocketAddress) {
        val channel = clientChannels[target]
        channel?.apply {
            writeAndFlush(delivery)
        }
    }

    private val _onReceive = PublishSubject.create<ReceivedMessage>().toSerialized()
    val onReceive: Observable<ReceivedMessage>
        get() = _onReceive


    data class ConnectionChange(val remoteAddress: InetSocketAddress, val connected: Boolean)

    private val _onConnection = PublishSubject.create<ConnectionChange>().toSerialized()
    val onConnection: Observable<ConnectionChange>
        get() = _onConnection

}