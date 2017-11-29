package net.corda.node.internal.protonwrapper.netty

import io.netty.bootstrap.Bootstrap
import io.netty.channel.*
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LoggingHandler
import io.netty.util.internal.logging.InternalLoggerFactory
import io.netty.util.internal.logging.Slf4JLoggerFactory
import net.corda.core.identity.CordaX500Name
import net.corda.core.utilities.NetworkHostAndPort
import net.corda.core.utilities.loggerFor
import net.corda.node.internal.protonwrapper.messages.ReceivedMessage
import net.corda.node.internal.protonwrapper.messages.SendableMessage
import net.corda.node.internal.protonwrapper.messages.impl.SendableMessageImpl
import rx.Observable
import rx.subjects.PublishSubject
import java.security.KeyStore
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.withLock

class AMQPClient(val target: NetworkHostAndPort,
                 val allowedRemoteLegalNames: Set<CordaX500Name>,
                 keyStore: KeyStore,
                 keyStorePrivateKeyPassword: String,
                 trustStore: KeyStore,
                 val trace: Boolean = false) : AutoCloseable {
    companion object {
        init {
            InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE)
        }

        val log = loggerFor<AMQPClient>()
        const val RETRY_INTERVAL = 1000L
    }

    private val lock = ReentrantLock()
    @Volatile
    private var stopping: Boolean = false
    private var workerGroup: EventLoopGroup? = null
    @Volatile
    private var clientChannel: Channel? = null
    private val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    private val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())

    init {
        keyManagerFactory.init(keyStore, keyStorePrivateKeyPassword.toCharArray())
        trustManagerFactory.init(trustStore)
    }

    private val connectListener = object : ChannelFutureListener {
        override fun operationComplete(future: ChannelFuture) {
            if (!future.isSuccess) {
                log.info("Failed to connect to $target")

                if (!stopping) {
                    workerGroup?.schedule({
                        log.info("Retry connect to $target")
                        restart()
                    }, RETRY_INTERVAL, TimeUnit.MILLISECONDS)
                }
            } else {
                log.info("Connected to $target")
                // Connection established successfully
                clientChannel = future.channel()
                clientChannel?.closeFuture()?.addListener(closeListener)
            }
        }
    }

    private val closeListener = object : ChannelFutureListener {
        override fun operationComplete(future: ChannelFuture) {
            log.info("Disconnected from $target")
            _onConnected.onNext(false)
            future.channel()?.disconnect()
            if (!stopping) {
                workerGroup?.schedule({
                    log.info("Retry connect to $target")
                    restart()
                }, RETRY_INTERVAL, TimeUnit.MILLISECONDS)
            }
        }
    }

    private class ClientChannelInitializer(val parent: AMQPClient) : ChannelInitializer<SocketChannel>() {
        override fun initChannel(ch: SocketChannel) {
            val pipeline = ch.pipeline()
            val handler = createClientSslHelper(parent.target, parent.keyManagerFactory, parent.trustManagerFactory)
            pipeline.addLast("sslHandler", handler)
            if (parent.trace) pipeline.addLast("logger", LoggingHandler(LogLevel.INFO))
            pipeline.addLast(AMQPChannelHandler(false,
                    parent.allowedRemoteLegalNames,
                    parent.trace,
                    { parent._onConnected.onNext(true) },
                    { parent._onConnected.onNext(false) },
                    { rcv -> parent._onReceive.onNext(rcv) }))
        }

    }

    fun start() {
        lock.withLock {
            log.info("connect to: $target")
            workerGroup = NioEventLoopGroup()
            restart()
        }
    }

    private fun restart() {
        val bootstrap = Bootstrap()
        bootstrap.group(workerGroup).
                channel(NioSocketChannel::class.java).
                handler(ClientChannelInitializer(this))
        val clientFuture = bootstrap.connect(target.host, target.port)
        clientFuture.addListener(connectListener)
    }

    fun stop() {
        lock.withLock {
            log.info("disconnect from: $target")
            stopping = true
            try {
                workerGroup?.shutdownGracefully()
                workerGroup?.terminationFuture()?.sync()
                workerGroup = null
            } finally {
                stopping = false
            }
            log.info("stopped connection to $target")
        }
    }

    override fun close() = stop()

    val connected: Boolean
        get() {
            val channel = lock.withLock { clientChannel }
            return channel?.isActive ?: false
        }

    fun createMessage(payload: ByteArray,
                      topic: String,
                      destinationLegalName: String,
                      properties: Map<Any?, Any?>): SendableMessage {
        return SendableMessageImpl(payload, topic, destinationLegalName, target, properties)
    }

    fun write(msg: SendableMessage) {
        val channel = clientChannel
        if (channel == null) {
            throw IllegalStateException("Connection to $target not active")
        } else {
            channel.writeAndFlush(msg)
        }
    }

    private val _onReceive = PublishSubject.create<ReceivedMessage>().toSerialized()
    val onReceive: Observable<ReceivedMessage>
        get() = _onReceive

    private val _onConnected = PublishSubject.create<Boolean>().toSerialized()
    val onConnected: Observable<Boolean>
        get() = _onConnected
}