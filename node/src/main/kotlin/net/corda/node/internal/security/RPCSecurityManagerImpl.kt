package net.corda.node.internal.security

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import net.corda.core.context.AuthServiceId
import net.corda.core.utilities.loggerFor
import net.corda.node.services.config.PasswordEncryption
import net.corda.node.services.config.SecurityDataSourceConfig
import net.corda.node.services.config.SecurityDataSourceType
import net.corda.nodeapi.User
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.SimpleAuthenticationInfo
import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.authc.credential.PasswordMatcher
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.authz.Permission
import org.apache.shiro.authz.SimpleAuthorizationInfo
import org.apache.shiro.authz.permission.DomainPermission
import org.apache.shiro.authz.permission.PermissionResolver
import org.apache.shiro.mgt.DefaultSecurityManager
import org.apache.shiro.realm.AuthorizingRealm
import org.apache.shiro.realm.jdbc.JdbcRealm
import org.apache.shiro.subject.PrincipalCollection
import org.apache.shiro.subject.SimplePrincipalCollection
import org.apache.shiro.subject.Subject

/**
 * Default implementation of [RPCSecurityManager] adapting
 * [org.apache.shiro.mgt.SecurityManager]
 */
class RPCSecurityManagerImpl(override val id: AuthServiceId,
                             val sourceConfigs: List<SecurityDataSourceConfig> = emptyList(),
                             val addedUsers: List<User> = emptyList()) : RPCSecurityManager {

    private val manager: DefaultSecurityManager

    init {
        manager = buildImpl(sourceConfigs, addedUsers)
    }

    override fun close() {
        manager.destroy()
    }

    override fun authenticate(principal: String, password: Password): AuthorizingSubject {
        password.use {
            val authToken = UsernamePasswordToken(principal, it.value)
            val authSubject = Subject.Builder(manager).buildSubject()
            authSubject.login(authToken)
            return ShiroAuthorizingSubject(authSubject)
        }
    }

    override fun tryAuthenticate(principal: String, password: Password): AuthorizingSubject? {
        password.use {
            val authToken = UsernamePasswordToken(principal, it.value)
            var authSubject = Subject.Builder(manager).buildSubject()
            try {
                authSubject.login(authToken)
            } catch (e: Exception) {
                authSubject = null
            }
            return ShiroAuthorizingSubject(authSubject)
        }
    }

    override fun subjectInSession(principal: String): AuthorizingSubject {
        val subject = Subject.Builder(manager)
                .authenticated(true)
                .principals(SimplePrincipalCollection(principal, id.value))
                .buildSubject()
        return ShiroAuthorizingSubject(subject)
    }

    companion object {

        private val logger = loggerFor<RPCSecurityManagerImpl>()

        /**
         * Helper function to instantiate security manager from a list of [User]
         */
        fun buildInMemory(id: AuthServiceId, users: List<User>) = RPCSecurityManagerImpl(id = id, addedUsers = users)

        private fun buildImpl(sourceConfigs: List<SecurityDataSourceConfig>, addedUsers: List<User>): DefaultSecurityManager {

            require(sourceConfigs.filter { it.type == SecurityDataSourceType.EMBEDDED }.size <= 1) {
                "Multiple Config-embedded security realms are not allowed"
            }

            val dataSources = sourceConfigs.map {
                when (it.type) {
                    SecurityDataSourceType.JDBC -> {
                        logger.info("Constructing JDBC-backed security data source: ${it.dataSourceProperties}")
                        NodeJdbcRealm(it)
                    }
                    SecurityDataSourceType.EMBEDDED -> {
                        logger.info("Constructing realm from list of users in config ${it.users!!}")
                        InMemoryRealm(it.users, "CONFIG_USERS", it.passwordEncryption)
                    }
                }
            }.plus(InMemoryRealm(addedUsers, "RPCUSERS_LIST", PasswordEncryption.NONE)).toList()

            return if (dataSources.isEmpty()) DefaultSecurityManager() else DefaultSecurityManager(dataSources)
        }
    }
}

/**
 * Provide a representation of RPC permissions based on Apache Shiro permissions framework.
 * A permission represents a set of actions: for example, the set of all RPC invocations, or the set
 * of RPC invocations acting on a given class of Flows in input. A permission `implies` another one if
 * its set of actions contains the set of actions in the other one. In Apache Shiro, permissions are
 * represented by instances of the [Permission] interface which offers a single method: [implies], to
 * test if the 'x implies y' binary predicate is satisfied.
 */
internal class RPCPermission : DomainPermission {

    /**
     * Helper constructor directly setting actions and target field
     *
     * @param methods Set of allowed RPC methods
     * @param target  An optional "target" type on which methods act
     */
    constructor(methods: Set<String>, target: String? = null) : super(methods, target?.let { setOf(it) })


    /**
     * Default constructor instantiate an "ALL" permission
     */
    constructor() : super()
}

/**
 * A [org.apache.shiro.authz.permission.PermissionResolver] implementation for RPC permissions.
 * Provides a method to construct an [RPCPermission] instance from its string representation
 * in the form used by a Node admin.
 *
 * Currently valid permission strings have the forms:
 *
 *   - `ALL`: allowing all type of RPC calls
 *
 *   - `InvokeRpc.$RPCMethodName`: allowing to call a given RPC method without restrictions on its arguments.
 *
 *   - `StartFlow.$FlowClassName`: allowing to call a `startFlow*` RPC method targeting a Flow instance
 *     of a given class
 *
 */
internal object RPCPermissionResolver : PermissionResolver {

    private val SEPARATOR = '.'
    private val ACTION_START_FLOW = "startflow"
    private val ACTION_INVOKE_RPC = "invokerpc"
    private val ACTION_ALL = "all"

    private val FLOW_RPC_CALLS = setOf("startFlowDynamic", "startTrackedFlowDynamic")

    override fun resolvePermission(representation: String): Permission {

        val action = representation.substringBefore(SEPARATOR).toLowerCase()
        when (action) {
            ACTION_INVOKE_RPC -> {
                val rpcCall = representation.substringAfter(SEPARATOR)
                require(representation.count { it == SEPARATOR } == 1) {
                    "Malformed permission string"
                }
                return RPCPermission(setOf(rpcCall))
            }
            ACTION_START_FLOW -> {
                val targetFlow = representation.substringAfter(SEPARATOR)
                require(targetFlow.isNotEmpty()) {
                    "Missing target flow after StartFlow"
                }
                return RPCPermission(FLOW_RPC_CALLS, targetFlow)
            }
            ACTION_ALL -> {
                // Leaving empty set of targets and actions to match everything
                return RPCPermission()
            }
            else -> throw IllegalArgumentException("Unkwnow permission action specifier: $action")
        }
    }
}

internal class ShiroAuthorizingSubject(private val impl: Subject) : AuthorizingSubject {

    override val principal: String
        get() = impl.principals.primaryPrincipal as String

    override fun isPermitted(action: String, vararg arguments: String) = impl.isPermitted(RPCPermission(setOf(action), arguments.firstOrNull()))
}

private fun buildCredentialMatcher(type: PasswordEncryption) = when (type) {

    PasswordEncryption.NONE -> SimpleCredentialsMatcher()
    PasswordEncryption.SHA256 -> PasswordMatcher()
}

internal class InMemoryRealm(users: List<User>, realmId: String, passwordEncryption: PasswordEncryption = PasswordEncryption.NONE) : AuthorizingRealm() {

    override fun doGetAuthenticationInfo(token: AuthenticationToken) = authenticationInfoByUser.getValue(token.principal as String)

    override fun doGetAuthorizationInfo(principals: PrincipalCollection) = authorizationInfoByUser.getValue(principals.primaryPrincipal as String)

    private val authorizationInfoByUser: Map<String, AuthorizationInfo>
    private val authenticationInfoByUser: Map<String, AuthenticationInfo>

    init {
        permissionResolver = RPCPermissionResolver
        users.forEach {
            require(it.username.matches("\\w+".toRegex())) {
                "Username ${it.username} contains invalid characters"
            }
        }
        val resolvePermission = { s: String -> permissionResolver.resolvePermission(s) }
        authorizationInfoByUser = users.associate {
            it.username to SimpleAuthorizationInfo().apply {
                objectPermissions = it.permissions.map { resolvePermission(it) }.toSet()
                roles = emptySet<String>()
                stringPermissions = emptySet<String>()
            }
        }
        authenticationInfoByUser = users.associate {
            it.username to SimpleAuthenticationInfo().apply {
                credentials = it.password
                principals = SimplePrincipalCollection(it.username, realmId)
            }
        }
        credentialsMatcher = buildCredentialMatcher(passwordEncryption)
    }
}

internal class NodeJdbcRealm(val config: SecurityDataSourceConfig) : JdbcRealm() {

    init {
        credentialsMatcher = buildCredentialMatcher(config.passwordEncryption)
        setPermissionsLookupEnabled(true)
        dataSource = HikariDataSource(HikariConfig(config.dataSourceProperties!!))
        permissionResolver = RPCPermissionResolver
    }
}
