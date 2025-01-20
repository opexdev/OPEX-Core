package co.nilin.opex.auth.gateway.extension

import co.nilin.opex.auth.gateway.ApplicationContextHolder
import co.nilin.opex.auth.gateway.data.*
import co.nilin.opex.auth.gateway.model.ActionTokenResult
import co.nilin.opex.auth.gateway.model.AuthEvent
import co.nilin.opex.auth.gateway.model.UserCreatedEvent
import co.nilin.opex.auth.gateway.model.WhiteListModel
import co.nilin.opex.auth.gateway.providers.CustomEmailTemplateProvider
import co.nilin.opex.auth.gateway.utils.*
import co.nilin.opex.common.OpexError
import org.apache.http.client.HttpClient
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.utils.URIBuilder
import org.apache.http.impl.client.HttpClientBuilder
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.email.EmailTemplateProvider
import org.keycloak.models.Constants
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserCredentialModel
import org.keycloak.models.UserModel
import org.keycloak.models.credential.OTPCredentialModel
import org.keycloak.models.utils.CredentialValidation
import org.keycloak.models.utils.HmacOTP
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.policy.PasswordPolicyManagerProvider
import org.keycloak.services.ErrorResponseException
import org.keycloak.services.managers.AuthenticationManager
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.urls.UrlType
import org.keycloak.utils.CredentialHelper
import org.keycloak.utils.TotpUtils
import org.slf4j.LoggerFactory
import org.springframework.kafka.core.KafkaTemplate
import java.util.concurrent.TimeUnit
import java.util.stream.Collectors
import javax.persistence.EntityManager
import javax.ws.rs.*
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.Response
import javax.ws.rs.core.UriBuilder

class UserManagementResource(private val session: KeycloakSession) : RealmResourceProvider {

    private val logger = LoggerFactory.getLogger(UserManagementResource::class.java)
    private val opexRealm = session.realms().getRealm("opex")
    private val verifyUrl by lazy {
        ApplicationContextHolder.getCurrentContext()!!.environment.resolvePlaceholders("\${verify-redirect-url}")
    }
    private val forgotUrl by lazy {
        ApplicationContextHolder.getCurrentContext()!!.environment.resolvePlaceholders("\${forgot-redirect-url}")
    }
    private val registerWhitelistIsEnable by lazy {
        ApplicationContextHolder.getCurrentContext()!!
            .environment
            .resolvePlaceholders("\${app.whitelist.register.enabled}")
            .toBoolean()
    }
    private val kafkaTemplate by lazy {
        ApplicationContextHolder.getCurrentContext()!!.getBean("authKafkaTemplate") as KafkaTemplate<String, AuthEvent>
    }

    @POST
    @Path("user")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun registerUser(request: RegisterUserRequest): Response {
        if (registerWhitelistIsEnable) {
            logger.info("register whitelist is enable, going to filter register requests ........")
            val em: EntityManager = session.getProvider(JpaConnectionProvider::class.java).entityManager
            val result: List<WhiteListModel> = em.createQuery("from whitelist", WhiteListModel::class.java).resultList
            if (!result.stream()
                    .map(WhiteListModel::identifier)
                    .collect(Collectors.toList()).contains(request.email)
            )
                throw ErrorResponseException(
                    OpexError.RegisterIsLimited.name,
                    OpexError.RegisterIsLimited.message,
                    Response.Status.BAD_REQUEST
                )

        }

        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

//        runCatching {
//            validateCaptcha("${request.captchaAnswer}-${session.context.connection.remoteAddr}")
//        }.onFailure {
//            return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.InvalidCaptcha)
//        }

        if (!request.isValid())
            return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.BadRequest)

        if (session.users().getUserByEmail(request.email, opexRealm) != null)
            return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.UserAlreadyExists)

        if (request.password != request.passwordConfirmation)
            return ErrorHandler.badRequest("Invalid password confirmation")

        val error = session.getProvider(PasswordPolicyManagerProvider::class.java)
            .validate(request.email, request.password)

        if (error != null) {
            logger.error(error.message)
            return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.InvalidPassword)
        }

        val user = session.users().addUser(opexRealm, request.email).apply {
            email = request.email
            firstName = request.firstName
            lastName = request.lastName
            isEnabled = true
            isEmailVerified = false

            addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL)
            val actions = requiredActionsStream.collect(Collectors.toList())
            val token = ActionTokenHelper.generateRequiredActionsToken(session, opexRealm, this, actions)
            val url = "${session.context.getUri(UrlType.BACKEND).baseUri}/realms/opex/user-management/user/verify"
            val link = ActionTokenHelper.attachTokenToLink(url, token)
            val expiration = TimeUnit.SECONDS.toMinutes(opexRealm.actionTokenGeneratedByAdminLifespan.toLong())
            logger.info(link)
            sendEmail(this) { it.sendVerifyEmail(link, expiration) }
        }

        session.userCredentialManager()
            .updateCredential(opexRealm, user, UserCredentialModel.password(request.password, false))

        logger.info("User create response ${user.id}")
        //TODO get mobile from keycloak
        sendUserEvent(user, request.mobileNumber)

        return Response.ok(RegisterUserResponse(user.id)).build()
    }

    @POST
    @Path("user/request-forgot")
    @Produces(MediaType.APPLICATION_JSON)
    fun forgotPassword(
        @QueryParam("email") email: String?,
        @QueryParam("captcha") captcha: String
    ): Response {
        val uri = UriBuilder.fromUri(forgotUrl)

        runCatching {
            validateCaptcha("$captcha-${session.context.connection.remoteAddr}")
        }.onFailure {
            return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.InvalidCaptcha)
        }

        val user = session.users().getUserByEmail(email, opexRealm)
        if (user != null) {
            val token = ActionTokenHelper.generateRequiredActionsToken(
                session,
                opexRealm,
                user,
                listOf(UserModel.RequiredAction.UPDATE_PASSWORD.name),
                verifyUrl
            )

            val link = uri.queryParam("key", token).build().toString()
            val expiration = TimeUnit.SECONDS.toMinutes(opexRealm.actionTokenGeneratedByAdminLifespan.toLong())
            logger.info(link)
            logger.info(expiration.toString())
            sendEmail(user) { it.sendPasswordReset(link, expiration) }
        }

        return Response.noContent().build()
    }

    @PUT
    @Path("user/forgot")
    fun forgotPassword(@QueryParam("key") key: String, body: ForgotPasswordRequest): Response {
        val actionToken = session.tokens().decode(key, ExecuteActionsActionToken::class.java)

        if (actionToken == null || !actionToken.isActive || actionToken.requiredActions.isEmpty())
            return ErrorHandler.badRequest()

        val user = session.users().getUserById(actionToken.subject, opexRealm) ?: return ErrorHandler.userNotFound()
        if (body.password != body.passwordConfirmation)
            return ErrorHandler.badRequest("Invalid password confirmation")

        val error = session.getProvider(PasswordPolicyManagerProvider::class.java)
            .validate(user.email, body.password)

        if (error != null) {
            logger.error(error.message)
            return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.InvalidPassword)
        }
        session.userCredentialManager()
            .updateCredential(opexRealm, user, UserCredentialModel.password(body.password, false))

        return Response.noContent().build()
    }

    @GET
    @Path("user/verify")
    fun verifyEmail(@QueryParam("key") key: String): Response {
        val uri = UriBuilder.fromUri(verifyUrl)
        val actionToken = session.tokens().decode(key, ExecuteActionsActionToken::class.java)

        if (actionToken == null || !actionToken.isActive || actionToken.requiredActions.isEmpty())
            return Response.seeOther(uri.queryParam("result", ActionTokenResult.FAILED).build()).build()

        val user = session.users().getUserById(actionToken.subject, opexRealm)
        if (actionToken.requiredActions.contains(UserModel.RequiredAction.VERIFY_EMAIL.name)) {
            user.removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL)
            user.isEmailVerified = true
        }

        return Response.seeOther(uri.queryParam("result", ActionTokenResult.SUCCEED).build()).build()
    }

    @POST
    @Path("user/request-verify")
    @Produces(MediaType.APPLICATION_JSON)
    fun requestVerifyEmail(@QueryParam("email") email: String?, @QueryParam("captcha") captcha: String): Response {
        runCatching {
            validateCaptcha("${captcha}-${session.context.connection.remoteAddr}")
        }.onFailure {
            return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.InvalidCaptcha)
        }

        val user = session.users().getUserByEmail(email, opexRealm)
        if (user?.isEmailVerified == true)
            return ErrorHandler.badRequest("User already verified")

        if (user != null) {
            val actions = user.requiredActionsStream.collect(Collectors.toList())
            val token = ActionTokenHelper.generateRequiredActionsToken(session, opexRealm, user, actions)
            val url = "${session.context.getUri(UrlType.BACKEND).baseUri}/realms/opex/user-management/user/verify"
            val link = ActionTokenHelper.attachTokenToLink(url, token)
            val expiration = TimeUnit.SECONDS.toMinutes(opexRealm.actionTokenGeneratedByAdminLifespan.toLong())
            logger.info(link)
            sendEmail(user) { it.sendVerifyEmail(link, expiration) }
        }

        return Response.noContent().build()
    }

    @PUT
    @Path("user/security/password")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun changePassword(body: ChangePasswordRequest): Response {
        // AccountFormService
        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

        val user = session.users().getUserById(auth.getUserId(), opexRealm) ?: return ErrorHandler.userNotFound()

        val cred = UserCredentialModel.password(body.password)
        if (!session.userCredentialManager().isValid(opexRealm, user, cred))
            return ErrorHandler.forbidden("Incorrect password")

        if (body.confirmation != body.newPassword)
            return ErrorHandler.badRequest("Invalid password confirmation")

        session.userCredentialManager()
            .updateCredential(opexRealm, user, UserCredentialModel.password(body.newPassword, false))

        return Response.noContent().build()
    }

    @GET
    @Path("user/security/otp")
    @Produces(MediaType.APPLICATION_JSON)
    fun get2FASecret(): Response {
        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

        val user = session.users().getUserById(auth.getUserId(), opexRealm) ?: return ErrorHandler.userNotFound()
        if (is2FAEnabled(user)) return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.OTPAlreadyEnabled)

        val secret = HmacOTP.generateSecret(64)
        val uri = OTPUtils.generateOTPKeyURI(opexRealm, secret, "Opex", user.email)
        val qr = TotpUtils.qrCode(secret, opexRealm, user)
        return Response.ok(Get2FAResponse(uri, secret, qr)).build()
    }

    @POST
    @Path("user/security/otp")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun setup2FA(body: Setup2FARequest): Response {
        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

        val user = session.users().getUserById(auth.getUserId(), opexRealm) ?: return ErrorHandler.userNotFound()
        if (is2FAEnabled(user)) return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.OTPAlreadyEnabled)

        val otpCredential = OTPCredentialModel.createFromPolicy(opexRealm, body.secret)
        if (!CredentialValidation.validOTP(
                body.initialCode, otpCredential, opexRealm.otpPolicy.lookAheadWindow
            )
        ) return ErrorHandler.response(Response.Status.BAD_REQUEST, OpexError.InvalidOTP)

        CredentialHelper.createOTPCredential(session, opexRealm, user, body.initialCode, otpCredential)
        return Response.noContent().build()
    }

    @DELETE
    @Path("user/security/otp")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun disable2FA(): Response {
        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

        val user = session.users().getUserById(auth.getUserId(), opexRealm) ?: return ErrorHandler.userNotFound()

        val response = Response.noContent().build()
        if (!is2FAEnabled(user)) return response

        session.userCredentialManager().getStoredCredentialsByTypeStream(opexRealm, user, OTPCredentialModel.TYPE)
            .collect(Collectors.toList()).find { it.type == OTPCredentialModel.TYPE }
            ?.let { session.userCredentialManager().removeStoredCredential(opexRealm, user, it.id) }

        return response
    }

    @GET
    @Path("user/security/check")
    @Produces(MediaType.APPLICATION_JSON)
    fun is2FAEnabled(@QueryParam("username") username: String?): Response {
        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

        val user = session.users().getUserByUsername(username, opexRealm) ?: return Response.ok(
            UserSecurityCheckResponse(false)
        ).build()

        return Response.ok(UserSecurityCheckResponse(is2FAEnabled(user))).build()
    }

    @POST
    @Path("user/logout")
    @Produces(MediaType.APPLICATION_JSON)
    fun logout(): Response {
        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

        val userSession = session.sessions().getUserSession(opexRealm, auth.token?.sessionState!!)
        AuthenticationManager.backchannelLogout(session, userSession, true)
        return Response.noContent().build()
    }

    @POST
    @Path("user/sessions/logout")
    @Produces(MediaType.APPLICATION_JSON)
    fun logoutAll(): Response {
        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

        val currentSession = auth.token?.sessionState!!
        session.sessions().getUserSessionsStream(opexRealm, auth.user)
            .collect(Collectors.toList())
            .filter { it.id != currentSession }
            .forEach { AuthenticationManager.backchannelLogout(session, it, true) }

        return Response.noContent().build()
    }

    @POST
    @Path("user/sessions/{sessionId}/logout")
    @Produces(MediaType.APPLICATION_JSON)
    fun logout(@PathParam("sessionId") sessionId: String): Response {
        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

        val userSession = session.sessions().getUserSession(opexRealm, sessionId)
            ?: return ErrorHandler.notFound("Session not found")

        if (userSession.user.id != auth.getUserId()) return ErrorHandler.forbidden()

        AuthenticationManager.backchannelLogout(session, userSession, true)
        return Response.noContent().build()
    }

    @GET
    @Path("user/sessions")
    @Produces(MediaType.APPLICATION_JSON)
    fun getActiveSessions(): Response {
        val auth = ResourceAuthenticator.bearerAuth(session)
        if (!auth.hasScopeAccess("trust")) return ErrorHandler.forbidden()

        val user = session.users().getUserById(auth.getUserId(), opexRealm) ?: return ErrorHandler.userNotFound()
        val sessions = session.sessions().getUserSessionsStream(opexRealm, user)
            .filter { tryOrElse(null) { it.notes["agent"] } != "opex-admin" }.map {
                UserSessionResponse(
                    it.id,
                    it.ipAddress,
                    it.started.toLong(),
                    it.lastSessionRefresh.toLong(),
                    it.state?.name,
                    tryOrElse(null) { it.notes["agent"] },
                    auth.token?.sessionState == it.id
                )
            }.collect(Collectors.toList())

        return Response.ok(sessions).build()
    }

    private fun sendEmail(user: UserModel, sendAction: (EmailTemplateProvider) -> Unit) {
        if (!user.isEnabled) throw OpexError.BadRequest.exception("User is disabled")
        val clientId = Constants.ACCOUNT_MANAGEMENT_CLIENT_ID
        val client = session.clients().getClientByClientId(opexRealm, clientId)
        if (client == null || !client.isEnabled) throw OpexError.BadRequest.exception("Client error")

        try {
            val provider = session.getAllProviders(EmailTemplateProvider::class.java)
                .find { it is CustomEmailTemplateProvider }!!
            //val provider = session.getProvider(CustomEmailTemplateProvider::class.java)
            sendAction(provider.setRealm(opexRealm).setUser(user))
        } catch (e: Exception) {
            logger.error("Unable to send verification email")
            e.printStackTrace()
        }
    }

    private fun sendUserEvent(user: UserModel, mobile: String?) {
        val kafkaEvent = UserCreatedEvent(user.id, user.firstName, user.lastName, user.email, mobile)
        kafkaTemplate.send("auth_user_created", kafkaEvent)
        logger.info("$kafkaEvent produced in kafka topic")
    }

    private fun is2FAEnabled(user: UserModel): Boolean {
        return session.userCredentialManager().isConfiguredFor(opexRealm, user, OTPCredentialModel.TYPE)
    }

    private fun validateCaptcha(proof: String) {
        val client: HttpClient = HttpClientBuilder.create().build()
        val post = HttpGet(URIBuilder("http://captcha:8080/verify").addParameter("proof", proof).build())
        client.execute(post).let { response ->
            logger.info(response.statusLine.statusCode.toString())
            check(response.statusLine.statusCode / 500 != 5) { "Could not connect to Opex-Captcha service." }
            require(response.statusLine.statusCode / 100 == 2) { "Invalid captcha" }
        }
    }

    @POST
    @Path("admin/whitelist")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun addWhitelist(request: WhiteListAdaptor): WhiteListAdaptor? {
        val em: EntityManager = session.getProvider(JpaConnectionProvider::class.java).entityManager
        for (d in request?.data!!) {
            val data = WhiteListModel()
            data.identifier = d
            data.id = KeycloakModelUtils.generateId()
            em.persist(data)
        }
        return getWhitelist()
    }


    @GET
    @Path("admin/whitelist")
    @Produces(MediaType.APPLICATION_JSON)
    fun getWhitelist(): WhiteListAdaptor? {
        val em: EntityManager = session.getProvider(JpaConnectionProvider::class.java).entityManager
        return em.createQuery("select w from whitelist w", WhiteListModel::class.java)
            ?.resultList?.stream()?.map(WhiteListModel::identifier)
            ?.collect(Collectors.toList())?.let { WhiteListAdaptor(it) }
    }


    @POST
    @Path("admin/delete/whitelist")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun deleteWhitelist(request: WhiteListAdaptor?): WhiteListAdaptor? {
        val em: EntityManager = session.getProvider(JpaConnectionProvider::class.java).entityManager
        val query = em.createQuery("delete  from whitelist w where w.identifier in :removedWhitelist")
        query.setParameter("removedWhitelist", request?.data)
        query.executeUpdate()
        return getWhitelist()
    }

    override fun close() {

    }

    override fun getResource(): Any {
        return this
    }
}
