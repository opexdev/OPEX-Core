package co.nilin.opex.auth.gateway.extension

import co.nilin.opex.auth.gateway.ApplicationContextHolder
import co.nilin.opex.auth.gateway.model.AuthEvent
import co.nilin.opex.auth.gateway.model.UserCreatedEvent
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventType
import org.keycloak.events.admin.AdminEvent
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.models.AbstractKeycloakTransaction
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmProvider
import org.slf4j.LoggerFactory
import org.springframework.kafka.core.KafkaTemplate

class ExtendedEventListenerProvider(private val session: KeycloakSession) : EventListenerProvider {

    private val logger = LoggerFactory.getLogger(ExtendedEventListenerProvider::class.java)
    private val model: RealmProvider = session.realms()
    private val objectMapper = jacksonObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

    data class UserData(
        val enabled: Boolean,
        val emailVerified: Boolean,
        val firstName: String?,
        val lastName: String?,
        val email: String?,
        val mobileNumber: String?
    )

    data class UserUuidDto(val type: String, val uuid: String, val email: String)


    override fun onEvent(event: Event) {
        logger.info("## NEW %s EVENT", event.type)
        logger.info("-----------------------------------------------------------")
        event.details.forEach { (key, value) -> logger.info("$key: $value") }

        // USE CASE SCENARIO, I'm sure there are better use case scenario's :p
        //
        // Let's assume for whatever reason you only want the user
        // to be able to verify his account if a transaction we make succeeds.
        // Let's say an external call to a service needs to return a 200 response code or we throw an exception.

        // When the user tries to login after a failed attempt,
        // the user remains unverified and when trying to login will receive another verify account email.
        if (EventType.VERIFY_EMAIL == event.type) {
            val realm = model.getRealm(event.realmId)
            val user = session.users().getUserById(event.userId, realm)
            if (user != null && user.email != null && user.isEmailVerified) {
                logger.info("USER HAS VERIFIED EMAIL : ${event.userId}" )

                // Example of adding an attribute when this event happens
                user.setSingleAttribute("attribute-key", "attribute-value")
                val userUuidDto = UserUuidDto(event.type.name, event.userId, user.email)
                val userVerifiedTransaction = UserVerifiedTransaction(userUuidDto)

                // enlistPrepare -> if our transaction fails than the user is NOT verified
                // enlist -> if our transaction fails than the user is still verified
                // enlistAfterCompletion -> if our transaction fails our user is still verified
                session.transactionManager.enlistPrepare(userVerifiedTransaction)
            }
        }
        logger.info("-----------------------------------------------------------")
    }

    override fun onEvent(adminEvent: AdminEvent, b: Boolean) {
        logger.info("## NEW ADMIN EVENT")
        logger.info("-----------------------------------------------------------")
        logger.info("Resource path" + ": " + adminEvent.resourcePath)
        logger.info("Resource type" + ": " + adminEvent.resourceType)
        logger.info("Operation type" + ": " + adminEvent.operationType)
        if (ResourceType.USER == adminEvent.resourceType && OperationType.CREATE == adminEvent.operationType) {
            logger.info("A new user has been created")
            val userData = objectMapper.readValue(adminEvent.representation, UserData::class.java)
            val uuid = adminEvent.resourcePath.substringAfter("/")
            val kafkaEvent = UserCreatedEvent(uuid, userData.firstName, userData.lastName, userData.email , userData.mobileNumber)
            (ApplicationContextHolder.getCurrentContext()!!
                .getBean("authKafkaTemplate") as KafkaTemplate<String, AuthEvent>)
                .send("auth_user_created", kafkaEvent)
            logger.info("{} produced in kafka topic", kafkaEvent)
        }
        logger.info("-----------------------------------------------------------")
    }

    override fun close() {
        // Nothing to close
    }

    class UserVerifiedTransaction(private val userUuidDto: UserUuidDto) : AbstractKeycloakTransaction() {
        override fun commitImpl() {
            logger.info("## USER VERIFIED TRANSACTION")
            logger.info("-----------------------------------------------------------")
            logger.info(userUuidDto.toString())
            logger.info("-----------------------------------------------------------")

            // You could make a http call here and send the object.
            // When we throw an exception here, the user would not be verified when using .enlistPrepare
            //throw new RuntimeException("External call failed!");
            try {

            } catch (e: Exception) {
                throw RuntimeException("##### USER VERIFIED TRANSACTION FAILED !", e)
            }
        }

        override fun rollbackImpl() {
            //
        }

    }
}