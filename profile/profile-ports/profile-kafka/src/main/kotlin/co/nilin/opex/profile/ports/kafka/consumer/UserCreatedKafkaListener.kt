package co.nilin.opex.profile.ports.kafka.consumer


import co.nilin.opex.profile.core.spi.UserCreatedEventListener
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import org.springframework.kafka.listener.MessageListener
import org.springframework.stereotype.Component
import co.nilin.opex.profile.core.data.event.UserCreatedEvent
@Component
class UserCreatedKafkaListener : MessageListener<String, UserCreatedEvent> {
    val eventListeners = arrayListOf<UserCreatedEventListener>()
    private val logger = LoggerFactory.getLogger(UserCreatedKafkaListener::class.java)
    override fun onMessage(data: ConsumerRecord<String, UserCreatedEvent>) {

        eventListeners.forEach { tl ->
            logger.info("incoming new event "+tl.id())
            tl.onEvent(data.value(), data.partition(), data.offset(), data.timestamp(),tl.id())
        }
    }

    fun addEventListener(tl: UserCreatedEventListener) {
        eventListeners.add(tl)
    }

    fun removeEventListener(tl: UserCreatedEventListener) {
        eventListeners.removeIf { item ->
            item.id() == tl.id()
        }
    }
}