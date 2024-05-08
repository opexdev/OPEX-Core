package co.nilin.opex.wallet.ports.kafka.submitter.config

import org.apache.kafka.clients.admin.NewTopic
import org.apache.kafka.common.config.TopicConfig
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.context.support.GenericApplicationContext
import org.springframework.kafka.config.TopicBuilder
import java.util.function.Supplier

@Configuration
class KafkaTopicConfig {

    private val logger = LoggerFactory.getLogger(KafkaTopicConfig::class.java)

    @Autowired
    fun createTopics(applicationContext: GenericApplicationContext) {
        logger.info("Creating kafka topic beans...")

        with(applicationContext) {
            registerBean("topic_fiAction", NewTopic::class.java, Supplier {
                TopicBuilder.name("fiAction_response")
                    .partitions(10)
                    .replicas(3)
                    .config(TopicConfig.MIN_IN_SYNC_REPLICAS_CONFIG, "2")
                    .build()
            })
        }
        logger.info("Kafka topics created")
    }

}