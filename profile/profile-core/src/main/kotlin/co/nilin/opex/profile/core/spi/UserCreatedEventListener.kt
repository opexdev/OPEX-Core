package co.nilin.opex.profile.core.spi

import co.nilin.opex.profile.core.data.event.UserCreatedEvent


interface UserCreatedEventListener {
    fun id(): String
    fun onEvent(event: UserCreatedEvent, partition: Int, offset: Long, timestamp: Long, eventId:String)

}