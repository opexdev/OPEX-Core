package co.nilin.opex.auth.gateway.model

class UserCreatedEvent : AuthEvent {
    lateinit var uuid: String
    var firstName: String? = null
    var lastName: String? = null
    var email: String? = null
    var mobile: String? = null


    constructor(uuid: String, firstName: String?, lastName: String?, email: String?, mobile : String?) : super() {
        this.uuid = uuid
        this.firstName = firstName
        this.lastName = lastName
        this.email = email
        this.mobile = mobile
    }
    constructor() : super()

    override fun toString(): String {
        return "UserCreatedEvent(uuid='$uuid', firstName='$firstName', lastName='$lastName', email='$email' , mobile='$mobile')"
    }

}