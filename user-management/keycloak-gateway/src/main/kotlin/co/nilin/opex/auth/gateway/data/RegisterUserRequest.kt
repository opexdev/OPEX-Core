package co.nilin.opex.auth.gateway.data

class RegisterUserRequest {

    var firstName: String? = null
    var lastName: String? = null
    var email: String? = null
    var mobileNumber: String? = null
    var captchaAnswer: String? = null
    var password: String? = null
    var passwordConfirmation: String? = null

    constructor()

    constructor(
        firstName: String?,
        lastName: String?,
        email: String?,
        mobileNumber: String?,
        captchaAnswer: String?,
        password: String?,
        passwordConfirmation: String?
    ) {
        this.firstName = firstName
        this.lastName = lastName
        this.email = email
        this.mobileNumber = mobileNumber
        this.captchaAnswer = captchaAnswer
        this.password = password
        this.passwordConfirmation = passwordConfirmation
    }

    fun isValid(): Boolean {
        return !firstName.isNullOrEmpty() && !lastName.isNullOrEmpty() && (!email.isNullOrEmpty() || !mobileNumber.isNullOrEmpty())
    }
}