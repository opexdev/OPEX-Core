package co.nilin.opex.wallet.app.dto

import java.math.BigDecimal

data class WithdrawHistoryResponse(
    val withdrawId: Long? = null,
    val uuid: String,
    val amount: BigDecimal,
    val currency: String,
    val acceptedFee: BigDecimal,
    val appliedFee: BigDecimal?,
    val destAmount: BigDecimal?,
    val destSymbol: String?,
    val destAddress: String?,
    val destNetwork: String?,
    var destNote: String?,
    var destTransactionRef: String?,
    val statusReason: String?,
    val status: String,
    val createDate: Long,
    val acceptDate: Long?
)