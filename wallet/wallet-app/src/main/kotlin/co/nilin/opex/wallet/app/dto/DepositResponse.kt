package co.nilin.opex.wallet.app.dto

import co.nilin.opex.wallet.core.model.DepositStatus
import co.nilin.opex.wallet.core.model.DepositType
import java.math.BigDecimal
import java.util.*

data class DepositResponse(
    val id: Long,
    val uuid: String,
    val currency: String,
    val amount: BigDecimal,
    val network: String?,
    val note: String?,
    val transactionRef: String?,
    val status: DepositStatus,
    val type: DepositType,
    val createDate: Date?
)