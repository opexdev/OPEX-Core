package co.nilin.opex.bcgateway.core.spi

import java.math.BigDecimal

interface WalletProxy {
    suspend fun transfer(
        uuid: String,
        symbol: String,
        amount: BigDecimal,
        hash: String,
        chain: String,
        gatewayUuid: String?
    )
}
