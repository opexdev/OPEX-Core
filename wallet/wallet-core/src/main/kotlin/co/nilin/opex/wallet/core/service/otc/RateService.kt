package co.nilin.opex.wallet.core.service.otc

import co.nilin.opex.wallet.core.model.otc.*

interface RateService {

    suspend fun addRate(rate: Rate, ignoreIfExist: Boolean? = false)

    suspend fun deleteRate(rate: Rate): Rates

    suspend fun getRate(): Rates

    suspend fun getRate(sourceSymbol: String, destinationSymbol: String): Rate?

    suspend fun updateRate(rate: Rate): Rates

    suspend fun addForbiddenPair(forbiddenPair: ForbiddenPair)

    suspend fun deleteForbiddenPair(forbiddenPair: ForbiddenPair): ForbiddenPairs

    suspend fun getForbiddenPairs(): ForbiddenPairs


    suspend fun addTransitiveSymbols(symbols: Symbols)

    suspend fun deleteTransitiveSymbols(symbols: Symbols): Symbols

    suspend fun getTransitiveSymbols(): Symbols

}