package co.nilin.opex.api.ports.proxy.impl

import co.nilin.opex.api.core.inout.PairFeeResponse
import co.nilin.opex.api.core.inout.PairInfoResponse
import co.nilin.opex.api.core.spi.AccountantProxy
import co.nilin.opex.api.ports.proxy.config.ProxyDispatchers
import co.nilin.opex.common.utils.LoggerDelegate
import kotlinx.coroutines.reactive.awaitSingle
import kotlinx.coroutines.withContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToFlux
import org.springframework.web.reactive.function.client.bodyToMono

@Component
class AccountantProxyImpl(private val webClient: WebClient) : AccountantProxy {

    private val logger by LoggerDelegate()

    @Value("\${app.accountant.url}")
    private lateinit var baseUrl: String

    override suspend fun getPairConfigs(): List<PairInfoResponse> {
        logger.info("fetching pair configs")
        return withContext(ProxyDispatchers.general) {
            webClient.get()
                .uri("$baseUrl/config/all")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .onStatus({ t -> t.isError }, { it.createException() })
                .bodyToFlux<PairInfoResponse>()
                .collectList()
                .awaitSingle()
        }
    }

    override suspend fun getFeeConfigs(): List<PairFeeResponse> {
        logger.info("fetching fee configs")
        return withContext(ProxyDispatchers.general) {
            webClient.get()
                .uri("$baseUrl/config/fee")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .onStatus({ t -> t.isError }, { it.createException() })
                .bodyToFlux<PairFeeResponse>()
                .collectList()
                .awaitSingle()
        }
    }

    override suspend fun getFeeConfig(symbol: String): PairFeeResponse {
        logger.info("fetching fee configs for $symbol")
        return withContext(ProxyDispatchers.general) {
            webClient.get()
                .uri("$baseUrl/config/fee/$symbol")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .onStatus({ t -> t.isError }, { it.createException() })
                .bodyToMono<PairFeeResponse>()
                .awaitSingle()
        }
    }
}