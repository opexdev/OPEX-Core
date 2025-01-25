package co.nilin.opex.wallet.ports.postgres.dao

import co.nilin.opex.wallet.ports.postgres.model.WalletOwnerModel
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.repository.reactive.ReactiveCrudRepository
import org.springframework.stereotype.Repository
import reactor.core.publisher.Mono

@Repository
interface WalletOwnerRepository : ReactiveCrudRepository<WalletOwnerModel, Long> {

    @Query("select * from wallet_owner where uuid = :uuid")
    fun findByUuid(uuid: String): Mono<WalletOwnerModel>
}