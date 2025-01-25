package co.nilin.opex.bcgateway.ports.postgres.impl

import co.nilin.opex.bcgateway.core.model.AddressStatus
import co.nilin.opex.bcgateway.core.model.AddressType
import co.nilin.opex.bcgateway.core.model.AssignedAddress
import co.nilin.opex.bcgateway.core.spi.AssignedAddressHandler
import co.nilin.opex.bcgateway.core.spi.ChainLoader
import co.nilin.opex.bcgateway.core.utils.LoggerDelegate
import co.nilin.opex.bcgateway.ports.postgres.dao.AddressTypeRepository
import co.nilin.opex.bcgateway.ports.postgres.dao.AssignedAddressChainRepository
import co.nilin.opex.bcgateway.ports.postgres.dao.AssignedAddressRepository
import co.nilin.opex.bcgateway.ports.postgres.model.AssignedAddressModel
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.reactive.awaitFirst
import kotlinx.coroutines.reactive.awaitFirstOrNull
import org.slf4j.Logger
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.time.LocalDateTime

@Service
class AssignedAddressHandlerImpl(
    val assignedAddressRepository: AssignedAddressRepository,
    val addressTypeRepository: AddressTypeRepository,
    val assignedAddressChainRepository: AssignedAddressChainRepository,
    val chainLoader: ChainLoader
) : AssignedAddressHandler {
    @Value("\${app.address.life-time}")
    private var addressLifeTime: Long? = null

    private val logger: Logger by LoggerDelegate()

    override suspend fun fetchAssignedAddresses(user: String, addressTypes: List<AddressType>): List<AssignedAddress> {
        addressLifeTime = 7200
        if (addressTypes.isEmpty()) return emptyList()
        val addressTypeMap = addressTypeRepository.findAll().map { aam ->
            AddressType(aam.id!!, aam.type, aam.addressRegex, aam.memoRegex)
        }.collectMap { it.id }.awaitFirst()
        return assignedAddressRepository.findByUuidAndAddressTypeAndStatus(
            user, addressTypes.map(AddressType::id), AddressStatus.Assigned
        ).map { model ->
            model.toDto(addressTypeMap).apply { id = model.id }
        }.filter { it.expTime?.let { it > LocalDateTime.now() } ?: true }.toList()
    }

    override suspend fun persist(assignedAddress: AssignedAddress) {

        logger.info("going to save new address .............")
        assignedAddressRepository.save(
            AssignedAddressModel(
                assignedAddress.id ?: null,
                assignedAddress.uuid,
                assignedAddress.address,
                assignedAddress.memo,
                assignedAddress.type.id,
                assignedAddress.id?.let { assignedAddress.expTime }
                    ?: (addressLifeTime?.let { (LocalDateTime.now().plusSeconds(addressLifeTime!!)) }
                        ?: null),
                assignedAddress.id?.let { assignedAddress.assignedDate } ?: LocalDateTime.now(),
                null,
                assignedAddress.status
            )
        ).awaitFirstOrNull()
    }


    override suspend fun revoke(assignedAddress: AssignedAddress) {

        assignedAddressRepository.save(
            AssignedAddressModel(
                assignedAddress.id,
                assignedAddress.uuid,
                assignedAddress.address,
                assignedAddress.memo,
                assignedAddress.type.id,
                assignedAddress.expTime,
                assignedAddress.assignedDate,
                assignedAddress.revokedDate,
                assignedAddress.status
            )
        ).awaitFirst()

    }

    override suspend fun findUuid(address: String, memo: String?): String? {
        return assignedAddressRepository.findByAddressAndMemoAndStatus(address, memo, AddressStatus.Assigned)
            .awaitFirstOrNull()?.uuid
    }

    override suspend fun fetchExpiredAssignedAddresses(): List<AssignedAddress>? {
        val now = LocalDateTime.now()
        val addressTypeMap = addressTypeRepository.findAll().map { aam ->
            AddressType(aam.id!!, aam.type, aam.addressRegex, aam.memoRegex)
        }.collectMap { it.id }.awaitFirst()
        //for having significant margin : (minus(5 mints)
        return assignedAddressRepository.findPotentialExpAddress(
            (now.minusSeconds(addressLifeTime!!)).minusMinutes(5),
            now,
            AddressStatus.Assigned
        )?.filter {
            it.expTime != null
        }?.map {
            it.toDto(addressTypeMap).apply { id = it.id }
        }?.toList()
    }

    private suspend fun AssignedAddressModel.toDto(addressTypeMap: MutableMap<Long, AddressType>): AssignedAddress {
        return AssignedAddress(
            this.uuid,
            this.address,
            this.memo,
            addressTypeMap.getValue(this.addressTypeId),
            assignedAddressChainRepository.findByAssignedAddress(this.id!!).map { cm ->
                chainLoader.fetchChainInfo(cm.chain)
            }.toList().toMutableList(),
            this.expTime,
            this.assignedDate,
            this.revokedDate,
            this.status,
            null
        )
    }
}