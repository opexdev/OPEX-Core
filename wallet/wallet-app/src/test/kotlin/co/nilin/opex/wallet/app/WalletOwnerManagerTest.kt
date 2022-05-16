package co.nilin.opex.wallet.app

import co.nilin.opex.wallet.core.model.Amount
import co.nilin.opex.wallet.core.model.Currency
import co.nilin.opex.wallet.core.model.WalletOwner
import co.nilin.opex.wallet.ports.postgres.dao.TransactionRepository
import co.nilin.opex.wallet.ports.postgres.dao.UserLimitsRepository
import co.nilin.opex.wallet.ports.postgres.dao.WalletConfigRepository
import co.nilin.opex.wallet.ports.postgres.dao.WalletOwnerRepository
import co.nilin.opex.wallet.ports.postgres.impl.WalletOwnerManagerImpl
import co.nilin.opex.wallet.ports.postgres.model.UserLimitsModel
import co.nilin.opex.wallet.ports.postgres.model.WalletConfigModel
import co.nilin.opex.wallet.ports.postgres.model.WalletOwnerModel
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyLong
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.math.BigDecimal

private class WalletOwnerManagerTest {
    @Mock
    private var userLimitsRepository: UserLimitsRepository

    @Mock
    private var transactionRepository: TransactionRepository

    @Mock
    private var walletOwnerRepository: WalletOwnerRepository

    @Mock
    private var walletConfigRepository: WalletConfigRepository

    private var walletOwnerManagerImpl: WalletOwnerManagerImpl

    private val walletOwner = object : WalletOwner {
        override fun id() = 2L
        override fun uuid() = "fdf453d7-0633-4ec7-852d-a18148c99a82"
        override fun title() = "wallet"
        override fun level() = "1"
        override fun isTradeAllowed() = true
        override fun isWithdrawAllowed() = true
        override fun isDepositAllowed() = true
    }

    private val currency = object : Currency {
        override fun getSymbol() = "ETH"
        override fun getName() = "Ethereum"
        override fun getPrecision() = 0.0001
    }

    init {
        MockitoAnnotations.openMocks(this)
        userLimitsRepository = mock {
            on { findByOwnerAndAction(anyLong(), eq("withdraw")) } doReturn flow {
                emit(
                    UserLimitsModel(
                        1L,
                        null,
                        walletOwner.id(),
                        "withdraw",
                        "main",
                        BigDecimal.valueOf(10),
                        100,
                        BigDecimal.valueOf(300),
                        3000,
                    )
                )
            }
        }
        walletOwnerRepository = mock {
            on { save(any()) } doReturn Mono.just(
                WalletOwnerModel(
                    walletOwner.id(),
                    walletOwner.uuid(),
                    walletOwner.title(),
                    walletOwner.level(),
                    walletOwner.isTradeAllowed(),
                    walletOwner.isWithdrawAllowed(),
                    walletOwner.isDepositAllowed()
                )
            )
            on { findByUuid(walletOwner.uuid()) } doReturn Mono.just( WalletOwnerModel(
                walletOwner.id(),
                walletOwner.uuid(),
                walletOwner.title(),
                walletOwner.level(),
                walletOwner.isTradeAllowed(),
                walletOwner.isWithdrawAllowed(),
                walletOwner.isDepositAllowed()
            ))
        }
        walletConfigRepository = mock {
            on { findAll() } doReturn Flux.just(WalletConfigModel("", "ETH"))
        }
        transactionRepository = mock {
            on {
                calculateDepositStatisticsBasedOnCurrency(
                    anyLong(),
                    anyString(),
                    any(),
                    any(),
                    anyString()
                )
            } doReturn Mono.empty()
            on {
                calculateWithdrawStatisticsBasedOnCurrency(
                    anyLong(),
                    anyString(),
                    any(),
                    any(),
                    anyString()
                )
            } doReturn Mono.empty()
        }
        walletOwnerManagerImpl = WalletOwnerManagerImpl(
            userLimitsRepository, transactionRepository, walletConfigRepository, walletOwnerRepository
        )
    }

    @Test
    fun givenFullWalletWithNoLimit_whenIsWithdrawAllowed_thenReturnTrue(): Unit = runBlocking {
        val isAllowed = walletOwnerManagerImpl.isWithdrawAllowed(walletOwner, Amount(currency, BigDecimal.valueOf(0.5)))

        assertThat(isAllowed).isTrue()
    }

    @Test
    fun givenEmptyWalletWithNoLimit_whenIsWithdrawAllowed_thenReturnFalse(): Unit = runBlocking {
        val isAllowed =
            walletOwnerManagerImpl.isWithdrawAllowed(walletOwner, Amount(currency, BigDecimal.valueOf(12)))

        assertThat(isAllowed).isFalse()
    }

    @Test
    fun givenUUID_whenFindWalletOwner_thenReturnWalletOwner(): Unit = runBlocking {
        val wo = walletOwnerManagerImpl.findWalletOwner(walletOwner.uuid())

        assertThat(wo!!.id()).isEqualTo(walletOwner.id())
        assertThat(wo.uuid()).isEqualTo(walletOwner.uuid())
    }

    @Test
    fun givenOwnerInfo_whenCreateWalletOwner_thenReturnWalletOwner(): Unit = runBlocking {
        val wo = walletOwnerManagerImpl.createWalletOwner(walletOwner.uuid(), walletOwner.title(), walletOwner.level())

        assertThat(wo.id()).isEqualTo(walletOwner.id())
        assertThat(wo.uuid()).isEqualTo(walletOwner.uuid())
    }
}
