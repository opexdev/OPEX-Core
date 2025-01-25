package co.nilin.opex.wallet.app.service

import co.nilin.opex.wallet.core.model.BriefWallet
import co.nilin.opex.wallet.core.model.WalletOwner
import co.nilin.opex.wallet.core.spi.WalletManager
import co.nilin.opex.wallet.core.spi.WalletOwnerManager
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.api.client.http.FileContent
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.gson.GsonFactory
import com.google.api.services.drive.Drive
import com.google.api.services.drive.DriveScopes
import com.google.auth.http.HttpCredentialsAdapter
import com.google.auth.oauth2.GoogleCredentials
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Profile
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import java.io.File
import java.nio.file.Files
import java.time.LocalDateTime
import java.util.concurrent.Executors
import com.google.api.services.drive.model.File as GoogleFile

@Service
@Profile("!test")
class BackupService(
    private val walletManager: WalletManager,
    private val walletOwnerManager: WalletOwnerManager,
    @Value("\${app.backup.enabled}")
    private val isBackupEnabled: Boolean,
    @Value("\${app.backup.drive.folder}")
    private val folderId: String
) {

    private val logger = LoggerFactory.getLogger(BackupService::class.java)
    private val dispatcher = Executors.newFixedThreadPool(4).asCoroutineDispatcher()
    private val mapper = ObjectMapper()

    data class OwnerAndWallets(val owner: WalletOwner, val wallets: List<BriefWallet>)

    @Scheduled(initialDelay = 60000, fixedDelay = 1000 * 60 * 10)
    private fun backup() {
        if (!isBackupEnabled) return
        runBlocking(dispatcher) {
            try {
                val data = arrayListOf<OwnerAndWallets>()
                walletOwnerManager.findAllWalletOwners().forEach {
                    data.add(OwnerAndWallets(it, walletManager.findAllWalletsBriefNotZero(it.id!!)))
                }

                val file = writeWalletsToFile(data)
                upload(file, file.name, folderId)
            } catch (e: Exception) {
                logger.error("Could not upload file to google drive", e)
            }
        }
    }

    private fun writeWalletsToFile(wallets: List<OwnerAndWallets>): File {
        val fileName = LocalDateTime.now().toString()
        val tempFile = Files.createTempFile(fileName, ".json").toFile()
        mapper.writeValue(tempFile, wallets)
        return tempFile
    }

    private fun upload(file: File, fileName: String, folderId: String) {
        try {
            val authFile = File("/drive-key.json")
            val credentials = GoogleCredentials.fromStream(authFile.inputStream()).createScoped(DriveScopes.DRIVE)
            val requestInitializer = HttpCredentialsAdapter(credentials)

            val service = Drive.Builder(NetHttpTransport(), GsonFactory.getDefaultInstance(), requestInitializer)
                .setApplicationName("Wallet backup")
                .build()

            val metadata = GoogleFile().apply {
                name = fileName
                parents = listOf(folderId)
            }
            val content = FileContent("text/*", file)

            val uploaded = service.files().create(metadata, content)
                .setFields("id,name")
                .execute()
            println("File uploaded: ${uploaded.id}--${uploaded.name}")
        } catch (e: Exception) {
            logger.error("Wallet backup is enabled but could not upload to Google Drive")
        }
    }

}