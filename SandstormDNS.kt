package com.example.dnstunnel

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.Deflater
import kotlin.math.min
import kotlin.random.Random

data class Config(
    val listenIp: String = "127.0.0.1",
    val listenPort: Int = 10800,
    val domain: String = "tunnel.mydomain.com",
    val resolvers: List<String> = listOf("1.1.1.1", "8.8.8.8", "77.88.8.8"),
    val resolverPort: Int = 53,
    val password: String = "SuperSecretDnsPass2026",
    val queryType: String = "AUTO", // TXT, A, AUTO
    val verbose: Boolean = true
)

class Fragment(
    val sessionId: Int, // uint16
    val packetId: Long, // uint32
    val fragIndex: Byte, // uint8
    val totalFrags: Byte, // uint8
    val isCompressed: Byte, // uint8 (0 or 1)
    val payload: ByteArray
)

class MainActivity : Activity() {
    private lateinit var logTextView: TextView
    private var tunnelClient: DnsTunnelClient? = null
    private var isRunning = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Создаем программный интерфейс (чтобы уместить все в один файл)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
            setBackgroundColor(Color.parseColor("#121212"))
        }

        val title = TextView(this).apply {
            text = "DNS Tunnel Client V2"
            textSize = 24f
            setTextColor(Color.WHITE)
            setPadding(0, 0, 0, 32)
        }
        layout.addView(title)

        val btnToggle = Button(this).apply {
            text = "CONNECT TO SERVER"
            setBackgroundColor(Color.parseColor("#6200EE"))
            setTextColor(Color.WHITE)
        }
        layout.addView(btnToggle)

        logTextView = TextView(this).apply {
            setTextColor(Color.parseColor("#00FF00"))
            textSize = 12f
            setPadding(16, 16, 16, 16)
        }
        
        val scroll = ScrollView(this).apply {
            addView(logTextView)
            setBackgroundColor(Color.parseColor("#1E1E1E"))
        }
        layout.addView(scroll)

        setContentView(layout)

        // Обработка кнопки
        btnToggle.setOnClickListener {
            if (isRunning) {
                tunnelClient?.stop()
                btnToggle.text = "CONNECT TO SERVER"
                btnToggle.setBackgroundColor(Color.parseColor("#6200EE"))
                log("Tunnel stopped.")
            } else {
                val config = Config()
                tunnelClient = DnsTunnelClient(config) { msg ->
                    runOnUiThread { log(msg) }
                }
                tunnelClient?.start()
                btnToggle.text = "DISCONNECT"
                btnToggle.setBackgroundColor(Color.parseColor("#B00020"))
                log("Tunnel starting on ${config.listenIp}:${config.listenPort}...")
            }
            isRunning = !isRunning
        }
    }

    private fun log(message: String) {
        val current = logTextView.text.toString()
        val newText = "[$current]\n$message"
        // Ограничиваем лог, чтобы не переполнять UI
        if (newText.length > 5000) {
            logTextView.text = newText.substring(newText.length - 5000)
        } else {
            logTextView.text = newText
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        tunnelClient?.stop()
    }
}

class DnsTunnelClient(private val config: Config, private val logCallback: (String) -> Unit) {
    private val TAG = "DnsTunnel"
    private var isRunning = false
    private var localSocket: DatagramSocket? = null
    private val sendQueue = ArrayBlockingQueue<String>(5000)
    private val workerPool = Executors.newFixedThreadPool(15)
    private val mainExecutor = Executors.newSingleThreadExecutor()
    
    private val customBase32: String
    private val sessionId: Int
    private val packetCounter = AtomicInteger(0)
    private val fragCounter = AtomicInteger(0)

    init {
        customBase32 = deriveAlphabet(config.password)
        sessionId = Random.nextInt(65535)
        log("Derived Alphabet: $customBase32")
        log("Session ID: $sessionId")
    }

    // Перемешивание алфавита Base32 (эквивалент Go реализации)
    private fun deriveAlphabet(password: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val hash = md.digest(password.toByteArray(Charsets.UTF_8))
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567".toCharArray()
        
        val n = alphabet.size
        for (i in n - 1 downTo 1) {
            // В Java байты знаковые, конвертируем в беззнаковый Int
            val hashByte = hash[i % 32].toInt() and 0xFF
            val j = hashByte % (i + 1)
            val temp = alphabet[i]
            alphabet[i] = alphabet[j]
            alphabet[j] = temp
        }
        return String(alphabet)
    }

    // XOR потоковое шифрование пакетов
    private fun xorCryptStream(data: ByteArray, password: String, sessId: Int, pktId: Long): ByteArray {
        val iv = ByteBuffer.allocate(6).apply {
            putShort(sessId.toShort())
            putInt(pktId.toInt())
        }.array()

        val md = MessageDigest.getInstance("SHA-256")
        md.update(password.toByteArray(Charsets.UTF_8))
        md.update(iv)
        val keyStream = md.digest()

        val res = ByteArray(data.size)
        for (i in data.indices) {
            res[i] = (data[i].toInt() xor keyStream[i % 32].toInt()).toByte()
        }
        return res
    }

    // Умное сжатие без zlib заголовков (raw deflate)
    private fun smartCompress(data: ByteArray): Pair<ByteArray, Boolean> {
        if (data.size <= 48) return Pair(data, false)

        val deflater = Deflater(Deflater.HUFFMAN_ONLY, true)
        deflater.setInput(data)
        deflater.finish()

        val outputStream = ByteArrayOutputStream(data.size)
        val buffer = ByteArray(1024)
        while (!deflater.finished()) {
            val count = deflater.deflate(buffer)
            outputStream.write(buffer, 0, count)
        }
        deflater.end()

        val compressed = outputStream.toByteArray()
        return if (compressed.size >= data.size) {
            Pair(data, false)
        } else {
            Pair(compressed, true)
        }
    }

    // Пользовательское кодирование Base32 (без padding)
    private fun customBase32Encode(data: ByteArray, alphabet: String): String {
        var buffer = 0
        var bitsLeft = 0
        val result = StringBuilder()

        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                bitsLeft -= 5
                val index = (buffer shr bitsLeft) and 0x1F
                result.append(alphabet[index])
            }
        }
        if (bitsLeft > 0) {
            val index = (buffer shl (5 - bitsLeft)) and 0x1F
            result.append(alphabet[index])
        }
        return result.toString()
    }

    private fun serializeFragment(f: Fragment): ByteArray {
        val buf = ByteBuffer.allocate(11 + f.payload.size)
        buf.putShort(f.sessionId.toShort())
        buf.putInt(f.packetId.toInt())
        buf.put(f.fragIndex)
        buf.put(f.totalFrags)
        buf.put(f.isCompressed)
        buf.putShort(f.payload.size.toShort())
        buf.put(f.payload)
        return buf.array()
    }

    fun start() {
        if (isRunning) return
        isRunning = true

        // Запуск воркеров отправки
        for (i in 0 until 15) {
            workerPool.submit {
                val udpSocket = DatagramSocket()
                while (isRunning) {
                    try {
                        val domain = sendQueue.take()
                        sendRawDNSRequest(udpSocket, domain)
                    } catch (e: InterruptedException) {
                        Thread.currentThread().interrupt()
                        break
                    } catch (e: Exception) {
                        Log.e(TAG, "Worker error", e)
                    }
                }
                udpSocket.close()
            }
        }

        // Главный цикл прослушивания локального порта
        mainExecutor.submit {
            try {
                localSocket = DatagramSocket(config.listenPort, InetAddress.getByName(config.listenIp))
                val buffer = ByteArray(65535)

                while (isRunning) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    localSocket?.receive(packet)

                    val payload = packet.data.copyOfRange(0, packet.length)
                    processIncomingPacket(payload)
                }
            } catch (e: Exception) {
                if (isRunning) {
                    log("Listener error: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        isRunning = false
        localSocket?.close()
        workerPool.shutdownNow()
        mainExecutor.shutdownNow()
    }

    private fun processIncomingPacket(data: ByteArray) {
        val pktId = packetCounter.incrementAndGet().toLong()

        val (compressedData, isCompressed) = smartCompress(data)
        val compFlag: Byte = if (isCompressed) 1 else 0

        val encrypted = xorCryptStream(compressedData, config.password, sessionId, pktId)

        val maxFragSize = 45
        var totalFrags = ((encrypted.size + maxFragSize - 1) / maxFragSize).toByte()
        if (totalFrags <= 0) totalFrags = 1

        for (i in 0 until totalFrags) {
            val start = i * maxFragSize
            val end = min(start + maxFragSize, encrypted.size)
            val chunk = encrypted.copyOfRange(start, end)

            val frag = Fragment(
                sessionId = sessionId,
                packetId = pktId,
                fragIndex = i.toByte(),
                totalFrags = totalFrags,
                isCompressed = compFlag,
                payload = chunk
            )

            val serialized = serializeFragment(frag)
            val encoded = customBase32Encode(serialized, customBase32)

            // Формируем доменные части
            val subdomains = mutableListOf<String>()
            subdomains.add(String.format("%x", System.nanoTime() % 1000000))
            
            var k = 0
            while (k < encoded.length) {
                val endK = min(k + 30, encoded.length)
                subdomains.add(encoded.substring(k, endK))
                k += 30
            }
            
            val fullDomain = subdomains.joinToString(".") + "." + config.domain
            sendQueue.put(fullDomain) // Блокирующий вызов, если очередь полна
        }
    }

    // Сборка и отправка сырого DNS пакета (Round-Robin по резолверам)
    private fun sendRawDNSRequest(socket: DatagramSocket, domain: String) {
        var qType: Short = 16 // TXT by default
        if (config.queryType == "AUTO") {
            qType = when (System.nanoTime() % 3) {
                0L -> 16 // TXT
                1L -> 1  // A
                else -> 15 // MX
            }
        } else if (config.queryType == "A") {
            qType = 1
        }

        val buffer = ByteBuffer.allocate(512)
        // Идентификатор транзакции и Флаги
        buffer.putShort(0xDEAD.toShort())
        buffer.putShort(0x0100.toShort()) // Standard query
        buffer.putShort(1) // QDCOUNT
        buffer.putShort(0) // ANCOUNT
        buffer.putShort(0) // NSCOUNT
        buffer.putShort(0) // ARCOUNT

        // QNAME
        val parts = domain.split(".")
        for (part in parts) {
            if (part.isNotEmpty()) {
                buffer.put(part.length.toByte())
                buffer.put(part.toByteArray(Charsets.US_ASCII))
            }
        }
        buffer.put(0.toByte()) // Конец имени

        // QTYPE и QCLASS (IN)
        buffer.putShort(qType)
        buffer.putShort(1)

        val packetData = buffer.array().copyOfRange(0, buffer.position())

        // Round-robin балансировка
        val rId = (fragCounter.incrementAndGet() and 0x7FFFFFFF) % config.resolvers.size
        val resolverAddr = InetAddress.getByName(config.resolvers[rId])
        
        val dp = DatagramPacket(packetData, packetData.size, resolverAddr, config.resolverPort)
        socket.send(dp)

        if (config.verbose) {
            logCallback("-> Sent ${if(qType.toInt() == 16) "TXT" else "A"} to ${config.resolvers[rId]} [${domain.take(25)}...]")
        }
    }
}