package top.suto.appopt

import java.util.concurrent.Executors

/** App 进程内唯一的校准命令队列，避免 start/stop 同时覆盖 calibrate.cmd。 */
internal object CalibrationCommandDispatcher {
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "AppOptCalibrationCommand").apply { isDaemon = true }
    }

    fun execute(command: () -> Unit) {
        executor.execute { command() }
    }
}
