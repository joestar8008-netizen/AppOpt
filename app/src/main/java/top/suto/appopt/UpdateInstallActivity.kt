package top.suto.appopt

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import kotlin.concurrent.thread
import top.suto.appopt.databinding.ActivityUpdateInstallBinding

class UpdateInstallActivity : AppCompatActivity() {

    private lateinit var binding: ActivityUpdateInstallBinding
    private lateinit var viewModel: UpdateInstallViewModel
    private var renderedLog = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityUpdateInstallBinding.inflate(layoutInflater)
        setContentView(binding.root)
        SystemBars.applyEdgeToEdge(this, binding.root, binding.updateInstallHeader)
        viewModel = ViewModelProvider(this)[UpdateInstallViewModel::class.java]
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (viewModel.state.value?.running != false) {
                    AppToast.show(this@UpdateInstallActivity, "正在刷入模块，请等待完成")
                } else {
                    finish()
                }
            }
        })
        binding.updateInstallBack.setOnClickListener {
            onBackPressedDispatcher.onBackPressed()
        }

        val update = readUpdateInfo()
        val zipPath = intent.getStringExtra(EXTRA_ZIP_PATH)
        if (update == null || zipPath.isNullOrBlank()) {
            AppToast.show(this, "更新信息无效")
            finish()
            return
        }

        binding.updateInstallSubtitle.text =
            "当前 ${update.localVersion} (${update.localVersionCode}) -> ${update.remoteVersion} (${update.remoteVersionCode})"

        viewModel.state.observe(this) { renderState(it) }
        viewModel.start(applicationContext, zipPath, update)
    }

    private fun renderState(state: UpdateInstallViewModel.State) {
        setStatus(state.statusTitle, state.statusDetail)
        if (renderedLog != state.log) {
            renderedLog = state.log
            binding.updateInstallLog.text = state.log.trimEnd()
            binding.updateInstallLogScroll.post {
                binding.updateInstallLogScroll.fullScroll(View.FOCUS_DOWN)
            }
        }
        if (state.running) {
            binding.updateInstallActions.visibility = View.GONE
        } else if (state.success == true) {
            showActionButton("重启系统") { rebootSystem() }
        } else {
            showActionButton("返回") { finish() }
        }
    }

    private fun setStatus(title: String, detail: String) {
        binding.updateInstallStatus.text = title
        binding.updateInstallDetail.text = detail
        binding.updateInstallDetail.visibility = if (detail.isBlank()) View.GONE else View.VISIBLE
    }

    private fun showActionButton(text: String, action: () -> Unit) {
        binding.updateInstallReboot.text = text
        binding.updateInstallReboot.isEnabled = true
        binding.updateInstallReboot.setOnClickListener { action() }
        binding.updateInstallActions.visibility = View.VISIBLE
    }

    private fun rebootSystem() {
        binding.updateInstallReboot.isEnabled = false
        setStatus("正在请求重启", "正在等待 Root 确认 reboot 命令")
        thread {
            val result = DaemonBridge.runRootCommand("reboot", timeoutSeconds = 5L)
            runOnUiThread {
                if (!isFinishing && !isDestroyed) {
                    if (result.success) {
                        setStatus("正在重启系统", "Root 已接受 reboot 命令")
                        binding.updateInstallReboot.postDelayed({
                            if (!isFinishing && !isDestroyed &&
                                !binding.updateInstallReboot.isEnabled) {
                                binding.updateInstallReboot.isEnabled = true
                                setStatus(
                                    "系统尚未重启",
                                    "reboot 命令已返回，但系统没有开始重启，可再次尝试"
                                )
                            }
                        }, 8_000L)
                    } else {
                        binding.updateInstallReboot.isEnabled = true
                        val detail = if (result.timedOut) {
                            "Root 命令等待超时，系统仍未重启时可再次尝试"
                        } else {
                            "Root 拒绝或无法执行 reboot，请检查 Root 授权"
                        }
                        setStatus("重启请求失败", detail)
                        AppToast.show(this@UpdateInstallActivity, "重启失败，设备尚未确认重启")
                    }
                }
            }
        }
    }

    private fun readUpdateInfo(): ModuleUpdater.UpdateInfo? {
        val localVersion = intent.getStringExtra(EXTRA_LOCAL_VERSION) ?: return null
        val localCode = intent.getIntExtra(EXTRA_LOCAL_CODE, -1).takeIf { it > 0 } ?: return null
        val remoteVersion = intent.getStringExtra(EXTRA_REMOTE_VERSION) ?: return null
        val remoteCode = intent.getIntExtra(EXTRA_REMOTE_CODE, -1).takeIf { it > 0 } ?: return null
        val zipUrl = intent.getStringExtra(EXTRA_ZIP_URL) ?: return null
        return ModuleUpdater.UpdateInfo(
            localVersion = localVersion,
            localVersionCode = localCode,
            remoteVersion = remoteVersion,
            remoteVersionCode = remoteCode,
            zipUrl = zipUrl,
            changelogUrl = null,
            changelogText = "",
            changelogLoadFailed = false
        )
    }

    companion object {
        private const val EXTRA_LOCAL_VERSION = "local_version"
        private const val EXTRA_LOCAL_CODE = "local_code"
        private const val EXTRA_REMOTE_VERSION = "remote_version"
        private const val EXTRA_REMOTE_CODE = "remote_code"
        private const val EXTRA_ZIP_URL = "zip_url"
        private const val EXTRA_ZIP_PATH = "zip_path"

        fun intent(context: Context, update: ModuleUpdater.UpdateInfo, zipPath: String): Intent {
            return Intent(context, UpdateInstallActivity::class.java)
                .putExtra(EXTRA_LOCAL_VERSION, update.localVersion)
                .putExtra(EXTRA_LOCAL_CODE, update.localVersionCode)
                .putExtra(EXTRA_REMOTE_VERSION, update.remoteVersion)
                .putExtra(EXTRA_REMOTE_CODE, update.remoteVersionCode)
                .putExtra(EXTRA_ZIP_URL, update.zipUrl)
                .putExtra(EXTRA_ZIP_PATH, zipPath)
        }
    }
}
