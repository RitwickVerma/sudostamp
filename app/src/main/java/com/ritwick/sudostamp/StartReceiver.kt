package com.ritwick.sudostamp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Brings the listener back after a reboot or an app update.
 *
 * Without it, both events left the agent down until someone happened to open the app:
 * sudo quietly fell back to the password, which is safe but looks exactly like a broken
 * setup. BOOT_COMPLETED arrives only after the first unlock, so the Keystore is
 * available; MY_PACKAGE_REPLACED covers `adb install -r`, which kills the old process.
 */
class StartReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> Unit
            else -> return
        }
        if (!Keys.exists()) return   // not set up yet: nothing to serve
        try {
            context.startForegroundService(Intent(context, AgentService::class.java))
            Log.i(AgentService.TAG, "listener started on ${intent.action}")
        } catch (e: Exception) {
            // e.g. an OEM build that refuses the start. Opening the app still starts it.
            Log.w(AgentService.TAG, "could not start listener on ${intent.action}: ${e.message}")
        }
    }
}
