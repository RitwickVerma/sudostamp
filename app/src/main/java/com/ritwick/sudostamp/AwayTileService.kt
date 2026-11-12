package com.ritwick.sudostamp

import android.app.KeyguardManager
import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log

/**
 * The Quick Settings tile: Listening, Away, or Off (something needs attention), and a tap
 * toggles Away. Plain platform TileService, no AndroidX.
 *
 * A tap goes Away for the last "resume automatically" choice made in the app (an hour until
 * one is made). On a secure lock screen the tap first asks to unlock: it is the owner's
 * switch, and a stranger holding the phone should not be able to flip it.
 */
class AwayTileService : TileService() {

    private fun model(): QuickTile.Model {
        val away = AwayControl.view(this).away
        return QuickTile.model(Hosts.all(this).isNotEmpty(), away, AgentService.listening)
    }

    override fun onStartListening() {
        super.onStartListening()
        AwayControl.tick(this)    // an Away whose timer ran out while nothing was watching
        update()
    }

    override fun onClick() {
        super.onClick()
        val act = {
            when (QuickTile.tap(model())) {
                QuickTile.Tap.GO_AWAY -> AwayControl.enter(this, AwayControl.choice(this))
                QuickTile.Tap.RESUME -> AwayControl.resume(this)
                QuickTile.Tap.OPEN_APP -> openApp()
            }
            update()
        }
        if (isSecure && isLocked) unlockAndRun(act) else act()
    }

    private fun openApp() {
        val i = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching {
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 5, i, PendingIntent.FLAG_IMMUTABLE))
            } else {
                // The PendingIntent overload only exists from API 34; below it this is the only call.
                @android.annotation.SuppressLint("StartActivityAndCollapseDeprecated")
                @Suppress("DEPRECATION") startActivityAndCollapse(i)
            }
        }.onFailure { Log.w(AgentService.TAG, "tile: cannot open the app: ${it.message}") }
    }

    private fun update() {
        val t = qsTile ?: return
        val m = model()
        t.label = getString(R.string.tile_label)
        t.icon = Icon.createWithResource(this, R.drawable.ic_stat_notify)
        t.state = if (m == QuickTile.Model.LISTENING) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        val sub = getString(when (m) {
            QuickTile.Model.LISTENING -> R.string.tile_listening
            QuickTile.Model.AWAY -> R.string.tile_away
            QuickTile.Model.OFF -> R.string.tile_off
        })
        t.subtitle = sub
        // Spoken with the label, since the tile's state colour is the only other cue.
        t.stateDescription = sub
        t.contentDescription = getString(R.string.tile_label)
        t.updateTile()
    }
}
