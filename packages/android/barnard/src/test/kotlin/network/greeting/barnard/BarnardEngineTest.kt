// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

import android.app.Activity
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

/**
 * [BarnardEngine] persists TEK/eventCode state to `SharedPreferences` under
 * the `barnard` prefs file (same behavior as the Flutter plugin's
 * `BarnardController`, and the same shape as the Swift port's
 * `BarnardRpidGenerator` tests). Each test uses a fresh Robolectric
 * application context so runs are independent of execution order.
 */
@RunWith(RobolectricTestRunner::class)
class BarnardEngineTest {
    private fun newContext(): Context = ApplicationProvider.getApplicationContext()

    @Test
    fun startsInAnonymousMode() {
        val engine = BarnardEngine(newContext())
        assertNull(engine.getCurrentEventCode())
        assertEquals("android", engine.getPermissionStatus().platform)
    }

    @Test
    fun joinEventSwitchesToEventModeAndChangesTek() {
        val engine = BarnardEngine(newContext())
        val anonymousTek = engine.exportCurrentTek()

        engine.joinEvent("EVT1")

        assertEquals("EVT1", engine.getCurrentEventCode())
        assertNotEquals(anonymousTek, engine.exportCurrentTek())
    }

    @Test
    fun leaveEventReturnsToAnonymousModeWithOriginalTek() {
        val engine = BarnardEngine(newContext())
        val anonymousTek = engine.exportCurrentTek()

        engine.joinEvent("EVT1")
        engine.leaveEvent()

        assertNull(engine.getCurrentEventCode())
        assertEquals(anonymousTek, engine.exportCurrentTek())
    }

    @Test
    fun deviceSecretIsStableAcrossInstances() {
        val context = newContext()
        val first = BarnardEngine(context)
        val secretDerivedTek1 = first.exportCurrentTek()

        val second = BarnardEngine(context)
        val secretDerivedTek2 = second.exportCurrentTek()

        // Same context (same SharedPreferences-backed device secret) must derive
        // the same anonymous TEK across independent BarnardEngine instances.
        assertEquals(secretDerivedTek1, secretDerivedTek2)
    }

    @Test
    fun eventCodeAndTekArePersistedAcrossInstances() {
        val context = newContext()
        val first = BarnardEngine(context)
        first.joinEvent("PERSIST-EVT")
        val tek = first.exportCurrentTek()

        val second = BarnardEngine(context)
        assertEquals("PERSIST-EVT", second.getCurrentEventCode())
        assertEquals(tek, second.exportCurrentTek())
    }

    @Test
    fun getMyDisplayIdIs8LowercaseHexChars() {
        val engine = BarnardEngine(newContext())
        val displayId = engine.getMyDisplayId()
        assertEquals(8, displayId.length)
        assertEquals(displayId, displayId.lowercase())
    }

    @Test
    fun getCurrentRpiIs32LowercaseHexChars() {
        val engine = BarnardEngine(newContext())
        val rpi = engine.getCurrentRpi()
        assertEquals(32, rpi.length)
        assertEquals(rpi, rpi.lowercase())
    }

    @Test
    fun getCapabilitiesReflectsConfiguredEninModeAndSeconds() {
        val engine = BarnardEngine(newContext())
        engine.configure(eninMode = BarnardEninMode.BEACON_SLOT, eninSeconds = 60L)

        val caps = engine.getCapabilities()
        assertEquals(BarnardEninMode.BEACON_SLOT, caps.eninMode)
        assertEquals(60L, caps.eninSeconds)
        assertEquals(listOf("ble"), caps.supportedTransports)
    }

    @Test
    fun configureClampsEninSecondsToValidRange() {
        val engine = BarnardEngine(newContext())

        engine.configure(eninSeconds = 1L)
        assertEquals(12L, engine.getCapabilities().eninSeconds)

        engine.configure(eninSeconds = 999_999L)
        assertEquals(3600L, engine.getCapabilities().eninSeconds)
    }

    @Test
    fun configureWithEventCodeJoinsEvent() {
        val engine = BarnardEngine(newContext())
        engine.configure(eventCode = "CONF-EVT")
        assertEquals("CONF-EVT", engine.getCurrentEventCode())
    }

    @Test
    fun getStateReflectsScanAndAdvertiseFlagsAndEventCode() {
        val engine = BarnardEngine(newContext())
        val state = engine.getState()
        assertFalse(state.isScanning)
        assertFalse(state.isAdvertising)
        assertNull(state.eventCode)
    }

    @Test
    fun disposeStopsDeliveringEventsAndDebugEvents() {
        val engine = BarnardEngine(newContext())
        var eventCount = 0
        engine.onEvent = { eventCount++ }

        engine.dispose()
        assertTrue(engine.onEvent == null)
    }

    // MARK: - requestPermissions error signaling (chk-android fix round, PR #71)

    @Test
    fun requestPermissionsWithNoAttachedActivityFailsWithENoActivity() {
        val engine = BarnardEngine(newContext())
        // No setActivity() call: runtime permissions are denied by default under
        // Robolectric, so requiredRuntimePermissions() is non-empty and requestable.
        var result: BarnardPermissionResult? = null

        engine.requestPermissions { result = it }

        val failed = result as? BarnardPermissionResult.Failed
            ?: throw AssertionError("expected Failed, got $result")
        assertEquals("E_NO_ACTIVITY", failed.error.code)
    }

    @Test
    fun requestPermissionsAlreadyInProgressFailsWithEPermissionRequestInProgress() {
        val engine = BarnardEngine(newContext())
        // Real Activity.shouldShowRequestPermissionRationale() defaults to
        // false and Robolectric has no shadow to override it; without forcing
        // it true here, the first call's markPermissionsRequested() side
        // effect would make isPermissionRequestBlocked() true for the second
        // call (already requested + no rationale), so requestPermissions()
        // would short-circuit to Granted before ever reaching the in-progress
        // guard this test targets — a Robolectric/test-double limitation, not
        // production behavior (on-device, the OS permission dialog is still
        // showing at this point, which is a distinct state from "denied with
        // no rationale").
        val activity = Robolectric.buildActivity(RationaleAlwaysTrueActivity::class.java).create().get()
        engine.setActivity(activity)

        var firstResult: BarnardPermissionResult? = null
        engine.requestPermissions { firstResult = it }
        // First call goes pending (activity.requestPermissions() was invoked; no
        // onRequestPermissionsResult has fired yet), so it must not have resolved.
        assertNull(firstResult)

        var secondResult: BarnardPermissionResult? = null
        engine.requestPermissions { secondResult = it }

        val failed = secondResult as? BarnardPermissionResult.Failed
            ?: throw AssertionError("expected Failed, got $secondResult")
        assertEquals("E_PERMISSION_REQUEST_IN_PROGRESS", failed.error.code)
        // The first (still in-flight) request must remain untouched by the second call.
        assertNull(firstResult)
    }

    @Test
    fun disposeMidRequestResolvesPendingCallbackInsteadOfHanging() {
        val engine = BarnardEngine(newContext())
        val activity = Robolectric.buildActivity(Activity::class.java).create().get()
        engine.setActivity(activity)

        var result: BarnardPermissionResult? = null
        engine.requestPermissions { result = it }
        assertNull(result) // pending: platform hasn't replied yet

        engine.dispose()

        // A caller suspended on this callback (e.g. suspendCancellableCoroutine)
        // must be resumed, not left hanging, once the engine is disposed.
        val failed = result as? BarnardPermissionResult.Failed
            ?: throw AssertionError("expected Failed after dispose(), got $result")
        assertEquals("E_DISPOSED", failed.error.code)
        assertNull(failed.error.status)
    }
}

/** Test-only: forces `shouldShowRequestPermissionRationale` true so a second, still-pending [BarnardEngine.requestPermissions] call is not short-circuited by [isPermissionRequestBlocked]'s already-requested check. */
private class RationaleAlwaysTrueActivity : Activity() {
    override fun shouldShowRequestPermissionRationale(permission: String): Boolean = true
}
