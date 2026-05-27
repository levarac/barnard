package network.greeting.barnard

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

internal class BarnardPermissionStatusTest {
    @Test
    fun firstMissingRuntimePermissionIsStillRequestableWhenRationaleIsFalse() {
        assertFalse(
            isRuntimePermissionRequestBlocked(
                sdkInt = 36,
                hasPermission = false,
                wasRequestedBefore = false,
                shouldShowRequestPermissionRationale = false
            )
        )
    }

    @Test
    fun deniedRuntimePermissionIsBlockedWhenAndroidWillNotShowRationale() {
        assertTrue(
            isRuntimePermissionRequestBlocked(
                sdkInt = 36,
                hasPermission = false,
                wasRequestedBefore = true,
                shouldShowRequestPermissionRationale = false
            )
        )
    }

    @Test
    fun deniedRuntimePermissionRemainsRequestableWhenAndroidShowsRationale() {
        assertFalse(
            isRuntimePermissionRequestBlocked(
                sdkInt = 36,
                hasPermission = false,
                wasRequestedBefore = true,
                shouldShowRequestPermissionRationale = true
            )
        )
    }

    @Test
    fun grantedRuntimePermissionIsNeverBlocked() {
        assertFalse(
            isRuntimePermissionRequestBlocked(
                sdkInt = 36,
                hasPermission = true,
                wasRequestedBefore = true,
                shouldShowRequestPermissionRationale = false
            )
        )
    }
}
