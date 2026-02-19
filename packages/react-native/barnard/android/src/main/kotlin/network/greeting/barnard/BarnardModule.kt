package network.greeting.barnard

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule

class BarnardModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
    private var controller: BarnardController? = null

    init {
        setupController(reactContext)
    }

    private fun setupController(context: ReactApplicationContext) {
        val ctrl = BarnardController(context.applicationContext)
        
        ctrl.onEvent = { eventName, payload ->
            sendEvent(context, eventName, payload)
        }
        
        ctrl.onDebugEvent = { eventName, payload ->
            sendEvent(context, eventName, payload)
        }
        
        controller = ctrl
    }

    private fun sendEvent(context: ReactApplicationContext, eventName: String, params: WritableMap) {
        context
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
            .emit(eventName, params)
    }

    override fun getName(): String {
        return "Barnard"
    }

    @ReactMethod
    fun getCapabilities(promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            promise.resolve(ctrl.getCapabilities())
        } catch (e: Exception) {
            promise.reject("E_GET_CAPABILITIES", e.message, e)
        }
    }

    @ReactMethod
    fun getState(promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            promise.resolve(ctrl.getState())
        } catch (e: Exception) {
            promise.reject("E_GET_STATE", e.message, e)
        }
    }

    @ReactMethod
    fun getEventMode(promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            promise.resolve(ctrl.getEventMode())
        } catch (e: Exception) {
            promise.reject("E_GET_EVENT_MODE", e.message, e)
        }
    }

    @ReactMethod
    fun startScan(config: ReadableMap?, promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            val allowDuplicates = if (config?.hasKey("allowDuplicates") == true) {
                config.getBoolean("allowDuplicates")
            } else {
                true
            }
            ctrl.startScan(allowDuplicates)
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_START_SCAN", e.message, e)
        }
    }

    @ReactMethod
    fun stopScan(promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            ctrl.stopScan()
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_STOP_SCAN", e.message, e)
        }
    }

    @ReactMethod
    fun startAdvertise(config: ReadableMap?, promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            val formatVersion = if (config?.hasKey("formatVersion") == true) {
                config.getInt("formatVersion")
            } else {
                1
            }
            ctrl.startAdvertise(formatVersion)
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_START_ADVERTISE", e.message, e)
        }
    }

    @ReactMethod
    fun stopAdvertise(promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            ctrl.stopAdvertise()
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_STOP_ADVERTISE", e.message, e)
        }
    }

    @ReactMethod
    fun startAuto(config: ReadableMap?, promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            
            var allowDuplicates = true
            var formatVersion = 1
            
            if (config?.hasKey("scan") == true) {
                val scan = config.getMap("scan")
                if (scan?.hasKey("allowDuplicates") == true) {
                    allowDuplicates = scan.getBoolean("allowDuplicates")
                }
            }
            
            if (config?.hasKey("advertise") == true) {
                val advertise = config.getMap("advertise")
                if (advertise?.hasKey("formatVersion") == true) {
                    formatVersion = advertise.getInt("formatVersion")
                }
            }
            
            val wasScanning = ctrl.getState().getBoolean("isScanning")
            val wasAdvertising = ctrl.getState().getBoolean("isAdvertising")
            
            ctrl.startScan(allowDuplicates)
            ctrl.startAdvertise(formatVersion)
            
            val nowScanning = ctrl.getState().getBoolean("isScanning")
            val nowAdvertising = ctrl.getState().getBoolean("isAdvertising")
            
            val result = Arguments.createMap()
            result.putBoolean("scanningStarted", !wasScanning && nowScanning)
            result.putBoolean("advertisingStarted", !wasAdvertising && nowAdvertising)
            result.putArray("issues", Arguments.createArray())
            
            promise.resolve(result)
        } catch (e: Exception) {
            promise.reject("E_START_AUTO", e.message, e)
        }
    }

    @ReactMethod
    fun stopAuto(promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            ctrl.stopScan()
            ctrl.stopAdvertise()
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_STOP_AUTO", e.message, e)
        }
    }

    @ReactMethod
    fun joinEvent(eventCode: String?, promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            if (eventCode.isNullOrBlank()) {
                promise.reject("E_INVALID_ARGUMENT", "eventCode required")
                return
            }
            ctrl.joinEvent(eventCode)
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_JOIN_EVENT", e.message, e)
        }
    }

    @ReactMethod
    fun leaveEvent(promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            ctrl.leaveEvent()
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_LEAVE_EVENT", e.message, e)
        }
    }

    @ReactMethod
    fun getExchangedTeks(eventCode: String?, promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            if (eventCode.isNullOrBlank()) {
                promise.reject("E_INVALID_ARGUMENT", "eventCode required")
                return
            }
            promise.resolve(ctrl.getExchangedTeks(eventCode))
        } catch (e: Exception) {
            promise.reject("E_GET_EXCHANGED_TEKS", e.message, e)
        }
    }

    @ReactMethod
    fun clearTeksForEvent(eventCode: String?, promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            if (eventCode.isNullOrBlank()) {
                promise.reject("E_INVALID_ARGUMENT", "eventCode required")
                return
            }
            promise.resolve(ctrl.clearTeksForEvent(eventCode))
        } catch (e: Exception) {
            promise.reject("E_CLEAR_TEKS_FOR_EVENT", e.message, e)
        }
    }

    @ReactMethod
    fun clearAllTeks(promise: Promise) {
        try {
            val ctrl = controller ?: run {
                promise.reject("E_NOT_INITIALIZED", "Controller not initialized")
                return
            }
            promise.resolve(ctrl.clearAllTeks())
        } catch (e: Exception) {
            promise.reject("E_CLEAR_ALL_TEKS", e.message, e)
        }
    }

    @ReactMethod
    fun dispose(promise: Promise) {
        try {
            controller?.dispose()
            controller = null
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_DISPOSE", e.message, e)
        }
    }

    override fun onCatalystInstanceDestroy() {
        super.onCatalystInstanceDestroy()
        controller?.dispose()
        controller = null
    }
}
