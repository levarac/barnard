package org.levarac.barnard

import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.embedding.engine.plugins.FlutterPlugin

class BarnardPlugin : FlutterPlugin, ActivityAware {
    private var controller: BarnardController? = null
    private var identityController: BarnardIdentityController? = null
    private var activityBinding: ActivityPluginBinding? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        controller = BarnardController(binding.applicationContext, binding.binaryMessenger)
        identityController = BarnardIdentityController(binding.applicationContext, binding.binaryMessenger)
        activityBinding?.let { attachControllerToActivity(it) }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        activityBinding?.let { detachControllerFromActivity(it) }
        controller?.dispose()
        controller = null
        identityController?.dispose()
        identityController = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
        attachControllerToActivity(binding)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activityBinding?.let { detachControllerFromActivity(it) }
        activityBinding = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activityBinding = binding
        attachControllerToActivity(binding)
    }

    override fun onDetachedFromActivity() {
        activityBinding?.let { detachControllerFromActivity(it) }
        activityBinding = null
    }

    private fun attachControllerToActivity(binding: ActivityPluginBinding) {
        val ctrl = controller ?: return
        ctrl.setActivity(binding.activity)
        binding.addRequestPermissionsResultListener(ctrl)
    }

    private fun detachControllerFromActivity(binding: ActivityPluginBinding) {
        val ctrl = controller ?: return
        binding.removeRequestPermissionsResultListener(ctrl)
        ctrl.setActivity(null)
    }
}
