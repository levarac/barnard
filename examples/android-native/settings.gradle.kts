pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "BarnardNativeExample"

include(":app")

// Flutter-free: consumes the packages/android/barnard Gradle library
// directly, the same way examples/ios-native depends on ../../packages/swift/barnard
// as a local SwiftPM package. No Flutter toolchain involved.
includeBuild("../../packages/android/barnard") {
    dependencySubstitution {
        substitute(module("org.levarac.barnard:barnard")).using(project(":"))
    }
}
