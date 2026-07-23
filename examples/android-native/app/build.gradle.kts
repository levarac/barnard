// Use of this source code is governed by a BSD-style license.

plugins {
    id("com.android.application") version "8.11.1"
    id("org.jetbrains.kotlin.android") version "2.2.20"
}

android {
    namespace = "org.levarac.barnard.example"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.levarac.barnard.example.native"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

dependencies {
    // Minimal native Android example (barnard#56): start/stop scan+advertise
    // against the Flutter-free `packages/android/barnard` Gradle library and
    // print events. No Flutter runtime involved.
    implementation("org.levarac.barnard:barnard:1.0-SNAPSHOT")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")

    // Real-device roles for issue #72. These tests drive BarnardEngine
    // directly; UIAutomator/Espresso would only add a brittle UI layer.
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
