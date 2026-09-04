// Use of this source code is governed by a BSD-style license.

plugins {
    id("com.android.library") version "8.11.1"
    id("com.vanniktech.maven.publish") version "0.34.0"
    id("org.jetbrains.kotlin.android") version "2.2.20"
}

val releaseVersion = providers.exec {
    commandLine("git", "describe", "--tags", "--match", "v[0-9]*", "--abbrev=0")
}.standardOutput.asText.map { tag ->
    tag.trim().also {
        require(Regex("v\\d+\\.\\d+\\.\\d+").matches(it)) {
            "Expected the nearest release tag to match vX.Y.Z, but found $it"
        }
    }.removePrefix("v")
}

group = "org.levarac"
version = releaseVersion.get()

android {
    namespace = "org.levarac.barnard"

    compileSdk = 36

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        buildConfig = true
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
        unitTests.all {
            it.testLogging {
                events("passed", "skipped", "failed", "standardOut", "standardError")
                showStandardStreams = true
            }
        }
    }
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk15to18:1.81")
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("junit:junit:4.13.2")
    testImplementation("androidx.test:core:1.5.0")
    testImplementation("org.robolectric:robolectric:4.11.1")
}

mavenPublishing {
    coordinates("org.levarac", "barnard", version.toString())

    publishToMavenCentral(automaticRelease = true)
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    pom {
        name.set("Barnard")
        description.set("Barnard protocol SDK for Android")
        url.set("https://github.com/levarac/barnard")

        licenses {
            license {
                name.set("MIT License")
                url.set("https://github.com/levarac/barnard/blob/main/LICENSE")
                distribution.set("repo")
            }
        }

        developers {
            developer {
                id.set("levarac")
                name.set("Levarac")
                url.set("https://github.com/levarac/barnard/issues")
            }
        }

        scm {
            url.set("https://github.com/levarac/barnard")
            connection.set("scm:git:git://github.com/levarac/barnard.git")
            developerConnection.set("scm:git:ssh://git@github.com/levarac/barnard.git")
        }
    }
}
