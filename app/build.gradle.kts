plugins {
    id("com.android.application")
}

android {
    namespace = "com.ritwick.sudostamp"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.ritwick.sudostamp"
        // API 30 is the true floor of the hard gate: KeyProperties.AUTH_BIOMETRIC_STRONG
        // and KeyGenParameterSpec.Builder.setUserAuthenticationParameters(0, ...) both
        // arrived in Android 11. Below 30 the "fresh biometric for EVERY use, and never
        // a device-credential fallback" guarantee is inexpressible, so a lower floor
        // would be a lie -- and the unguarded call would crash at key-creation time.
        minSdk = 30
        targetSdk = 36
        versionCode = 14
        versionName = "2.0.0"
    }

    // No signing config, on purpose: Gradle only ever builds the release UNSIGNED. The release key
    // is applied afterwards by scripts/sign-apk.sh (apksigner/jarsigner), so no build plugin or
    // dependency ever runs in a process that holds it (docs/RELEASING.md).
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    // No "dependency info" block in the APK or bundle signature. AGP encrypts it for Google with a
    // fresh random key on every build, so two signed builds of the same source differed; it lists
    // no dependencies here anyway (there are none), and F-Droid/IzzyOnDroid flag the extra block.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    // The fuzz tests (*FuzzTest) size themselves from -Dsudostamp.fuzz.iterations / .seed. Gradle's
    // -D reaches only the Gradle JVM, not the test worker, so they are handed on here; unset, the
    // tests use their small CI default.
    testOptions {
        unitTests.all { test ->
            listOf("sudostamp.fuzz.iterations", "sudostamp.fuzz.seed").forEach { key ->
                System.getProperty(key)?.let { test.systemProperty(key, it) }
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// NO runtime dependencies: this app uses only platform APIs. That is a security
// property -- every third-party artifact in the signed-approval path would be
// something else to trust -- so the block stays empty as a speed bump.
//
// The TEST dependency below does not ship. Unit tests run on the JVM and are never
// packaged into the APK, so this does not weaken the shipped-artifact property.
dependencies {
    testImplementation("junit:junit:4.13.2")
}
