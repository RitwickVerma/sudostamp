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
        versionCode = 7
        versionName = "1.2.4"
    }

    // Release signing comes from the environment, never from the repo: CI passes the keystore
    // as protected, masked variables (docs/RELEASING.md). With none set, `assembleRelease`
    // still builds, but UNSIGNED -- it cannot be installed, which is the safe failure.
    val keystorePath = System.getenv("SUDOSTAMP_KEYSTORE")
    signingConfigs {
        if (keystorePath != null) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("SUDOSTAMP_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("SUDOSTAMP_KEY_ALIAS")
                keyPassword = System.getenv("SUDOSTAMP_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (keystorePath != null) signingConfig = signingConfigs.getByName("release")
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
