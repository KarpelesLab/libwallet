// Android half of the libwallet Flutter plugin: the vault's secure backend
// (Android Keystore + BiometricPrompt). The Rust library itself still ships
// through the Dart build hook as a code asset; this module only adds the
// Kotlin glue it calls over JNI (see rust/src/vault/platform/android.rs).
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

group = "com.karpeleslabs.libwallet"
version = "1.0"

buildscript {
    val kotlinVersion = "2.3.20"
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.13.1")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
    }
}

rootProject.allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

plugins {
    id("com.android.library")
    id("kotlin-android")
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.fromTarget(JavaVersion.VERSION_17.toString())
    }
}

// The bundled native library is named after the package version
// (liblibwallet-android-<abi>-v<version>.so, see hook/build.dart); the bridge
// needs that name to load it.
val libwalletVersion: String =
    Regex("""(?m)^version:\s*(\S+)""")
        .find(file("../pubspec.yaml").readText())
        ?.groupValues?.get(1) ?: "0.0.0"

android {
    namespace = "com.karpeleslabs.libwallet"
    compileSdk = 36

    defaultConfig {
        minSdk = 21
        buildConfigField("String", "LIBWALLET_VERSION", "\"$libwalletVersion\"")
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.core:core:1.18.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment:1.8.9")
}
