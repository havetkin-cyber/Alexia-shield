plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "sk.alexia.shield"
    compileSdk = 35

    defaultConfig {
        applicationId = "sk.alexia.shield"
        minSdk = 26
        targetSdk = 35
        versionCode = System.getenv("GITHUB_RUN_NUMBER")?.toIntOrNull() ?: 1
        versionName = "0.3.1"
    }

    // Stály podpisový kľúč: zašifrovaný súbor je v repe, heslo je GitHub Secret SIGNING_PASSWORD.
    // Bez hesla (napr. lokálne v Android Studiu) sa použije bežný debug kľúč.
    val signingPassword = System.getenv("SIGNING_PASSWORD").orEmpty()
    val keystoreFile = rootProject.file("signing/alexia-shield.p12")
    val stableSigning = if (signingPassword.isNotEmpty() && keystoreFile.exists()) {
        signingConfigs.create("stable") {
            storeFile = keystoreFile
            storeType = "PKCS12"
            storePassword = signingPassword
            keyAlias = "alexia"
            keyPassword = signingPassword
        }
    } else null

    buildTypes {
        debug {
            if (stableSigning != null) signingConfig = stableSigning
        }
        release {
            if (stableSigning != null) signingConfig = stableSigning
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
