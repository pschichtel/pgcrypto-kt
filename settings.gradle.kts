
rootProject.name = "pgcrypto-kt"

pluginManagement {

    val kotlinVersion: String by settings
    val dokkaVersion: String by settings
    val nexusPublishingVersion: String by settings
    val detektVersion: String by settings

    plugins {
        kotlin("jvm") version(kotlinVersion)
        id("org.jetbrains.dokka") version(dokkaVersion)
        id("io.github.gradle-nexus.publish-plugin") version(nexusPublishingVersion)
        id("io.gitlab.arturbosch.detekt") version(detektVersion)
    }
}

