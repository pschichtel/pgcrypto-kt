import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    signing
    java
    `maven-publish`
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.dokka)
    alias(libs.plugins.nexusPublishing)
    alias(libs.plugins.detekt)
}

group = "tel.schich"
version = "1.2.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.bouncyCastleBcpg)
    libs.bcrypt.let {
        compileOnly(it)
        testImplementation(it)
    }
    libs.commonsCodec.let {
        compileOnly(it)
        testImplementation(it)
    }

    testImplementation(kotlin("test"))
    testImplementation(libs.testContainersJunitJupiter)
    testImplementation(libs.testContainersPostgresql)
    testImplementation(libs.postgresqlDriver)
    testImplementation(libs.slf4jSimple)
}

tasks.test {
    useJUnitPlatform()

    testLogging {
        showStackTraces = true
        exceptionFormat = TestExceptionFormat.FULL
    }
}

kotlin {
    jvmToolchain(8)

    compilerOptions {
        jvmTarget = JvmTarget.fromTarget("1.8")
    }
}

repositories {
    mavenCentral()
}

val sourcesJar by tasks.creating(Jar::class) {
    dependsOn(JavaPlugin.CLASSES_TASK_NAME)
    archiveClassifier.set("sources")
    from(sourceSets["main"].allSource)
}

val javadocJar by tasks.creating(Jar::class) {
    dependsOn(tasks.dokkaJavadoc)
    archiveClassifier.set("javadoc")
    from(tasks.dokkaJavadoc)
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifact(sourcesJar)
            artifact(javadocJar)
            pom {
                name.set("pgcrypto-kt")
                description.set("A kotlin reimplementation of the pgcrypto extension.")
                url.set("https://github.com/pschichtel/pgcrypto-kt")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("pschichtel")
                        name.set("Phillip Schichtel")
                        email.set("phillip@schich.tel")
                    }
                }
                scm {
                    url.set("https://github.com/pschichtel/pgcrypto-kt")
                    connection.set("scm:git:https://github.com/pschichtel/pgcrypto-kt")
                    developerConnection.set("scm:git:git@github.com:pschichtel/pgcrypto-kt")
                }
            }
        }
    }
}

signing {
    useGpgCmd()
    sign(publishing.publications["mavenJava"])
}

nexusPublishing {
    repositories {
        sonatype()
    }
}

detekt {
    basePath = rootDir.absolutePath
    config.setFrom("$rootDir/detekt.yml")
    parallel = true
    buildUponDefaultConfig = true
}
