plugins {
    kotlin("jvm") version "2.4.0"
    application
}

repositories { mavenCentral() }

dependencies {
    implementation("io.modelcontextprotocol:kotlin-sdk-core-jvm:0.15.0")
}

kotlin { jvmToolchain(21) }

application { mainClass.set("HarnessKt") }
