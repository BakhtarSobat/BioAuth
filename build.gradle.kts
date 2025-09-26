buildscript {
    extra.apply {
        set("kotlin_version", "1.9.20")
        set("compose_version", "2023.10.01")
        set("gsonVersion", "2.10.1")
        set("publishedGroupId", "com.bioauth")
        set("artifact", "bioauth-lib")
        set("libraryVersion", "1.0.0")
    }

    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }

    dependencies {
        classpath("com.android.tools.build:gradle:8.2.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.20")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

tasks.register("clean", Delete::class) {
    delete(rootProject.buildDir)
}