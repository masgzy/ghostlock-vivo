@file:Suppress("UnstableApiUsage")

pluginManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        /* Robolectric's android-all SDK jars are ~200 MB apiece and live
         * only on Maven Central, whose CDN rate-limits shared datacenter IP
         * ranges (GitHub-hosted runners included) with HTTP 429. Serve the
         * org.robolectric group from the Aliyun mirror of Central first;
         * anything the mirror lacks (404) falls through to mavenCentral()
         * below, and every other group skips this repository entirely. */
        maven("https://maven.aliyun.com/repository/public") {
            name = "AliyunCentral"
            mavenContent {
                includeGroup("org.robolectric")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "GhostLock"
include(":app")
include(":profile-core")
