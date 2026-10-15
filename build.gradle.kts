// Matches the AGP version used by ~/Projects/Kaeru so both projects share one
// Gradle/AGP toolchain and one set of cached dependencies. Bumping this independently
// of Kaeru would mean two AGP copies in ~/.gradle and two upgrade paths.
plugins {
    id("com.android.application") version "9.0.0" apply false
}
