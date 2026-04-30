plugins {
    java
    id("com.gradleup.shadow") version "8.3.5"
}

group = "com.cryptomobile"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    // Burp Montoya API (provided at runtime by Burp, so compileOnly)
    compileOnly("net.portswigger.burp.extensions:montoya-api:2024.12")

    // BouncyCastle for edge algorithms (ECDH-ES, extra KDFs, etc.)
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")

    // Nimbus JOSE+JWT for robust JWE support (all algorithm combinations)
    implementation("com.nimbusds:nimbus-jose-jwt:9.40")

    // Lightweight JSON for ConfigStore serialization.
    implementation("com.google.code.gson:gson:2.11.0")

    // Unit tests
    testImplementation("net.portswigger.burp.extensions:montoya-api:2024.12")
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.compilerArgs.add("-Xlint:all")
}

tasks.shadowJar {
    archiveBaseName.set("CryptoChef")
    archiveClassifier.set("")
    archiveVersion.set(project.version.toString())
    mergeServiceFiles()
    // Montoya API is provided by Burp — do NOT bundle it.
    // BouncyCastle, Nimbus, Gson, JsonPath are bundled.
}

tasks.build { dependsOn(tasks.shadowJar) }
