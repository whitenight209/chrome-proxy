import com.google.protobuf.gradle.id

plugins {
	java
	id("org.springframework.boot") version "3.5.6"
	id("io.spring.dependency-management") version "1.1.7"
	id("org.hibernate.orm") version "6.6.29.Final"
	id("org.graalvm.buildtools.native") version "0.10.6"
	id("com.google.protobuf") version "0.9.5"

}

group = "dev.chpark"
version = "0.0.1-SNAPSHOT"
description = "backend-api"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

configurations {
	compileOnly {
		extendsFrom(configurations.annotationProcessor.get())
	}
}

repositories {
	mavenCentral()
}


protobuf {
	protoc {
		artifact = "com.google.protobuf:protoc:3.25.3"
	}
	plugins {
		id("grpc") {
			artifact = "io.grpc:protoc-gen-grpc-java:1.63.0"
		}
	}
	generateProtoTasks {
		all().forEach {
			it.plugins {
				id("grpc")
			}
		}
	}
}

// 👇 This is the key part — tell Gradle where your .proto files live
sourceSets {
	main {
		proto {
			// direct reference to your flat domain directories
			srcDir("../grpc-spec")
		}
	}
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-web")
	compileOnly("org.projectlombok:lombok")
	annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
	annotationProcessor("org.projectlombok:lombok")
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
	implementation("org.postgresql:postgresql:42.7.8")
	implementation("io.grpc:grpc-services")
	implementation("net.devh:grpc-spring-boot-starter:3.1.0.RELEASE")
	implementation("io.grpc:grpc-stub")
	implementation("io.grpc:grpc-protobuf")
	implementation("javax.annotation:javax.annotation-api:1.3.2")

}

hibernate {
	enhancement {
		enableAssociationManagement = true
	}
}

tasks.withType<Test> {
	useJUnitPlatform()
}
