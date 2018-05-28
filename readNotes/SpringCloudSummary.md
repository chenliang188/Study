# Spring Cloud Summary

> https://cloud.spring.io/spring-cloud-static/Finchley.RC1/single/spring-cloud.html

> Spring Cloud provides tools for developers to quickly build some of the common patterns in distributed systems (e.g. configuration management, service discovery, circuit breakers, intelligent routing, micro-proxy, control bus). Coordination of distributed systems leads to boiler plate patterns, and using Spring Cloud developers can quickly stand up services and applications that implement those patterns. They will work well in any distributed environment, including the developer’s own laptop, bare metal data centres, and managed platforms such as Cloud Foundry.

- Spring Cloud focuses on providing good out of box experience for typical use cases and extensibility mechanism to cover others.

  - Distributed/versioned configuration
  - Service registration and discovery
  - Routing
  - Service-to-service calls
  - Load balancing
  - Circuit Breakers
  - Distributed messaging

## Cloud Native Applications

> Cloud Native is a style of application development that encourages easy adoption of best practices in the areas of continuous delivery and value-driven development. A related discipline is that of building 12-factor Applications, in which development practices are aligned with delivery and operations goals — for instance, by using declarative programming and management and monitoring. Spring Cloud facilitates these styles of development in a number of specific ways. The starting point is a set of features to which all components in a distributed system need easy access.

## Spring Cloud Config

> Spring Cloud Config provides server-side and client-side support for externalized configuration in a distributed system. With the Config Server, you have a central place to manage external properties for applications across all environments. The concepts on both client and server map identically to the Spring Environment and PropertySource abstractions, so they fit very well with Spring applications but can be used with any application running in any language. As an application moves through the deployment pipeline from dev to test and into production, you can manage the configuration between those environments and be certain that applications have everything they need to run when they migrate. The default implementation of the server storage backend uses git, so it easily supports labelled versions of configuration environments as well as being accessible to a wide range of tooling for managing the content. It is easy to add alternative implementations and plug them in with Spring configuration.

## Spring Cloud Netflix

> This project provides Netflix OSS integrations for Spring Boot apps through autoconfiguration and binding to the Spring Environment and other Spring programming model idioms. With a few simple annotations you can quickly enable and configure the common patterns inside your application and build large distributed systems with battle-tested Netflix components. The patterns provided include Service Discovery (Eureka), Circuit Breaker (Hystrix), Intelligent Routing (Zuul) and Client Side Load Balancing (Ribbon).

### Service Discovery: Eureka

> Service Discovery is one of the key tenets of a microservice-based architecture. Trying to hand-configure each client or some form of convention can be difficult to do and can be brittle. Eureka is the Netflix Service Discovery Server and Client. The server can be configured and deployed to be highly available, with each server replicating state about the registered services to the others.


### Circuit Breaker: Hystrix

> Netflix has created a library called Hystrix that implements the circuit breaker pattern. In a microservice architecture, it is common to have multiple layers of service calls.

### Client Side Load Balancer: Ribbon

> Ribbon is a client-side load balancer that gives you a lot of control over the behavior of HTTP and TCP clients. Feign already uses Ribbon

### External Configuration: Archaius

### Router and Filter: Zuul

### Polyglot support with Sidecar

> Do you have non-JVM languages with which you want to take advantage of Eureka, Ribbon, and Config Server? The Spring Cloud Netflix Sidecar was inspired by Netflix Prana. It includes an HTTP API to get all of the instances (by host and port) for a given service. You can also proxy service calls through an embedded Zuul proxy that gets its route entries from Eureka. The Spring Cloud Config Server can be accessed directly through host lookup or through the Zuul Proxy. The non-JVM application should implement a health check so the Sidecar can report to Eureka whether the app is up or down.

### Metrics: Spectator, Servo, and Atlas

- When used together, Spectator (or Servo) and Atlas provide a near real-time operational insight platform. Spectator and Servo are Netflix’s metrics collection libraries. Atlas is a Netflix metrics backend that manages dimensional time-series data.

- Servo served Netflix for several years and is still usable but is gradually being phased out in favor of Spectator, which is designed to work only with Java 8. Spring Cloud Netflix provides support for both, but Java 8-based applications are encouraged to use Spectator.

### Metrics Backend: Atlas

- Atlas was developed by Netflix to manage dimensional time-series data for near real-time operational insight. Atlas features in-memory data storage, letting it gather and report large numbers of metrics quickly.

- Atlas captures operational intelligence. Whereas business intelligence is data gathered for analyzing trends over time, operational intelligence provides a picture of what is currently happening within a system.

### Retrying Failed Requests

> Spring Cloud Netflix offers a variety of ways to make HTTP requests. You can use a load balanced RestTemplate, Ribbon, or Feign. No matter how you choose to create your HTTP requests, there is always a chance that a request may fail. When a request fails, you may want to have the request be retried automatically. To do so when using Sping Cloud Netflix, you need to include Spring Retry on your application’s classpath. When Spring Retry is present, load-balanced RestTemplates, Feign, and Zuul automatically retry any failed requests (assuming your configuration allows doing so).

## Spring Cloud OpenFeign

> Feign is a declarative web service client. It makes writing web service clients easier. To use Feign create an interface and annotate it. It has pluggable annotation support including Feign annotations and JAX-RS annotations. Feign also supports pluggable encoders and decoders. Spring Cloud adds support for Spring MVC annotations and for using the same HttpMessageConverters used by default in Spring Web. Spring Cloud integrates Ribbon and Eureka to provide a load balanced http client when using Feign.

## Spring Cloud Stream

> Spring Cloud Stream is a framework for building message-driven microservice applications. Spring Cloud Stream builds upon Spring Boot to create standalone, production-grade Spring applications and uses Spring Integration to provide connectivity to message brokers. It provides opinionated configuration of middleware from several vendors, introducing the concepts of persistent publish-subscribe semantics, consumer groups, and partitions.

- Spring Cloud Stream provides a number of abstractions and primitives that simplify the writing of message-driven microservice applications. This section gives an overview of the following:

  - Spring Cloud Stream’s application model
  - Section 28.2, “The Binder Abstraction”
  - Persistent publish-subscribe support
  - Consumer group support
  - Partitioning support
  - A pluggable Binder SPI
  
- Spring Cloud Stream provides a **Binder** abstraction for use in connecting to physical destinations at the external middleware. 

### Binder Implementations

- The Apache Kafka Binder implementation maps each destination to an Apache Kafka topic. The consumer group maps directly to the same Apache Kafka concept. Partitioning also maps directly to Apache Kafka partitions as well.
- Spring Cloud Stream’s Apache Kafka support also includes a binder implementation designed explicitly for Apache Kafka Streams binding. With this native integration, a Spring Cloud Stream "processor" application can directly use the Apache Kafka Streams APIs in the core business logic.
- Kafka Streams binder implementation builds on the foundation provided by the Kafka Streams in Spring Kafka project.

## Spring Cloud Bus

> Spring Cloud Bus links the nodes of a distributed system with a lightweight message broker. This broker can then be used to broadcast state changes (such as configuration changes) or other management instructions. A key idea is that the bus is like a distributed actuator for a Spring Boot application that is scaled out. However, it can also be used as a communication channel between apps. This project provides starters for either an AMQP broker or Kafka as the transport.

## Spring Cloud Sleuth

> Spring Cloud Sleuth implements a distributed tracing solution for Spring Cloud.

## Spring Cloud Consul

> This project provides Consul integrations for Spring Boot apps through autoconfiguration and binding to the Spring Environment and other Spring programming model idioms. With a few simple annotations you can quickly enable and configure the common patterns inside your application and build large distributed systems with Consul based components. The patterns provided include Service Discovery, Control Bus and Configuration. Intelligent Routing (Zuul) and Client Side Load Balancing (Ribbon), Circuit Breaker (Hystrix) are provided by integration with Spring Cloud Netflix.

## Spring Cloud Zookeeper

> This project provides Zookeeper integrations for Spring Boot applications through autoconfiguration and binding to the Spring Environment and other Spring programming model idioms. With a few annotations, you can quickly enable and configure the common patterns inside your application and build large distributed systems with Zookeeper based components. The provided patterns include Service Discovery and Configuration. Integration with Spring Cloud Netflix provides Intelligent Routing (Zuul), Client Side Load Balancing (Ribbon), and Circuit Breaker (Hystrix).

## Spring Cloud Security

> Spring Cloud Security offers a set of primitives for building secure applications and services with minimum fuss. A declarative model which can be heavily configured externally (or centrally) lends itself to the implementation of large systems of co-operating, remote components, usually with a central indentity management service. It is also extremely easy to use in a service platform like Cloud Foundry. Building on Spring Boot and Spring Security OAuth2 we can quickly create systems that implement common patterns like single sign on, token relay and token exchange.

## Spring Cloud for Cloud Foundry

> Spring Cloud for Cloudfoundry makes it easy to run Spring Cloud apps in Cloud Foundry (the Platform as a Service). Cloud Foundry has the notion of a "service", which is middlware that you "bind" to an app, essentially providing it with an environment variable containing credentials (e.g. the location and username to use for the service).

## Spring Cloud Contract

> You need confidence when pushing new features to a new application or service in a distributed system. This project provides support for Consumer Driven Contracts and service schemas in Spring applications (for both HTTP and message-based interactions), covering a range of options for writing tests, publishing them as assets, and asserting that a contract is kept by producers and consumers.

## Spring Cloud Vault

> Spring Cloud Vault Config provides client-side support for externalized configuration in a distributed system. With HashiCorp’s Vault you have a central place to manage external secret properties for applications across all environments. Vault can manage static and dynamic secrets such as username/password for remote applications/resources and provide credentials for external services such as MySQL, PostgreSQL, Apache Cassandra, MongoDB, Consul, AWS and more.

## Spring Cloud Gateway

> This project provides an API Gateway built on top of the Spring Ecosystem, including: Spring 5, Spring Boot 2 and Project Reactor. Spring Cloud Gateway aims to provide a simple, yet effective way to route to APIs and provide cross cutting concerns to them such as: security, monitoring/metrics, and resiliency.



