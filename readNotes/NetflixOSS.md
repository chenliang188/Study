# Netflix OSS

> https://netflix.github.io/
> Netflix is committed to open source. Netflix both leverages and provides open source technology focused on providing the leading Internet television network. Our technology focuses on providing immersive experiences across all internet-connected screens. Netflix's deployment technology allows for continuous build and integration into our worldwide deployments serving members in over 50 countries. Our focus on reliability defined the bar for cloud based elastic deployments with several layers of failover. Netflix also provides the technology to operate services responsibly with operational insight, peak performance, and security. We provide technologies for data (persistent & semi-persistent) that serve the real-time load to our 62 million members, as well as power the big data analytics that allow us to make informed decisions on how to improve our service. If you want to learn more, jump into any of the functional areas below to learn more.

## Big Data

> Tools and services to get the most out of your (big) data

- Data is invaluable in making Netflix such an exceptional service for our customers. Behind the scenes, we have a rich ecosystem of (big) data technologies facilitating our algorithms and analytics. We use and contribute to broadly-adopted open source technologies including Hadoop, Hive, Pig, Parquet, Presto, and Spark. In addition, we’ve developed and contributed some additional tools and services, which have further elevated our data platform. [Genie](https://github.com/Netflix/genie) is a powerful, REST-based abstraction to our various data processing frameworks, notably Hadoop. [Inviso](https://github.com/Netflix/inviso) provides detailed insights into the performance of our Hadoop jobs and clusters. [Lipstick](https://github.com/Netflix/lipstick) shows the workflow of Pig jobs in a clear, visual fashion. And [Aegisthus](https://github.com/Netflix/aegisthus) enables the bulk abstraction of data out of Cassandra for downstream analytic processing.

## Build and Delivery Tools

> Taking code from desktop to the cloud

- Netflix has open sourced many of our Gradle plugins under the name [Nebula](https://nebula-plugins.github.io/). Nebula started off as a set of strong opinions to make Gradle simple to use for our developers. But we quickly learned that we could use the same assumptions on our open source projects and on other Gradle plugins to make them easy to build, test and deploy. By standardizing plugin development, we've lowered the barrier to generating them, allowing us to keep our build modular and composable.

- We require additional tools to take these builds from the developers' desks to AWS. There are tens of thousands of instances running Netflix. Every one of these runs on top of an image created by our open source tool [Aminator](https://github.com/Netflix/aminator). Once packaged, these AMIs are deployed to AWS using our Continuous Delivery Platform, Spinnaker. [Spinnaker](https://www.spinnaker.io/) facilitates releasing software changes with high velocity and confidence.

## Common Runtime Services & Libraries

> Runtime containers, libraries and services that power microservices

- The cloud platform is the foundation and technology stack for the majority of the services within Netflix. The cloud platform consists of cloud services, application libraries and application containers. Specifically, the platform provides service discovery through [Eureka](https://github.com/Netflix/eureka), distributed configuration through [Archaius](https://github.com/Netflix/archaius), resilent and intelligent inter-process and service communication through [Ribbon](https://github.com/Netflix/ribbon). To provide reliability beyond single service calls, [Hystrix](https://github.com/Netflix/hystrix) is provided to isolate latency and fault tolerance at runtime. The previous libraries and services can be used with any JVM based container.

- The platform provides JVM container services through [Karyon](https://github.com/Netflix/karyon) and [Governator](https://github.com/Netflix/governator) and support for non-JVM runtimes via the [Prana](https://github.com/Netflix/prana) sidecar. While Prana provides proxy capabilities within an instance, [Zuul](https://github.com/Netflix/zuul) (which integrates Hystrix, Eureka, and Ribbon as part of its IPC capabilities) provides dyamically scriptable proxying at the edge of the cloud deployment.

- The platform works well within the EC2 cloud utilizing the Amazon autoscaler. For container applications and batch jobs running on Apache Mesos, [Fenzo](https://github.com/Netflix/Fenzo) is a scheduler that provides advanced scheduling and resource management for cloud native frameworks. Fenzo provides plugin implementations for bin packing, cluster autoscaling, and custom scheduling optimizations can be implemented through user-defined plugins.

## Content Encoding

> Automated Scalable Multimedia Ingest and Encoding

- One of the great challenges for Netflix is managing the large and numerous audio and video assets at scale. This scale challenge is bounded by Hollywood master files that can be multiple terabytes in size, and cellular audio and video encodes which must provide an excellent customer experience at 200 Kilobits-per-second. As part of the Netflix Digital Supply Chain, our encoding-related open-source efforts focus on tools and technologies that allow us meet the challenges of content ingest, and encoding, at scale.

- [Photon](https://github.com/Netflix/photon) is a Java implementation of the Interoperable Master Format (IMF) standard. IMF is a SMPTE standard whose core constraints are defined in the specification st2067-2:2013. [VMAF](https://github.com/Netflix/vmaf) is a perceptual quality metric that out-performs the many objective metrics that are currently used for video encoder quality tests.

## Data Persistence

> Storing and Serving data in the Cloud.

- Handling over a trillion data operations per day requires an interesting mix of “off the shelf OSS” and in house projects. No single data technology can meet every use case or satisfy every latency requirement. Our needs range from non-durable in-memory stores like Memcached, Redis, and [Hollow](http://hollow.how/), to searchable datastores such as Elastic and durable must-never-go-down datastores like Cassandra and MySQL.

- Our Cloud usage and the scale at which we consume these technologies, has required us to build tools and services that enhance the datastores we use. We’ve created the sidecars [Raigad](https://github.com/Netflix/Raigad) and [Priam](https://github.com/Netflix/Priam) to help with the deployment, management and backup/recovery of our hundreds of Elastic and Cassandra clusters. We’ve created [EVCache](https://github.com/Netflix/EVCache) and [Dynomite](https://github.com/Netflix/dynomite) to use Memcached and Redis at scale. We’ve even developed the [Dyno](https://github.com/Netflix/dyno) client library to better consume Dynomite in the Cloud.

## Insight, Reliability and Performance

> Providing Actionable Insight at Massive Scale

- Telemetry and metrics play a critical role in the operations of any company, and at more than a billion metrics per minute flowing into [Atlas](https://github.com/Netflix/atlas), our time-series telemetry platform, they play a critical role at Netflix. However, Operational Insight is considered a higher-order family of products at Netflix, including the ability to understand the current components of our cloud ecosystem via [Edda](https://github.com/Netflix/edda), and the easy integration of Java application code with Atlas via the [Spectator](https://github.com/Netflix/spectator) library.

- Effective performance instrumentation allows engineers to drill quickly on a massive volume of metrics, making critical decisions quickly and efficiently. [Vector](https://github.com/Netflix/vector) exposes high-resolution host-level metrics with minimal overhead.

- Being able to understand the current state of our complex microservice architecture at a glance is crucial when making remediation decisions. [Vizceral](https://github.com/Netflix/vizceral) helps provide this at-a-glance intuition without needing to first build up a mental model of the system.

Finally to validate reliability, we have [Chaos Monkey](https://github.com/Netflix/chaosmonkey) which tests our instances for random failures, along with the [Simian Army](https://github.com/Netflix/SimianArmy).

## Security

> Defending at Scale

Security is an increasingly important area for organizations of all types and sizes, and Netflix is happy to contribute a variety of security tools and solutions to the open source community. Our security-related open source efforts focus primarily on operational tools and systems to make security teams more efficient and effective when securing large and dynamic environments.

[Security Monkey](https://github.com/Netflix/security_monkey) helps monitor and secure large AWS-based environments, allowing security teams to identify potential security weaknesses. [Scumblr](https://github.com/Netflix/scumblr) is an intelligence gathering tool that leverages Internet-wide targeted searches to surface specific security issues for investigation. [Stethoscope](https://github.com/Netflix/stethoscope) is a web application that collects information from existing systems management tools (e.g., JAMF or LANDESK) on a given employee’s devices and gives them clear and specific recommendations for securing their systems.

## User Interface

> Libraries to help you build rich client applications

Every month, Netflix members around the world discover and watch more than ten billion hours of movies and shows on their TV, mobile and desktop devices. Using modern UI technologies like Node.js, React and RxJS, our engineers build rich client applications that run across thousands of devices. We strive to create cinematic, immersive experiences that delight our members, exhibit exceptional performance and work flawlessly. We're continuously improving the product through data-driven A/B testing that enables us to experiment with novel concepts and understand the value of every feature we ship.

We created [Falcor](https://netflix.github.io/falcor) for efficient data fetching. We help maintain [Restify](https://github.com/restify/node-restify) to enable us to scale Node.js applications with full observability. We're helping to build the next version of [RxJS](https://github.com/ReactiveX/RxJS) to improve its performance and debuggability.
