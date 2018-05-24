# Node.js API文档阅读笔记

> V10.1.0文档中文版

## assert断言

- 当使用 strict 模式时，任何 assert 函数都会使用严格函数模式的等式。 所以 assert.deepEqual() 会等同于 assert.deepStrictEqual()。除此以外，涉及对象的错误信息会产生一个错误差异比较，而不是展示双方的对象。 legacy 模式则不会这样。

## Buffer缓冲

- 在 ECMAScript 2015 (ES6) 引入 TypedArray 之前，JavaScript 语言没有读取或操作二进制数据流的机制。 Buffer 类被引入作为 Node.js API 的一部分，使其可以在 TCP 流或文件系统操作等场景中处理二进制数据流。

- 为了使 Buffer 实例的创建更可靠、更不容易出错，各种 new Buffer() 构造函数已被 废弃，并由 Buffer.from()、Buffer.alloc()、和 Buffer.allocUnsafe() 方法替代。



- TypedArray 现已被添加进 ES6 中，Buffer 类以一种更优化、更适合 Node.js 用例的方式实现了 Uint8Array API。

- Buffer 类的实例类似于整数数组，但 Buffer 的大小是固定的、且在 V8 堆外分配物理内存。 Buffer 的大小在被创建时确定，且无法调整。

# child_process - 子进程

- child_process 模块提供了衍生子进程的功能，它与 popen(3) 类似，但不完全相同。 这个功能主要由 child_process.spawn() 函数提供：

- 默认情况下，Node.js 的父进程与衍生的子进程之间会建立 stdin、stdout 和 stderr 的管道。 数据能以非阻塞的方式在管道中流通。 有些程序会在内部使用行缓冲 I/O，虽然这并不影响 Node.js，但发送到子进程的数据可能无法被立即使用。

- Buffer 实例也是 Uint8Array 实例。 但是与 ECMAScript 2015 中的 TypedArray 规范还是有些微妙的不同。 例如，当 ArrayBuffer#slice() 创建一个切片的副本时，Buffer#slice() 的实现是在现有的 Buffer 上不经过拷贝直接进行创建，这也使得 Buffer#slice() 更高效。

- child_process.spawn() 函数会异步地衍生子进程，且不会阻塞 Node.js 事件循环。 child_process.spawnSync() 函数则以同步的方式提供同样的功能，但会阻塞事件循环，直到衍生的子进程退出或被终止。

# cluster (集群)

- Node.js在单个线程中运行单个实例。 用户(开发者)为了使用现在的多核系统，有时候,用户(开发者)会用一串Node.js进程去处理负载任务。

- cluster 模块允许简单容易的创建共享服务器端口的子进程。
- 工作进程由child_process.fork()方法创建，因此它们可以使用IPC和父进程通信，从而使各进程交替处理连接服务。

- cluster模块支持两种连接分发模式（将新连接安排给某一工作进程处理）。

    1. 第一种方法（也是除Windows外所有平台的默认方法），是循环法。由主进程负责监听端口，接收新连接后再将连接循环分发给工作进程。在分发中使用了一些内置技巧防止工作进程任务过载。

    2. 第二种方法是，主进程创建监听socket后发送给感兴趣的工作进程，由工作进程负责直接接收连接。

- 理论上第二种方法应该是效率最佳的，但在实际情况下，由于操作系统调度机制的难以捉摸，会使分发变得不稳定。我们遇到过这种情况：8个进程中的2个，分担了70%的负载。

## console (控制台)

- console 模块提供了一个简单的调试控制台，类似于 Web 浏览器提供的 JavaScript 控制台。

- 该模块导出了两个特定的组件：

    - 一个 Console 类，包含 console.log() 、 console.error() 和 console.warn() 等方法，可以被用于写入到任何 Node.js 流。
    - 一个全局的 console 实例，可被用于写入到 process.stdout 和 process.stderr。 全局的 console 使用时无需调用 require('console')。
- 注意：全局的 console 对象的方法既不总是同步的（如浏览器中类似的 API），也不总是异步的（如其他 Node.js 流）。 详见 进程 I/O。

## crypto (加密)

- crypto 模块提供了加密功能，包含对 OpenSSL 的哈希、HMAC、加密、解密、签名、以及验证功能的一整套封装。

## dgram (数据报)

- dgram模块提供了 UDP 数据包 socket 的实现。

## dns (域名服务器)

- dns 模块包含两类函数：
    1. 第一类函数，使用底层操作系统工具进行域名解析，且无需进行网络通信。 这类函数只有一个：dns.lookup()。
    2. 第二类函数，连接到一个真实的 DNS 服务器进行域名解析，且始终使用网络进行 DNS 查询。 这类函数包含了 dns 模块中除 dns.lookup() 以外的所有函数。 这些函数使用与 dns.lookup() 不同的配置文件（例如 /etc/hosts）。 这类函数适合于那些不想使用底层操作系统工具进行域名解析、而是想使用网络进行 DNS 查询的开发者。

## Error (错误)

- Node.js 中运行的应用程序一般会遇到以下四类错误：
    - 标准的 JavaScript 错误
    - 
由底层操作系触发的系统错误，例如试图打开一个不存在的文件、试图通过一个已关闭的 socket 发送数据等。
    - 由应用程序代码触发的用户自定义的错误。
    - 断言错误是错误的一个特殊类别，每当 Node.js 检测到一个不应该发生的异常逻辑时触发。 这类错误通常由 assert 模块引起。
- 同步的 API（任何不接受 callback 函数的阻塞方法，例如 fs.readFileSync）会使用 throw 报告错误。

- 异步的 API 中发生的错误可能会以多种方式进行报告：
    - 错误回调函数
    - 当一个异步方法被一个 EventEmitter 对象调用时，错误会被分发到对象的 'error' 事件上。
    - 少数仍然用throw

## events (事件)

- 大多数 Node.js 核心 API 都采用惯用的异步事件驱动架构，其中某些类型的对象（触发器）会周期性地触发命名事件来调用函数对象（监听器）。
- 所有能触发事件的对象都是 EventEmitter 类的实例。 这些对象开放了一个 eventEmitter.on() 函数，允许将一个或多个函数绑定到会被对象触发的命名事件上。 事件名称通常是驼峰式的字符串，但也可以使用任何有效的 JavaScript 属性名。当 EventEmitter 对象触发一个事件时，所有绑定在该事件上的函数都被同步地调用。 监听器的返回值会被丢弃。

- eventEmitter.emit() 方法允许将任意参数传给监听器函数。 当一个普通的监听器函数被 EventEmitter 调用时，标准的 this 关键词会被设置指向监听器所附加的 EventEmitter。也可以使用 ES6 的箭头函数作为监听器。但是这样 this 关键词就不再指向 EventEmitter 实例

- EventEmitter 会按照监听器注册的顺序同步地调用所有监听器。 所以需要确保事件的正确排序且避免竞争条件或逻辑错误。 监听器函数可以使用 setImmediate() 或 process.nextTick() 方法切换到异步操作模式

- 使用 eventEmitter.once() 方法时可以注册一个对于特定事件最多被调用一次的监听器

## fs - 文件系统

- fs 模块提供了一些 API，用于以一种类似标准 POSIX 函数的方式与文件系统进行交互。
- 所有的文件系统操作都有异步和同步两种形式。异步形式的最后一个参数都是完成时回调函数。 传给回调函数的参数取决于具体方法，但回调函数的第一个参数都会保留给异常。 如果操作成功完成，则第一个参数会是 null 或 undefined。当使用同步操作时，任何异常都会被立即抛出，可以使用 try/catch 来处理异常，或让异常向上冒泡。

## global - 全局变量

- 全局变量在所有模块中均可使用。 以下变量虽然看起来像全局变量，但实际上不是。 它们的作用域只在模块内，详见 module文档：

    - __dirname
    - __filename
    - exports
    - module
    - require()

## http

- 要使用 HTTP 服务器与客户端，需要 require('http')。
- Node.js 中的 HTTP 接口被设计成支持协议的许多特性。 比如，大块编码的消息。 这些接口不缓冲完整的请求或响应，用户能够以流的形式处理数据。
- 为了支持各种可能的 HTTP 应用，Node.js 的 HTTP API 是非常底层的。 它只涉及流处理与消息解析。 它把一个消息解析成消息头和消息主体，但不解析具体的消息头或消息主体。

## https

- HTTPS 是 HTTP 基于 TLS/SSL 的版本。在 Node.js 中，它被实现为一个独立的模块。

## module (模块)

- 在 Node.js 模块系统中，每个文件都被视为独立的模块。
- 当 Node.js 直接运行一个文件时，require.main 会被设为它的 module。 这意味着可以通过 require.main === module 来判断一个文件是否被直接运行
- Node.js 的 require() 函数的语义被设计得足够通用化，可以支持许多合理的目录结构。 包管理器程序（如 dpkg、rpm 和 npm）可以不用修改就能够从 Node.js 模块构建本地包。
- 模块在第一次加载后会被缓存。 这也意味着（类似其他缓存机制）如果每次调用 require('foo') 都解析到同一文件，则返回相同的对象。
- 模块是基于其解析的文件名进行缓存的。 由于调用模块的位置的不同，模块可能被解析成不同的文件名（比如从 node_modules 目录加载），这样就不能保证 require('foo') 总能返回完全相同的对象。

## net(网络)
- net 模块提供了创建基于流的 TCP 或 IPC 服务器(net.createServer())和客户端(net.createConnection()) 的异步网络 API。

## os (操作系统)

- os 模块提供了一些操作系统相关的实用方法。

## path (路径)

- path 模块提供了一些工具函数，用于处理文件与目录的路径。

## process - 进程

- process 对象是一个全局变量，它提供当前 Node.js 进程的有关信息，以及控制当前 Node.js 进程。 因为是全局变量，所以无需使用 require()。

## querystring - 查询字符串

- querystring 模块提供了一些实用函数，用于解析与格式化 URL 查询字符串

## readline (逐行读取)

- require('readline') 模块提供了一个接口，用于从可读流（如 process.stdin）读取数据，每次读取一行。

## repl (交互式解释器)

- repl 模块提供了一种“读取-求值-输出”循环（REPL）的实现，它可作为一个独立的程序或嵌入到其他应用中

- repl 模块导出了 repl.REPLServer 类。 当 repl.REPLServer 实例运行时，它接收用户输入的每一行，根据用户定义的解释函数解释这些输入，然后输出结果。 输入可以是 stdin，输出可以是 stdout，或者也可以连接到其他任何 Node.js 流。

- repl.REPLServer 实例支持输入的自动补全、精简 Emacs 风格的行编辑、多行输入、ANSI 风格的输出、当前 REPL 会话状态的保存与恢复、错误校正、以及可定制的解释函数。

## stream (流)

- 流（stream）在 Node.js 中是处理流数据的抽象接口（abstract interface）。 stream 模块提供了基础的 API 。使用这些 API 可以很容易地来构建实现流接口的对象。

- Node.js 提供了多种流对象。 例如， HTTP 请求 和 process.stdout 就都是流的实例。

- 流可以是可读的、可写的，或是可读写的。所有的流都是 EventEmitter 的实例。

- 尽管所有的 Node.js 用户都应该理解流的工作方式，这点很重要， 但是 stream 模块本身只对于那些需要创建新的流的实例的开发者最有用处。 对于主要是 消费 流的开发者来说，他们很少（如果有的话）需要直接使用 stream 模块。

## string_decoder - 字符串解码器

- string_decoder 模块提供了一个 API，用于把 Buffer 对象解码成字符串，但会保留编码过的多字节 UTF-8 与 UTF-16 字符。

## 定时器

- timer 模块暴露了一个全局的 API，用于在某个未来时间段调用调度函数。 因为定时器函数是全局的，所以使用该 API 无需调用 require('timers')。

- Node.js 中的计时器函数实现了与 Web 浏览器提供的定时器类似的 API，除了它使用了一个不同的内部实现，它是基于 Node.js 事件循环构建的。

## tls (安全传输层)

- tls 模块是对安全传输层（TLS）及安全套接层（SSL）协议的实现，建立在OpenSSL的基础上。

## tty - 终端

- tty 模块提供了 tty.ReadStream 类和 tty.WriteStream 类。 大多数情况下无需直接使用该模块。

## url

- url 模块提供了一些实用函数，用于 URL 处理与解析

## util(实用工具)

- util 模块主要用于支持 Node.js 内部 API 的需求。 大部分实用工具也可用于应用程序与模块开发者

## V8

- v8 模块暴露了特定于V8版本内置到 Node.js 二进制文件中的API.

## vm (虚拟机)

- vm 模块提供了一系列 API 用于在 V8 虚拟机环境中编译和运行代码。

## Zlib 

- zlib模块提供通过 Gzip 和 Deflate/Inflate 实现的压缩功能

## C++ 插件

- 目前用于实现插件的方法相当复杂，涉及多个组件和 API 的知识：
    - V8：Node.js 目前用于提供 JavaScript 实现的 C++ 库。
    - libuv：实现了 Node.js 的事件循环、工作线程、以及平台所有的的异步操作的 C 库。
    - 内置的 Node.js 库。Node.js 自身开放了一些插件可以使用的 C++ API。
    - Node.js 包含一些其他的静态链接库，如 OpenSSL。
