#依赖注入#

通常对于一个对象如何得到它的依赖项有三种方法:

1. 我们可以内部创建依赖者所需的依赖项.
2. 我们在变量空间中查找它然后像全局变量那样引用它.
3. 当依赖者需要的时候把依赖项传递给它.

对于依赖注入来说,我们使用第三种方式(另外两种方式意味着非常难的挑战:比如污染全局变量空间而且作用域隔离几乎不可能).依赖注入是一种设计模式,它可以使得我们避免硬代码依赖关系,因此就可以在运行时移除和改变这些依赖关系.

这种运行时修改依赖关系的特性可以帮助我们创建理想的隔离测试环境.然后在生产环境中再用真实对象取代测试环境中的模拟对象.

从功能实现上来说,把依赖的资源插入目标这种模式在下面这种场景中是非常有必要的：自动查找预先准备好的依赖项或者给依赖项提供插入目标.

当我们基于其它的对象和库编写组件的时候，我们就需要描述它所需的依赖项.在运行时,一个插入器将会创建依赖项的实例并且把它传递给依赖者使用.

    // Great example from the Angular docs
    function SomeClass(greeter) {
    this.greeter = greeter;
    }
    SomeClass.prototype.greetName = function(name) {
    this.greeter.greet(name)
    }

注意：这个例子里在全局命名空间构建控制器的做法并不够好.我们以它为例仅仅是因为这个例子够简单.

在运行时,SomeClass的实例对象并不在乎如何得到greeter这个依赖,只要得到它就行.为了把greeter依赖传递给SomeClass。SomeClass对象的创建者有责任在它创建时把它所需的依赖(greeter)传递给它.

正因为此,AngualrJS使用`$injector`来管理依赖项的查找和初始化.实际上,`$injector`服务负责管理所有AngularJS组件的初始化,包扩我们的应用模块(module)、指令(directive)、控制器(controller)等等.

举例来说,下面这个简单的应用定义了一个简单的模块和一个简单的控制器:

    angular.module('myApp', [])
    .factory('greeter', function() {
        return {
            greet: function(msg) { alert(msg); }
        }
    })
    .controller('MyController',
        function($scope, greeter) {
            $scope.sayHello = function() {
                greeter.greet("Hello!");
            };
    });

在运行时,当AngularJS初始这个模块实例时,它会寻找greeter依赖项然后顺理成章地把它传递给模块.

    <div ng-app="myApp">
        <div ng-controller="MyController">
            <button ng-click="sayHello()">Hello</button>
        </div>
    </div>

Angular在后台的处理过程大概像这样:

    // Load the app with the injector
    var injector = angular.injector(['ng', 'myApp']);
    // Load the $controller service with the injector
    var $controller = injector.get('$controller');
    var scope = injector.get('$rootScope').$new();
    // Load the controller, passing in a scope
    // which is how angular does it at runtime
    var MyController = $controller('MyController', {$scope: scope})

上面的例子中我们没有描述如何找到greeter依赖项,但是它依旧可以正常工作,因为injector注入器会负责为我们找到它并加载它.

AngualrJS使用annotate函数来负责在初始化时把传入参数数组的属性分析出来,你可以在Chrome开发工具栏控制台界面中输入以下代码来看看这个函数的作用：

    > injector.annotate(function($q, greeter) {}) //(译者注:输入代码)
    ["$q", "greeter"] //(译者注：输出结果)
    //译者试了一下,$injector和injector在全局变量空间下都找不到,可能版本原因.

在每一个Angualr应用中，$injector服务都已经在工作，无论你是否知道它.当我们写控制器时没有用[]中括号或者通过明确定义来设置他们时,$injector服务都会基于参数名来推断依赖项.

##通过推断来注解##

如果没有明确指定,Angular假设函数的参数名称就是依赖项的名称.因此,它会在函数对象上调用toString()函数,解析并提取出函数参数,然后使用$injector服务来把这些参数注入进对象的初始化过程.

注入过程看上去像这样:

    injector.invoke(function($http, greeter) {});

注意这个注入过程仅在代码不压缩、不混淆的情况下可以正常工作,因为Angular需要解析完整的参数名称.

在这种JavaScript参数推断过程中,顺序是不重要的:Anguarlar将会搞定这个问题并以正确的顺序注入正确的属性.

JavaScript压缩器通常将会把函数参数名称改变到最小的字符数目(同时处理空格,移除换行和注释等等)以便把JavaScript文件大小压缩到最小.在这种情况下,如果我们没有明确描述参数,Angular将无法推断出需要注入的参数.

##显式注解##

Angular提供了一种方法来帮我们显式定义函数调用时所需要的依赖.这种方法在压缩器修改函数参数名称时,依旧可以给函数注入正确的服务.

注入过程使用$inejct属性来注解函数.函数的$inject属性是一个数组，数组内包含需要注入的依赖服务的名称.

要使用$inject属性方法，我们可以在函数或命名上设置它:

    var aControllerFactory =
        function aController($scope, greeter) {
            console.log("LOADED controller", greeter);
            // ... Controller
        };
    aControllerFactory.$inject = ['$scope', 'greeter'];
    // Greeter service
    var greeterService = function() {
        console.log("greeter service");
    }
    // Our app controller
    angular.module('myApp', [])
        .controller('MyController', aControllerFactory)
        .factory('greeter', greeterService);    
    // Grab the injector and create a new scope
    var injector = angular.injector(['ng', 'myApp']),
        controller = injector.get('$controller'),
        rootScope = injector.get('$rootScope'),
        newScope = rootScope.$new();
    // Invoke the controller
    controller('MyController', {$scope: newScope});

    使用这种注解风格,顺序是很重要的,因为$inject数组必须匹配注入参数的顺序.这种注入方法在代码压缩情况下正常使用.因为注解信息是和函数打包在一起的.
    
##内联注解##

Angular提供的最后一个开箱即用注解特性是内联注解.这个语法糖实际运作方式和上面注解的$inject方法(译注：显式注解这种)实际一样,但是允许我们把参数和函数定义内联在一起.另外它还可以让我们在定义时不使用临时变量.

内联注解允许我们在定义一个Angular对象时传入一个参数数组来代替函数.这个数组内部的元素是注入依赖项字符串列表,最后一个参数是对象的定义函数.

举例如下:

    angular.module('myApp')
        .controller('MyController',
            ['$scope', 'greeter',
                function($scope, greeter) {
        }]);
        
内联注解方法在使用压缩器的情况下也可以使用,因为我们传进的是一个字符串列表,我们通常也把这种方法称为括号法或者数组标识([])法.

##$inject API参考##

尽管需要我们直接使用$injector的情景是相当稀少的,但是知道它的API仍然可以帮助我们深入理解它的工作机制.

###annotate()###

annotate()这个函数返回一个函数对象初始化时需要被注入的服务名数组。annotate()函数被注入器服务用来判定函数调用时需要注入那些服务.

annotate()函数仅有一个参数:

+ fn(function or array)

fn参数可以是函数或一个数组,这个数组就是函数定义里面括号表示法里的那个数组(参见内联注解)

annotate方法返回一个服务名数组，这些服务将在函数调用时注入进函数.

    var injector = angular.injector(['ng', 'myApp']);
    injector.annotate(function($q, greeter) {});
    // ['$q', 'greeter']
    
在你的Chrome调试器里面试一下上面这段代码.

###get()###

get()方法只有一个参数，返回一个服务实例

+ name (string)

name参数是我们需要的服务实例的名称.

get()通过名称来得到返回对应服务的实例.

###has()###

当注入器服务确定所需的注入服务项在注册库里存在时，has()方法返回true,如果不存在当然返回false.它也仅有一个参数

+ name(string)

这个字符串就是我们想在注入器服务的注册库中查找的依赖服务的名称.

###instantiate()###

instantiate()方法创建一个JavaScript Type类的新实例.它用new操作符调用一个构造函数并提供确认的参数,它需要两个参数:

+ Type(function)

注解构造器函数调用此函数.

+ locals (object – optional)

这个可选参数提供另外一种方法：这个方法可以在函数被调用时，把参数名称传给函数.

instantiate()方法返回Type类的一个新实例.

###invoke()###

invoke()方法调用方法，并且从$injector服务中给方法添加方法参数.

invoke()方法有是那个参数

+ fn(function)

这是一个将被调用的函数.函数的参数将会通过函数注解得到.

+ self(object-optional)

self参数将会用来给被调用的方法添加this参数(方法所有者对象).

+ locals(object-optional)

这个可选参数将会提供另外一种当方法被调用时给方法传递参数名的方式.

invoke方法返回fn函数的返回值.

##ngMin##

使用上面这三种注解定义方法,务必要注意这些方法只有在定义函数时才可用.然后在实际生产项目中,经常性地显示关注参数的顺序和代码膨胀总是有点繁琐.

ngMin这个工具可以减轻我们在显示定义依赖方面的责任.ngMin是一个面向Angular应用的预压缩器.他可以分析我们的Angular应用,为我们创建依赖注入代码.

例如:它会转换下面这段代码:

    angular.module('myApp', [])
    .directive('myDirective',
        function($http) {
    })
    .controller('IndexController',
        function($scope, $q) {
    });
    
上面的代码会转换成下面这样:

    angular.module('myApp', [])
    .directive('myDirective', [
        '$http',
        function ($http) {
        }
    ]).controller('IndexController', [
        '$scope',
        '$q',
        function ($scope, $q) {
        }
    ]);

ngMin可以节省我们大量的输入工作,并且显著净化了我们的代码文件.

###安装###

为了安装ngMin，我们将会使用npm包管理器：

    $ npm install -g ngmin
    
如果我们使用Grunt,我们可以安装grunt-ngmin这个Grunt任务组件.如果我们使用Rails，我们可以使用Ruby gem包：ngmin-rails.

###使用ngMin###

我们可以在命令行环境下使用标准模式的ngMin:主要给它传递两个参数:input.js(输入JavaScript文件)和output.js(输出JavaScript文件)或者通过sdtio/stdout.像下面这样:

    $ ngmin input.js output.js
    # or
    $ ngmin < input.js > output.js

input.js使我们的原先的源代码文件,output.js是注解后的输出代码文件.

###它是怎样工作的###

ngMin的核心是使用抽象语法树(Abstract Syntax Tree/AST)来解析JavaScript代码文件.通过astral(一个抽象语法树工具框架-译注:https://github.com/btford/astral)的帮助,ngMin可以重新构建源代码文件，给它添加必需的注解，然后使用escodegen(译注:https://github.com/Constellation/escodegen)生成更新后的源码文件.

ngmin要求我们的Angular代码是由逻辑声明组成.如果我们的代码使用的语法类似于这本书中的代码,ngMin将可以解析代码并预压缩它.
