# 3、如何布局Django项目

项目布局是Django核心开发者关于最佳实践问题有分歧的领域之一。在这一章，我们展示我们的方法，它是最通行的方法之一。

-----------------------
**包提示：Django项目模板**

有很多项目模板都可以用来快速启动一个Django项目，而且这些模板都是遵从上一章描述的模式。这里有两个链接，在你想快速启动一个项目时，也许用得着：

- https://github.com/pydanny/cookiecutter-django 本章提到的模板
- https://www.djangopackages.com/grids/g/cookiecutters/ 可以替代上面模板的模板列表

-----------------------

## 3.1、Django1.8默认的项目目录文件布局

让我看一下当你创建项目且创建App以后的默认项目布局

```
Example 3.1

$django-admin.py startproject mysite
$cd mysite
$django-admin.py startapp my_app
```

下面是上面命令产生的项目布局

```
Example 3.2
mysite/
    manage.py
    my_app/
        __init__.py
        admin.py
        models.py
        tests.py
        views.py
    mysite/
        __init__.py
        settings.py
        urls.py
        wsgi.py
```        

Django默认项目布局有很多问题，它被用作教程中时是有用的，当被用作组合实际项目时就不是非常够用了，本章的剩余部分将会解释这里面的原因。

## 3.2、我们倾向的项目的布局

当我们基于*django-admin.py startproject*指令生成的布局工作时，我们信赖使用一个三层的文件布局:把生成的文件布局再放进另外一个文件目录中，另外这个目录同时也作为版本库的根目录，我们这个项目布局高度概括为：
```
Example 3.2
<repository_root>/
    <django_project_root>/
        <configuration_root>/
```
我们来深入一下每一层的细节

### 3.2.1、顶层:版本库根目录

顶层*<repositoryroot>/*根目录是项目的绝对根目录，里面除了放置*<djangoprojectroot>*目录以外，我也要放置一下关键组件：比如README.rst,docs/directory,.gitignore,requirements.txt文件，还有一些其他高等级文件，都是部署时需要的。

-----------------------

图 3.1: 为什么库目录重要的另外一个原因(到原PDF中找图吧)

-----------------------

-----------------------
**提示：通用实践在这儿有所变化**

有些开发者喜欢把*<djangoprojectroot>*目录作为项目的版本库根目录

-----------------------

### 3.2.2、第二层:项目根目录

第二层才是实际Django项目的根目录，所有的Python代码文件都在*<djangoprojectroot>/*目录以及其子目录内，甚至更深层子目录内。

如果你要用*django-admin.py startproject*命令启动项目，你得在版本库根目录内运行这个命令，然后命令产生的Django项目目录就是项目根目录

### 3.2.3 第三层:配置根目录

*<conl·gurationroot>*目录是放置项目配置模块settings.py和根URL配置(urls.py)文件的地方，它必须是一个合法的Python包(得包含一个*__init__.py*文件模块)

配置根目录里面的文件都是*django-admin.py startproject*命令自动生成文件的一部分。

## 3.3、项目布局样例

让我们看一个通用的样例：一个简单的评分站点，假设我们要做冰激凌评价网，这是一个对不同品牌和口味的冰激凌打分的Web应用。

下面就是我们做出的这个项目的布局：

```
Example 3.3

icecreamratings_project/
    .gitignore
    Makefile
    docs/
    README.rst
    requirements.txt
    icecreamratings/
        manage.py
        media/
        products/
        profiles/
        ratings/
        static/
        templates/
        config/
            __init__.py
            settings/
            urls.py
            wsgi.py
```
让我们对这个样例布局做个深度分析：就像你所看到的，*icecreamratingsproject/*目录就是我们之前所提到的*<repositoryroot>*版本库根目录,我们拥有这些文件和目录，我们将在下面的表格中对它们做一说明：

文件或目录      | 用途   
----------------|--------------
.gitignore      |列出Git系统忽略的文件和目录列表.(对于不同的版本控制系统，这个文件是不一样的。比如如果你用Mercurial，那这个文件就是.hgignore)
README.rstand docs/ |面向开发者的项目文档，在第23章，你将会学到它的更多内容
Makefile | 包括简单的部署任务和宏，对于较复杂的部署，你可能得依赖一些工具，比如：Invoke,Paver, 或Fabric.
requirements.txt | 你的项目所需Python包的列表，其中包括Django1.8包，在第21章(Django秘制调味:第三方包)，你将会学到更多这方面的知识。
icecreamratings/ | 项目的Django根目录

表格 3.1：版本库根目录中的文件和目录

当任何人访问这个项目的时候，他们看到的这个项目的高层次视图，我们发现这样可以帮助我们更好地与其他开发者协作，甚至非开发者。比如把设计者关注的目录就可以放在版本库根目录中是一个比较通行的做法。

许多开发者喜欢把这个目录做到和版本库目录同级，Ok，对于我们来说，这也没有问题，我们仅仅是喜欢把我们的项目看得稍微更独立一点。

在*icecreamratingsproject/icecreamratings*目录,既Django项目根目录中,我们放置了下面的文件和目录

文件或目录      | 用途   
----------------|--------------
config/   |项目的配置根目录
