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

当我们基于django-admin.py启动项目指令生成的布局工作时，我们信赖使用一个三层的文件布局:把生成的文件布局再放进另外一个文件目录中，另外这个目录同时也作为Git库的根目录，我们这个项目布局高度概括为：
```
Example 3.2
<repository_root>/
    <django_project_root>/
        <configuration_root>/
```
我们来深入一下每一层的细节

### 3.2.1、顶层:Git库根目录

