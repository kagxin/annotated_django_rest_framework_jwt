#### rest_framework_jwt 的注释版本
##### 查看建议
* 查看获取token过程，从[view.py](https://github.com/kagxin/annotated_django_rest_framework_jwt/blob/master/rest_framework_jwt/views.py) 中 ObtainJSONWebToken这个view开始看
* 然后查看鉴权构成，从[authentication.py](https://github.com/kagxin/annotated_django_rest_framework_jwt/blob/master/rest_framework_jwt/authentication.py) 的 BaseJSONWebTokenAuthentication开始看。
* [工程样例](https://github.com/kagxin/recipes/tree/master/projwt)