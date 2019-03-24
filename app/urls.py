from django.conf.urls import url
from django.views.generic.base import RedirectView
from . import views

app_name = 'app'

favicon_view = RedirectView.as_view(url='/static/favicon.ico', permanent=True)

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^oauth/?$', views.oauth, name='oauth'),
    url(r'^openid/?$', views.openid, name='openid'),
    url(r'^callback/?$', views.callback, name='callback'),
    url(r'^connected/?$', views.connected, name='connected'),
    url(r'^qbo_request/?$', views.qbo_request, name='qbo_request'),
    url(r'^revoke/?$', views.revoke, name='revoke'),
    url(r'^refresh/?$', views.refresh, name='refresh'),
    url(r'^user_info/?$', views.user_info, name='user_info'),
    url(r'^mytokens/?$', views.mytokens, name='mytokens'),
    url(r'^newAToken/?$', views.get_access_from_refresh, name='get_access_from_refresh'),
    url(r'^getTaxcodes/?$', views.get_taxcodes, name='get_taxcodes'),
    url(r'^importInvoice/?$', views.import_invoice, name='import_invoice'),
    url(r'^getsales/?$', views.get_sales, name='get_sales'),
    url(r'^getmarginzsales/?$', views.get_marginz_sales_fn, name='get_marginz_sales_fn'),
    url(r'^GetPercentagesAndCOP/?$', views.get_percentages_COP_fn, name='get_percentages_COP_fn'),
    url(r'^migration/?$', views.migration, name='migration'),
]


