import requests
from django.conf import settings
import json

def qbo_api_call(access_token, realm_id):
    """[summary]
    
    """
    
    if settings.ENVIRONMENT == 'production':
        base_url = settings.QBO_BASE_PROD
    else:
        base_url =  settings.QBO_BASE_SANDBOX

    route = '/v3/company/{0}/companyinfo/{0}'.format(realm_id)
    auth_header = 'Bearer {0}'.format(access_token)
    headers = {
        'Authorization': auth_header, 
        'Accept': 'application/json'
    }
    return requests.get('{0}{1}'.format(base_url, route), headers=headers)

def qbo_data_call(access_token, realm_id, type, payload=None):
    """[summary]
    
    """
    if settings.ENVIRONMENT == 'production':
        base_url = settings.QBO_BASE_PROD
    else:
        base_url =  settings.QBO_BASE_SANDBOX


    if type == 'import_invoice':
        route = '/v3/company/{0}/invoice'.format(realm_id)
    elif type == 'companyinfo':
        route = '/v3/company/{0}/companyinfo/{0}'.format(realm_id)
    elif type == 'get_taxcodes':
        route = '/v3/company/{0}/query?query=select%20%2a%20from%20taxcode'.format(realm_id)
    elif type == 'get_sales':
        route = '/v3/company/{0}/reports/ItemSales?date_macro=This%20Fiscal%20Year-to-date'.format(realm_id)
    elif type == 'get_inventory':
        route = '/v3/company/{0}/query?query=select%20Name%2c%20PurchaseCost%2c%20QtyOnHand%2c%20Type%20from%20item'.format(realm_id)

    auth_header = 'Bearer {0}'.format(access_token)
    headers = {
        'Authorization': auth_header, 
        'Accept': 'application/json',
        'Content-Type' : 'application/json;charset=utf-8'
    }

    print('SENDING DATA')
    url = '{0}{1}'.format(base_url, route)
    print('URL IS: ', url)
    if payload is None:
        print('SENDING WITHOUT PAYLOAD..')
        r = requests.get(url, headers=headers)
    else:
        print('SENDING WITH PAYLOAD..')
        r = requests.get(url, data=json.dumps(payload), headers=headers)

    print("RESPONSE IS", r)
    #print('RESPONSE CONTENT IS: ', r.content)
    return r