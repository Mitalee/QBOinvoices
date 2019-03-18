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

def qbo_data_call(access_token, realm_id, type):
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

    auth_header = 'Bearer {0}'.format(access_token)
    headers = {
        'Authorization': auth_header, 
        'Accept': 'application/json',
        'Content-Type' : 'application/json;charset=utf-8'
    }
    payload = {
      "Line": [
        {
          "DetailType": "SalesItemLineDetail", 
          "Amount": 500.0, 
          "SalesItemLineDetail": {
            "ItemRef": {
              "name": "I phone", 
              "value": "3"
            },
            "Qty": 1,
            "TaxCodeRef":
                {
                "value": "14"
                }
          }
        }
      ], 
      "CustomerRef": {
        "value": "15"
      },
      "TxnDate": "2019-01-10",
      "DueDate": "2019-03-18",
      "GlobalTaxCalculation": "TaxExcluded",
    }

    # TxnDate
    # GlobalTaxCalculation
    # TransactionLocationType
    # TxnTaxDetail
        #TxnTaxCodeRef
    print('SENDING DATA')
    url = '{0}{1}'.format(base_url, route)
    print('URL IS: ', url)
    r = requests.post(url, data=json.dumps(payload), headers=headers)
    print("RESPONSE IS", r)
    return r