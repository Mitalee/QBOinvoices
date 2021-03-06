from __future__ import absolute_import

from requests import HTTPError
import json

from intuitlib.client import AuthClient
from intuitlib.migration import migrate
from intuitlib.enums import Scopes
from intuitlib.exceptions import AuthClientError

from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseServerError
from django.conf import settings
from django.core import serializers

from app.services import qbo_api_call, qbo_data_call

# Create your views here.
def index(request):
    return render(request, 'index.html')

def oauth(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT,
    )

    url = auth_client.get_authorization_url([Scopes.ACCOUNTING])
    request.session['state'] = auth_client.state_token
    return redirect(url)

def openid(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT,
    )

    url = auth_client.get_authorization_url([Scopes.OPENID, Scopes.EMAIL])
    request.session['state'] = auth_client.state_token
    return redirect(url)

def callback(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        state_token=request.session.get('state', None),
    )

    state_tok = request.GET.get('state', None)
    error = request.GET.get('error', None)
    
    if error == 'access_denied':
        return redirect('app:index')
    
    if state_tok is None:
        return HttpResponseBadRequest()
    elif state_tok != auth_client.state_token:  
        return HttpResponse('unauthorized', status=401)
    
    auth_code = request.GET.get('code', None)
    realm_id = request.GET.get('realmId', None)
    request.session['realm_id'] = realm_id

    if auth_code is None:
        return HttpResponseBadRequest()

    try:
        auth_client.get_bearer_token(auth_code, realm_id=realm_id)
        request.session['access_token'] = auth_client.access_token
        request.session['refresh_token'] = auth_client.refresh_token
        request.session['id_token'] = auth_client.id_token
    except AuthClientError as e:
        # just printing status_code here but it can be used for retry workflows, etc
        print(e.status_code)
        print(e.content)
        print(e.intuit_tid)
    except Exception as e:
        print(e)
    return redirect('app:connected')

def connected(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        access_token=request.session.get('access_token', None), 
        refresh_token=request.session.get('refresh_token', None), 
        id_token=request.session.get('id_token', None),
    )

    if auth_client.id_token is not None:
        return render(request, 'connected.html', context={'openid': True})
    else:
        return render(request, 'connected.html', context={'openid': False})

def qbo_request(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        access_token=request.session.get('access_token', None), 
        refresh_token=request.session.get('refresh_token', None), 
        realm_id=request.session.get('realm_id', None),
    )

    if auth_client.access_token is not None:
        access_token = auth_client.access_token

    if auth_client.realm_id is None:
        raise ValueError('Realm id not specified.')
    response = qbo_api_call(auth_client.access_token, auth_client.realm_id)
    
    if not response.ok:
        return HttpResponse(' '.join([response.content, str(response.status_code)]))
    else:
        return HttpResponse(response.content)

def user_info(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        access_token=request.session.get('access_token', None), 
        refresh_token=request.session.get('refresh_token', None), 
        id_token=request.session.get('id_token', None),
    )

    try:
        response = auth_client.get_user_info()
    except ValueError:
        return HttpResponse('id_token or access_token not found.')
    except AuthClientError as e:
        print(e.status_code)
        print(e.intuit_tid)
    return HttpResponse(response.content)

def mytokens(request):
    data = dict()
    data['access_token']=request.session.get('access_token', None) 
    data['refresh_token']=request.session.get('refresh_token', None)

    print(json.dumps(data))
    return HttpResponse(json.dumps(data), content_type='application/json')
    #return HttpResponse(data)
    #return HttpResponse('sent from view')
        
def get_access_from_refresh(request):
    refresh_token = request.session.get('refresh_token', None)

    if refresh_token is None:
        return self.refresh()
    else:
        try:
            auth_client = AuthClient(
                settings.CLIENT_ID, 
                settings.CLIENT_SECRET, 
                settings.REDIRECT_URI, 
                settings.ENVIRONMENT, 
                access_token=request.session.get('access_token', None), 
                refresh_token=refresh_token, 
            )
            current_refresh_token = request.session.get('refresh_token')
            print('CURRENT REFRESH TOKEN IS: ', current_refresh_token)
            auth_client.refresh(refresh_token=current_refresh_token) 
            print(auth_client)
        except AuthClientError as e:
            print(e.status_code)
            print(e.intuit_tid)


        return HttpResponse(json.dumps({'access_token': auth_client.access_token, 'refresh_token': auth_client.refresh_token}), content_type='application/json')



def getBearerTokenFromRefreshToken(self, request):

    refresh_token=request.session.get('refresh_token', None)

    print('REFRESH TOKEN IS: ', refresh_token)


    if refresh_token is None:
        return self.refresh()
    else:
        payload = {
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }

        import requests
        token_endpoint = settings.TOKEN_ENDPOINT
        #token_endpoint = TOKEN_ENDPOINT
        auth_header = 'Basic ' + stringToBase64(settings.CLIENT_ID + ':' + settings.CLIENT_SECRET)
        #auth_header = 'Basic ' + stringToBase64(CLIENT_ID + ':' + CLIENT_SECRET)
        headers = {'Accept': 'application/json', 'content-type': 'application/x-www-form-urlencoded',
               'Authorization': auth_header}

        response = requests.post(token_endpoint, data=payload, headers=headers)
        bearer_raw = json.loads(response.text)

        if 'id_token' in bearer_raw:
            idToken = bearer_raw['id_token']
        else:
            idToken = None

        return HttpResponse(json.dumps(bearer_raw), content_type='application/json')

def stringToBase64(s):
    import base64
    return base64.b64encode(bytes(s, 'utf-8')).decode()

def refresh(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        access_token=request.session.get('access_token', None), 
        refresh_token=request.session.get('refresh_token', None), 
    )

    try:
        auth_client.refresh() 
    except AuthClientError as e:
        print(e.status_code)
        print(e.intuit_tid)
    return HttpResponse('New refresh_token: {0}'.format(auth_client.refresh_token))

def revoke(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        access_token=request.session.get('access_token', None), 
        refresh_token=request.session.get('refresh_token', None), 
    )
    try:
        is_revoked = auth_client.revoke()
    except AuthClientError as e:
        print(e.status_code)
        print(e.intuit_tid)
    return HttpResponse('Revoke successful')

# product_names_in_scenario = ['Amida TM 500gm', 'Lifuran TM 50ML']

# product_rm_allocation = {
#                     'Lifuran TM 50ML': {
#                         'Lifuran 50ML': 1,
#                         'Lifuran Filling Service':2,
#                         'Labels':1,
#                         'Bottle 50ML':1},
#                     'Amida TM 500gm': {
#                         'Amida 500GM':1,
#                         'Packaging Amida':1,
#                         'Labels':4,
#                         'Box of Amida':1}
#                     }


# purchase_cost_of_raw_materials = {
#                         'Lifuran 50ML': 50,
#                         'Lifuran Filling Service':25,
#                         'Labels':3,
#                         'Bottle 50ML':20,
#                         'Amida 500GM':65,
#                         'Packaging Amida':30,
#                         'Box of Amida':35
# }

# product_DL_DOH_allocation = {
#                         'Lifuran TM 50ML': {
#                             'DL': 0.60,
#                             'DOH':0.30
#                             },
#                         'Amida TM 500gm': {
#                             'DL': 0.40,
#                             'DOH':0.10
#                             }
#                     }



# DL_DOH = {'DL':200,'DOH':350}


product_names_in_scenario = ['I phone']

product_rm_allocation = {
                    'I phone': {
                        'Parker Pen': 1,
                        'I Pad':1}
                    }


purchase_cost_of_raw_materials = {
                                'Parker Pen': 25,
                                'I Pad':35
                                }

product_DL_DOH_allocation = {
                            'I phone': {
                                'DL': 0.60,
                                'DOH':0.30
                                }
                            }



DL_DOH = {'DL':200,'DOH':350}

def get_unit_economics_table(request, product_info, cost_of_production):
    table = []

    for product in product_info:
        table_column = dict()

        # Compute Sales per product
        table_column['product_sales'] = product_info[product]['product_quantity_sold'] * \
                                        product_info[product]['product_price']
        table_column['units_sold'] = product_info[product]['product_quantity_sold']
        table_column['price_per_unit'] = product_info[product]['product_price']
        table_column['cost_per_unit'] = cost_of_production[product]['cost_per_unit']
        table_column['profit_per_unit'] = table_column['price_per_unit'] - table_column['cost_per_unit']

        table.append({ product: table_column })
    
    return {'unit_econ_table': table}


def get_percentages_COP_fn(request):
    #change this for different companies
    product_names_in_scenario = ['Amida TM 500gm', 'Lifuran TM 50ML']
    product_info, inventory = get_marginz_sales_fn(request)
    context = []

    print('PRODUCT INFO IN COP FUNCTION IS: ', product_info)
    print('INVENTORY IN COP FUNCTION IS: ', inventory)
    print('PRODUCT RM ALLOCATION IS: ', product_rm_allocation)
    print('DL DOH IS: ', DL_DOH)
    print('DL DOH ALLOCATION IS: ', product_DL_DOH_allocation)

    cost_of_production = dict()
    
    for product_name in product_names_in_scenario:
        # initialize a product dict to store all attributes
        product_costs_all = dict()
        print('PRODUCT NAME IS: ', product_name)

        try: 
            product_costs_all['number_of_finished_goods'] = product_info[product_name]['product_quantity_on_hand'] +\
                                                                  product_info[product_name]['product_quantity_sold']


            rm_allocation = product_rm_allocation[product_name]
            rm_cost = {k:v*purchase_cost_of_raw_materials[k] for k,v in rm_allocation.items() if k in purchase_cost_of_raw_materials}
            product_costs_all.update(rm_cost)
            print(' FINISHED GOODS AND RM COSTS ARE:', product_costs_all)
            

            DL_DOH_allocation = product_DL_DOH_allocation[product_name]
            DL_DOH_cost = {k:v*DL_DOH[k]/product_costs_all['number_of_finished_goods'] for k,v in DL_DOH_allocation.items()}
            print('DL_DOH COSTS ARE:', product_costs_all)
            product_costs_all.update(DL_DOH_cost)


            product_costs_all['cost_per_unit'] = sum(product_costs_all.values())
            print('PER UNIT COSTS ARE:', product_costs_all)
            

            #cost_of_production_for_products[product_name] = cost_of_production_dict
            cost_of_production[product_name] = product_costs_all
            print('COST OF PRODUCTION IS: ', cost_of_production)

        except KeyError:
            cost_of_production[product_name] = 'Product Not Available in Records'

    context.append({'COP': cost_of_production})
    print('COP without UNIT ECON TABLE is: ', context)
    

    unit_econ_table = get_unit_economics_table(request, product_info, cost_of_production)
    context.append(unit_econ_table)

    print('CONTEXT WITH UNIT ECON TABLE: ', context)
    return HttpResponse(json.dumps(context), content_type='application/json')


def get_marginz_sales_fn(request):

    #change this for different companies
    product_names_in_scenario = ['Amida TM 500gm', 'Lifuran TM 50ML']

    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        access_token=request.session.get('access_token', None), 
        refresh_token=request.session.get('refresh_token', None), 
        realm_id=request.session.get('realm_id', None),
    )

    if auth_client.access_token is not None:
        access_token = auth_client.access_token

    if auth_client.realm_id is None:
        raise ValueError('Realm id not specified.')

    response_sales = qbo_data_call(auth_client.access_token, 
                             auth_client.realm_id, 
                             type='get_sales')
    
    data_call_response = json.loads(response_sales.content)
    print('RESPONSE IS: ', data_call_response)

    try: 
        sections_in_response = [s for s in data_call_response['Rows']['Row'] 
                            if ('type' in s and s['type'] == 'Section')]

        print('SECTIONS IN RESPONSE ARE: ', sections_in_response)

        if len(sections_in_response) == 0: 
            #print('returning no sales')
            #return 'No sales'
            direct_sales_data = data_call_response['Rows']['Row'][:-1] #remove the last TOTAL row
            if direct_sales_data == 0:
                print('no sales')
                return ('no sale')
            product_sale_details = dict()
            for sale_entry in direct_sales_data:
                sold_product_name = sale_entry['ColData'][0]['value']
                sold_product_quantity = sale_entry['ColData'][1]['value']
                sold_product_average_price = sale_entry['ColData'][4]['value']
                product_sale_details[sold_product_name] = dict()
                product_sale_details[sold_product_name]['quantity'] = sold_product_quantity
                product_sale_details[sold_product_name]['price'] = sold_product_average_price

        else:
            product_sale_details = dict()
            #for each section, remove the header, and extract the data
            for section in sections_in_response:
                if 'Header' in section:
                    section_data = section['Rows']['Row']
                    for sale_entry in section_data:
                        if sale_entry['type'] == 'Data': #Unnecessary check, implicit in section as leaf row
                            sold_product_name = sale_entry['ColData'][0]['value']
                            sold_product_quantity = sale_entry['ColData'][1]['value']
                            sold_product_average_price = sale_entry['ColData'][4]['value']
                            product_sale_details[sold_product_name] = dict()
                            product_sale_details[sold_product_name]['quantity'] = sold_product_quantity
                            product_sale_details[sold_product_name]['price'] = sold_product_average_price

    except Exception as e:
        return('error: ', str(e))

    print('PRODUCT SALE DETAILS ARE: ', product_sale_details)

    response_inventory = qbo_data_call(auth_client.access_token,
                             auth_client.realm_id,
                             type='get_inventory')
    
    data_call_response = json.loads(response_inventory.content)

    print('RESPONSE FOR GET INVENTORY IS: ', data_call_response)

    inventory = data_call_response['QueryResponse']['Item']


    all_inventory_names = [inventory_item['Name'] for inventory_item in inventory]

    #print('ALL INVENTORY NAMES ARE: ', all_inventory_names)


    inventory_name_to_quantity_map = {inventory_item['Name']: inventory_item['QtyOnHand'] if 'QtyOnHand' in inventory_item else 0 
                                        for inventory_item in inventory}

    print('product_names_in_scenario are: ', product_names_in_scenario)
    product_names = [inventory_name for inventory_name in all_inventory_names
                         if inventory_name in product_names_in_scenario]

    print('PRODUCT NAMES ARE: ', product_names)


    product_sales_info = dict()
    for product_name in product_names:
        product = dict()
        #product['product_name'] = product_name
        print('INVENTORY FOR '+product_name + ' is ' + str(inventory_name_to_quantity_map[product_name]))
        product['product_quantity_on_hand'] = (inventory_name_to_quantity_map[product_name])
        try:
            product['product_quantity_sold'] = float(product_sale_details[product_name]['quantity'])
            product['product_price'] = float(product_sale_details[product_name]['price'])
        except: 
            product['product_quantity_sold'] = 0
            product['product_price'] = 0
        product_sales_info[product_name] = product
    
    print('PRODUCT SALES INFO IS: ', product_sales_info)

    number_of_products = len(product_names)

    return (product_sales_info, inventory)
    #return HttpResponse(json.dumps(product_sales_info), content_type='application/json')





def get_sales(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        access_token=request.session.get('access_token', None), 
        refresh_token=request.session.get('refresh_token', None), 
        realm_id=request.session.get('realm_id', None),
    )

    if auth_client.access_token is not None:
        access_token = auth_client.access_token

    if auth_client.realm_id is None:
        raise ValueError('Realm id not specified.')

    response = qbo_data_call(auth_client.access_token, 
                             auth_client.realm_id, 
                             type='get_sales')
    
    data_call_response = json.loads(response.content)
    print('RESPONSE IS: ', data_call_response)

    try: 
        sections_in_response = [s for s in data_call_response['Rows']['Row'] 
                            if ('type' in s and s['type'] == 'Section')]

        print('SECTIONS IN RESPONSE ARE: ', sections_in_response)

        if len(sections_in_response) == 0: 
            print('returning no sales')
            return 'No sales'

        product_sale_details = dict()
        
        #for each section, remove the header, and extract the data
        for section in sections_in_response:
            if 'Header' in section:
                section_data = section['Rows']['Row']
                for sale_entry in section_data:
                    if sale_entry['type'] == 'Data': #Unnecessary check, implicit in section as leaf row
                        sold_product_name = sale_entry['ColData'][0]['value']
                        sold_product_quantity = sale_entry['ColData'][1]['value']
                        sold_product_average_price = sale_entry['ColData'][4]['value']
                        product_sale_details[sold_product_name] = dict()
                        product_sale_details[sold_product_name]['quantity'] = sold_product_quantity
                        product_sale_details[sold_product_name]['price'] = sold_product_average_price

    except Exception as e:
        return('error: ', str(e))

    print('PRODUCT SALE DETAILS ARE: ', product_sale_details)
    
    if not response.ok:
        return HttpResponse(' '.join([response.content, str(response.status_code)]))
    else:
        return HttpResponse(json.dumps(product_sale_details), content_type='application/json')

def get_taxcodes(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        access_token=request.session.get('access_token', None), 
        refresh_token=request.session.get('refresh_token', None), 
        realm_id=request.session.get('realm_id', None),
    )

    if auth_client.access_token is not None:
        access_token = auth_client.access_token

    if auth_client.realm_id is None:
        raise ValueError('Realm id not specified.')

    response = qbo_data_call(auth_client.access_token, 
                             auth_client.realm_id, 
                             type='get_taxcodes')
    
    

    taxcodes = json.loads(response.content)
    #print(taxcodes)
    taxrates = dict()

    for t in taxcodes['QueryResponse']['TaxCode']:
        taxrates[t['Description']] = t['Id']

    print(taxrates)
    if not response.ok:
        return HttpResponse(' '.join([response.content, str(response.status_code)]))
    else:
        return HttpResponse(json.dumps(taxrates), content_type='application/json')

def import_invoice(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT, 
        access_token=request.session.get('access_token', None), 
        refresh_token=request.session.get('refresh_token', None), 
        realm_id=request.session.get('realm_id', None),
    )

    print('CUSTOMER IS: ', request.GET.get('customer_ref'))
    if auth_client.access_token is not None:
        access_token = auth_client.access_token

    if auth_client.realm_id is None:
        raise ValueError('Realm id not specified.')

    payload = {
      "Line": [
        {
          "DetailType": "SalesItemLineDetail", 
          "Amount": request.GET.get('amount'), 
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
      "TxnDate": request.GET.get('txn_date'),
      "DueDate": "2019-03-18",
      "GlobalTaxCalculation": "TaxExcluded",
    }

    response = qbo_data_call(auth_client.access_token, 
                             auth_client.realm_id, 
                             type='import_invoice',
                             payload=payload)
    
    print(response.content)
    if not response.ok:
        return HttpResponse(' '.join([response.content, str(response.status_code)]))
    else:
        return HttpResponse(response.content)

def migration(request):
    auth_client = AuthClient(
        settings.CLIENT_ID, 
        settings.CLIENT_SECRET, 
        settings.REDIRECT_URI, 
        settings.ENVIRONMENT,
    )
    try:
        migrate(
            settings.CONSUMER_KEY, 
            settings.CONSUMER_SECRET, 
            settings.ACCESS_KEY, 
            settings.ACCESS_SECRET, 
            auth_client, 
            [Scopes.ACCOUNTING]
        )
    except AuthClientError as e:
        print(e.status_code)
        print(e.intuit_tid)
    return HttpResponse('OAuth2 refresh_token {0}'.format(auth_client.refresh_token))
