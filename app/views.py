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
