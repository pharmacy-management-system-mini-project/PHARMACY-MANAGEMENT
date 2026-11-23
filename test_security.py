"""Security regressions use Flask's local client and never connect to real data."""
import json
import re
from unittest.mock import patch, MagicMock
import pytest
import app as module

@pytest.fixture
def client():
    module.app.config.update(TESTING=True, SECRET_KEY='test-only-not-a-deployment-secret')
    with module.app.test_client() as c:
        yield c

def token(client, login=False):
    client.get('/login')
    with client.session_transaction() as sess:
        if login: sess['username']='security-test'
        return sess['csrf_token']

def test_reset_cannot_change_password(client):
    csrf=token(client)
    with patch.object(module,'get_db_connection',side_effect=AssertionError('must not access database')):
        assert client.post('/forgot_password',data={'csrf_token':csrf,'username':'any','email':'any','new_password':'changed'}).status_code==403

def test_hosted_signup_disabled(client,monkeypatch):
    monkeypatch.setenv('VERCEL','1')
    monkeypatch.delenv('ALLOW_PUBLIC_REGISTRATION',raising=False)
    assert client.get('/register').status_code==403

def test_forms_receive_csrf(client):
    r=client.get('/login')
    assert b'name="csrf_token"' in r.data
    assert client.post('/login',data={}).status_code==403

def test_cross_site_blocked(client):
    csrf=token(client)
    assert client.post('/login',data={'csrf_token':csrf},headers={'Origin':'https://other.invalid'}).status_code==403

@pytest.mark.parametrize('path',['/delete_medicine/1','/delete_supplier/1','/clear_sales'])
def test_get_cannot_delete(client,path):
    token(client,True)
    with patch.object(module,'get_db_connection',side_effect=AssertionError('must not delete')):
        r=client.get(path)
        assert r.status_code==200 and b'Confirm deletion' in r.data

@pytest.mark.parametrize('qty',[-1,0,1.5,'1.5','-1','NaN',True,None])
def test_bad_quantities(client,qty):
    csrf=token(client,True)
    with patch.object(module,'get_db_connection',side_effect=AssertionError('must not access database')):
        r=client.post('/process_sale',data={'csrf_token':csrf,'customer_name':'test','cart_json':json.dumps([{'id':1,'qty':qty}])})
        assert r.status_code==302

@pytest.mark.parametrize('cart',['broken','null','{}','[]','[null]'])
def test_bad_carts(client,cart):
    csrf=token(client,True)
    with patch.object(module,'get_db_connection',side_effect=AssertionError('must not access database')):
        assert client.post('/process_sale',data={'csrf_token':csrf,'customer_name':'test','cart_json':cart}).status_code==302

@pytest.mark.parametrize('price',['NaN','inf','-1','abc'])
def test_bad_purchase_price(client,price):
    csrf=token(client,True)
    with patch.object(module,'get_db_connection',side_effect=AssertionError('must not access database')):
        assert client.post('/add_purchase',data={'csrf_token':csrf,'quantity':'1','unit_price':price}).status_code==302

def test_server_price_not_browser_price(client):
    csrf=token(client,True)
    db=MagicMock();cur=db.cursor.return_value
    cur.fetchone.return_value={'MEDICINE_NAME':'Test','PRICE':50,'PURCHASE_PRICE':20,'STOCK_QUANTITY':10}
    with patch.object(module,'get_db_connection',return_value=db):
        r=client.post('/process_sale',data={'csrf_token':csrf,'customer_name':'test','cart_json':json.dumps([{'id':1,'qty':2,'price':0.01}])})
    assert r.status_code==302
    inserts=[c for c in cur.execute.call_args_list if c.args[0].startswith('INSERT INTO sales')]
    assert inserts[0].args[1][3]==100
    assert any('FOR UPDATE' in c.args[0] for c in cur.execute.call_args_list)
    db.commit.assert_called_once()

def test_headers_and_size(client):
    r=client.get('/login')
    assert r.headers['X-Content-Type-Options']=='nosniff'
    assert r.headers['X-Frame-Options']=='DENY'
    assert client.post('/login',data=b'x'*(2*1024*1024+1)).status_code==413
