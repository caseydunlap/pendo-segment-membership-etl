import snowflake.connector
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import requests
import json
import base64
from sqlalchemy import create_engine
import boto3
import pandas as pd

#Load secrets from secrets manager
def get_secrets(secret_names, region_name="us-east-1"):
    secrets = {}
    
    client = boto3.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    for secret_name in secret_names:
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name)
        except Exception as e:
                raise e
        else:
            if 'SecretString' in get_secret_value_response:
                secrets[secret_name] = get_secret_value_response['SecretString']
            else:
                secrets[secret_name] = base64.b64decode(get_secret_value_response['SecretBinary'])

    return secrets
    
#Extract secret values from fetched secrets
def extract_secret_value(data):
    if isinstance(data, str):
        return json.loads(data)
    return data

secrets = ['pendo_api_key','snowflake_bizops_user','snowflake_account','snowflake_key_pass','snowflake_bizops_wh','snowflake_fivetran_db','snowflake_bizops_role','segment_membership_table']

fetch_secrets = get_secrets(secrets)

extracted_secrets = {key: extract_secret_value(value) for key, value in fetch_secrets.items()}

pendo_api_key = extracted_secrets['pendo_api_key']['pendo_api_key']
snowflake_user = extracted_secrets['snowflake_bizops_user']['snowflake_bizops_user']
snowflake_account = extracted_secrets['snowflake_account']['snowflake_account']
snowflake_key_pass = extracted_secrets['snowflake_key_pass']['snowflake_key_pass']
snowflake_bizops_wh = extracted_secrets['snowflake_bizops_wh']['snowflake_bizops_wh']
snowflake_schema = 'PENDO'
snowflake_fivetran_db = extracted_secrets['snowflake_fivetran_db']['snowflake_fivetran_db']
snowflake_role = extracted_secrets['snowflake_bizops_role']['snowflake_bizops_role']
dest_table = extracted_secrets['segment_membership_table']['segment_membership_table']

password = snowflake_key_pass.encode()

#AWS S3 Configuration params
s3_bucket = 'aws-glue-assets-bianalytics'
s3_key = 'BIZ_OPS_ETL_USER.p8'

#Function to download file from S3
def download_from_s3(bucket, key):
    s3_client = boto3.client('s3')
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        return response['Body'].read()
    except Exception as e:
        print(f"Error downloading from S3: {e}")
        return None

#Download the private key file from S3
key_data = download_from_s3(s3_bucket, s3_key)

#Load the private key as PEM
private_key = load_pem_private_key(key_data, password=password)

#Extract the private key bytes in PKCS8 format
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption())

#Fetch all segment ids
url = f'https://app.pendo.io//api/v1/segment'

headers = {
    'x-pendo-integration-key':pendo_api_key,
    'Content-Type': 'application/json',
    'x-pendo-base64-encoded-params':'true'
}

response = requests.get(url, headers=headers)
all_segments = response.json()
segment_ids = [segment.get('rootVersionId') for segment in all_segments]

#Fetch high level segment details
segment_data = []

for i in segment_ids:
    url = f'https://app.pendo.io/api/v1/segment/{i}'
    response = requests.get(url, headers=headers)
    segment_info = response.json()
    segment_data.append(segment_info)
    
seg_dets = []

for segment in segment_data:
    segment_id = segment.get('id')
    segment_name = segment.get('name')
    seg_dets.append({'Segment ID': segment_id, 'Name': segment_name})

segment_base_df = pd.DataFrame(seg_dets)

#Iterate through each segment, use the aggregation endpoint to fetch membership
membership_url = 'https://app.pendo.io/api/v1/aggregation'

headers = {
    'Content-Type': 'application/json',
    'X-Pendo-Integration-Key': pendo_api_key
}


segment_membership = []

for i in segment_ids:
    payload = {
        "response": {
            "mimeType": "application/json"
        },
        "request": {
            "pipeline": [
                {
                    "source": {
                        "visitors": None
                    }
                },
                {
                    "identified": "visitorId"
                },
                {
                    "eval": {
                        "accountId": "metadata.auto.accountids"
                    }
                },
                {
                    "unwind": {
                        "field": "accountId",
                        "keepEmpty": True
                    }
                },
                {
                    "bulkExpand": {
                        "account": {
                            "account": "accountId"
                        }
                    }
                },
                {
                    "segment": {
                        "id": i
                    }
                },
                {
                    "select": {
                        "visitorId": "visitorId",
                        "accountId": "accountId"
                    }
                }
            ]
        }
    }
    response = requests.post(membership_url, headers=headers, json=payload)

    if response.status_code == 200:
        data = response.json()
        segment_membership.append({
        'segmentid': i,
        'results': data.get('results', [])
    })

#Extract data at the visitor level
segment_visitors = []

for segment in segment_membership:
    segment_id = segment['segmentid']
    results = segment.get('results', [])

    #Loop through each result to extract visitorId and accountId
    for result in results:
        visitor_id = result.get('visitorId')
        account_id = result.get('accountId')
        segment_visitors.append({
            'Segment ID': segment_id,
            'Visitor ID': visitor_id,
            'Account ID': account_id
        })

#Convert the list of dictionaries to a dataframe
detailed_membership = pd.DataFrame(segment_visitors)

#Build the import dataframe
import_df = pd.merge(detailed_membership,segment_base_df,left_on='Segment ID',right_on='Segment ID')

#Do some data cleanup, preparing for snowflake import
import_df.drop(columns=['Account ID'],inplace=True)
cols_mapping = {'Segment ID':'segment_id','Visitor ID':'visitor_id','Name':'segment_name'}
import_df.rename(columns=cols_mapping,inplace=True)

#Delete existing rows, start fresh for each run 
ctx = snowflake.connector.connect(
    user=snowflake_user,
    account=snowflake_account,
    private_key=private_key_bytes,
    role=snowflake_role,
    warehouse=snowflake_bizops_wh)

cs = ctx.cursor()
script = f"""
delete from "{snowflake_fivetran_db}"."{snowflake_schema}"."{dest_table.upper()}"
"""
delete = cs.execute(script)

#Construct the SQLAlchemy connection string
connection_string = f"snowflake://{snowflake_user}@{snowflake_account}/{snowflake_fivetran_db}/{snowflake_schema}?warehouse={snowflake_bizops_wh}&role={snowflake_role}&authenticator=externalbrowser"

#Instantiate SQLAlchemy engine with the private key
engine = create_engine(
    connection_string,
    connect_args={
        "private_key": private_key_bytes
    }
)

#Import data to snowflake
chunk_size = 10000
chunks = [x for x in range(0, len(import_df), chunk_size)] + [len(import_df)]
table_name = dest_table

for i in range(len(chunks) - 1):
    import_df[chunks[i]:chunks[i + 1]].to_sql(table_name, engine, if_exists='append', index=False)




