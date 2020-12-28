from flask import request, url_for, Flask, jsonify, flash
import parameters
from parameters import keycloak_server, keycloak_realm, client_id, client_secret, ssl_mode, admin_id, admin_pwd, save_stats
import os
import os.path
import requests
app = Flask(__name__)
import logging
import json
import sys
import ssl

import io 
import csv
from flask import make_response
import time

def __init__():
    global logger
    logger =  logging.getLogger("kc-pep."+__name__)
    logging.basicConfig(level=logging.DEBUG)

__init__()

@app.errorhandler(Exception)
def unhandle_request_error(error):
    import traceback as tb
    logger.error("An unhandle exception occured:{}".format(error))
    response = jsonify(dict(message=str(error)))
    response.status_code= 500
    return response

@app.route('/setup', methods=['POST'])
def setup():
    csvList = [["user_name","pwd","device_id","scope"]]
    si = io.StringIO()
    cw = csv.writer(si)
    
    # Read parameters
    input_json_body = request.json
    entries = input_json_body ['entries']
    user_prefix = input_json_body ['user_prefix']
    role_name = input_json_body ['role_name']
    start_index = input_json_body['start_index']
    
    # Response
    response = dict(status_code="", message="", data=[])

    # Get admin access token
    admin_AT = get_admin_access_token()
    if admin_AT == "":
        response["message"] = "Unable to login admin user."
        response["status_code"] = 400
        response = jsonify(dict(message=str(error)))
        response.status_code= 400
        return response
    # get role ID
    role_id = get_role_id(admin_AT,role_name)
    if role_id == "":
        response["message"] = "Unable to obtain role_id."
        response["status_code"] = 400
        response = jsonify(dict(message=str(error)))
        response.status_code= 400
        return response
    # Creat Users, Resources, Policies
    for entry in range(entries):
        index = entry + int(start_index)
        userName, pwd = add_user(admin_AT,index,user_prefix,role_id)
        if userName != "" and pwd != "":
            user_id = get_user_id(admin_AT,userName)
            logger.info("user_id => {0}".format(user_id))
            assign_role_to_user(admin_AT,user_id,role_id,role_name)
            tmpList=[userName,pwd,"deviceB","access"]
            csvList.append(tmpList)
    # Response
    for row in csvList:
        cw.writerow(row)
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=export.csv"
    output.headers["Content-type"] = "text/csv"
    return output

def get_admin_access_token():
    try:
        kc_token_URL = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/token"
        grant_type = "password"
        payload = {"grant_type":grant_type, "client_id":client_id, "client_secret": client_secret, "username":admin_id, "password":admin_pwd}
        r = requests.post(kc_token_URL, data=payload)
        logger.info(r.status_code)
        response  = r.json()
        access_token = response['access_token']
        logger.info("access token: {0}".format(access_token))
        return access_token
    except Exception as e:
        logger.error(e)
        raise e

def get_role_id(access_token,role_name):
        role_id = ""
        role_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/roles/" + role_name 
        headers = {'Authorization': 'Bearer ' + access_token}
        r = requests.get(role_api_url,headers=headers)
        logger.info("Get role id response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == 200:
            result_json = r.json()
            if "id" in result_json.keys():
                role_id = result_json["id"]
        return role_id

def add_user(access_token,entry,user_prefix,role_id):
    user_id = user_prefix + str(entry)
    pwd = user_prefix + str(entry)
    fName = user_prefix
    lName = str(entry)
    email = user_prefix + str(entry) + "@test.com"
    try: 		
        new_user_data = {"email": email,
            "username": user_id,
            "enabled": True,
            "firstName": fName,
            "lastName": lName,
            "realmRoles": ["user_default", ],
            "credentials": [{"value": pwd,"type": "password",}]
        }
        user_uri = keycloak_server + "admin/realms/" + keycloak_realm + "/users"
        headers = {'Authorization': 'Bearer ' + access_token}
        r = requests.post(user_uri,json=new_user_data,headers=headers)
        logger.info("Status Code => {0} \n Text => {1}".format(r.status_code,r.text))
        if r.status_code == 201:
            return user_id,pwd
        return "",""
    except Exception as error:
        logger.error(error)
        raise error

def get_user_id(access_token,user_name):
        user_id = ""
        users_api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users?username=" + user_name 
        headers = {'Authorization': 'Bearer ' + access_token}
        r = requests.get(users_api_url,headers=headers)
        logger.info("Get user id response. \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == 200:
            ret  = r.json()
            if ret!=[]: 
                user_id  = r.json()[0]['id']
        return user_id

def assign_role_to_user(access_token,user_id,role_id,role_name):   # assign role to user
    try:
        api_url = keycloak_server + "admin/realms/" + keycloak_realm + "/users/" + user_id + "/role-mappings/realm"
        headers = {'Authorization': 'Bearer ' + access_token}
        roles = [{"id": role_id, "name": role_name}]
        r = requests.post(api_url,json=roles,headers=headers)
        logger.info("Assign role response: \n status_code => {0} \n response_message => {1}".format(r.status_code,r.text))
        if r.status_code == 204:
            logger.info("Role assignment successful.")
        else:
            logger.error("Role assignment unsuccessful")
    except Exception as e:
        logger.error(e)
        raise e

def record_stat(start_time):
    if save_stats == True:
        end_time = time.time()
        elapsed = end_time - start_time
        row = "\n" + str(start_time) + "," + str(end_time) + "," + str(elapsed)
        f = open("results.csv", "a")
        f.write(row)
        f.close()
        
@app.route('/access', methods=['POST'])
def access():
    """ API to get access to a particular device a application
        :params user: dictionary with user credentials atributes
        :type input: dictionary
        :params device: dictionary with device information.
        :type input: dictionary
    """
    start_time = time.time()
    response = dict(status_code="", message="", data=[])
    try:
        logger.debug("User access request received.")

        # Fetch input data
        input_json_body = request.json
        user_id = input_json_body ['user_id']
        user_pwd = input_json_body ['pwd']
        device_id = input_json_body ['device_id']
        access_scope = input_json_body ['scope']

        # Login user to fetch access token
        kc_token_URL = keycloak_server + "realms/" + keycloak_realm + "/protocol/openid-connect/token"
        grant_type = "password"
        payload = {"grant_type":grant_type, "client_id":client_id, "client_secret": client_secret, "username":user_id, "password":user_pwd}
        r_authenticate = requests.post(kc_token_URL, data=payload) # The payload format, as per Keycloak API, is x-www-form-urlencoded
        if r_authenticate.status_code == 200:
            # Obtain RPT
            access_token = r_authenticate.json()['access_token']
            logger.info("Access token => {0}".format(access_token))
            permission = device_id + "#" + access_scope
            rpt_payload = {"grant_type":"urn:ietf:params:oauth:grant-type:uma-ticket", "audience":client_id, "permission":permission} 
            headers = {"Authorization": "Bearer " + access_token}
            r_authorise = requests.post(kc_token_URL, headers=headers, data=rpt_payload) # The payload format, as per Keycloak API, is x-www-form-urlencoded
            if r_authorise.status_code == 200:
                logger.info("Authorise. The rpt toke is => {0}".format(r_authorise.json()['access_token']))
                response["message"] = "Access granted"
                response["status_code"] = 200
            elif r_authorise.status_code == 403:
                logger.info("Not Authorise")
                response["message"] = "Not Authorise"
                response["status_code"] = 403
            else:
                logger.info("Bad request => {0}".format(r_authorise.text))
                response["message"] = "Bad request"
                response["status_code"] = r_authorise.status_code
                response["data"].append('Keycloak returned error: {}'.format(r_authorise.text))
        else:
            logger.info("Bad request => {0}".format(r_authenticate.text))
            response["message"] = "Bad request"
            response["status_code"] = r_authenticate.status_code
            response["data"].append('Keycloak returned error: {}'.format(r_authenticate.text))
        record_stat(start_time)
        return jsonify(response)
    except Exception as error:
        logger.error(error)
        response["message"]= "Invalid request: {}".format(error)
        response["status_code"]= 422
        record_stat(start_time)
        return jsonify(response)

@app.route('/test', methods=['POST'])
def test():
    """ Post test API
    """
    response = dict(status_code="", message="", data=[])
    try:
        #logger.debug("Test post request received.")

        # Fetch input data
        input_json_body = request.json
        user_id = input_json_body ['user_id']
        user_pwd = input_json_body ['pwd']
        device_id = input_json_body ['device_id']
        access_scope = input_json_body ['scope']
        logger.info("Test post request received \
            \n\tUserID => {0} \n\tPwd => {1} \n\tDeviceID => {2} \n\tScope => {3}" \
                .format(user_id,user_pwd,device_id,access_scope))
        response["message"] = "Success"
        response["status_code"] = 200
        return jsonify(response)
    except Exception as error:
        logger.error(error)
        response["message"]= "Invalid request: {}".format(error)
        response["status_code"]= 422
        record_stat(start_time)
        return jsonify(response)

@app.route('/status', methods=['GET'])
def status():
    """ API function to get the service status"""
    response = dict(status_code=200, message="The pep service is running.", data=[])
    return jsonify(response)

if __name__ == "__main__":
    __init__()
    logger.info("kc-pep started with: \nOperational ssl_mode is => {0} \nSave stats => {1}".format(ssl_mode,save_stats))
    if save_stats == True:
        f = open("results.csv", "w")
        f.write("start_time,end_time,proc_time")
        f.close()

    if int(ssl_mode) == 1 or int(ssl_mode) == 2:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        if os.path.exists('certs/server.crt') == False or os.path.exists('certs/server.key') == False:
            logger.error("Certificates files are missing")
            sys.exit()
        if int(ssl_mode) == 2:
            if os.path.exists('certs/ca.crt') == False:
                logger.error("CA certificate file is missing")
                sys.exit()
            else:
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations("certs/ca.crt")
        context.load_cert_chain("certs/server.crt", "certs/server.key")
        app.run(host="0.0.0.0",debug=True, port=5000, ssl_context=context)
    else:
        app.run(host="0.0.0.0",debug=True, port=5000)