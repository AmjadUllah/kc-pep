from flask import request, url_for, Flask, jsonify, flash
from parameters import keycloak_server, keycloak_realm, client_id, client_secret
import os
import requests
app = Flask(__name__)
import logging
import json

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


@app.route('/access', methods=['POST'])
def access():
    """ API to get access to a particular device a application
        :params user: dictionary with user credentials atributes
        :type input: dictionary
        :params device: dictionary with device information.
        :type input: dictionary
    """
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
        return jsonify(response)
    except Exception as error:
        logger.error(error)
        response["message"]= "Invalid request: {}".format(error)
        response["status_code"]= 422
        return jsonify(response)

@app.route('/status', methods=['GET'])
def status():
    """ API function to get the service status"""
    response = dict(status_code=200, message="The pep service is running.", data=[])
    return jsonify(response)

if __name__ == "__main__":
    __init__()
    app.run(host="0.0.0.0",debug=True, port=5000)