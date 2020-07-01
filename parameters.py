import os
import logging

""" Configurable parameters provided as enviornment variables """

keycloak_server = os.getenv("KEYCLOAK_SERVER","http://127.0.0.1/auth/")
keycloak_realm = os.getenv("KEYCOLAK_REALM","acFog")
client_id = os.getenv("CLIENT_ID","smartFog")
client_secret = os.getenv("CLIENT_SECRET","dea3ddd2-bca3-4b19-9881-a1637ae69b45")