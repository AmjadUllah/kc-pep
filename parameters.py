import os
import logging

""" Configurable parameters provided as enviornment variables """

keycloak_server = os.getenv("KEYCLOAK_SERVER","http://kc-server/auth/")
keycloak_realm = os.getenv("KEYCOLAK_REALM","acFog")
client_id = os.getenv("CLIENT_ID","smartFog")
client_secret = os.getenv("CLIENT_SECRET","dea3ddd2-bca3-4b19-9881-a1637ae69b45")
ssl_mode = os.getenv("SSL_MODE","0") # For (http = 0, https = 1, mTLS = 2)
admin_id = os.getenv("ADMIN_ID","fogmanager")
admin_pwd = os.getenv("ADMIN_PWD","fogmanager")
save_stats = True if os.getenv("SAVE_STATS","false") == "true" else False