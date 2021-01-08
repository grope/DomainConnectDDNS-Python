# DynDNS Update Server for router initiated ddns updates
# http://user:password@ddns/update?ipv6=::&ipv4=1.2.3.4&ipv6prefix=::

import bottle
import validators
from bottle import auth_basic, get, request

from .users import authenticate

USERCONFIG = 'users.txt'
def is_authenticated_user(userid, password):
    return authenticate(USERCONFIG, userid, password)

def update_ipv4(userid, ipv4):
    # load user
    # update ipv4 in ddns
    pass

def update_ipv6(userid, ipv6):
    # load user
    # update ipv6 in ddns
    pass

def update_ipv6prefix(userid, ipv6prefix):
    # load user
    # combine prefix with suffix for all domain names (with old prefix?)
    # update ipv4 in ddns
    pass

@get('/ddns/update')
@auth_basic(is_authenticated_user)
def update():
    myip = request.query.myip
    myipv6 = request.query.myipv6
    myipv6prefix = request.query.myipv6prefix
    userid, password = request.auth
    if myip:
      res = validators.ipv4(myip)
      if not res:
        return "Invalid IPv4 address myip={}".format(myip)
      update_ipv4(userid, myip)
    if myipv6:
      res = validators.ipv6(myipv6)
      if not res:
        return "Invalid IPv6 address myipv6={}".format(myipv6)
      update_ipv6(userid, myipv6)
    if myipv6prefix:
      res = validators.ipv6_cidr(myipv6prefix)
      if not res:
        return "Invalid IPv6 prefix myipv6prefix={}".format(myipv6prefix)
      update_ipv6prefix(userid, myipv6prefix)
    return "nothing"

app = application = bottle.default_app()

if __name__ == '__main__':
    bottle.run(host = '0.0.0.0', port = 8000)
