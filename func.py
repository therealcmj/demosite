import io
import json
import logging
import pytest

from fdk import fixtures
from fdk import response

from oauthlib.oauth2 import WebApplicationClient

# fnConfig = None
from Configuration import Configuration
from ObjectStore import ObjectStore

# we declare these 2 globally to save compute time on every invocation
fnConfig = None
myosc = None

callbackURL = None

def handler(ctx, data: io.BytesIO=None):
    logging.getLogger().info("Inside Python function")

    global fnConfig
    global myosc

    try:
        if None == fnConfig:
            fnConfig = Configuration(ctx.Config())

            # if the config is OK then initialize the Objest Store layer
            if fnConfig.isConfigOK():
                myosc = ObjectStore(fnConfig.getRegion(), fnConfig.getBucketName())

        # if we are invoked by a means other than HTTP we return some debugging info to the caller
        # TODO: add a way to test retrieve an object from the bucket
        if None == ctx.RequestURL():
            logging.getLogger().info("Collecting debug info for caller")

            retstring = ""
            retstring += "Funtion loaded properly but not invoked via an HTTP request!\n"
            retstring += "\n"
            retstring += "Environment:\n"
            retstring += "------------\n"
            import os
            for k, v in os.environ.items():
                retstring += "%s=%s\n" % (k, v)
            retstring += "\n"

            retstring += "Configuration OK: {}\n".format( fnConfig.isConfigOK() )
            retstring += "----------------  -----------------------------------------------------------------------\n"
            retstring += "     Bucket Name: {}\n".format( fnConfig.getBucketName())
            retstring += "          Region: {}\n".format( fnConfig.getRegion() )
            retstring += " Protected Paths: {}\n".format( fnConfig.getProtectedPaths() )
            retstring += "        IDCS URL: {}\n".format( fnConfig.getIDCSURL() )
            retstring += "       Client ID: {}\n".format( fnConfig.getClientID() )
            retstring += "          Secret: {}\n".format( fnConfig.getClientSecret() )
            return retstring

        else:
            logging.debug("HTTP Headers:")
            for k, v in ctx.HTTPHeaders().items():
                logging.debug('"%s" => "%s"' % (k, v))
                # logging.debug('"%s" => "%s"' % (k, ctx.HTTPHeaders().get(k)))
                # k = k.upper()
                # logging.debug('"%s" => "%s"' % (k, ctx.HTTPHeaders().get(k)))

        global callbackURL
        if not callbackURL:
            logging.debug("Constructing callback URL")
            logging.debug("Host: {}".format(ctx.HTTPHeaders().get("host")))
            # we're assuming https here.
            callbackURL = "https://" + ctx.HTTPHeaders().get("host") + "/callback/"
            logging.debug("Callback URL: {}".format(callbackURL))

        if fnConfig.isConfigOK():
            logging.info("Configuration appears to be OK. Proceeding.")
        else:
            logging.error("Configuration NOT ok. returning runtime error.")
            raise RuntimeError("Invalid configuration. Please see logs")

        # now on to the meat of the function...

        # ctx.RequestURL() returns a URI, not a URL. For historical reasons.
        logging.getLogger().info("URI: " + ctx.RequestURL() )
        # URI will always be well formed (i.e. no ../ or anything like that) because the API GW
        # and/or FDK strip that out

        file_object_name = ctx.RequestURL()

        if fnConfig.protectedPathsDefined():
            # check the URL to see if it's protected
            # WARNING:
            # WARNING:   This check is before we tack on index.html
            # WARNING:
            # WARNING:   This means that if you protect /foo/index.html and the user accesses /foo/ it will NOT be
            # WARNING:   protected.
            # WARNING:
            # WARNING:   This is intentional since the ≤ CORRECT ≥ thing to do is to protect /foo/
            # WARNING:   Since this is an example it's fine but you should be aware of this nuance and why it works
            # WARNING    this way..

            logging.debug("Protected paths defined!")
            # first check to see if the user is coming back to the callback URL

            if ctx.RequestURL().startswith("/callback/"):
                # handle the callback
                logging.debug("Request is for callback URL - processing callback")

                # when in doubt...
                location = "/"
                username = None

                from oauthlib.common import urldecode
                from oauthlib.oauth2 import WebApplicationClient
                client = WebApplicationClient(fnConfig.getClientID())

                # this is silly but we have to pre-pend the request URI with https://something in order to get the parse_request_uri_response to not complain about HTTP vs HTTPS
                params = client.parse_request_uri_response( "https://me" + ctx.RequestURL() )
                logging.debug("Client state: {}".format(params["state"]))

                if params["state"] and params["state"].startswith("/"):
                    # a little safety here - make sure state starts with / to prevent open an redirect attack
                    location = params["state"]
                    logging.debug('Redirect location from state is now "{}"'.format(location))
                if client.code:
                    azCode = client.code
                    logging.info( 'AZ Code: "{}"'.format( azCode ))

                    # swap it
                    postpayload = client.prepare_request_body(
                        code=azCode,
                        redirect_uri=callbackURL,
                        client_id=fnConfig.getClientID(),
                        client_secret=fnConfig.getClientSecret()
                    )

                    logging.debug("POST payload: " + postpayload)

                    import requests
                    r = requests.post(
                        fnConfig.getIDCSTokenEndpoint(),
                        data = urldecode(postpayload)
                    )
                    logging.debug("HTTP response code {}".format(str(r.status_code)))

                    logging.debug("POST payload response:")
                    logging.debug(r.text)

                    jr = json.loads( r.text )
                    logging.debug( "JSON:\n{}".format( json.dumps(jr,indent=4,sort_keys=True)))

                    if not jr["id_token"]:
                        logging.error("No ID token")
                    else:
                        logging.debug("ID Token located in payload")
                        idtoken = jr["id_token"]

                        # OK this is dangerous.
                        # not super duper dangerous (since we got the payload over HTTPS
                        # but still not great
                        import jwt
                        claims = jwt.decode(idtoken, options={"verify_signature": False})

                        logging.debug("Claims:")
                        logging.debug( json.dumps( claims, indent=4 ) )

                        username = claims["sub"]
                        logging.debug("Username: {}".format(username))

                redirectHeaders = {
                    "location": location
                }
                if username:
                    import codecs
                    redirectHeaders["Set-Cookie"] = "username=" + codecs.encode(username, 'rot_13') + "; path=/"

                # import codecs
                logging.debug('Redirecting to "{}" with username {}'.format(location,username))
                return response.Response( ctx,
                                          headers = redirectHeaders,
                                          response_data = "Page moved",
                                          status_code = 302)

            # and then check the path to see if the URL they're accessing it protected
            if not fnConfig.isProtected( file_object_name ):
                logging.info( "{} is NOT a protected path".format( file_object_name ) )
            else:
                logging.info( "{} IS a protected path".format( file_object_name ) )

                username = None
                if None == ctx.HTTPHeaders().get("cookie"):
                    logging.info("No cookie header.")
                else:
                    logging.debug("Getting cookies")
                    cookies = ctx.HTTPHeaders().get("cookie").split(';')
                    print( "Number of cookies: ".format( len(cookies)) )
                    for cookie in cookies:
                        # if we find a cookie with username= at start then that's the username
                        if cookie.startswith( "username="):
                            # we should be mnore careful here but this is just example code so...
                            try:
                                import codecs
                                username = codecs.encode(cookie[9:], 'rot_13')
                            except:
                                logging.error("Failed to decode username from username cookie")

                logging.info("Username: {}".format(username))

                if not username:
                    # construct the AZ URL call
                    from oauthlib.oauth2 import WebApplicationClient
                    client = WebApplicationClient(fnConfig.getClientID())
                    location = client.prepare_request_uri( fnConfig.getIDCSAuthorizationEndpoint(),
                                                        redirect_uri=callbackURL,
                                                        scope=['openid'],
                                                        state=ctx.RequestURL()
                                                        # scope = ['profile', 'openid'])
                                                           )
                    logging.info("Redirecting user to " + location )

                    return response.Response( ctx,
                                              headers={
                                                  "Location": location
                                              },
                                              response_data = "Page moved",
                                              status_code = 302)

        if file_object_name.endswith("/"):
            logging.getLogger().info("Adding index.html to request URL " + file_object_name)
            file_object_name += "index.html"
        # strip off the first character of the URI (i.e. the /)
        file_object_name = file_object_name[1:]

        logging.getLogger().info("getting object " + file_object_name)
        try:
            obj = myosc.getObject(file_object_name)
        except:
            # TODO: separate 404 from 500
            logging.getLogger().info("Exception caught, returning 404!")
            return response.Response(
                ctx, response_data="File not found",
                headers={"Content-Type": "text/plain"}
            )

        logging.getLogger().info("Returning response")
        return response.Response(
            ctx, response_data=obj.data.content,
            headers={"Content-Type": obj.headers['Content-type']}
        )

    except (Exception) as e:
        logging.getLogger().critical('Exception: ' + str(e))
        logging.critical(e, exc_info=True)

        return response.Response(
            ctx,
            status_code=500,
            response_data="500 Server error\n"+str(e),
            headers={"Content-Type": "text/plain"}
            )

    logging.getLogger().info("Returning a 200")
    return response.Response(
        ctx,
        status_code=200,
        response_data="OK 4\n",
        headers={"Content-Type": "text/plain"}
        )

# if __name__ == '__main__':
#     class Context:
#         def RequestURL(self):
#             return "/"
#             # return None
#         def Config(self):
#             def get(self, str):
#                 return ""
#
#         def SetResponseHeaders(self, headers, status_code):
#             return
#
#     ctx = Context()
#     handler( ctx, None)
#
# # @pytest.mark.asyncio
# # async def test_parse_request_without_data():
# #     call = await fixtures.setup_fn_call(handler)
# #
# #     content, status, headers = await call
# #
# #     assert 202 == status
# #     assert {"message": "Hello World"} == json.loads(content)


@pytest.mark.asyncio
async def test_parse_request_without_data():
    call = await fixtures.setup_fn_call(handler)

    content, status, headers = await call

    assert 500 == status
    # assert {"message": "Hello World"} == json.loads(content)
