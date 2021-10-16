import logging


class Configuration:
    _configOK = False

    _region = None
    _bucketName = None

    _protectedPaths = []

    _idcsURL = None
    _clientID = None
    _clientSecret = None
    # these are calculated
    # they SHOULD come from the OpenID Connect discovery
    # but I'm just calculating them directly myself
    _azURL = None
    _tokenURL = None

    def __init__(self, configCtx):
        logging.debug("Processing configuration")
        try:
            logging.debug('Getting "BucketName" setting')
            self._bucketName = configCtx.get("BucketName")
            logging.info('Bucket name set to "{}"'.format( self._bucketName) )

            # Region is optional b/c ObjectStore class will default to current
            logging.debug('Checking "Region" setting')
            if "Region" in configCtx:
                logging.debug("Region setting present")
                self._region = configCtx.get("Region")
                logging.info("Region for bucket set to {}".format( self._region))
            else:
                logging.debug("No Region setting. Will assume same region as Function is running within.")

            # the next few are optional but paired up

            # check for protected paths

            if not "ProtectedPaths" in configCtx:
                logging.debug("No protected paths")
            else:
                logging.debug("'ProtectedPaths' setting IS present.")

                # protected paths in this implementation is just a comma separtated list of path prefixes
                self._protectedPaths = configCtx.get("ProtectedPaths").split(",")
                logging.debug("Protected paths setting specifies {} paths".format(len(self._protectedPaths)))
                # sanity check on the paths - they must start with /
                # though they probably should, they don't actually have to end with /
                for path in self._protectedPaths:
                    logging.debug('Checking that "{}" begins with "/"'.format( path ))
                    if not path.startswith("/"):
                        logging.error( "Path {} does not begin with / character".format( path ) )
                        raise RuntimeError("Invalid path specified")
                    else:
                        logging.debug("path OK")

                # if protected paths are specified we need 2 other settings:
                # 1: IDCS URL
                # 2: Client ID
                #
                # and we should have a client secret. More on that in a second

                if not "ProtectedPaths" in configCtx:
                    logging.debug('Missing "IDCSURL" setting')
                    raise RuntimeError("Missing IDCS URL")

                logging.debug("Getting IDCSURL setting")
                self._idcsURL = configCtx.get("IDCSURL")
                logging.info('IDCS URL set to "{}"'.format(self._idcsURL))

                # then sanity check it
                from urllib.parse import urlparse, urljoin
                try:
                    o = urlparse( self._idcsURL)
                except:
                    logging.error("Failed to parse URL")
                    raise RuntimeError("Invalid URL")

                # set AZ and Token URLs
                self._azURL = urljoin(self._idcsURL, "/oauth2/v1/authorize")
                self._tokenURL = urljoin(self._idcsURL, "/oauth2/v1/token")

                logging.debug("Constructed Authorization URL {}".format(self._azURL))
                logging.debug("Constructed Token URL {}".format(self._tokenURL))

                logging.debug("Getting ClientID setting")
                self._clientID = configCtx.get("ClientID")
                logging.info('OAuth Client ID set to "{}"'.format(self._clientID))

                # now about that client secret thing
                # i don't /want/ someone putting the client secret right in the app
                # but I'm putting that outside the scope of this work for now
                # TODO: move that to a Vault
                logging.debug("Getting ClientSecret setting")
                self._clientSecret = configCtx.get("ClientSecret")
                logging.info('OAuth Client Secret set to "{}"'.format(self._clientSecret))

                #TODO: add a check to verify the IDCS URL is good
                #      WITHOUT taking too long

            # if we get to this point the config is OK
            self._configOK = True
        except (Exception) as e:
            logging.error("Invalid configuration")
            logging.critical('Exception: ' + str(e))
            logging.critical(e, exc_info=True)

    def isConfigOK(self):
        return self._configOK

    def getRegion(self):
        return self._region

    def getBucketName(self):
        return self._bucketName

    def protectedPathsDefined(self):
        return len( self._protectedPaths ) > 0

    def getProtectedPaths(self):
        return self._protectedPaths

    def getIDCSURL(self):
        return self._idcsURL

    def getIDCSAuthorizationEndpoint(self):
        return self._azURL

    def getIDCSTokenEndpoint(self):
        return self._tokenURL

    def getClientID(self):
        return self._clientID

    def getClientSecret(self):
        return self._clientSecret

    def isProtected(self, path):
        for ppath in self._protectedPaths:
            logging.debug('Checking {} against protected path "{}"'.format(path,ppath))
            if path.startswith(ppath):
                logging.debug("Protected!")
                return True
            else:
                logging.debug("NOT protected")
                return False

# import pytest
# @pytest.mark
