import logging

import oci
import os


class ObjectStore:
    _region = ""
    _signer = None
    _bucket_name = None
    _object_storage_client = None
    _namespace = None

    def __init__(self, region, bucketname):
        logging.debug("Initializing object store layer.")
        self._region = region
        self._bucket_name = bucketname

        #TODO: come up with some way to tell this class that we're running a test

        try:
            logging.debug("Instantiating Resource Principal Signer")
            # we are going to use the Resource Principal signer to sign out requests to Object Store:
            self._signer = oci.auth.signers.get_resource_principals_signer()

            if None == region:
                self._region = self._signer.region

            logging.getLogger().info('Getting object store handle')
            self._object_storage_client = oci.object_storage.ObjectStorageClient({ "region": self._region}, signer=self._signer)
            self._namespace = self._object_storage_client.get_namespace().data

        except (Exception) as e:
            logging.getLogger().critical('Exception: ' + str(e))
            logging.critical(e, exc_info=True)
            raise e


    def getObject(self, objectname):

        obj = self._object_storage_client.get_object(self._namespace, self._bucket_name, objectname)

        logging.getLogger().info("Checking content type")
        logging.getLogger().info("Content type of object is " + obj.headers['Content-type'])

        return obj

