=========================
SakuraCloud
=========================

This provider uses a Kubernetes ``Secret`` Resource to work. In the
following example, the secret will have to be named ``sakuracloud-dns``
and have a subkey ``access-token`` and ``access-secret`` with the APIKey in it.

To create an API Access Key, see `SakuraCloud documentation <https://manual.sakura.ad.jp/cloud/api/apikey.html/>`_.
Handy direct link: https://secure.sakura.ad.jp/cloud/?#!/apikey/top/


.. code-block:: yaml
   :emphasize-lines: 10-16

   apiVersion: cert-manager.io/v1alpha2
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
       ...
       solvers:
       - dns01:
           sakuracloud:
             accessTokenSecretRef:
               name: sakuracloud-dns
               key: access-token
             accessSecretSecretRef:
               name: sakuracloud-dns
               key: access-secret
